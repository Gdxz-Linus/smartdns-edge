use super::{DnsHandle, reap_tasks, sanitize_src_address};
use crate::{dns::SerialMessage, libdns::Protocol, log};
use std::sync::Arc;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

// 🌟 接收外部传入的 token，不再自己创建和返回
pub fn serve(socket: net::UdpSocket, handler: DnsHandle, token: CancellationToken) {
    let cancellation_token = token;
    
    // 🌟 终极优化：在 Linux 下配合 SO_REUSEPORT 实现内核级多队列负载均衡！
    // 配合底层的 4MB SO_RCVBUF，彻底榨干网卡吞吐极限！
    let socket = Arc::new(socket);

    tokio::spawn(async move {
        // 🌟 核心修复：引入 BytesMut 内存池，彻底解决堆碎片化与 to_vec 拷贝开销
        let mut buf = bytes::BytesMut::with_capacity(65536);
        let mut inner_join_set = JoinSet::new();
        
        log::debug!("UDP IO Reactor started");

        loop {
            // 定期清理已完成的发送子任务，防止内存泄漏
            reap_tasks(&mut inner_join_set);

            // 确保缓冲池始终有足够连续空间接收一个极限大小的 UDP 包 (通常 4096 足矣)
            if buf.capacity() < 4096 {
                buf.reserve(65536);
            }

            let (_len, src_addr) = tokio::select! {
                // 🌟 使用 recv_buf_from 替代 recv_from，直接写入内存池并自动步进指针！
                res = socket.recv_buf_from(&mut buf) => match res {
                    Ok(res) => res,
                    Err(e) => {
                        log::warn!("error receiving message on udp_socket: {}", e);
                        continue;
                    }
                },
                _ = cancellation_token.cancelled() => break,
            };

            log::debug!("received udp request from: {}", src_addr);

            // 验证地址合法性
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!("address can not be responded to {}: {}", src_addr, e);
                // 如果地址不合法，必须丢弃这次读到的数据，防止残留到下一个包！
                buf.clear(); 
                continue;
            }

            // 🌟 零拷贝截取：底层仅仅是增加一次引用计数，分离出一个只读视图 (Bytes)，毫无堆分配与内存复制开销！
            // split() 会精确截取刚才 recv_buf_from 读取的长度，而 buf 会被清空并保留剩余 capacity 给下一个包。
            let packet = buf.split().freeze();
            let handler = handler.clone();
            let socket_clone = socket.clone();

            // 🌟 业务解耦：把查缓存、双栈测速的重活，全部扔给 Tokio 多核线程池并发执行！
            inner_join_set.spawn(async move {
                let req_message = SerialMessage::binary(packet, src_addr, Protocol::Udp);
                let res_message = handler.send(req_message).await;
                
                if let Ok(buffer) = Vec::<u8>::try_from(res_message) {
                    // 🌟 核心修复 2：严格拦截暗号！如果发现是系统降载产生的空包，
                    // 绝不发送给任何人，直接当场沉默丢弃，彻底熔断反射攻击链！
                    if !buffer.is_empty() {
                        // 发包时也不阻塞，直接通过 Arc Socket 返回客户端
                        if let Err(err) = socket_clone.send_to(&buffer, src_addr).await {
                            log::trace!("UDP stream send failed: {:?}", err); // 降级为 trace
                        }
                    }
                }
            });
        }
    });
}