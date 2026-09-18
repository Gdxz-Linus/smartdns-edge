use super::{DnsHandle, reap_tasks, sanitize_src_address};
use crate::{dns::SerialMessage, libdns::Protocol, log};
use std::sync::Arc;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

/// 单个 UDP 监听任务的接收缓冲大小（用户定调：不大于 16 KiB）。
///
/// 为什么不是 64 KiB、也不是"只保证 4096"：
/// * 合法查询报文极小 —— 普通查询几十字节，即使按 RFC 8467 做 EDNS 填充也停在几百字节；
///   公开测量（.nl 1140 亿条、Google Public DNS）里 >1232 字节的报文不到 1%，
///   >4 KiB 的查询基本只出现在攻击/畸形流量里。所以 16 KiB 已经覆盖了全部正常使用。
/// * 但"缓冲开多大"和"每次收包时能用多少"是两件事：原来初建 64 KiB，可每收一个包
///   `split()` 就把**该包长度**从剩余容量里切走，补货阈值却只保证"剩余 ≥ 4096" ——
///   于是收包时的可用空间在 4096～65536 之间漂移。后果：同一实例里先收一条 60 KB 的包，
///   之后 12 KB 的**合法**查询就收不到了（Windows 报 `os error 10040` 直接丢包，
///   Linux 由内核静默截断成残包）。
/// * 现在改为"定长缓冲 + 每次收包都是完整的 16 KiB"：行为确定，内存固定 16 KiB/监听任务。
///   超过 16 KiB 的报文一律收不全（Windows 报错丢包并告警，Linux 静默截断），
///   这是刻意接受的边界。
const UDP_RECV_BUFFER_SIZE: usize = 16 * 1024;

// 🌟 接收外部传入的 token，不再自己创建和返回
pub fn serve(socket: net::UdpSocket, handler: DnsHandle, token: CancellationToken) {
    let cancellation_token = token;

    // 🌟 终极优化：在 Linux 下配合 SO_REUSEPORT 实现内核级多队列负载均衡！
    // 配合底层的 4MB SO_RCVBUF，彻底榨干网卡吞吐极限！
    let socket = Arc::new(socket);

    tokio::spawn(async move {
        // 定长接收缓冲：生命周期与监听任务相同，收包时永远是完整的 16 KiB
        // （不再用 BytesMut + split()：那会把容量一点点吃掉，可用空间随前序流量漂移）
        let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
        let mut inner_join_set = JoinSet::new();

        log::debug!("UDP IO Reactor started");

        // 🔐 P2：连续收包出错的次数（用于退避 + 日志降频）
        let mut err_streak: u32 = 0;
        // 🔐 A5：累计收到"超过接收缓冲"的大包次数。**故意不随成功收包清零** ——
        // 否则攻击者用"大包与正常包交替"就能让日志降频失效（每条错误都被当成第 1 次打印）。
        let mut oversize_total: u32 = 0;

        loop {
            // 定期清理已完成的发送子任务，防止内存泄漏
            reap_tasks(&mut inner_join_set);

            let (len, src_addr) = tokio::select! {
                // 收一个包到定长缓冲；可读长度由 len 给出
                res = socket.recv_from(&mut buf) => match res {
                    Ok(res) => {
                        // 收包恢复正常：退避计数归零
                        err_streak = 0;
                        res
                    }
                    Err(e) => {
                        // 🔐 A5：报文本身超过接收缓冲（Windows 报 os error 10040，Linux 报 EMSGSIZE）
                        // 属"单包可恢复"：内核已丢掉这条报文、循环不会空转，所以**不参与退避** ——
                        // 否则攻击者每发一条 >16 KiB 的包就能让本监听睡最多 1 秒（4 MB 内核缓冲
                        // ÷ 16 KiB ≈ 255 条即可填满队列），正常查询跟着排队甚至被丢弃。


                        // 🔐 A5：报文本身超过接收缓冲（Windows 报 os error 10040，Linux 报 EMSGSIZE）
                        // 属"单包可恢复"：内核已丢掉这条报文、循环不会空转，所以**不参与退避** ——
                        // 否则攻击者每发一条 >16 KiB 的包就能让本监听睡最多 1 秒（4 MB 内核缓冲
                        // ÷ 16 KiB ≈ 255 条即可填满队列），正常查询跟着排队甚至被丢弃。
                        if crate::server::is_oversized_datagram(&e) {
                            oversize_total = oversize_total.saturating_add(1);
                            if crate::server::should_log_stream_error(oversize_total) {
                                log::warn!(
                                    "UDP 报文超过接收缓冲上限 {} 字节，已丢弃（累计第 {} 次；这类客户端应改用 TCP 重问）: {}",
                                    UDP_RECV_BUFFER_SIZE,
                                    oversize_total,
                                    e
                                );
                            }
                            continue;
                        }
                        // 🔐 P2：不再"出错就立刻 continue"——持续性错误（网卡消失、fd 耗尽）
                        // 会让循环 100% CPU 空转并把日志刷爆。这里退避 + 日志降频。
                        err_streak = err_streak.saturating_add(1);
                        if crate::server::should_log_stream_error(err_streak) {
                            log::warn!(
                                "error receiving message on udp_socket（连续第 {} 次）: {}",
                                err_streak,
                                e
                            );
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(crate::server::error_backoff_delay(err_streak)) => {}
                            _ = cancellation_token.cancelled() => break,
                        }
                        continue;
                    }
                },
                _ = cancellation_token.cancelled() => break,
            };

            log::debug!("received udp request from: {}", src_addr);

            // 验证地址合法性
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!("address can not be responded to {}: {}", src_addr, e);
                // 定长缓冲下不需要"清残留"：下面只按本次的 len 取数据，不会串到下一个包
                continue;
            }

            // 只拷贝本次读到的 len 字节：一次拷贝换来"缓冲不再是共享资产"，
            // 也避免把整块缓冲钉在 in-flight 的请求上（原来 split() 会让每个待处理请求
            // 都引用同一块大缓冲的引用计数）。
            let packet = bytes::Bytes::copy_from_slice(&buf[..len]);
            let handler = handler.clone();
            let socket_clone = socket.clone();

            // 🌟 业务解耦：把查缓存、双栈测速的重活，全部扔给 Tokio 多核线程池并发执行！
            inner_join_set.spawn(async move {
                let req_message = SerialMessage::binary(packet, src_addr, Protocol::Udp);
                let res_message = handler.send(req_message).await;

                if let Ok(buffer) = Vec::<u8>::try_from(res_message) {
                    // 只放行"真正的应答"（至少 12 字节报文头 + QR=1）。
                    // 原来的判断是 `!buffer.is_empty()`，它只拦得住"系统降载/请求被丢弃"那条
                    // 返回**空 Vec** 的暗号（`server/mod.rs` 的 Load Shedding），却拦不住另一类：
                    // 报文解析失败的兜底曾把一个 `Message::query()`（QR=0、全零计数）当应答发出去
                    // —— 序列化后是 12 字节，非空 → 照样发（客户端 ID 对不上，表现为超时）。
                    if is_dns_response(&buffer) {
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

/// 判断一个序列化后的报文是不是"可以发出去的 DNS 应答"。
///
/// 判据用协议位、不用字节长度（长度判不出语义）：
/// - 至少要有 12 字节的报文头：`server/mod.rs` 在"系统降载/请求被丢弃"时返回的是**空 Vec**
///   （沉默丢弃的暗号），半截包也不该发；
/// - QR 位必须是 1（这是应答，不是查询）：实测解析失败的兜底曾发过 QR=0 的 12 字节包。
fn is_dns_response(buffer: &[u8]) -> bool {
    buffer.len() >= 12 && buffer[2] & 0x80 != 0
}

#[cfg(test)]
mod tests {
    use super::is_dns_response;

    #[test]
    fn test_only_real_dns_responses_are_sendable() {
        // 降载/丢弃暗号：空 Vec
        assert!(!is_dns_response(&[]), "空包（沉默丢弃暗号）不得发出");
        // 不足一个报文头
        assert!(!is_dns_response(&[0u8; 11]), "不足 12 字节不得发出");
        // 12 字节、QR=0（解析失败兜底以前发的那个"查询当应答"）
        assert!(
            !is_dns_response(&[0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]),
            "QR=0 的报文不是应答，不得发出"
        );
        // 12 字节、QR=1（FormErr / NotImp / Refused 这类正常应答，可以没有记录）
        assert!(
            is_dns_response(&[0x12, 0x34, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0]),
            "QR=1 的应答应当放行"
        );
    }
}
