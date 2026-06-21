use std::time::Duration;

use futures_util::StreamExt;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    dns::SerialMessage,
    libdns::{
        Protocol,
        proto::runtime::iocompat::AsyncIoTokioAsStd,
        proto::{tcp::TcpStream, xfer::DnsStreamHandle as _},
    },
    log,
    third_ext::FutureTimeoutExt,
};

use super::{DnsHandle, reap_tasks, sanitize_src_address};

pub fn serve(
    listener: net::TcpListener,
    handler: DnsHandle,
    timeout: Duration,
) -> CancellationToken {
    log::debug!("TCP listener successfully registered on {}", listener.local_addr().unwrap());

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    tokio::spawn(async move {
        let mut inner_join_set = JoinSet::new();
        loop {
            let (tcp_stream, src_addr) = tokio::select! {
                tcp_stream = listener.accept() => match tcp_stream {
                    Ok((t, s)) => (t, s),
                    Err(e) => {
                        log::debug!("error receiving TCP tcp_stream error: {}", e);
                        continue;
                    },
                },
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!(
                    "address can not be responded to {src_addr}: {e}",
                    src_addr = src_addr,
                    e = e
                );
                continue;
            }

            let handler = handler.clone();

            // and spawn to the io_loop
            inner_join_set.spawn(async move {
                log::debug!("accepted request from: {}", src_addr);
                // take the created stream...
                let (mut buf_stream, stream_handle) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(tcp_stream), src_addr);

                // 🌟 核心修复：单连接并发数上限 (防 Pipelining 任务爆炸与 OOM)
                let conn_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(200));

                while let Ok(Some(message)) = buf_stream.next().timeout(timeout).await {
                    let message = match message {
                        Ok(message) => message,
                        Err(e) => {
                            log::debug!("error in TCP request_stream src: {} error: {}", src_addr, e);
                            return; // 网络中断，断开连接
                        }
                    };

                    // 🚦 申请并发许可。如果该连接堆积了 200 个未决请求，这里会阻塞挂起，
                    // 暂停从 TCP 缓冲区读取，从而利用 TCP 底层窗口机制产生背压 (Backpressure)。
                    let permit = match conn_semaphore.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    let (bytes, addr) = message.into_parts();
                    let req_message = SerialMessage::binary(bytes, addr, Protocol::Tcp);
                    
                    let handler = handler.clone();
                    let mut stream_handle = stream_handle.clone(); 

                    tokio::spawn(async move {
                        let _permit = permit; // 🌟 绑定许可的生命周期，任务结束时自动归还令牌
                        let res_message = handler.send(req_message).await;
                        
                        if let Err(err) = res_message
                            .try_into()
                            .map(|buffer| stream_handle.send(buffer))
                        {
                            log::error!("TCP stream processing failed from {:?}", err);
                        }
                    });
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    token
}
