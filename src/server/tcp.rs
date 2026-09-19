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
    first_packet_timeout: Option<std::time::Duration>,
) -> CancellationToken {
    log::debug!(
        "TCP listener successfully registered on {}",
        listener.local_addr().unwrap()
    );

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    tokio::spawn(async move {
        // 🔐 逐监听连接上限（若该监听单独配了 max-connections*，与全局限额同时生效）
        let listener_limiter = listener
            .local_addr()
            .ok()
            .and_then(crate::server::limit::for_listener);

        let mut inner_join_set = JoinSet::new();
        // 🔐 P2：连续 accept 出错的次数（用于退避 + 日志降频）
        let mut err_streak: u32 = 0;
        loop {
            let (tcp_stream, src_addr) = tokio::select! {
                tcp_stream = listener.accept() => match tcp_stream {
                    Ok((t, s)) => {
                        // accept 恢复正常：退避计数归零
                        err_streak = 0;
                        (t, s)
                    }
                    Err(e) => {
                        // 🔐 P2：不再"出错就立刻 continue"——持续性错误（fd 耗尽、网卡消失）
                        // 会让循环 100% CPU 空转并把日志刷爆。这里退避 + 日志降频。
                        err_streak = err_streak.saturating_add(1);
                        if crate::server::should_log_stream_error(err_streak) {
                            log::warn!(
                                "error accepting a TCP connection (consecutive #{}): {}",
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
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!(
                    "cannot respond to address {src_addr}: {e}",
                    src_addr = src_addr,
                    e = e
                );
                continue;
            }

            // 🔐 P0-5：连接数上限。超出预算就拒绝新连接（不影响已有连接），保护进程内存。
            // 默认上限按物理内存自动推算：家庭小机器自动收紧，企业大机器自动放宽。
            let Some(conn_guard) = crate::server::limit::global().acquire(src_addr.ip()) else {
                log::debug!("global connection limit reached; refusing the new connection from {src_addr}");
                continue;
            };

            // 🔐 该监听自身（若单独配置过）的限额也要通过
            let listener_guard = match listener_limiter.as_ref() {
                Some(l) => match l.acquire(src_addr.ip()) {
                    Some(guard) => Some(guard),
                    None => {
                        log::debug!("per-listener connection limit reached; refusing the new connection from {src_addr}");
                        continue;
                    }
                },
                None => None,
            };

            let handler = handler.clone();

            // and spawn to the io_loop
            inner_join_set.spawn(async move {
                let _conn_guard = conn_guard; // 连接结束时自动归还配额
                let _listener_guard = listener_guard;
                log::debug!("accepted request from: {}", src_addr);
                // take the created stream...
                let (mut buf_stream, stream_handle) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(tcp_stream), src_addr);

                // 🌟 核心修复：单连接并发数上限 (防 Pipelining 任务爆炸与 OOM)
                let conn_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(200));

                // 🔐 P0-5：连接建立后，"第一个完整报文"必须在首包超时内到达；之后回落到空闲超时。
                // 攻击者"只发长度前缀、不发正文"的路子会被迅速切断，长连接复用不受影响。
                let mut is_first_packet = true;
                loop {
                    let wait = if is_first_packet {
                        first_packet_timeout.unwrap_or(timeout)
                    } else {
                        timeout
                    };
                    let next = buf_stream.next().timeout(wait).await;
                    is_first_packet = false;
                    let message = match next {
                        Ok(Some(Ok(message))) => message,
                        Ok(Some(Err(e))) => {
                            log::debug!(
                                "DNS request stream from {} failed: {}",
                                src_addr,
                                e
                            );
                            return; // 网络中断，断开连接
                        }
                        Ok(None) => break,
                        Err(_) => {
                            log::debug!("timed out waiting for a DNS message; closing the connection: {}", src_addr);
                            return;
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
