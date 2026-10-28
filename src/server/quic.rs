use std::{io, sync::Arc, time::Duration};

use crate::rustls::ResolvesServerCert;
use tokio::{
    net,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use super::{DnsHandle, reap_tasks, sanitize_src_address};

use crate::{dns::SerialMessage, libdns::Protocol, log};

const MAX_CONCURRENT_SUBSTREAMS: usize = 32;

fn try_admit(sem: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    sem.clone().try_acquire_owned().ok()
}

pub fn serve(
    socket: net::UdpSocket,
    handler: DnsHandle,
    _timeout: Duration,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
    _dns_hostname: Option<String>,
    first_packet_timeout: Option<std::time::Duration>,
) -> io::Result<CancellationToken> {
    use crate::libdns::proto::quic::{DoqErrorCode, QuicServer};

    log::debug!("registered quic: {:?}", socket);

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    // 🔐 逐监听限额需要监听地址：socket 随后会被移交，先在这里取出来
    let listener_local_addr = socket.local_addr().ok();
    let mut server = QuicServer::with_socket(socket, server_cert_resolver)?;

    tokio::spawn(async move {
        // 🔐 逐监听连接上限（若该监听单独配了 max-connections*，与全局限额同时生效）
        let listener_limiter = listener_local_addr.and_then(crate::server::limit::for_listener);

        let mut inner_join_set = JoinSet::new();
        // 🔐 P2-7：连续 accept 错误计数（用于退避与日志降频）。
        let mut err_streak: u32 = 0;
        loop {
            let (mut quic_streams, src_addr) = tokio::select! {
                result = server.next() => match result {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        // 🔐 编号 42：`endpoint.accept()` 返回 None 表示 endpoint 已关闭
                        // （`quic_server.rs:75-84` 把它映射成 `Ok(None)`）。原来这里 `continue`
                        // 回到 loop，而 endpoint 已关闭、`accept()` 会**立即**再次返回 None ——
                        // 形成无等待的忙循环，把一个 tokio worker 线程钉在 100% CPU，
                        // 且 `cancellation_token` 永远轮不到被检查。
                        // endpoint 关闭属不可恢复状态，退出 accept 循环。
                        log::debug!(
                            "the QUIC endpoint closed; stopping the accept loop for this listener"
                        );
                        break;
                    }
                    Err(e) => {
                        // 🔐 P2-7：与 UDP/TCP/TLS 监听同口径 —— 连续出错按指数退避，
                        // 防止持续性错误把循环打成 100% CPU 空转；日志降频防刷屏。
                        err_streak = err_streak.saturating_add(1);
                        if crate::server::should_log_stream_error(err_streak) {
                            log::warn!("error receiving a QUIC connection (streak {err_streak}): {e}");
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
            err_streak = 0;
            // verify that the src address is safe for responses
            // TODO: we're relying the quinn library to actually validate responses before we get here, but this check is still worth doing
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
                log::debug!(
                    "global connection limit reached; refusing the new connection from {src_addr}"
                );
                continue;
            };

            // 🔐 该监听自身（若单独配置过）的限额也要通过
            let listener_guard = match listener_limiter.as_ref() {
                Some(l) => match l.acquire(src_addr.ip()) {
                    Some(guard) => Some(guard),
                    None => {
                        log::debug!(
                            "per-listener connection limit reached; refusing the new connection from {src_addr}"
                        );
                        continue;
                    }
                },
                None => None,
            };

            let handler = handler.clone();
            let cancellation_token = cancellation_token.clone();

            inner_join_set.spawn(async move {
                let _conn_guard = conn_guard; // 连接结束时自动归还配额
                let _listener_guard = listener_guard;
                log::debug!("starting quic stream request from: {src_addr}");

                // 🔐 限制的是“同时处理中的子流数”，不是连接生命周期内的累计查询数。
                // 正常 DoQ 客户端会长期复用连接；累计计数会在第 32 条查询时错误断开它。
                let substream_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_SUBSTREAMS));

                // Accept all inbound quic streams sent over the connection.
                loop {
                    let mut request_stream = tokio::select! {
                        result = quic_streams.next() => match result {
                            Some(Ok(next_request)) => next_request,
                            Some(Err(err)) => {
                                log::warn!("error accepting request {}: {}", src_addr, err);
                                break;
                            }
                            None => break,
                        },
                        _ = cancellation_token.cancelled() => break,
                    };

                    let permit = match try_admit(&substream_limit) {
                        Some(permit) => permit,
                        None => {
                            log::debug!(
                                "substream concurrency limit ({MAX_CONCURRENT_SUBSTREAMS}) reached on {src_addr}; rejecting this substream"
                            );
                            let _ = request_stream.stop(DoqErrorCode::ExcessiveLoad);
                            continue;
                        }
                    };

                    let handler = handler.clone();

                    // 🌟 核心修复：拿到一个新的 QUIC Stream 后，立刻派发后台处理！
                    // 主循环秒级回归，疯狂接收该 QUIC 连接发来的下一个并发查询流，彻底实现 QUIC 多路复用。
                    tokio::spawn(async move {
                        let _permit = permit;

                        // 🔐 P0-5：单条子流的"首包"同样要限时——
                        // 否则只发 2 字节长度前缀就能长期占住这条流（DoQ 是最便宜的放大面）。
                        let read_result = match first_packet_timeout {
                            Some(t) => {
                                match tokio::time::timeout(t, request_stream.receive_bytes()).await
                                {
                                    Ok(r) => r,
                                    Err(_) => {
                                        log::debug!("QUIC substream first-packet timeout; closing the substream: {src_addr}");
                                        let _ = request_stream.stop(DoqErrorCode::NoError);
                                        return;
                                    }
                                }
                            }
                            None => request_stream.receive_bytes().await,
                        };
                        let bytes = match read_result {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                log::warn!("error receiving bytes {}", err);
                                // 🌟 核心修复：即使读取失败，也必须显式向操作系统和内核宣告关闭该 QUIC 子流！
                                // 否则底层的 Quinn 状态机将永远残留，导致僵尸 Stream 最终耗尽服务器内存。
                                let _ = request_stream.stop(DoqErrorCode::NoError);
                                return; // 局部流接收失败，仅退出当前流，保持主 QUIC 连接不断！
                            }
                        };

                        log::debug!("Received bytes {} from {src_addr} {bytes:?}", bytes.len());

                        let req_message = SerialMessage::binary(bytes, src_addr, Protocol::Quic);
                        let res_message = handler.send(req_message).await;

                        if let Err(err) = match res_message.try_into() {
                            Ok(buffer) => request_stream.send_bytes(buffer).await,
                            Err(err) => Err(err),
                        } {
                            log::trace!("quic stream processing failed from {src_addr}: {err}");
                        }

                        // DOQ_NO_ERROR (0x0): No error. 完美关闭当前子流。
                        let _ = request_stream.stop(DoqErrorCode::NoError);
                    });
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substream_limit_admits_32_then_rejects() {
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SUBSTREAMS));
        let permits = (0..MAX_CONCURRENT_SUBSTREAMS)
            .map(|_| try_admit(&sem).expect("前 32 条子流必须获准"))
            .collect::<Vec<_>>();

        assert!(try_admit(&sem).is_none(), "第 33 条并发子流必须被拒绝");
        drop(permits);
    }

    #[test]
    fn substream_permit_is_returned_on_drop() {
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_SUBSTREAMS));
        let mut permits = (0..MAX_CONCURRENT_SUBSTREAMS)
            .map(|_| try_admit(&sem).expect("前 32 条子流必须获准"))
            .collect::<Vec<_>>();

        assert!(try_admit(&sem).is_none());
        drop(permits.pop().expect("至少有一个许可"));
        assert!(try_admit(&sem).is_some(), "子流任务结束后许可必须归还");
    }
}
