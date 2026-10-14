// Copyright 2015-2016 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `RetryDnsHandle` allows for DnsQueries to be reattempted on failure

#[cfg(any(feature = "std", feature = "no-std-rand"))]
use alloc::boxed::Box;
use core::pin::Pin;
use core::task::{Context, Poll};

use futures_util::stream::{Stream, StreamExt};

use crate::DnsHandle;
use crate::error::{ProtoError, ProtoErrorKind};
use crate::xfer::{DnsRequest, DnsResponse};

/// Can be used to reattempt queries if they fail
///
/// Note: this does not reattempt queries that fail with a negative response.
/// For example, if a query gets a `NODATA` response from a name server, the
/// query will not be retried. It only reattempts queries that effectively
/// failed to get a response, such as queries that resulted in IO or timeout
/// errors.
///
/// Whether an error is retryable by the [`RetryDnsHandle`] is determined by the
/// [`ProtoError::should_retry()`] method.
///
/// *note* Current value of this is not clear, it may be removed
#[derive(Clone)]
#[must_use = "queries can only be sent through a ClientHandle"]
#[allow(dead_code)]
pub struct RetryDnsHandle<H>
where
    H: DnsHandle + Unpin + Send,
{
    handle: H,
    attempts: usize,
}

impl<H> RetryDnsHandle<H>
where
    H: DnsHandle + Unpin + Send,
{
    /// Creates a new Client handler for reattempting requests on failures.
    ///
    /// # Arguments
    ///
    /// * `handle` - handle to the dns connection
    /// * `attempts` - number of attempts before failing
    pub fn new(handle: H, attempts: usize) -> Self {
        Self { handle, attempts }
    }
}

#[cfg(any(feature = "std", feature = "no-std-rand"))]
impl<H: DnsHandle> DnsHandle for RetryDnsHandle<H> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;

    fn send(&self, request: DnsRequest) -> Self::Response {
        // need to clone here so that the retry can resend if necessary...
        //  obviously it would be nice to be lazy about this...
        let stream = self.handle.send(request.clone());

        Box::pin(RetrySendStream {
            request,
            handle: self.handle.clone(),
            stream,
            remaining_attempts: self.attempts,
            busy_poll_cooldown: 0,
            busy_shift: 0,
        })
    }
}

/// A stream for retrying (on failure, for the remaining number of times specified)
struct RetrySendStream<H>
where
    H: DnsHandle,
{
    request: DnsRequest,
    handle: H,
    stream: <H as DnsHandle>::Response,
    remaining_attempts: usize,
    /// 🔐 R-P3-7：Busy 退避计数。Busy 错误 `attempted()==false`（不消耗重试次数）且
    /// `should_retry()==true`——原实现立即 clone 重发并立即再 poll，形成无出口的
    /// 紧热循环（CPU 100%，单任务锁死）。这里按 2 的幂穿插"让出轮"：两次重发之间
    /// 穿插 64~4096 次让出（执行器得以运行其它任务），把空转稀释为低频探测。
    /// 注：精确时间退避需要 Time 抽象（见 runtime.rs），no_std 兼容下留待上游重构。
    busy_poll_cooldown: u32,
    /// 🔐 R-P3-7：Busy 退避的幂次（0..=6），连续 Busy 时递增（让出轮 64 → 4096）。
    busy_shift: u32,
}

impl<H: DnsHandle + Unpin> Stream for RetrySendStream<H> {
    type Item = Result<DnsResponse, ProtoError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 🔐 R-P3-7：冷却期——递减计数、安排唤醒、返回 Pending 让出执行权。
        // 不查 stream：上游刚表示忙，立刻再 poll 只会立刻再失败。
        // 最后一轮冷却时重发请求（此时距上次 Busy 已隔了整个冷却期）。
        if self.busy_poll_cooldown > 0 {
            self.busy_poll_cooldown -= 1;
            if self.busy_poll_cooldown == 0 {
                let request = self.request.clone();
                self.stream = self.handle.send(request);
            }
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        // loop over the stream, on errors, spawn a new stream
        //  on ready and not ready return.
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Err(e))) => {
                    if self.remaining_attempts == 0 || !e.should_retry() {
                        return Poll::Ready(Some(Err(e)));
                    }

                    if e.attempted() {
                        self.remaining_attempts -= 1;
                    }

                    // 🔐 R-P3-7：Busy 退避——让出轮数按 2 的幂递增（64 起步、4096 封顶），
                    // 消除"立即重发→立即失败"的无出口热循环。
                    // 设置冷却后立即返回 Pending（冷却分支负责 wake），否则本函数内的
                    // loop 会不等冷却立即重发，等于没修。
                    if matches!(e.kind(), ProtoErrorKind::Busy) {
                        let shift = (self.busy_shift.saturating_add(1)).min(6);
                        self.busy_shift = shift;
                        self.busy_poll_cooldown = 1u32 << (shift + 6); // 64 ..= 4096
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }

                    // TODO: if the "sent" Message is part of the error result,
                    //  then we can just reuse it... and no clone necessary
                    let request = self.request.clone();
                    self.stream = self.handle.send(request);
                }
                poll => return poll,
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU16, Ordering};

    use super::*;
    use crate::error::*;
    use crate::op::*;
    use crate::xfer::FirstAnswer;

    use futures_executor::block_on;
    use futures_util::future::{err, ok};
    use futures_util::stream::*;
    use test_support::subscribe;

    #[derive(Clone)]
    struct TestClient {
        last_succeed: bool,
        retries: u16,
        attempts: Arc<AtomicU16>,
    }

    impl DnsHandle for TestClient {
        type Response = Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>;

        fn send(&self, _: DnsRequest) -> Self::Response {
            let i = self.attempts.load(Ordering::SeqCst);

            if (i > self.retries || self.retries - i == 0) && self.last_succeed {
                let mut message = Message::response(0, OpCode::Query);
                message.set_id(i);
                return Box::new(once(ok(DnsResponse::from_message(message).unwrap())));
            }

            self.attempts.fetch_add(1, Ordering::SeqCst);
            Box::new(once(err(ProtoError::from("last retry set to fail"))))
        }
    }

    #[test]
    fn test_retry() {
        subscribe();
        let handle = RetryDnsHandle::new(
            TestClient {
                last_succeed: true,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = DnsRequest::from(Message::query());
        let result = block_on(handle.send(test1).first_answer()).expect("should have succeeded");
        assert_eq!(result.id(), 1); // this is checking the number of iterations the TestClient ran
    }

    /// 🔐 R-P3-7：Busy 重试必须带冷却（回归测试）。
    ///
    /// 持续返回 Busy 的客户端：修复前每次 poll 都立即重发并立即再 poll（紧热循环）；
    /// 修复后两次重发之间穿插 64..=4096 次让出轮，连续驱动 1000 次仍应处于冷却期
    /// （不应产生任何实际结果）。
    #[test]
    fn test_busy_retry_has_cooldown() {
        use core::task::Waker;

        // 一直返回 Busy 的客户端
        #[derive(Clone)]
        struct BusyClient;
        impl DnsHandle for BusyClient {
            type Response =
                Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>;
            fn send(&self, _: DnsRequest) -> Self::Response {
                Box::new(once(err(ProtoError::from(ProtoErrorKind::Busy))))
            }
        }

        let handle = RetryDnsHandle::new(BusyClient, 5);
        let test1 = DnsRequest::from(Message::query());
        let mut stream = handle.send(test1);

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        // 驱动 1000 次 poll：修复前是紧热循环；修复后始终处于冷却期
        for _ in 0..1000 {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Pending => {}
                other => panic!("Busy 冷却期内不应产生结果，实际: {other:?}"),
            }
        }
    }

    #[test]
    fn test_error() {
        subscribe();
        let client = RetryDnsHandle::new(
            TestClient {
                last_succeed: false,
                retries: 1,
                attempts: Arc::new(AtomicU16::new(0)),
            },
            2,
        );
        let test1 = DnsRequest::from(Message::query());
        assert!(block_on(client.send(test1).first_answer()).is_err());
    }
}
