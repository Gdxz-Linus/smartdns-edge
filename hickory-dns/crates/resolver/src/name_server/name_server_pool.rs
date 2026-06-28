// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::time::{Duration, Instant};

use futures_util::future::FutureExt;
use futures_util::stream::{FuturesUnordered, Stream, StreamExt, once};
use hickory_proto::NoRecords;
use hickory_proto::op::ResponseCode;
use smallvec::SmallVec;
use tracing::debug;

use crate::config::{NameServerConfig, ResolverConfig, ResolverOpts, ServerOrderingStrategy};
use crate::name_server::connection_provider::ConnectionProvider;
use crate::name_server::name_server::NameServer;
use crate::proto::runtime::{RuntimeProvider, Time};
use crate::proto::xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer, Protocol};
use crate::proto::{ProtoError, ProtoErrorKind};

/// Abstract interface for mocking purpose
#[derive(Clone)]
pub struct NameServerPool<P: ConnectionProvider> {
    state: Arc<PoolState<P>>,
}

impl<P: ConnectionProvider> NameServerPool<P> {
    pub(crate) fn from_config_with_provider(
        config: &ResolverConfig,
        options: Arc<ResolverOpts>,
        conn_provider: P,
    ) -> Self {
        Self::from_config(config.name_servers(), options, conn_provider)
    }

    /// Construct a NameServerPool from a set of name server configs
    pub fn from_config(
        name_servers: &[NameServerConfig],
        options: Arc<ResolverOpts>,
        conn_provider: P,
    ) -> Self {
        let mut servers = Vec::with_capacity(name_servers.len());
        for server in name_servers {
            for conn in &server.connections {
                servers.push(NameServer::new(
                    server,
                    conn.clone(),
                    options.clone(),
                    conn_provider.clone(),
                ));
            }
        }

        Self::from_nameservers(servers, options)
    }

    #[doc(hidden)]
    pub fn from_nameservers(servers: Vec<NameServer<P>>, options: Arc<ResolverOpts>) -> Self {
        Self {
            state: Arc::new(PoolState::new(servers, options)),
        }
    }

    /// Returns the pool's options.
    pub fn options(&self) -> &ResolverOpts {
        &self.state.options
    }
}

impl<P: ConnectionProvider> DnsHandle for NameServerPool<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let state = self.state.clone();
        Box::pin(once(async move {
            debug!("sending request: {:?}", request.queries());
            state.try_send(request).await
        }))
    }
}

struct PoolState<P: ConnectionProvider> {
    servers: Vec<NameServer<P>>,
    options: Arc<ResolverOpts>,
    next: AtomicUsize,
}

// 🌟 辅助枚举：用于控制处理后的流程走向，极简优雅
enum Proceed {
    ReturnOk(DnsResponse),
    ReturnErr(ProtoError),
    Next,
}

impl<P: ConnectionProvider> PoolState<P> {
    fn new(mut servers: Vec<NameServer<P>>, options: Arc<ResolverOpts>) -> Self {
        // Unless the user specified that we should follow the configured order,
        // re-order the servers to prioritize UDP.
        if options.server_ordering_strategy != ServerOrderingStrategy::UserProvidedOrder {
            servers.sort_by_key(|ns| (ns.protocol() != Protocol::Udp) as u8);
        }

        Self {
            servers,
            options,
            next: AtomicUsize::new(0),
        }
    }

    // 🌟 辅助函数：统一、单进程化地处理并发竞速的结果
    #[inline]
    fn process_res(
        result: Result<DnsResponse, (NameServer<P>, ProtoError)>,
        skip_udp: &mut bool,
        err: &mut ProtoError,
        busy: &mut SmallVec<[NameServer<P>; 2]>,
    ) -> Proceed {
        let (conn, e) = match result {
            Ok(response) if response.truncated() => {
                debug!("truncated response received, retrying over TCP");
                *skip_udp = true;
                *err = ProtoError::from("received truncated response");
                return Proceed::Next;
            }
            Ok(response) => return Proceed::ReturnOk(response),
            Err((conn, e)) => (conn, e),
        };

        use ProtoErrorKind::*;
        match e.kind() {
            QueryCaseMismatch => *skip_udp = true,
            Busy => busy.push(conn),
            Io(_) | NoConnections => {}
            NoRecordsFound(NoRecords {
                response_code: ResponseCode::NXDomain,
                ..
            }) if !conn.trust_negative_responses() => {}
            _ => return Proceed::ReturnErr(e),
        }

        if err.cmp_specificity(&e) == Ordering::Less {
            *err = e;
        }
        Proceed::Next
    }

    async fn try_send(&self, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
        let mut conns = self.servers.clone();
        match self.options.server_ordering_strategy {
            ServerOrderingStrategy::QueryStatistics => {
                // 🌟 核心优化 1：时间戳只取一次，且 O(N) 预计算衰减值，防止 O(N log N) 排序时频繁锁竞争
                let now = Instant::now();
                let mut decayed_conns: Vec<(f64, NameServer<P>)> = conns
                    .into_iter()
                    .map(|conn| (conn.decayed_srtt(now), conn))
                    .collect();

                decayed_conns.sort_by(|(srtt_a, a), (srtt_b, b)| {
                    match (a.protocol(), b.protocol()) {
                        (ap, bp) if ap == bp => srtt_a.total_cmp(srtt_b),
                        (Protocol::Udp, _) => Ordering::Less,
                        (_, Protocol::Udp) => Ordering::Greater,
                        (_, _) => srtt_a.total_cmp(srtt_b),
                    }
                });

                conns = decayed_conns.into_iter().map(|(_, conn)| conn).collect();
            }
            ServerOrderingStrategy::UserProvidedOrder => {}
            ServerOrderingStrategy::RoundRobin => {
                let num_concurrent_reqs = if self.options.num_concurrent_reqs > 1 {
                    self.options.num_concurrent_reqs
                } else {
                    1
                };
                if num_concurrent_reqs < conns.len() {
                    let index = self
                        .next
                        .fetch_add(num_concurrent_reqs, AtomicOrdering::SeqCst)
                        % conns.len();
                    conns.rotate_left(index);
                }
            }
        }

        let mut conns = VecDeque::from(conns);
        let mut backoff = Duration::from_millis(20);
        let mut busy = SmallVec::<[NameServer<P>; 2]>::new();
        let mut err = ProtoError::from(ProtoErrorKind::NoConnections);
        let mut skip_udp = false;

        loop {
            let mut par_conns = SmallVec::<[NameServer<P>; 2]>::new();
            while !conns.is_empty()
                && par_conns.len() < Ord::max(self.options.num_concurrent_reqs, 1)
            {
                if let Some(conn) = conns.pop_front() {
                    if !(skip_udp && conn.protocol() == Protocol::Udp) {
                        par_conns.push(conn);
                    }
                }
            }

            if par_conns.is_empty() {
                if !busy.is_empty() && backoff < Duration::from_millis(300) {
                    <<P as ConnectionProvider>::RuntimeProvider as RuntimeProvider>::Timer::delay_for(
                        backoff,
                    )
                    .await;
                    conns.extend(
                        busy.drain(..)
                            .filter(|ns| !(skip_udp && ns.protocol() == Protocol::Udp)),
                    );
                    backoff *= 2;
                    continue;
                }
                return Err(err);
            }

            // 🌟 核心优化 2：利用栈上并发调度，消灭 FuturesUnordered 的堆分配和冗余装箱
            let len = par_conns.len();
            
            if len == 1 {
                // 🚀 单发包特化处理：直接 await，0 额外开销
                let conn = par_conns.pop().unwrap();
                let result = conn.send(request.clone()).first_answer().await.map_err(|e| (conn, e));
                match Self::process_res(result, &mut skip_udp, &mut err, &mut busy) {
                    Proceed::ReturnOk(res) => return Ok(res),
                    Proceed::ReturnErr(e) => return Err(e),
                    Proceed::Next => {}
                }
                
            } else if len == 2 {
                // 🚀 双并发发包特化处理：使用 select 宏原生无锁堆竞速！
                let conn2 = par_conns.pop().unwrap();
                let conn1 = par_conns.pop().unwrap();
                let fut1 = conn1.send(request.clone()).first_answer().map(|res| res.map_err(|e| (conn1, e)));
                let fut2 = conn2.send(request.clone()).first_answer().map(|res| res.map_err(|e| (conn2, e)));

                let res = futures_util::future::select(fut1, fut2).await;
                let (result1, remaining) = match res {
                    futures_util::future::Either::Left((r, rem)) => (r, futures_util::future::Either::Left(rem)),
                    futures_util::future::Either::Right((r, rem)) => (r, futures_util::future::Either::Right(rem)),
                };

                match Self::process_res(result1, &mut skip_udp, &mut err, &mut busy) {
                    Proceed::ReturnOk(res) => return Ok(res),
                    Proceed::ReturnErr(e) => return Err(e),
                    Proceed::Next => {
                        // 第一个未来失败了，我们在栈上继续等待第二个未完成的未来
                        let result2 = match remaining {
                            futures_util::future::Either::Left(rem) => rem.await,
                            futures_util::future::Either::Right(rem) => rem.await,
                        };
                        match Self::process_res(result2, &mut skip_udp, &mut err, &mut busy) {
                            Proceed::ReturnOk(res) => return Ok(res),
                            Proceed::ReturnErr(e) => return Err(e),
                            Proceed::Next => {}
                        }
                    }
                }
                
            } else {
                // 兜底处理：罕见的 3+ 并发，回退使用原始堆分配队列
                let mut requests = par_conns
                    .into_iter()
                    .map(|conn| {
                        conn.send(request.clone())
                            .first_answer()
                            .map(|result| result.map_err(|e| (conn, e)))
                    })
                    .collect::<FuturesUnordered<_>>();

                while let Some(result) = requests.next().await {
                    match Self::process_res(result, &mut skip_udp, &mut err, &mut busy) {
                        Proceed::ReturnOk(res) => return Ok(res),
                        Proceed::ReturnErr(e) => return Err(e),
                        Proceed::Next => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "tokio")]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use test_support::subscribe;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::config::NameServerConfig;
    use crate::proto::op::Query;
    use crate::proto::rr::{Name, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::xfer::{DnsHandle, DnsRequestOptions};

    #[ignore]
    // because of there is a real connection that needs a reasonable timeout
    #[test]
    #[allow(clippy::uninlined_format_args)]
    fn test_failed_then_success_pool() {
        subscribe();

        let mut config1 = NameServerConfig::udp(IpAddr::from([127, 0, 0, 252]));
        config1.trust_negative_responses = false;
        let config2 = NameServerConfig::udp(IpAddr::from([8, 8, 8, 8]));

        let mut resolver_config = ResolverConfig::default();
        resolver_config.add_name_server(config1);
        resolver_config.add_name_server(config2);

        let io_loop = Runtime::new().unwrap();
        let pool = NameServerPool::tokio_from_config(
            &resolver_config,
            Arc::new(ResolverOpts::default()),
            TokioRuntimeProvider::new(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();

        // TODO: it's not clear why there are two failures before the success
        for i in 0..2 {
            assert!(
                io_loop
                    .block_on(
                        pool.lookup(
                            Query::query(name.clone(), RecordType::A),
                            DnsRequestOptions::default()
                        )
                        .first_answer()
                    )
                    .is_err(),
                "iter: {}",
                i
            );
        }

        for i in 0..10 {
            assert!(
                io_loop
                    .block_on(
                        pool.lookup(
                            Query::query(name.clone(), RecordType::A),
                            DnsRequestOptions::default()
                        )
                        .first_answer()
                    )
                    .is_ok(),
                "iter: {}",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_multi_use_conns() {
        subscribe();

        let conn_provider = TokioRuntimeProvider::default();
        let opts = Arc::new(ResolverOpts {
            try_tcp_on_error: true,
            ..ResolverOpts::default()
        });

        let tcp = NameServerConfig::tcp(IpAddr::from([8, 8, 8, 8]));
        let connection_config = tcp.connections.first().unwrap().clone();
        let name_server = NameServer::new(&tcp, connection_config, opts.clone(), conn_provider);
        let name_servers = vec![name_server];
        let pool = NameServerPool::from_nameservers(name_servers.clone(), opts);

        let name = Name::from_str("www.example.com.").unwrap();

        // first lookup
        let response = pool
            .lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("lookup failed");

        assert!(!response.answers().is_empty());

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );

        // first lookup
        let response = pool
            .lookup(
                Query::query(name, RecordType::AAAA),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("lookup failed");

        assert!(!response.answers().is_empty());

        assert!(
            name_servers[0].is_connected(),
            "if this is failing then the NameServers aren't being properly shared."
        );
    }

    impl NameServerPool<TokioRuntimeProvider> {
        pub(crate) fn tokio_from_config(
            config: &ResolverConfig,
            options: Arc<ResolverOpts>,
            provider: TokioRuntimeProvider,
        ) -> Self {
            Self::from_config_with_provider(config, options, provider)
        }
    }
}
