// Copyright 2015-2019 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::{self, Debug, Formatter};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
#[cfg(not(test))]
use std::time::{Duration, Instant};

use futures_util::lock::Mutex as AsyncMutex;
use futures_util::stream::{Stream, once};
use parking_lot::Mutex as SyncMutex;
#[cfg(test)]
use tokio::time::{Duration, Instant};
use tracing::debug;

use crate::config::{ConnectionConfig, NameServerConfig, ResolverOpts};
use crate::name_server::connection_provider::ConnectionProvider;
use crate::proto::{
    NoRecords, ProtoError, ProtoErrorKind,
    op::ResponseCode,
    xfer::{DnsHandle, DnsRequest, DnsResponse, FirstAnswer, Protocol},
};

/// This struct is used to create `DnsHandle` with the help of `P`.
#[derive(Clone)]
pub struct NameServer<P: ConnectionProvider> {
    inner: Arc<NameServerState<P>>,
}

impl<P: ConnectionProvider> NameServer<P> {
    /// Construct a new Nameserver with the configuration and options. The connection provider will create UDP and TCP sockets
    pub fn new(
        server_config: &NameServerConfig,
        config: ConnectionConfig,
        options: Arc<ResolverOpts>,
        connection_provider: P,
    ) -> Self {
        Self {
            inner: Arc::new(NameServerState::new(
                server_config,
                config,
                options,
                None,
                connection_provider,
            )),
        }
    }

    #[doc(hidden)]
    pub fn from_conn(
        server_config: &NameServerConfig,
        config: ConnectionConfig,
        options: Arc<ResolverOpts>,
        client: P::Conn,
        connection_provider: P,
    ) -> Self {
        Self {
            inner: Arc::new(NameServerState::new(
                server_config,
                config,
                options,
                Some(client),
                connection_provider,
            )),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn is_connected(&self) -> bool {
        use Status::*;
        match (self.inner.status(), self.inner.client.try_lock()) {
            (Established | Init, Some(client)) => client.is_some(),
            (Failed, _) => false,
            // assuming that if someone has it locked it will be or is connected
            (_, None) => true,
        }
    }

    // 🌟 性能优化：接收外部统一传入的时间戳，消灭高频系统调用
    pub(super) fn decayed_srtt(&self, now: Instant) -> f64 {
        self.inner.stats.decayed_srtt(now)
    }

    pub(super) fn protocol(&self) -> Protocol {
        self.inner.config.protocol.to_protocol()
    }

    pub(super) fn trust_negative_responses(&self) -> bool {
        self.inner.trust_negative_responses
    }
}

impl<P: ConnectionProvider> DnsHandle for NameServer<P> {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

    fn is_verifying_dnssec(&self) -> bool {
        #[cfg(feature = "__dnssec")]
        {
            self.inner.options.validate
        }
        #[cfg(not(feature = "__dnssec"))]
        {
            false
        }
    }

    // TODO: there needs to be some way of customizing the connection based on EDNS options from the server side...
    fn send(&self, request: DnsRequest) -> Self::Response {
        let this = self.clone();
        // if state is failed, return future::err(), unless retry delay expired..
        Box::pin(once(this.inner.send(request)))
    }
}

impl<P: ConnectionProvider> Debug for NameServer<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "config: {:?}, options: {:?}",
            self.inner.config, self.inner.options
        )
    }
}

struct NameServerState<P: ConnectionProvider> {
    ip: IpAddr,
    config: ConnectionConfig,
    options: Arc<ResolverOpts>,
    client: AsyncMutex<Option<P::Conn>>,
    status: AtomicU8,
    stats: NameServerStats,
    trust_negative_responses: bool,
    connection_provider: P,
}

impl<P: ConnectionProvider> NameServerState<P> {
    fn new(
        server_config: &NameServerConfig,
        config: ConnectionConfig,
        options: Arc<ResolverOpts>,
        client: Option<P::Conn>,
        connection_provider: P,
    ) -> Self {
        Self {
            ip: server_config.ip,
            config,
            options,
            client: AsyncMutex::new(client),
            status: AtomicU8::new(Status::Init.into()),
            stats: NameServerStats::default(),
            trust_negative_responses: server_config.trust_negative_responses,
            connection_provider,
        }
    }

    async fn send(self: Arc<Self>, request: DnsRequest) -> Result<DnsResponse, ProtoError> {
        let client = self.connected_mut_client().await?;
        let now = Instant::now();
        let response = client.send(request).first_answer().await;
        let rtt = now.elapsed();

        match response {
            Ok(response) => {
                // First evaluate if the message succeeded.
                let result = ProtoError::from_response(response);
                self.stats.record(rtt, &result);
                let response = result?;

                // take the remote edns options and store them
                self.set_status(Status::Established);

                Ok(response)
            }
            Err(error) => {
                debug!(ip = %self.ip, config = ?self.config, %error, "failed to connect to name server");

                // this transitions the state to failure
                self.set_status(Status::Failed);

                // record the failure
                self.stats.record_connection_failure();

                // These are connection failures, not lookup failures, that is handled in the resolver layer
                Err(error)
            }
        }
    }

    /// This will return a mutable client to allows for sending messages.
    ///
    /// If the connection is in a failed state, then this will establish a new connection
    async fn connected_mut_client(&self) -> Result<P::Conn, ProtoError> {
        let mut client = self.client.lock().await;

        // if this is in a failure state
        if self.status() == Status::Failed || client.is_none() {
            debug!("reconnecting: {:?}", self.config);

            self.set_status(Status::Init);

            let new_client = Box::pin(self.connection_provider.new_connection(
                self.ip,
                &self.config,
                &self.options,
            )?)
            .await?;

            // establish a new connection
            *client = Some(new_client);
        } else {
            debug!("existing connection: {:?}", self.config);
        }

        Ok((*client)
            .clone()
            .expect("bad state, client should be connected"))
    }

    fn set_status(&self, status: Status) {
        self.status.store(status.into(), Ordering::Release);
    }

    fn status(&self) -> Status {
        Status::from(self.status.load(Ordering::Acquire))
    }
}

struct NameServerStats {
    srtt_microseconds: AtomicU32,
    last_update: Arc<SyncMutex<Option<Instant>>>,
}

impl NameServerStats {
    fn new(initial_srtt: Duration) -> Self {
        Self {
            srtt_microseconds: AtomicU32::new(initial_srtt.as_micros() as u32),
            last_update: Arc::new(SyncMutex::new(None)),
        }
    }

    /// Records the measured `rtt` for a particular result.
    ///
    /// Tries to guess if the result was a failure that should penalize the expected RTT.
    fn record(&self, rtt: Duration, result: &Result<DnsResponse, ProtoError>) {
        let error = match result {
            Ok(_) => {
                self.record_rtt(rtt);
                return;
            }
            Err(err) => err,
        };

        use ResponseCode::*;
        match error.kind() {
            ProtoErrorKind::NoRecordsFound(NoRecords { response_code, .. }) => {
                match response_code {
                    ServFail | Refused => self.record_connection_failure(),
                    _ => self.record_rtt(rtt),
                }
            }
            ProtoErrorKind::Busy
            | ProtoErrorKind::Io(_)
            | ProtoErrorKind::Timeout
            | ProtoErrorKind::RequestRefused => self.record_connection_failure(),
            #[cfg(feature = "__quic")]
            ProtoErrorKind::QuinnConfigError(_)
            | ProtoErrorKind::QuinnConnect(_)
            | ProtoErrorKind::QuinnConnection(_)
            | ProtoErrorKind::QuinnTlsConfigError(_) => self.record_connection_failure(),
            #[cfg(feature = "__tls")] 
            ProtoErrorKind::RustlsError(_) => self.record_connection_failure(),
            ProtoErrorKind::NoError => self.record_rtt(rtt),
            _ => {}
        }
    }

    fn record_rtt(&self, rtt: Duration) {
        self.update_srtt(
            rtt.as_micros() as u32,
            |cur_srtt_microseconds, last_update| {
                // 🌟 性能优化：传入当前时间
                let factor = compute_srtt_factor(last_update, Instant::now(), 3);
                let new_srtt = (1.0 - factor) * (rtt.as_micros() as f64)
                    + factor * f64::from(cur_srtt_microseconds);
                new_srtt.round() as u32
            },
        );
    }

    /// Records a connection failure for a particular query.
    fn record_connection_failure(&self) {
        self.update_srtt(
            Self::CONNECTION_FAILURE_PENALTY,
            |cur_srtt_microseconds, _last_update| {
                cur_srtt_microseconds.saturating_add(Self::CONNECTION_FAILURE_PENALTY)
            },
        );
    }

    /// Returns the raw SRTT value.
    #[cfg(all(test, feature = "tokio"))]
    fn srtt(&self) -> Duration {
        Duration::from_micros(u64::from(self.srtt_microseconds.load(Ordering::Acquire)))
    }

    // 🌟 性能优化：支持接收外部统一传入的时间戳进行衰减计算，大幅降低锁竞争和 exp 数学运算开销
    fn decayed_srtt(&self, now: Instant) -> f64 {
        let srtt = f64::from(self.srtt_microseconds.load(Ordering::Acquire));
        self.last_update.lock().map_or(srtt, |last_update| {
            srtt * compute_srtt_factor(last_update, now, 180)
        })
    }

    /// Updates the SRTT value.
    fn update_srtt(&self, default: u32, update_fn: impl Fn(u32, Instant) -> u32) {
        let last_update = self.last_update.lock().replace(Instant::now());
        let _ = self.srtt_microseconds.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            move |cur_srtt_microseconds| {
                Some(
                    last_update
                        .map_or(default, |last_update| {
                            update_fn(cur_srtt_microseconds, last_update)
                        })
                        .min(Self::MAX_SRTT_MICROS),
                )
            },
        );
    }

    const CONNECTION_FAILURE_PENALTY: u32 = Duration::from_millis(150).as_micros() as u32;
    const MAX_SRTT_MICROS: u32 = Duration::from_secs(5).as_micros() as u32;
}

impl Default for NameServerStats {
    fn default() -> Self {
        Self::new(Duration::from_micros(rand::random_range(1..32)))
    }
}

// 🌟 性能优化：支持使用传入的统一时间戳计算衰减因子
fn compute_srtt_factor(last_update: Instant, now: Instant, weight: u32) -> f64 {
    let exponent = (-now.saturating_duration_since(last_update).as_secs_f64().max(1.0)) / f64::from(weight);
    exponent.exp()
}

/// State of a connection with a remote NameServer.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
enum Status {
    Failed = 0,
    Init = 1,
    Established = 2,
}

impl From<Status> for u8 {
    fn from(val: Status) -> Self {
        val as Self
    }
}

impl From<u8> for Status {
    fn from(val: u8) -> Self {
        match val {
            2 => Self::Established,
            1 => Self::Init,
            _ => Self::Failed,
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use std::cmp;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::time::Duration;

    use test_support::subscribe;
    use tokio::net::UdpSocket;
    use tokio::spawn;

    use super::*;
    use crate::config::ProtocolConfig;
    use crate::proto::op::{Message, Query, ResponseCode};
    use crate::proto::rr::rdata::NULL;
    use crate::proto::rr::{Name, RData, Record, RecordType};
    use crate::proto::runtime::TokioRuntimeProvider;
    use crate::proto::xfer::{DnsHandle, DnsRequestOptions, FirstAnswer};

    #[tokio::test]
    async fn test_name_server() {
        subscribe();

        let config = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let connection_config = config.connections.first().unwrap().clone();
        let name_server = NameServer::new(
            &config,
            connection_config,
            Arc::new(ResolverOpts::default()),
            TokioRuntimeProvider::default(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        let response = name_server
            .lookup(
                Query::query(name.clone(), RecordType::A),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
            .expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn test_failed_name_server() {
        subscribe();

        let options = ResolverOpts {
            timeout: Duration::from_millis(1),
            ..ResolverOpts::default()
        };

        let config = NameServerConfig::udp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 252)));
        let connection_config = config.connections.first().unwrap().clone();
        let name_server = NameServer::new(
            &config,
            connection_config,
            Arc::new(options),
            TokioRuntimeProvider::default(),
        );

        let name = Name::parse("www.example.com.", None).unwrap();
        assert!(
            name_server
                .lookup(
                    Query::query(name.clone(), RecordType::A),
                    DnsRequestOptions::default(),
                )
                .first_answer()
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn case_randomization_query_preserved() {
        subscribe();

        let provider = TokioRuntimeProvider::default();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let name = Name::from_str("dead.beef.").unwrap();
        let data = b"DEADBEEF";

        spawn({
            let name = name.clone();
            async move {
                let mut buffer = [0_u8; 512];
                let (len, addr) = server.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[0..len]).unwrap();
                let mut response = Message::response(request.id(), request.op_code());
                response.add_queries(request.queries().to_vec());
                response.add_answer(Record::from_rdata(
                    name,
                    0,
                    RData::NULL(NULL::with(data.to_vec())),
                ));
                let response_buffer = response.to_vec().unwrap();
                server.send_to(&response_buffer, addr).await.unwrap();
            }
        });

        let config = NameServerConfig {
            ip: server_addr.ip(),
            trust_negative_responses: true,
            connections: vec![ConnectionConfig {
                port: server_addr.port(),
                protocol: ProtocolConfig::Udp,
                bind_addr: None,
            }],
        };

        let resolver_opts = ResolverOpts {
            case_randomization: true,
            ..Default::default()
        };

        let mut request_options = DnsRequestOptions::default();
        request_options.case_randomization = true;
        let connection_config = config.connections.first().unwrap().clone();
        let ns = NameServer::new(
            &config,
            connection_config,
            Arc::new(resolver_opts),
            provider,
        );

        let stream = ns.lookup(
            Query::query(name.clone(), RecordType::NULL),
            request_options,
        );
        let response = stream.first_answer().await.unwrap();

        let response_query_name = response.queries().first().unwrap().name();
        assert!(response_query_name.eq_case(&name));
    }

    #[allow(clippy::extra_unused_type_parameters)]
    fn is_send_sync<S: Sync + Send>() -> bool {
        true
    }

    #[test]
    fn stats_are_sync() {
        assert!(is_send_sync::<NameServerStats>());
    }

    #[tokio::test(start_paused = true)]
    async fn test_stats_cmp() {
        use std::cmp::Ordering;
        let server_a = NameServerStats::new(Duration::from_micros(10));
        let server_b = NameServerStats::new(Duration::from_micros(20));

        assert_eq!(cmp(&server_a, &server_b), Ordering::Less);

        server_a.record_rtt(Duration::from_millis(30));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Greater);

        server_b.record_rtt(Duration::from_millis(50));
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Less);

        server_a.record_connection_failure();
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Greater);

        while cmp(&server_a, &server_b) != Ordering::Less {
            server_b.record_rtt(Duration::from_millis(50));
            tokio::time::advance(Duration::from_secs(5)).await;
        }

        server_a.record_rtt(Duration::from_millis(30));
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(cmp(&server_a, &server_b), Ordering::Less);
    }

    fn cmp(a: &NameServerStats, b: &NameServerStats) -> cmp::Ordering {
        a.decayed_srtt(Instant::now()).total_cmp(&b.decayed_srtt(Instant::now()))
    }

    #[tokio::test(start_paused = true)]
    async fn test_decayed_srtt() {
        let initial_srtt = 10;
        let server = NameServerStats::new(Duration::from_micros(initial_srtt));

        assert_eq!(server.decayed_srtt(Instant::now()) as u32, initial_srtt as u32);

        tokio::time::advance(Duration::from_secs(5)).await;
        server.record_rtt(Duration::from_millis(100));

        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(server.decayed_srtt(Instant::now()) as u32, 99445);

        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(server.decayed_srtt(Instant::now()) as u32, 96990);
    }
}