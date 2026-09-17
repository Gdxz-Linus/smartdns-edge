use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    path::PathBuf,
    slice::Iter,
    sync::Arc,
};

use tokio::sync::RwLock;

use crate::third_ext::FutureJoinAllExt;
use crate::{
    dns::DnsResponse,
    dns_conf::NameServerInfo,
    dns_error::LookupError,
    log::{self, debug, info, warn},
    proxy::ProxyConfig,
    rustls::TlsClientConfigBundle,
};

use crate::libdns::{
    proto::{
        DnsHandle, ProtoError,
        op::{Edns, Message, Query},
        rr::{
            Record, RecordType,
            domain::{IntoName, Name},
            rdata::opt::{ClientSubnet, EdnsOption},
        },
        xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    },
    resolver::config::{ResolverOpts, ServerOrderingStrategy},
};
pub use bootstrap::BootstrapResolver;
pub use name_server::NameServer;
pub use name_server_group::NameServerGroup;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
///   Setting this to a value of 1 day, in seconds
pub const MAX_TTL: u32 = 86400_u32;

#[derive(Default)]
pub struct DnsClientBuilder {
    server_infos: Vec<NameServerInfo>,
    ca_file: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    client_subnet: Option<ClientSubnet>,
}

impl DnsClientBuilder {
    pub fn add_servers<S: Into<NameServerInfo>>(self, servers: Vec<S>) -> Self {
        servers.into_iter().fold(self, |b, s| b.add_server(s))
    }

    pub fn add_server<S: Into<NameServerInfo>>(mut self, server: S) -> Self {
        self.server_infos.push(server.into());
        self
    }

    pub fn with_ca_file(mut self, file: PathBuf) -> Self {
        self.ca_file = Some(file);
        self
    }

    pub fn with_ca_path(mut self, file: PathBuf) -> Self {
        self.ca_path = Some(file);
        self
    }

    pub fn with_proxies(mut self, proxies: Arc<HashMap<String, ProxyConfig>>) -> Self {
        self.proxies = proxies;

        self
    }

    pub fn with_client_subnet<S: Into<ClientSubnet>>(mut self, subnet: S) -> Self {
        self.client_subnet = Some(subnet.into());
        self
    }

    pub async fn build(self) -> DnsClient {
        let DnsClientBuilder {
            server_infos,
            ca_file,
            ca_path,
            proxies,
            client_subnet,
        } = self;

        let tls_client_config = TlsClientConfigBundle::new(ca_path, ca_file);

        let mut server_instances = HashMap::<&NameServerInfo, _>::new();
        let mut make_server = |server_config, resolver, dedup| {
            let entry = server_instances.entry(server_config);
            if let std::collections::hash_map::Entry::Occupied(_) = entry
                && dedup {
                    return None;
                }
            let server = entry.or_insert_with(|| {
                let proxy = server_config
                    .proxy
                    .as_deref()
                    // 名字写错会**明确告警**并改直连，而不是无声直连（见 `proxy::resolve_proxy`）
                    .map(|n| crate::proxy::resolve_proxy(proxies.as_ref(), n))
                    .unwrap_or_default()
                    .cloned();
                match NameServer::new(
                    server_config.clone(),
                    proxy,
                    Some(tls_client_config.clone()),
                    resolver,
                    client_subnet,
                ) {
                    Ok(server) => Some(Arc::new(server)),
                    Err(err) => {
                        let url = server_config.server.to_string();
                        log::error!("failed to create nameserver {url}, error: {err}");
                        None
                    }
                }
            });
            server.clone()
        };

        let mut bootstrap_servers;
        let bootstrap = {
            bootstrap_servers = server_infos
                .iter()
                .filter(|info| info.bootstrap_dns)
                .filter(|info| {
                    let ok = info.server.has_ip();
                    if !ok {
                        warn!("bootstrap-dns must use ip addess, {:?}", info.server.host());
                    }
                    ok
                })
                .collect::<Vec<_>>();

            if bootstrap_servers.is_empty() {
                bootstrap_servers = server_infos
                    .iter()
                    .filter(|info| info.server.has_ip() && info.proxy.is_none())
                    .collect::<Vec<_>>()
            }

            if bootstrap_servers.is_empty() {
                warn!("not bootstrap-dns found, use system_conf instead.");
            }

            if !bootstrap_servers.is_empty() {
                for info in &bootstrap_servers {
                    info!("bootstrap-dns {}", info.server.to_string());
                }
            }

            let boot = Arc::new(BootstrapResolver::from_system_conf());

            let resolver: Arc<BootstrapResolver> = if !bootstrap_servers.is_empty() {
                let servers = bootstrap_servers
                    .iter()
                    .flat_map(|server_config| make_server(server_config, None, true))
                    .collect();

                let new_resolver = NameServerGroup {
                    resolver_opts: boot.resolver_opts.clone(),
                    servers,
                };

                Arc::new(BootstrapResolver::new(new_resolver.into()))
            } else {
                boot
            };

            resolver
        };

        // 🌟 P1-6：只有"真的一个上游都没有"才算致命错误。
        //
        // 这里原来是 `assert!(!bootstrap.is_empty(), ...)` —— 与上面那句 exit(1) 叠加成
        // 容器里的"启动即死"组合拳：读不到系统 DNS 就崩，而用户配置的上游明明可用。
        if bootstrap.is_empty() {
            if server_infos.is_empty() {
                // 既没有配置任何上游，也读不到系统 DNS：确实无路可走，明确报错退出。
                // （这条路径上给出的建议才是真正有效的。）
                crate::log::error!(
                    "no upstream DNS server available: no `server` / `bootstrap-dns` is configured, \
                     and the system DNS configuration could not be read either. \
                     Please configure an upstream, e.g. `server 119.29.29.29` or `server tls://dns.alidns.com`."
                );
                // 先把已经写下的日志落盘，再退出（否则用户看不到上面这条救命信息）
                crate::infra::mapped_file::flush_all(std::time::Duration::from_millis(500));
                std::process::exit(crate::dns_conf::EXIT_CODE_CONFIG_ERROR);
            }

            // 有上游、只是没有"用来解析上游主机名"的 bootstrap：可用性优先，
            // 继续启动（能直连的 IP 上游照常工作），但把话说清楚。
            warn!(
                "no bootstrap DNS available (system DNS unreadable); upstreams whose host names \
                 must be resolved (DoH/DoT/DoQ) may fail until you configure `bootstrap-dns <ip>`"
            );
        }

        let mut server_config_groups = HashMap::<Option<&str>, HashSet<&NameServerInfo>>::new();
        for (g, server_config) in server_infos.iter().flat_map(|serv_conf| {
            let group = serv_conf.group.iter().map(move |g| (Some(&**g), serv_conf));
            let default = (!serv_conf.exclude_default_group).then_some((None, serv_conf));
            group.chain(default)
        }) {
            server_config_groups
                .entry(g)
                .or_default()
                .insert(server_config);
        }

        let mut server_groups = HashMap::with_capacity(server_config_groups.len());
        let mut default_group_servers = (*bootstrap).clone();

        let resolver_opts = Arc::new(bootstrap.options().clone());

        for (group_name, group) in &server_config_groups {
            let servers = group
                .iter()
                .flat_map(|server_config| {
                    make_server(*server_config, Some(bootstrap.clone()), false)
                })
                .collect();

            let server_group = NameServerGroup {
                resolver_opts: resolver_opts.clone(),
                servers,
            };

            debug!(
                "create nameserver group [{}], servers {}",
                group_name.as_deref().unwrap_or("default"),
                server_group.len()
            );

            if let Some(group_name) = group_name {
                server_groups.insert(group_name.to_string(), Arc::new(server_group));
            } else {
                default_group_servers = Arc::new(server_group);
            }
        }

        server_groups.values().map(|s| s.warmup()).join_all().await;

        DnsClient {
            default: default_group_servers,
            bootstrap,
            servers: server_groups,
        }
    }
}

pub struct DnsClient {
    default: Arc<NameServerGroup>,
    bootstrap: Arc<BootstrapResolver>,
    servers: HashMap<String, Arc<NameServerGroup>>,
}

impl DnsClient {
    pub fn builder() -> DnsClientBuilder {
        DnsClientBuilder::default()
    }

    pub async fn default(&self) -> Arc<NameServerGroup> {
        self.deref().clone()
    }

    pub async fn get_server_group(&self, name: &str) -> Option<Arc<NameServerGroup>> {
        if name.is_empty() || name.eq_ignore_ascii_case("default") {
            return Some(self.default.clone());
        }
        self.servers.get(name).cloned()
    }

    pub async fn lookup_nameserver(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> Option<DnsResponse> {
        self.bootstrap.local_lookup(name, record_type).await
    }
}

impl std::ops::Deref for DnsClient {
    type Target = Arc<NameServerGroup>;

    fn deref(&self) -> &Self::Target {
        &self.default
    }
}

#[derive(Clone)]
pub struct NameServerOpts {
    /// filter result with blacklist ip
    pub blacklist_ip: bool,

    /// filter result with whitelist ip,  result in whitelist-ip will be accepted.
    pub whitelist_ip: bool,

    /// result must exist edns RR, or discard result.
    pub check_edns: bool,

    pub client_subnet: Option<ClientSubnet>,

    resolver_opts: ResolverOpts,
}

impl NameServerOpts {
    #[inline]
    pub fn new(
        blacklist_ip: bool,
        whitelist_ip: bool,
        check_edns: bool,
        client_subnet: Option<ClientSubnet>,
        resolver_opts: ResolverOpts,
    ) -> Self {
        Self {
            blacklist_ip,
            whitelist_ip,
            check_edns,
            client_subnet,
            resolver_opts,
        }
    }

    pub fn with_resolver_opts(mut self, resolver_opts: ResolverOpts) -> Self {
        self.resolver_opts = resolver_opts;
        self
    }
}

impl Default for NameServerOpts {
    fn default() -> Self {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.edns0 = true;

        Self {
            blacklist_ip: Default::default(),
            whitelist_ip: Default::default(),
            check_edns: Default::default(),
            client_subnet: Default::default(),
            resolver_opts,
        }
    }
}

impl Deref for NameServerOpts {
    type Target = ResolverOpts;

    fn deref(&self) -> &Self::Target {
        &self.resolver_opts
    }
}

#[derive(Clone)]
pub struct LookupOptions {
    pub is_dnssec: bool,
    pub record_type: RecordType,
    pub client_subnet: Option<ClientSubnet>,
}

impl Default for LookupOptions {
    fn default() -> Self {
        Self {
            is_dnssec: false,
            record_type: RecordType::A,
            client_subnet: Default::default(),
        }
    }
}

mod name_server_group {
    use super::*;

    #[derive(Default)]
    pub struct NameServerGroup {
        pub resolver_opts: Arc<ResolverOpts>,
        pub servers: Vec<Arc<NameServer>>,
    }

    impl NameServerGroup {
        pub async fn warmup(&self) {
            let futures = self.servers.iter().map(|server| {
                tokio::time::timeout(std::time::Duration::from_secs(5), server.warmup())
            });
            futures.join_all().await;
        }
        #[inline]
        pub fn iter(&self) -> Iter<'_, Arc<NameServer>> {
            self.servers.iter()
        }

        #[inline]
        pub fn len(&self) -> usize {
            self.servers.len()
        }

        #[inline]
        pub fn is_empty(&self) -> bool {
            self.servers.is_empty()
        }

        fn options(&self) -> &Arc<ResolverOpts> {
            &self.resolver_opts
        }

        /// 🔐 第三部分第 3 条（上游 `-fallback`）用的"一整批同时问"：
        /// 谁先给出"正常答案"或"明确的不存在"、或者谁先回来算谁的。
        /// 参数是 `Vec<Arc<NameServer>>`，调用方负责把"正常那批"和"后备那批"分好。
        async fn race_servers<O: Into<LookupOptions> + Send + Clone>(
            servers: &[Arc<NameServer>],
            name: Name,
            options: O,
        ) -> Result<DnsResponse, LookupError> {
            use futures_util::future::select_all;
            let mut tasks = servers
                .iter()
                .map(|ns| GenericResolver::lookup(ns.as_ref(), name.clone(), options.clone()))
                .collect::<Vec<_>>();

			// 🌟 核心防御保护：拦截空任务列表，防止 select_all 触发 Panic 崩盘
            if tasks.is_empty() {
                return Err(crate::libdns::proto::ProtoErrorKind::NoConnections.into());
            }

            // 被"截断但 rcode=NOERROR"的响应：不作为赢家，记下来留到最后兜底（见循环尾部）
            let mut truncated_result: Option<Result<DnsResponse, LookupError>> = None;

            loop {
                let (res, _idx, rest) = select_all(tasks).await;

                let mut is_truncated = false;

                if let Ok(lookup) = res.as_ref() {
                    use crate::libdns::proto::op::ResponseCode;
                    let rcode = lookup.response_code();
                    // 🌟 正常答案（非截断）或明确的不存在（NXDomain）：立刻斩断等待！
                    if rcode == ResponseCode::NXDomain
                        || (rcode == ResponseCode::NoError && !lookup.truncated())
                    {
                        return res;
                    }
                    // 截断包的 rcode 同样是 NOERROR，但它只是"答案太大装不下"的半成品：
                    // 让它赢下竞速，会把其他上游正在路上的完整答案丢掉，越坏的上游反而越快（P1-5）。
                    is_truncated = rcode == ResponseCode::NoError && lookup.truncated();
                }

                if rest.is_empty() {
                    // 所有上游都试完了：只能退回截断包（TC 位会透传给客户端，由客户端按规范换 TCP）
                    return truncated_result.unwrap_or(res);
                }

                if is_truncated && truncated_result.is_none() {
                    truncated_result = Some(res);
                }

                tasks = rest;
            }
        }

    }

    #[async_trait::async_trait]
    impl GenericResolver for NameServerGroup {
        fn options(&self) -> &ResolverOpts {
            &self.resolver_opts
        }

        async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
            &self,
            name: N,
            options: O,
        ) -> Result<DnsResponse, LookupError> {
            let name = name.into_name()?;

            // 🔐 第三部分第 3 条（上游 `-fallback`）：标了后备的服务器**第一轮不参与** ——
            // 只有正常那批给不出可用答案时，才把它拉进来再竞一次。
            // 语义对齐 C 版 `src/dns_client/dns_client.c:405`：skip fallback server for first query。
            let (primary, fallback): (Vec<Arc<NameServer>>, Vec<Arc<NameServer>>) = self
                .servers
                .iter()
                .cloned()
                .partition(|ns| !ns.is_fallback());

            // 组里全是后备服务器（或只有一条且被标了后备）：那就照旧一起用，别把查询搞成失败
            let (primary, fallback) = if primary.is_empty() {
                (fallback, Vec::new())
            } else {
                (primary, fallback)
            };

            let first = Self::race_servers(&primary, name.clone(), options.clone()).await;

            // 第一轮已经拿到可用答案，或者压根没有后备可问 → 就用它
            if fallback.is_empty() || !needs_fallback(&first) {
                return first;
            }

            // 第二轮：把后备服务器拉进来再竞一次
            let second = Self::race_servers(&fallback, name, options).await;

            // 第二轮也没给出更好的结果 → 保留第一轮的（可能是截断包，或更具体的原因）
            if needs_fallback(&second) {
                first
            } else {
                second
            }
        }
    }
}

/// 🔐 第三部分第 3 条（上游 `-fallback`）：这次竞速的结果算不算"拿到可用答案"？
///
/// 判据与竞速循环自己的一致：**正常答案（NOERROR 且没被截断）** 或 **明确的"这个名字不存在"（NXDOMAIN）**
/// 才算"有答案"；超时、上游故障、只剩截断包，都算"没答案"—— 这时候才轮到后备服务器上场。
pub(crate) fn needs_fallback(res: &Result<DnsResponse, LookupError>) -> bool {
    use crate::libdns::proto::op::ResponseCode;

    match res {
        Err(_) => true,
        Ok(resp) => {
            let rcode = resp.response_code();
            !(rcode == ResponseCode::NXDomain
                || (rcode == ResponseCode::NoError && !resp.truncated()))
        }
    }
}

mod name_server {
    use super::*;
    use crate::dns_url::{DnsUrl, ProtocolConfig};
    use crate::libdns::custom::{
        connection_provider::{Connection, ConnectionProvider},
        warmup::DnsHandleWarmpup,
    };

    pub struct NameServer {
        options: Arc<NameServerOpts>,
        connection: Connection,
        /// 仅 UDP 上游才会有：同一个地址、同一个端口的 TCP 备用通路（URL 只用于日志）。
        ///
        /// 用途（RFC 1035 §4.2.1）：UDP 收到 TC=1 截断包（"答案太大，UDP 装不下"）时，
        /// 必须改用 TCP 向**同一个上游**重问一次；不做这一步就只能把残缺答案当正常答案返回。
        ///
        /// 两条刻意的约束（都有实测依据）：
        /// 1. 构建它不产生任何网络 IO（首次 send 时才真正连接）；
        /// 2. 失败时**只回退、不新建连接重试** —— 实测在"上游 TCP 不可达"的网络里，新建连接会一直
        ///    挂到请求超时（5 秒），反而把"立刻退回截断答案"变成"客户端超时失败"。池化连接若被
        ///    上游单方面关掉，本次查询会立刻退回截断答案（与修复前一致），下一次查询 hickory 会
        ///    自行重连，不影响后续升级。
        tcp_fallback: Option<(DnsUrl, Connection)>,
        /// 🔐 这条上游是不是"后备服务器"（配置里的 `-fallback`）。
        /// 后备服务器**第一轮不参与**竞速，只有同组正常那批给不出可用答案时才上场。
        is_fallback: bool,
    }

    impl NameServer {
        pub fn new(
            config: NameServerInfo,
            proxy: Option<ProxyConfig>,
            tls_client_config: Option<TlsClientConfigBundle>,
            resolver: Option<Arc<BootstrapResolver>>,
            default_client_subnet: Option<ClientSubnet>,
        ) -> anyhow::Result<Self> {
            let url = &config.server;

            if !url.has_ip() && resolver.is_none() {
                anyhow::bail!("Parameter resolver is required for non-ip upstream");
            }

            let tls_config = if url.proto().is_encrypted() {
                let Some(tls_client_config) = tls_client_config else {
                    anyhow::bail!("Parameter tls_client_config is required for Encrypted upstream");
                };

                // 🔐 第三部分第 2 条（`-spki-pin`）：配了 pin 的上游，在原有校验（或用 `-k`
                // 关掉链校验）之上**再**核对证书公钥 —— 与 C 版 `client_tls.c` 的语义一致：
                // pin 是额外的确认条件，绝不是"跳过校验"的借口；两者叠加就是"纯 pin"模式。
                let config = match url.spki_pin() {
                    Some(pin) => {
                        tls_client_config.with_spki_pin(pin, url.ssl_verify(), url.sni_off())?
                    }
                    None => {
                        if !url.ssl_verify() {
                            tls_client_config.verify_off
                        } else if url.sni_off() {
                            tls_client_config.sni_off
                        } else {
                            tls_client_config.normal
                        }
                    }
                };

                Some(config)
            } else {
                // 🌟 别让"配了却不起作用"重演：明文上游上写 -spki-pin 等于没配，说清楚
                if url.spki_pin().is_some() {
                    crate::log::warn!(
                        "{}：`-spki-pin` 只对加密上游（tls / https / quic / h3）有效，这条是明文上游，已忽略",
                        url
                    );
                }
                None
            };

            let mut options = NameServerOpts::new(
                config.blacklist_ip,
                config.whitelist_ip,
                config.check_edns,
                config.subnet.map(|x| x.into()).or(default_client_subnet),
                resolver
                    .as_ref()
                    .map(|r| r.options().clone())
                    .unwrap_or_default(),
            );

            if let Some(tls_config) = tls_config.as_deref() {
                options.resolver_opts.tls_config = tls_config.clone();
            }

            options.resolver_opts.server_ordering_strategy =
                ServerOrderingStrategy::QueryStatistics;

            let so_mark = config.so_mark;
            let device = config.interface;

            // UDP 上游额外准备一条"同地址、同端口"的 TCP 备用通路（只在收到截断包时用）
            let tcp_fallback = matches!(config.server.proto(), ProtocolConfig::Udp).then(|| {
                let mut tcp_url = config.server.clone();
                tcp_url.set_proto(ProtocolConfig::Tcp);
                let connection = ConnectionProvider::new(
                    tcp_url.clone(),
                    Arc::new(options.deref().clone()),
                    resolver.clone(),
                    proxy.clone(),
                    so_mark,
                    device.clone(),
                );
                (tcp_url, connection)
            });

            let connection = ConnectionProvider::new(
                config.server,
                Arc::new(options.deref().clone()),
                resolver,
                proxy,
                so_mark,
                device,
            );

            Ok(Self {
                options: options.into(),
                connection,
                tcp_fallback,
                is_fallback: config.fallback,
            })
        }

        pub async fn warmup(&self) -> Result<(), ProtoError> {
            self.connection.warmup().await?;
            Ok(())
        }

        #[inline]
        pub fn options(&self) -> &NameServerOpts {
            &self.options
        }

        /// 🔐 这条上游是不是配了 `-fallback`（后备服务器）
        #[inline]
        pub fn is_fallback(&self) -> bool {
            self.is_fallback
        }
    }

    #[async_trait::async_trait]
    impl GenericResolver for NameServer {
        fn options(&self) -> &ResolverOpts {
            &self.options().resolver_opts
        }

        async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
            &self,
            name: N,
            options: O,
        ) -> Result<DnsResponse, LookupError> {
            let name = name.into_name()?;
            let options: LookupOptions = options.into();

            let query = Query::query(name, options.record_type);

            let client_subnet = options.client_subnet.or(self.options().client_subnet);

            if options.client_subnet.is_none()
                && let Some(subnet) = client_subnet.as_ref() {
                    log::debug!(
                        "query name: {} type: {} subnet: {}/{}",
                        query.name(),
                        query.query_type(),
                        subnet.addr(),
                        subnet.scope_prefix(),
                    );
                }

            let request_options = {
                let opts = &self.options();
                let mut request_opts = DnsRequestOptions::default();
                request_opts.recursion_desired = opts.recursion_desired;
                request_opts.use_edns = opts.edns0 || client_subnet.is_some();
                request_opts
            };

            let req = DnsRequest::new(
                build_message(query, request_options, client_subnet, options.is_dnssec),
                request_options,
            );

            // 只有 UDP 上游才需要留一份请求副本：截断后要用它改走 TCP 重问
            let tcp_req = self.tcp_fallback.as_ref().map(|_| req.clone());

            let res = {
                let ns = &self.connection;
                ns.send(req).first_answer().await?
            };

            // RFC 1035 §4.2.1：UDP 收到 TC=1 表示"答案太大，UDP 装不下"，标准做法是改用 TCP
            // 向**同一个上游**重问一次。缺了这一步，就只能把残缺答案当正常答案返回：半截地址
            // 会被写进缓存、参与测速，并在整个 TTL 内发给所有客户端（P1-5）。
            //
            // 🔐 ## 2026-09-17：整条 TCP 腿加"上限"，并在"死得太快"时允许重来一次
            //
            // 实测（`run_p2tcpretry.py`，真实二进制 + 可控假上游）两个问题：
            // ① **连接在应答途中被上游重置**（一问一关的代理、RST）→ 这一次查询直接退回半截答案；
            // ② **上游压根不接受 TCP 连接**（连接被拒）→ 要**卡 4.07 秒**才退回半截答案
            //    （清单里原以为"立刻退回"，实测不是）。
            //
            // 所以这里做两件事：
            //   a. 整条 TCP 腿套一个明确上限 `TCP_FALLBACK_DEADLINE`：无论上游是黑洞还是半死不活，
            //      最坏只多花这一点时间，随后如实把带 TC 的应答交给客户端（由客户端按规范改走 TCP 来问我们）。
            //   b. 如果第一次失败得**很快**（说明是"这条连接已经死了"，不是"网络黑洞在耗时间"），
            //      就重来一次 —— hickory 上一次失败已把该连接标记为 Failed，下一次 send 会自己重连，
            //      于是"被掐掉的那一次"也能拿到完整答案。重来同样受上面的上限约束，不会退化成死等。
            //
            // 上限取值 800ms 的理由：TCP 重问的代价是"连接（1 个往返）+ 查询（1 个往返）"，
            // 800ms 足够覆盖到单程 400ms 的上游；而 TC=1 本来就少见（只出现在大答案上），
            // 拿这点时间换"不把半截答案交出去"是划算的。上限只影响 TCP 这条腿，UDP 主路不变。
            if res.truncated()
                && let (Some((url, tcp)), Some(tcp_req)) = (self.tcp_fallback.as_ref(), tcp_req)
            {
                // 第一次尝试的预算
                const TCP_FALLBACK_DEADLINE: std::time::Duration =
                    std::time::Duration::from_millis(800);
                // 重来一次的预算（更小）：保证"最坏也只是多花这么点"，绝不会演变成死等。
                const TCP_FALLBACK_RETRY_DEADLINE: std::time::Duration =
                    std::time::Duration::from_millis(300);

                let first =
                    tokio::time::timeout(TCP_FALLBACK_DEADLINE, tcp.send(tcp_req.clone()).first_answer())
                        .await;

                // 先记下第一次为什么失败（只为日志），再把结果用掉
                let first_why = match &first {
                    Ok(Ok(_)) => String::new(), // 成功了就走不到重来那一段
                    Ok(Err(err)) => format!("error: {err}"),
                    Err(_) => format!("timeout after {TCP_FALLBACK_DEADLINE:?}"),
                };

                if let Ok(Ok(full)) = first {
                    debug!("{url}: udp response is truncated, retried over tcp and got a complete answer");
                    return Ok(From::<Message>::from(full.into()));
                }

                // 第一次没成 → **无条件重来一次**（换一条新连接：hickory 上一次失败已把该连接标记为
                // Failed，下一次 send 会自己重连）。
                //
                // 为什么不做"看错误种类 / 看失败快慢"的区分（2026-09-17 定）：
                // 实测同一种"上游把连接重置"的故障，会随时序表现为两种样子 ——
                // 有时是立刻报错、有时却是"读一直挂到我们的上限"，用启发式判据必然漏掉一种
                // （见 `run_p2tcpretry.py` 的复现记录：加上"只认快失败"之后，3 次里有 1 次又退回半截答案）。
                // 改成无条件重来 + 重来那条腿只给 300ms，最坏也只是在"对端彻底沉默"时多花 0.3 秒，
                // 却能把"被掐掉的那一次"稳稳救回来。
                match tokio::time::timeout(
                    TCP_FALLBACK_RETRY_DEADLINE,
                    tcp.send(tcp_req).first_answer(),
                )
                .await
                {
                    Ok(Ok(full)) => {
                        debug!("{url}: udp response is truncated, tcp retry succeeded after first attempt failed ({first_why}), got a complete answer");
                        return Ok(From::<Message>::from(full.into()));
                    }
                    Ok(Err(err2)) => debug!(
                        "{url}: udp response is truncated, tcp retry failed too (first: {first_why}; retry: {err2}), returning the truncated answer"
                    ),
                    Err(_) => debug!(
                        "{url}: udp response is truncated, tcp retry exceeded {TCP_FALLBACK_RETRY_DEADLINE:?} (first: {first_why}), returning the truncated answer"
                    ),
                }
            }

            Ok(From::<Message>::from(res.into()))
        }
    }

    struct ClientHandle {
        connection: Arc<Connection>,
    }

    /// 🌟 核心修复 1：将 1232 提升到 4096，包容不守规矩的上游和巨型 DNSSEC 数据包.
    ///
    /// ⚠️ **4096 这个值已定案，不要再往下调**（2026-09-17 查证，三条依据）：
    /// 1. **与 C 版一致**：C 版发给上游的 OPT 载荷也是 4096
    ///    （`src/dns_client/packet.c:78` 用 `DNS_IN_PACKSIZE`，定义 `src/include/smartdns/dns.h:30` = `512 * 8`）。
    /// 2. **与内嵌 hickory 的收包上限一致，不虚标**：hickory 的 UDP 读缓冲是
    ///    `MAX_RECEIVE_BUFFER_SIZE.min(声明的 max_payload)`，而 `MAX_RECEIVE_BUFFER_SIZE = 4096`
    ///    （`hickory-dns/crates/proto/src/udp/mod.rs:27`、`udp/udp_client_stream.rs:167`）。
    ///    所以 4096 就是"我们实际能收下的最大包"，声明 4096 = 说到做到。
    /// 3. **声明小反而会招故障**：DNS Flag Day 2020 建议把默认值降到 1232 是为了避免 IP 分片，
    ///    但那是站在"权威服务器只发合规大小的包"这个前提上。真有上游不理 EDNS、照发 2~4 KB 的包时，
    ///    我们声明 1232 只会让内核只读 1232 字节 —— 多出来的部分在 Linux 被**静默截断**（变成残包）、
    ///    在 Windows 被**整包丢弃**（WSAEMSGSIZE），正是本项目最想避免的"查不出来"的故障。
    ///    真要处理超长答案，正确做法是走 TC → TCP 重问（已实现，见本文件 `tcp_fallback`）。
    /// 客户端方向是另一条独立的路：对客户端声明的尺寸做 [512, 4096] 收口，超了就贴 TC=1
    /// （`src/app.rs:954`），不受这里的值影响。
    const MAX_PAYLOAD_LEN: u16 = 4096;

    fn build_message(
        query: Query,
        request_options: DnsRequestOptions,
        client_subnet: Option<ClientSubnet>,
        is_dnssec: bool,
    ) -> Message {
        // build the message

        let mut message = Message::query();
        // TODO: This is not the final ID, it's actually set in the poll method of DNS future
        message
            .add_query(query)
            .set_recursion_desired(request_options.recursion_desired);

        // Extended dns
        if client_subnet.is_some() || request_options.use_edns || is_dnssec {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(MAX_PAYLOAD_LEN)
                .set_version(0);

            if let (Some(client_subnet), Some(edns)) = (client_subnet, message.extensions_mut()) {
                edns.options_mut().insert(EdnsOption::Subnet(client_subnet));
            }

            if let (true, Some(edns)) = (is_dnssec, message.extensions_mut()) {
                edns.set_dnssec_ok(is_dnssec);
            }
        }
        message
    }
}

mod bootstrap {
    use super::*;
    use crate::dns_url::DnsUrl;
    use std::time::{Duration, Instant}; // 🌟 修复报错：引入标准库的钟表和时间工具！

    pub struct BootstrapResolver<T: GenericResolver = NameServerGroup>
    where
        T: Send + Sync,
    {
        resolver: Arc<T>,
        // 🌟 修复炸弹一：加入 Instant 记录这个 IP 的绝对过期时间
        ip_store: RwLock<HashMap<Query, (Instant, Arc<[Record]>)>>,
    }

    impl<T: GenericResolver + Sync + Send> BootstrapResolver<T> {
        pub fn new(resolver: Arc<T>) -> Self {
            Self {
                resolver,
                ip_store: Default::default(),
            }
        }

        pub fn with_new_resolver(self, resolver: Arc<T>) -> Self {
            Self {
                resolver,
                ip_store: self.ip_store,
            }
        }

        pub async fn local_lookup(
            &self,
            name: Name,
            record_type: RecordType,
        ) -> Option<DnsResponse> {
            let query = Query::query(name.clone(), record_type);
            let store = self.ip_store.read().await;

            // 🌟 修复炸弹一：不仅要看有没有，还要看有没有过期！
            if let Some((valid_until, records)) = store.get(&query)
                && Instant::now() < *valid_until {
                    return Some(DnsResponse::new_with_deadline(query, records.to_vec(), *valid_until));
                }
            None
        }
    }

    impl BootstrapResolver<NameServerGroup> {
        pub fn from_system_conf() -> Self {
            let (resolv_config, resolv_opts) =
                crate::libdns::resolver::system_conf::read_system_conf().unwrap_or_else(|err| {
                    // 🌟 核心修复：贯彻 Fail-Fast 原则，绝不静默兜底撒谎！
                    // 一旦读取系统网卡 DNS 失败，立刻大声报错并终止程序。
                    // 强迫用户直面网络配置问题，或引导其使用命令行参数显式指定。
                    
                    // 使用 ANSI 转义码在控制台打印高亮的红、黄、绿色文本
                    // 🔐 B4：这里**不会退出**（P1-6 起已改成降级继续运行），所以不能再喊 FATAL ——
                    // 用户看到"致命错误"却发现服务照常跑，会以为出了更严重的问题。
                    eprintln!(
                        "\n\x1b[33;1m[警告]\x1b[0m 读不到系统网卡上的 DNS 配置：{}",
                        err
                    );
                    eprintln!(
                        "\x1b[33;1m已降级继续运行\x1b[0m：用 IP 形式的上游（server / -s）不受影响；\
                         需要解析主机名的上游（DoH/DoT/DoQ）会失败，请显式指定 \
                         \x1b[32m-s 119.29.29.29\x1b[0m 或配置 `bootstrap-dns <ip>`。\n"
                    );
                    
                    // 同时也记录到标准日志中，以防是作为后台服务运行时的静默崩溃
                    crate::log::error!("read system conf failed: {}", err);
                    
                    // 🌟 P1-6 修复：这里原来是 `std::process::exit(1)`。
                    //
                    // 原来的行为有两个致命问题：
                    //   1. 它是**无条件**执行的 —— 用户哪怕已经在配置/命令行里写明了上游，
                    //      只要容器里没有 /etc/resolv.conf（或网卡读不到、权限受限），
                    //      整个进程也会直接以退出码 1 终止，表现为"服务启动即崩、反复重启"；
                    //   2. 库代码里直接杀进程，上层没有任何补救余地。
                    // 而且它给出的排障建议（用 `-s <IP>`）在这条路径上根本无效。
                    //
                    // 现在改成"大声告警 + 返回一个没有兜底上游的空解析器"，
                    // 到底算不算致命，交给调用方按"还有没有别的上游可用"来判断。
                    crate::infra::mapped_file::flush_all(std::time::Duration::from_millis(500));
                    (Default::default(), Default::default())
                });
            let mut name_servers = vec![];

            for config in resolv_config.name_servers() {
                if let Ok(ns) = NameServer::new(DnsUrl::from(config).into(), None, None, None, None)
                {
                    name_servers.push(Arc::new(ns));
                }
            }

            let resolv_opts = Arc::new(resolv_opts);

            Self::new(Arc::new(NameServerGroup {
                resolver_opts: resolv_opts.clone(),
                servers: name_servers,
            }))
        }
    }

    impl<T: GenericResolver + Sync + Send> std::ops::Deref for BootstrapResolver<T> {
        type Target = Arc<T>;

        fn deref(&self) -> &Self::Target {
            &self.resolver
        }
    }

    #[async_trait::async_trait]
    impl<T: GenericResolver + Sync + Send> GenericResolver for BootstrapResolver<T> {
        fn options(&self) -> &ResolverOpts {
            self.resolver.options()
        }

        #[inline]
        async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
            &self,
            name: N,
            options: O,
        ) -> Result<DnsResponse, LookupError> {
            let name = name.into_name()?;
            let options: LookupOptions = options.into();
            let record_type = options.record_type;
            if let Some(lookup) = self.local_lookup(name.clone(), record_type).await {
                return Ok(lookup);
            }

            match GenericResolver::lookup(self.resolver.as_ref(), name.clone(), options).await {
                Ok(lookup) => {
                    let records = lookup.records().to_vec();

                    debug!(
                        "lookup nameserver {} {}, {:?}",
                        name,
                        record_type,
                        records
                            .iter()
                            .flat_map(|r| r.data().ip_addr())
                            .collect::<Vec<_>>()
                    );

                    // 🌟 【修复炸弹二】：护栏！只有拿到真实 IP，才允许存入账本！
                if !records.is_empty() {
                    let min_ttl = lookup.min_ttl().unwrap_or(60);
                    let valid_until = Instant::now() + Duration::from_secs(min_ttl as u64);

                    self.ip_store.write().await.insert(
                        Query::query(
                            {
                                let mut name = name.clone();
                                name.set_fqdn(true);
                                name
                            },
                            record_type,
                        ),
                        (valid_until, records.into()), 
                    );
                }

                    Ok(lookup)
                }
                err => err,
            }
        }
    }

    impl<T: GenericResolver + Sync + Send> From<Arc<T>> for BootstrapResolver<T> {
        fn from(resolver: Arc<T>) -> Self {
            Self::new(resolver)
        }
    }

    impl<T: GenericResolver + Sync + Send> From<&BootstrapResolver<T>> for Arc<T> {
        fn from(value: &BootstrapResolver<T>) -> Self {
            value.resolver.clone()
        }
    }
}

#[async_trait::async_trait]
pub trait GenericResolver {
    fn options(&self) -> &ResolverOpts;

    /// Lookup any RecordType
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup, all RecordData responses will be filtered to this type
    ///
    /// # Returns
    ///
    ///  A future for the returned Lookup RData
    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError>;
}

#[async_trait::async_trait]
pub trait GenericResolverExt {
    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    async fn lookup_ip<N: IntoName + Send>(&self, host: N) -> Result<DnsResponse, LookupError>;
}

#[async_trait::async_trait]
impl<T> GenericResolverExt for T
where
    T: GenericResolver + Sync,
{
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    async fn lookup_ip<N: IntoName + Send>(&self, host: N) -> Result<DnsResponse, LookupError> {
        let mut finally_ip_addr: Option<Record> = None;
        let maybe_ip = host.to_ip();
        let maybe_name: Result<Name, ProtoError> = host.into_name();

        // if host is a ip address, return directly.
        if let Some(ip_addr) = maybe_ip {
            let ip_addr = ip_addr.into();
            let name = maybe_name.clone().unwrap_or_default();
            let record = Record::from_rdata(name.clone(), MAX_TTL, Clone::clone(&ip_addr));

            // if ndots are greater than 4, then we can't assume the name is an IpAddr
            //   this accepts IPv6 as well, b/c IPv6 can take the form: 2001:db8::198.51.100.35
            //   but `:` is not a valid DNS character, so technically this will fail parsing.
            //   TODO: should we always do search before returning this?
            if self.options().ndots > 4 {
                finally_ip_addr = Some(record);
            } else {
                let query = Query::query(name, ip_addr.record_type());
                let lookup = DnsResponse::new_with_max_ttl(query, vec![record]);
                return Ok(lookup);
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                let query = Query::query(ip_addr.name().clone(), ip_addr.record_type());
                let lookup = DnsResponse::new_with_max_ttl(query, vec![ip_addr.clone()]);
                return Ok(lookup);
            }
            (Err(err), None) => {
                return Err(err.into());
            }
        };

        let strategy = self.options().ip_strategy;
        use crate::libdns::resolver::config::LookupIpStrategy::*;

        match strategy {
            Ipv4Only => self.lookup(name.clone(), RecordType::A).await,
            Ipv6Only => self.lookup(name.clone(), RecordType::AAAA).await,
            Ipv4AndIpv6 => {
                use futures_util::future::select_all;
                use futures_util::FutureExt;
                let mut tasks = vec![
                    self.lookup(name.clone(), RecordType::A).boxed(),
                    self.lookup(name.clone(), RecordType::AAAA).boxed(),
                ];

                loop {
                    let (res, _, rest) = select_all(tasks).await;
                    
                    // 🌟 修复炸弹一：只有拿到包含真实 IP 的包裹，才算赢得比赛！空包直接无视，等另一个！
                    if matches!(res.as_ref(), Ok(lookup) if !lookup.records().is_empty()) {
                        return res;
                    }
                    
                    if rest.is_empty() {
                        return res; // 如果两个都不通或者都是空包，只能无奈认命返回
                    }
                    tasks = rest;
                }
            }
            Ipv6thenIpv4 => match self.lookup(name.clone(), RecordType::AAAA).await {
                // 🌟 同理：不能是空包！如果是空包也必须降级去查另一个！
                Ok(lookup) if !lookup.records().is_empty() => Ok(lookup),
                _ => self.lookup(name.clone(), RecordType::A).await,
            },
            Ipv4thenIpv6 => match self.lookup(name.clone(), RecordType::A).await {
                Ok(lookup) if !lookup.records().is_empty() => Ok(lookup),
                _ => self.lookup(name.clone(), RecordType::AAAA).await,
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        dns_url::DnsUrl,
        preset_ns::{ALIDNS, CLOUDFLARE},
        third_ext::{FutureJoinAllExt, FutureTimeoutExt},
    };
    use std::net::IpAddr;
    use std::str::FromStr;

        #[tokio::test]
    async fn test_with_default() {
        let client = DnsClient::builder().build().await;
        let lookup_ip = client
            .lookup("dns.alidns.com", RecordType::A)
            .await
            .unwrap();
        assert!(
            lookup_ip
                .ip_addrs()
                .into_iter()
                .any(|i| i == "223.5.5.5".parse::<IpAddr>().unwrap()
                    || i == "223.6.6.6".parse::<IpAddr>().unwrap())
        );
    }

    async fn query_google(client: &DnsClient) -> bool {
        let name = "dns.google";
        let addrs = match client
            .lookup_ip(name)
            .timeout(std::time::Duration::from_secs(5))
            .await
        {
            Ok(Ok(lookup)) => lookup
                .ip_addrs()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };
        // println!("name: {} addrs => {}", name, addrs);
        addrs.contains("8.8.8.8") || addrs.contains("8.8.4.4")
    }

    async fn query_alidns(client: &DnsClient) -> bool {
        let name = "dns.alidns.com";
        let addrs = match client
            .lookup_ip(name)
            .timeout(std::time::Duration::from_secs(5))
            .await
        {
            Ok(Ok(lookup)) => lookup
                .ip_addrs()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };

        // println!("name: {} addrs => {}", name, addrs);
        addrs.contains("223.5.5.5") || addrs.contains("223.6.6.6")
    }

    #[tokio::test]
        #[cfg(feature = "dns-over-tls")]
    async fn test_nameserver_tls_resolve() {
        let urls = [
            DnsUrl::from_str("tls://dns.google?enable_sni=false").unwrap(),
            DnsUrl::from_str("tls://dns.cloudflare.com?enable_sni=false").unwrap(),
            DnsUrl::from_str("tls://dns.quad9.net?enable_sni=false").unwrap(),
            DnsUrl::from_str("tls://dns.alidns.com").unwrap(),
            DnsUrl::from_str("tls://dot.pub").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        let total = results.len() as f32;
        let success = results.into_iter().filter(|r| *r).count();
        println!("test_nameserver_tls_resolve, success: {success}/{total}");
        assert!(success > 0);
    }

    #[tokio::test]
        #[cfg(feature = "dns-over-https")]
    async fn test_nameserver_https_resolve() {
        let urls = [
            DnsUrl::from_str("https://dns.cloudflare.com/dns-query").unwrap(),
            DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap(),
            DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap(),
            DnsUrl::from_str("https://doh.pub/dns-query").unwrap(),
            DnsUrl::from_str("https://dns.adguard-dns.com/dns-query").unwrap(),
            DnsUrl::from_str("https://dns.quad9.net/dns-query").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().any(|r| r));
    }

    #[tokio::test]
    #[ignore = "需要能直连 AdGuard 的 HTTP/3（出站 UDP 443）；国内网络通常被阻断"]
    #[cfg(feature = "dns-over-h3")]
    async fn test_nameserver_h3_resolve() {
        let urls = [DnsUrl::from_str("h3://dns.adguard-dns.com/dns-query").unwrap()];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-h3")]
    async fn test_nameserver_h3_with_ipv6_address_resolve() {
        // Skip the test if the IPv6 address is not reachable.
        if crate::infra::ping::ping(
            "https://2001:4860:4860::8888".parse().unwrap(),
            None,
            Default::default(),
        )
        .await
        .is_err()
        {
            return;
        }

        let urls = [DnsUrl::from_str("h3://[2001:4860:4860::8888]").unwrap()];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

        #[tokio::test]
    async fn test_nameserver_cloudflare_resolve() {
        let dns_urls = CLOUDFLARE
            .ips
            .iter()
            .copied()
            .map(DnsUrl::from)
            .collect::<Vec<_>>();

        let client = DnsClient::builder().add_servers(dns_urls).build().await;
        assert!(query_google(&client).await);
        assert!(query_alidns(&client).await);
    }

        #[tokio::test]
    async fn test_nameserver_alidns_resolve() {
        let dns_urls = ALIDNS
            .ips
            .iter()
            .copied()
            .map(DnsUrl::from)
            .collect::<Vec<_>>();
        let client = DnsClient::builder().add_servers(dns_urls).build().await;
        assert!(query_google(&client).await);
        assert!(query_alidns(&client).await);
    }

    #[tokio::test]
    #[ignore = "需要能直连 AdGuard 的 DoQ（出站 UDP 443）；国内网络通常被阻断"]
    #[cfg(feature = "dns-over-quic")]
    async fn test_nameserver_quic_resolve() {
        let urls = [
            DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap(),
            DnsUrl::from_str("quic://unfiltered.adguard-dns.com?enable_sni=true").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

    // 已删除 test_nameserver_quic_over_proxy_resolve：
    // 它的正文与 test_nameserver_quic_resolve 逐字节相同（并未配置任何代理，只是函数名不同），
    // 而它名字所描述的「DoQ 走代理」在生产里根本不会发生——
    // connection_provider.rs 一旦检测到代理就把 Quic 降级为 Tls、H3 降级为 Https(H2)，
    // 生产不会经代理跑 DoQ/H3。留着它只会让人误以为这条链路被测过。
    //
    // 如果将来要覆盖「降级」这个真实行为，正确写法是：配一个带 -proxy 的 quic 上游，
    // 断言它被降级为 DoT 且仍然可用，而不是像原来那样再查一遍 AdGuard。

    // #[test]
    // fn test_bootstrap_resolver() {
    //     assert_eq!(bootstrap::RESOLVER.deref(), &99);
    //     *once_cell::sync::Lazy::force_mut(&mut lazy) = 88;
    //     assert_eq!(bootstrap::RESOLVER.deref(), &88);
    // }
}
