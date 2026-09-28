use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    path::PathBuf,
    slice::Iter,
    sync::Arc,
};

use tokio::sync::RwLock;

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
                && dedup
            {
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

        // 🔐 问题 46：**不再做启动预热**。
        //
        // 原来这里会对每个上游发一条固定的 `example.com` A 查询来"预热"。
        // 去掉它的理由与建连路径那次相同（**内网上游会被永久判死**、
        // 隐私暴露、审计噪声），详见 `libdns/custom/connection_provider.rs` 里的说明。
        //
        // 另外这里本来就**丢掉全部结果**（`join_all` 的返回值没有使用），
        // 所以预热从没影响过任何判断：上游可用与否完全由真实查询决定。
        // 去掉后，连接改为在首次真实查询时建立 —— 代价只是第一个查询多一次建连往返，
        // 而收益是内网上游不再被这个固定域名卡住。

        // 🔐 问题 46：**不再做启动预热**。
        //
        // 原来这里会对每个上游发一条固定的 `example.com` A 查询来"预热"。
        // 去掉它的理由与建连路径那次相同（**内网上游会被永久判死**、
        // 隐私暴露、审计噪声），详见 `libdns/custom/connection_provider.rs` 里的说明。
        //
        // 另外这里本来就**丢掉全部结果**（`join_all` 的返回值没有使用），
        // 所以预热从没影响过任何判断：上游可用与否完全由真实查询决定。
        // 去掉后，连接改为在首次真实查询时建立 —— 代价只是第一个查询多一次建连往返，
        // 而收益是内网上游不再被这个固定域名卡住。

        // 🔐 问题 46：**不再做启动预热**。
        //
        // 原来这里会对每个上游发一条固定的 `example.com` A 查询来"预热"。
        // 去掉它的理由与建连路径那次相同（**内网上游会被永久判死**、
        // 隐私暴露、审计噪声），详见 `libdns/custom/connection_provider.rs` 里的说明。
        //
        // ⚠️ 顺带一个**原来就有的缺陷**：这行写的是 `server_groups.values()`，
        // 而**未命名的默认组被存进的是 `default_group_servers`、不在 `server_groups` 里** ——
        // 所以默认组的上游从来没被启动预热碰过（只有写了 `-group` 的命名组才会）。
        // 这也意味着"预热"的行为本来就不一致；一并去掉后这种不一致也消失了。

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
            let mut truncated_result: Option<DnsResponse> = None;

            // 🔐 达不到"定论"标准的应答（不带 SOA 的 NXDOMAIN、空应答等）全部暂存，
            // 等所有上游说完再按 `response_rank` 择优 —— 这正是问题 6 的修复：
            // 原先不带 SOA 的 NXDOMAIN 能立刻赢下竞速，一个被污染的上游
            // 就能把结果钉进否定缓存，让所有客户端在整个 TTL 内都解析不出来。
            let mut held: Vec<Result<DnsResponse, LookupError>> = Vec::new();

            loop {
                let (res, _idx, rest) = select_all(tasks).await;

                // 达到定论标准（正牌答案，或带 SOA 的规范 NXDOMAIN）：立刻斩断等待
                if let Ok(lookup) = res.as_ref()
                    && is_conclusive(lookup)
                {
                    return res;
                }

                if rest.is_empty() {
                    // 所有上游都试完了：按可信度择优，截断包留作最后兜底
                    return pick_best(held, res, truncated_result);
                }

                // 截断包单独留出来作兜底；其余一律进候选池等评分
                if let Ok(lookup) = res.as_ref()
                    && lookup.truncated()
                {
                    truncated_result.get_or_insert_with(|| lookup.clone());
                } else {
                    held.push(res);
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
/// 🔐 判据必须与竞速循环**完全一致**（都用 [`is_conclusive`]），否则
/// 「什么时候停止等待」会和「什么时候该叫后备上游」对不上：
/// 例如第一轮已经拿到「带 SOA 的规范 NXDOMAIN」——那是足够可信的结论，
/// 不该再浪费一次查询去叫后备上游。
///
/// 注意这里**不再把「不带 SOA 的 NXDOMAIN」当作拿到答案**：那种应答会被竞速
/// 暂存并继续等其他上游（问题 6），既然没有定论，后备上游自然该上场。
pub(crate) fn needs_fallback(res: &Result<DnsResponse, LookupError>) -> bool {
    !is_conclusive_result(res)
}

/// 🔐 应答可信度评分：**数字越小越可信**。
///
/// 这是全项目**唯一**的一套「谁更值得采信」标准 —— 原先它只存在于 IP 类查询的兜底
/// 逻辑里（`dns_mw_ns.rs`），而非 IP 类查询的竞速路径按「谁先回来算谁的」采信，
/// 于是同一个程序里对「应答质量」有两套口径（详见问题 6）。
/// 现在抽到这里共用，避免再次漂移。
///
/// 判据：
///   * 有没有答案（Answer 区非空）；
///   * 有没有 SOA（三个区任意一处）—— 带 SOA 说明是上游**权威**给出的规范否定/空应答，
///     不带 SOA 的「不存在」很可能是被污染或被中间设备伪造的；
///   * 响应码。
pub(crate) fn response_rank(res: &DnsResponse) -> u8 {
    use crate::libdns::proto::op::ResponseCode;
    use crate::libdns::proto::rr::RecordType;

    let code = res.response_code();
    let has_answers = !res.answers().is_empty();

    let has_soa = res
        .authorities()
        .iter()
        .any(|r| r.record_type() == RecordType::SOA)
        || res
            .answers()
            .iter()
            .any(|r| r.record_type() == RecordType::SOA)
        || res
            .additionals()
            .iter()
            .any(|r| r.record_type() == RecordType::SOA);

    match (code, has_answers, has_soa) {
        (ResponseCode::NoError, true, _) => 0, // 有 Answer 的完美合法包
        (ResponseCode::NoError, false, true) => 1, // 带真实 SOA 的合法 NoData
        (ResponseCode::NoError, false, false) => 2, // 不带 SOA 的残缺空包
        (ResponseCode::NXDomain, _, true) => 3, // 带 SOA 的规范 NXDOMAIN
        (ResponseCode::NXDomain, _, false) => 4, // 光秃秃的虚假 NXDOMAIN
        _ => 5,
    }
}

/// 这份应答是否「好到不用再等其他上游」——竞速里允许立刻返回的判据。
///
/// 🔐 只有两种情形够格：
///   1. **NOERROR 且有答案、且未被截断**：正牌答案，不亏待它；
///   2. **带 SOA 的 NXDOMAIN**：上游权威给出的规范「不存在」，可采信。
///
/// 其余一律**不许立刻赢**，包括：
///   * **不带 SOA 的 NXDOMAIN** —— 很可能是伪造/污染，必须等其他上游交叉验证
///     （这正是问题 6：原先它也能立刻赢，一个坏上游就能把结果钉死）；
///   * 空应答（NoData）—— 同上，等交叉验证；
///   * 截断包 —— 它只是"答案太大装不下"的半成品，之前已经按 P1-5 排除在赢家之外。
pub(crate) fn is_conclusive(res: &DnsResponse) -> bool {
    // 截断包只是"答案太大装不下"的半成品，无论什么 rcodes 都不能算定论
    // （这是 P1-5 的结论：让它赢会把其他上游正在路上的完整答案丢掉）
    if res.truncated() {
        return false;
    }

    match response_rank(res) {
        // NoError + 有答案：正牌答案，不亏待它
        0 => true,
        // NXDomain + 带 SOA：上游权威给出的规范"不存在"，可采信
        3 => true,
        // 其余一律等其他上游交叉验证：
        //   1 = NoData（带 SOA 的空包）
        //   2 = 不带 SOA 的残缺空包
        //   4 = 不带 SOA 的 NXDOMAIN（很可能是伪造/污染 —— 问题 6 的根源）
        _ => false,
    }
}

/// 🔐 这一批竞速的结果，算不算"我们已经有了可用的结论"？
///
/// 用于上游 `-fallback` 的触发判据（`needs_fallback`）与竞速循环共用同一套标准，
/// 两者必须保持一致，否则「什么时候该叫后备上游」会和「什么时候停止等待」对不上。
pub(crate) fn is_conclusive_result(res: &Result<DnsResponse, LookupError>) -> bool {
    match res {
        Ok(resp) => is_conclusive(resp),
        Err(_) => false,
    }
}

/// 竞速收尾：所有候选里挑最可信的一个返回。
///
/// 排序依据是 [`response_rank`]（数字越小越可信）。全部候选都是错误时，
/// 把其中一个错误如实抛出去 —— 让上层看到真实原因，而不是伪造一个"空应答"。
///
/// `truncated` 是单独留出来的截断包：它只作**最后的兜底**，
/// 因为 TC 位会透传给客户端、由客户端按规范改用 TCP 重问（P1-5）。
fn pick_best(
    held: Vec<Result<DnsResponse, LookupError>>,
    last: Result<DnsResponse, LookupError>,
    truncated: Option<DnsResponse>,
) -> Result<DnsResponse, LookupError> {
    let mut candidates = held;
    candidates.push(last);

    // 1. 按可信度择优：只考虑真正拿到的应答
    if let Some(best) = candidates
        .iter()
        .filter_map(|c| c.as_ref().ok())
        .min_by_key(|resp| response_rank(resp))
    {
        return Ok(best.clone());
    }

    // 2. 一个应答都没有：退回截断包（至少让客户端知道"太大装不下、请改 TCP"）
    if let Some(t) = truncated {
        return Ok(t);
    }

    // 3. 连截断包都没有：把真实错误抛出去（超时 / 上游故障 / 无可用上游）
    candidates.into_iter().find_map(|c| c.err()).map_or_else(
        || Err(crate::libdns::proto::ProtoErrorKind::Timeout.into()),
        Err,
    )
}

mod name_server {
    use super::*;
    use crate::dns_url::{DnsUrl, ProtocolConfig};
    use crate::libdns::custom::connection_provider::{Connection, ConnectionProvider};

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
        /// 🔐 Q16：查询里要不要带 EDNS 的 TCP keepalive 选项（RFC 7828）
        tcp_keepalive: Option<u16>,
        /// 🔐 Q17：配了 ECS 时，是不是所有查询类型都带（默认只有 A / AAAA 带）
        subnet_all_query_types: bool,
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
                        "{}: `-spki-pin` only applies to encrypted upstreams (tls / https / quic / h3); this upstream is plaintext, so it was ignored",
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
            let tcp_keepalive = config.tcp_keepalive;
            let subnet_all_query_types = config.subnet_all_query_types;

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
                tcp_keepalive,
                subnet_all_query_types,
            })
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
                && let Some(subnet) = client_subnet.as_ref()
            {
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
                build_message(
                    query,
                    request_options,
                    client_subnet,
                    options.is_dnssec,
                    self.tcp_keepalive,
                    self.subnet_all_query_types,
                ),
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

                let first = tokio::time::timeout(
                    TCP_FALLBACK_DEADLINE,
                    tcp.send(tcp_req.clone()).first_answer(),
                )
                .await;

                // 先记下第一次为什么失败（只为日志），再把结果用掉
                let first_why = match &first {
                    Ok(Ok(_)) => String::new(), // 成功了就走不到重来那一段
                    Ok(Err(err)) => format!("error: {err}"),
                    Err(_) => format!("timeout after {TCP_FALLBACK_DEADLINE:?}"),
                };

                if let Ok(Ok(full)) = first {
                    debug!(
                        "{url}: udp response is truncated, retried over tcp and got a complete answer"
                    );
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
                        debug!(
                            "{url}: udp response is truncated, tcp retry succeeded after first attempt failed ({first_why}), got a complete answer"
                        );
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

    /// EDNS 的 TCP keepalive 选项码（RFC 7828）
    const EDNS_OPTION_TCP_KEEPALIVE: u16 = 11;

    fn build_message(
        query: Query,
        request_options: DnsRequestOptions,
        client_subnet: Option<ClientSubnet>,
        is_dnssec: bool,
        tcp_keepalive: Option<u16>,
        subnet_all_query_types: bool,
    ) -> Message {
        // build the message

        // 先记下查询类型：下面 `add_query` 会把 query 移走
        let qtype = query.query_type();

        let mut message = Message::query();
        // TODO: This is not the final ID, it's actually set in the poll method of DNS future
        message
            .add_query(query)
            .set_recursion_desired(request_options.recursion_desired);

        // 🔐 Q17：ECS 只给 A / AAAA 带（与 C 版 `packet.c:87-97` 的默认一致）；
        // 加了 `-subnet-all-query-types` 才给所有查询类型带。
        //
        // 为什么默认收窄：ECS 等于把客户端所在网段告诉上游，类型越多暴露越多；
        // 而且只有 A/AAAA 的答案真的会按网段挑节点。需要更精细的场景再打开这个开关。
        let use_subnet = match client_subnet {
            Some(_) => matches!(qtype, RecordType::A | RecordType::AAAA) || subnet_all_query_types,
            None => false,
        };

        // Extended dns
        if use_subnet || request_options.use_edns || is_dnssec || tcp_keepalive.is_some() {
            message
                .extensions_mut()
                .get_or_insert_with(Edns::new)
                .set_max_payload(MAX_PAYLOAD_LEN)
                .set_version(0);

            if let (true, Some(client_subnet), Some(edns)) =
                (use_subnet, client_subnet, message.extensions_mut())
            {
                edns.options_mut().insert(EdnsOption::Subnet(client_subnet));
            }

            // 🔐 Q16：EDNS 的 TCP keepalive 选项（RFC 7828）。值 = 100 毫秒为单位，
            // 0 时不带内容（= "问上游你愿意留多久"）—— 与 C 版 `dns.c:1152` 的字节一致。
            if let (Some(value), Some(edns)) = (tcp_keepalive, message.extensions_mut()) {
                let data = if value == 0 {
                    Vec::new()
                } else {
                    value.to_be_bytes().to_vec()
                };
                edns.options_mut()
                    .insert(EdnsOption::Unknown(EDNS_OPTION_TCP_KEEPALIVE, data));
            }

            if let (true, Some(edns)) = (is_dnssec, message.extensions_mut()) {
                edns.set_dnssec_ok(is_dnssec);
            }
        }
        message
    }

    #[cfg(test)]
    mod build_message_tests {
        use std::str::FromStr;

        use super::*;

        use crate::libdns::proto::{
            op::Query,
            rr::{Name, RecordType},
        };

        use crate::libdns::proto::rr::rdata::opt::{EdnsCode, EdnsOption};

        fn query_of(qtype: RecordType) -> Query {
            Query::query(Name::from_str("example.com.").unwrap(), qtype)
        }

        /// 造一条查询，返回它带的 EDNS（没有就 None）
        fn edns_of(
            qtype: RecordType,
            subnet: bool,
            all_types: bool,
            keepalive: Option<u16>,
        ) -> Option<Edns> {
            let subnet = subnet.then(|| ClientSubnet::new("192.168.1.1".parse().unwrap(), 24, 0));
            let msg = build_message(
                query_of(qtype),
                DnsRequestOptions::default(),
                subnet,
                false,
                keepalive,
                all_types,
            );
            msg.extensions().clone()
        }

        fn has_subnet(edns: &Option<Edns>) -> bool {
            edns.as_ref()
                .and_then(|e| e.option(EdnsCode::Subnet))
                .is_some()
        }

        /// 选项码 11（RFC 7828 TCP keepalive）的内容；没有这个选项就是 None
        fn keepalive_data(edns: &Option<Edns>) -> Option<Vec<u8>> {
            edns.as_ref()
                .and_then(|e| e.option(EdnsCode::Keepalive))
                .and_then(|opt| match opt {
                    EdnsOption::Unknown(11, data) => Some(data.clone()),
                    _ => None,
                })
        }

        /// 🔐 Q17：配了 `-subnet` 时，默认只有 A / AAAA 带 ECS（与 C 版默认一致）
        #[test]
        fn ecs_only_for_a_and_aaaa_by_default() {
            assert!(
                has_subnet(&edns_of(RecordType::A, true, false, None)),
                "A 该带 ECS"
            );
            assert!(
                has_subnet(&edns_of(RecordType::AAAA, true, false, None)),
                "AAAA 该带 ECS"
            );
            assert!(
                !has_subnet(&edns_of(RecordType::TXT, true, false, None)),
                "默认下 TXT 不该带 ECS"
            );
        }

        /// 🔐 Q17：开了 `-subnet-all-query-types` 之后，所有类型都带
        #[test]
        fn ecs_for_all_types_when_flag_on() {
            assert!(has_subnet(&edns_of(RecordType::TXT, true, true, None)));
            assert!(has_subnet(&edns_of(RecordType::HTTPS, true, true, None)));
        }

        /// 没配 `-subnet`：任何类型都不带 ECS（开关本身不制造 ECS）
        #[test]
        fn no_subnet_configured_means_no_ecs() {
            assert!(!has_subnet(&edns_of(RecordType::A, false, true, None)));
        }

        /// 🔐 Q16：`-tcp-keepalive 300` → EDNS 里带选项码 11、内容是大端 300
        #[test]
        fn tcp_keepalive_is_written_as_edns_option_11() {
            let edns = edns_of(RecordType::A, false, false, Some(300));
            assert_eq!(
                keepalive_data(&edns),
                Some(vec![0x01, 0x2c]),
                "300 = 0x012c 大端"
            );

            // 即使没配 subnet、没开 edns，也要因为这个选项而带起 EDNS（否则选项发不出去）
            assert!(!has_subnet(&edns), "不该凭空多出 ECS");
        }

        /// `-tcp-keepalive 0` → 空内容（RFC 7828：0 长度 = 问上游"你愿意留多久"）
        #[test]
        fn tcp_keepalive_zero_sends_empty_option() {
            let edns = edns_of(RecordType::A, false, false, Some(0));
            assert_eq!(keepalive_data(&edns), Some(Vec::new()));
        }

        /// 没配就不该有这个选项（不无中生有）
        #[test]
        fn no_keepalive_configured_means_no_option() {
            let edns = edns_of(RecordType::A, false, false, None);
            assert_eq!(keepalive_data(&edns), None);
        }
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
                && Instant::now() < *valid_until
            {
                return Some(DnsResponse::new_with_deadline(
                    query,
                    records.to_vec(),
                    *valid_until,
                ));
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
                        "\n\x1b[33;1m[WARN]\x1b[0m cannot read the DNS configuration of the system interfaces: {}",
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
                use futures_util::FutureExt;
                use futures_util::future::select_all;
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

    /// 下面几条用例必须**真连公网 DNS** 才能验证，因此按项目测试约定：开关与目标只从环境变量读，
    /// 未提供时打印说明并跳过（测试里不保留硬编码的探测地址）。
    ///
    /// - 开关：`SMARTDNS_TEST_RESOLVE`（非空 / 非 0 / 非 false 视为开启；CI 里已设置）；
    /// - TLS 用例的目标：`SMARTDNS_TEST_TLS_URLS`（逗号分隔，如
    ///   `tls://dns.google?enable_sni=false,tls://dot.pub`）。
    fn resolve_tests_enabled(what: &str) -> bool {
        let on = std::env::var("SMARTDNS_TEST_RESOLVE")
            .map(|v| {
                !matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "no"
                )
            })
            .unwrap_or(false);
        if !on {
            println!(
                "跳过 {what}：需要真实公网 DNS 才能验证。\
                 设 SMARTDNS_TEST_RESOLVE=1 后重跑（CI 里已设置）。"
            );
        }
        on
    }

    #[tokio::test]
    async fn test_with_default() {
        if !resolve_tests_enabled("test_with_default") {
            return;
        }
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
        // 目标从环境变量读（项目测试约定：测试里不保留硬编码的探测地址）。
        // 形如：SMARTDNS_TEST_TLS_URLS="tls://dns.google?enable_sni=false,tls://dot.pub"
        let urls: Vec<DnsUrl> = std::env::var("SMARTDNS_TEST_TLS_URLS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| DnsUrl::from_str(s).ok())
            .collect();
        if urls.is_empty() {
            println!(
                "跳过 test_nameserver_tls_resolve：未设置 SMARTDNS_TEST_TLS_URLS\
                 （形如 tls://dns.google?enable_sni=false,tls://dot.pub）。"
            );
            return;
        }
        if !resolve_tests_enabled("test_nameserver_tls_resolve") {
            return;
        }

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
        if !resolve_tests_enabled("test_nameserver_cloudflare_resolve") {
            return;
        }
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
        if !resolve_tests_enabled("test_nameserver_alidns_resolve") {
            return;
        }
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

    // ───────────────────────── 问题 6：竞速采信标准（纯逻辑，不依赖网络）─────────────────────────

    use crate::dns::DefaultSOA as _;
    use crate::libdns::proto::{
        op::{Message, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::SOA},
    };

    /// 造一份应答：可指定响应码、是否带答案、是否带 SOA、是否截断
    fn make_resp(
        rcode: ResponseCode,
        with_answer: bool,
        with_soa: bool,
        truncated: bool,
    ) -> DnsResponse {
        let name: Name = "example.test".parse().unwrap();
        let mut msg = Message::query();
        msg.add_query(crate::libdns::proto::op::Query::query(
            name.clone(),
            RecordType::A,
        ));
        let mut message: Message = msg;
        message.set_response_code(rcode);
        message.set_truncated(truncated);

        if with_answer {
            message.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::A("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap().into()),
            ));
        }
        if with_soa {
            message.add_authority(Record::from_rdata(
                name.clone(),
                300,
                RData::SOA(SOA::default_soa()),
            ));
        }

        DnsResponse::from(message)
    }

    /// 🔐 核心回归（问题 6）：**不带 SOA 的 NXDOMAIN 绝不允许立刻赢下竞速**。
    ///
    /// 它很可能是被污染或被中间设备伪造的；以前它能立刻返回，于是一个坏上游
    /// 就能把结果钉进否定缓存，让所有客户端在整个 TTL 内都解析不出来。
    #[test]
    fn fake_nxdomain_is_never_conclusive() {
        let fake = make_resp(ResponseCode::NXDomain, false, false, false);
        assert_eq!(
            response_rank(&fake),
            4,
            "不带 SOA 的 NXDOMAIN 是最低等级之一"
        );
        assert!(
            !is_conclusive(&fake),
            "不带 SOA 的 NXDOMAIN 必须继续等其他上游交叉验证"
        );
        assert!(needs_fallback(&Ok(fake)), "既然没有定论，后备上游就该上场");
    }

    /// 带 SOA 的 NXDOMAIN 是上游权威给出的规范否定，可以立刻采信。
    #[test]
    fn authoritative_nxdomain_is_conclusive() {
        let authoritative = make_resp(ResponseCode::NXDomain, false, true, false);
        assert_eq!(response_rank(&authoritative), 3);
        assert!(is_conclusive(&authoritative), "带 SOA 的规范否定可以采信");
        assert!(
            !needs_fallback(&Ok(authoritative)),
            "已经是定论了，不该再浪费一次查询去叫后备上游"
        );
    }

    /// 正牌答案（NOERROR + 有答案 + 未截断）可以立刻采信。
    #[test]
    fn positive_answer_is_conclusive() {
        let ok = make_resp(ResponseCode::NoError, true, false, false);
        assert_eq!(response_rank(&ok), 0);
        assert!(is_conclusive(&ok));
        assert!(!needs_fallback(&Ok(ok)));
    }

    /// 空应答（NoData）不是定论，无论带不带 SOA 都要等其他上游。
    #[test]
    fn empty_answers_are_not_conclusive() {
        let nodata_with_soa = make_resp(ResponseCode::NoError, false, true, false);
        assert_eq!(response_rank(&nodata_with_soa), 1);
        assert!(!is_conclusive(&nodata_with_soa), "空应答要等交叉验证");

        let bare_empty = make_resp(ResponseCode::NoError, false, false, false);
        assert_eq!(response_rank(&bare_empty), 2);
        assert!(!is_conclusive(&bare_empty));
    }

    /// 截断包永远不是定论（P1-5：让它赢会把其他上游的完整答案丢掉）。
    #[test]
    fn truncated_is_never_conclusive() {
        let truncated = make_resp(ResponseCode::NoError, true, false, true);
        assert!(!is_conclusive(&truncated), "截断包只是半成品，不能算定论");
        assert!(needs_fallback(&Ok(truncated)));
    }

    /// 真故障（SERVFAIL 等）排在最后。
    #[test]
    fn servfail_ranks_last() {
        let servfail = make_resp(ResponseCode::ServFail, false, false, false);
        assert_eq!(response_rank(&servfail), 5);
        assert!(!is_conclusive(&servfail));
    }

    /// 🔐 择优：一个假 NXDOMAIN 与一个真答案同时存在时，必须选中真答案。
    ///
    /// 这是问题 6 的实际危害场景：修复前假 NXDOMAIN 先到就赢了；
    /// 修复后两者都进候选池，由评分决定，真答案（rank 0）胜出。
    #[test]
    fn pick_best_prefers_a_real_answer_over_fake_nxdomain() {
        let fake = make_resp(ResponseCode::NXDomain, false, false, false);
        let real = make_resp(ResponseCode::NoError, true, false, false);

        // 假 NXDOMAIN 先到（进候选池），真答案随后
        let got = pick_best(vec![Ok(fake)], Ok(real), None).expect("应当选出真答案");
        assert_eq!(
            got.response_code(),
            ResponseCode::NoError,
            "必须选真答案，而不是先到的假 NXDOMAIN"
        );
        assert!(!got.answers().is_empty(), "选出的应答应当带答案");
    }

    /// 择优顺序：有答案 > 带 SOA 空包 > 无 SOA 空包 > 带 SOA 的 NXDOMAIN > 无 SOA 的 NXDOMAIN
    #[test]
    fn pick_best_follows_the_documented_priority() {
        let bare_empty = make_resp(ResponseCode::NoError, false, false, false); // rank 2
        let nodata = make_resp(ResponseCode::NoError, false, true, false); // rank 1
        let real = make_resp(ResponseCode::NoError, true, false, false); // rank 0

        let got = pick_best(vec![Ok(bare_empty.clone())], Ok(nodata.clone()), None)
            .expect("应当选出带 SOA 的空包");
        assert_eq!(response_rank(&got), 1, "带 SOA 的空包优先于裸空包");

        let got =
            pick_best(vec![Ok(bare_empty), Ok(nodata)], Ok(real), None).expect("应当选出真答案");
        assert_eq!(response_rank(&got), 0, "真答案优先级最高");
    }

    /// 所有候选都是错误时，如实抛出错误（而不是伪造一个空应答）。
    #[test]
    fn pick_best_reports_error_when_nothing_usable() {
        let e1: LookupError = crate::libdns::proto::ProtoErrorKind::Timeout.into();
        let e2: LookupError = crate::libdns::proto::ProtoErrorKind::Timeout.into();

        let got = pick_best(vec![Err(e1)], Err(e2), None);
        assert!(got.is_err(), "没有任何可用应答时应当报错，不能伪造空应答");
    }

    /// 一个可用应答都没有、但有截断包时，退回截断包（让客户端知道该改走 TCP）。
    #[test]
    fn pick_best_falls_back_to_truncated() {
        let truncated = make_resp(ResponseCode::NoError, true, false, true);
        let e: LookupError = crate::libdns::proto::ProtoErrorKind::Timeout.into();

        let got = pick_best(
            vec![Err(e)],
            Err(crate::libdns::proto::ProtoErrorKind::Timeout.into()),
            Some(truncated),
        )
        .expect("应当退回截断包");
        assert!(got.truncated(), "退回应答应保留 TC 位，客户端据此改走 TCP");
    }
}
