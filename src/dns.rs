#![allow(unused_imports)]

use std::borrow::Borrow;
use std::fmt::Debug;

use std::net::IpAddr;
use std::{str::FromStr, sync::Arc, time::Duration};

use crate::dns_error::LookupError;
use crate::dns_rule::DomainRuleTreeNode;

use crate::config::ServerOpts;
use crate::dns_conf::RuntimeConfig;

pub use crate::dns_rule::DomainRuleGetter;

pub use crate::libdns::proto::{
    ProtoErrorKind, op,
    rr::{self, Name, RData, Record, RecordType, rdata::SOA},
};

pub use crate::libdns::{
    proto::xfer::Protocol,
    resolver::{config::NameServerConfig, lookup::Lookup},
};

#[derive(Clone)]
pub struct DnsContext {
    cfg: Arc<RuntimeConfig>,
    pub server_opts: ServerOpts,
    pub domain_rule: Option<Arc<DomainRuleTreeNode>>,
    pub fastest_speed: Duration,
    pub source: LookupFrom,
    pub no_cache: bool,
    // 🌟 补上这个被遗漏的货厢：用来运送双栈优选中被淘汰的附属记录
    pub extra_cache_records: Vec<(crate::libdns::proto::op::Query, DnsResponse)>,
}

impl DnsContext {
    pub fn new(name: &Name, cfg: Arc<RuntimeConfig>, server_opts: ServerOpts) -> Self {
        let group_name = server_opts.rule_group.as_deref().unwrap_or_default();

        // 🔐 P2（用户定策）：规则组不存在 → 走默认组（下面 find_domain_rule 本来就会回退到
        // default 组找域规则），但必须**点名告警一次** —— 否则用户拼错组名 / 改名后忘了同步，
        // 永远不知道自己其实没在用那套规则（只报一次，别在热路径上刷屏）。
        if !cfg.has_rule_group(group_name)
            && crate::log::warn_once(&format!("rule-group:{group_name}"))
        {
            crate::log::warn!(
                "no rule group named `{}` in the configuration (query {} matched it); falling back to the default group's rules. Check the group names in group-begin / client-rules for typos or renames",
                group_name,
                name
            );
        }

        let domain_rule = cfg.find_domain_rule(name, group_name);

        let no_cache = domain_rule.get(|n| n.no_cache).unwrap_or_default();

        DnsContext {
            cfg,
            server_opts,
            domain_rule,
            fastest_speed: Default::default(),
            source: Default::default(),
            no_cache,
            extra_cache_records: Vec::new(), // 🌟 初始化空货厢
        }
    }

    #[inline]
    pub fn cfg(&self) -> &Arc<RuntimeConfig> {
        &self.cfg
    }

    /// 🔐 本次查询实际生效的规则组名（用于取组级参数）。
    ///
    /// 与 `DnsContext::new` 里解析 `domain_rule` 用的是同一个值，避免两处口径不一致。
    ///
    /// 📌 对上层公开：`dns_mw_ns.rs` 的**并发折叠键**必须含它（见那里的说明）——
    /// 折叠键的注释原先写着"客户端规则能带来的差异只有选哪个分组"，而那个"分组"
    /// 指的是**上游分组**；甲类铺开后**规则组**也能改变答案（TTL 裁剪等），
    /// 这条假设不再成立。
    pub fn effective_rule_group(&self) -> &str {
        self.server_opts.rule_group.as_deref().unwrap_or_default()
    }

    /// 🔐 `force-no-CNAME` 的**生效值**，优先级：bind 级 > 组级 > 全局。
    ///
    /// * bind 级：`bind ... -force-no-CNAME`（`ServerOpts` 里显式指定的）；
    /// * 组级：写在 `group-begin ... group-end` 块里的；
    /// * 全局：顶层 `force-no-CNAME`。
    ///
    /// 三层都没写 → `false`（保持既有行为，开关默认关闭）。
    pub fn force_no_cname(&self) -> bool {
        self.server_opts.force_no_cname.unwrap_or_else(|| {
            self.cfg
                .force_no_cname_in_group(self.effective_rule_group())
        })
    }

    /// 🔐 `force-AAAA-SOA` 的**生效值**，优先级同上。
    ///
    /// 这里必须读 `server_opts` 里的原始 `Option`，不能用 `ServerOpts::force_aaaa_soa()`
    /// —— 那个访问器会 `unwrap_or_default()`，把"本监听没写"当成"显式关闭"，
    /// 从而永远压住组级与全局的值。
    pub fn force_aaaa_soa(&self) -> bool {
        self.server_opts.force_aaaa_soa.unwrap_or_else(|| {
            self.cfg
                .force_aaaa_soa_in_group(self.effective_rule_group())
        })
    }

    // ── 📌 甲类（2026-09-26 铺开）：这些参数**没有 bind 级对应项**，
    //    所以只有两层：**组级 > 全局**。调用方一律走这些入口，
    //    不要再直接读 `cfg().xxx()` —— 那样会绕过组级、表现成"配了组级不生效"。

    /// `ipset-timeout` 的生效值（组级 > 全局）
    #[inline]
    pub fn ipset_timeout(&self) -> bool {
        self.cfg.ipset_timeout_in_group(self.effective_rule_group())
    }

    /// `nftset-timeout` 的生效值（组级 > 全局）
    #[inline]
    pub fn nftset_timeout(&self) -> bool {
        self.cfg
            .nftset_timeout_in_group(self.effective_rule_group())
    }

    /// `rr-ttl-min` 的生效值（组级 > 全局）
    #[inline]
    pub fn rr_ttl_min(&self) -> Option<u64> {
        self.cfg.rr_ttl_min_in_group(self.effective_rule_group())
    }

    /// `rr-ttl-max` 的生效值（组级 > 全局）
    #[inline]
    pub fn rr_ttl_max(&self) -> Option<u64> {
        self.cfg.rr_ttl_max_in_group(self.effective_rule_group())
    }

    /// `rr-ttl-reply-max` 的生效值（组级 > 全局）
    #[inline]
    pub fn rr_ttl_reply_max(&self) -> Option<u64> {
        self.cfg
            .rr_ttl_reply_max_in_group(self.effective_rule_group())
    }

    /// `local-ttl` 的生效值（组级 > 全局）
    #[inline]
    pub fn local_ttl(&self) -> u64 {
        self.cfg.local_ttl_in_group(self.effective_rule_group())
    }

    /// `dualstack-ip-allow-force-AAAA` 的生效值（组级 > 全局）
    #[inline]
    pub fn dualstack_ip_allow_force_aaaa(&self) -> bool {
        self.cfg
            .dualstack_ip_allow_force_aaaa_in_group(self.effective_rule_group())
    }

    /// `dualstack-ip-selection-threshold` 的生效值（组级 > 全局）
    #[inline]
    pub fn dualstack_ip_selection_threshold(&self) -> u64 {
        self.cfg
            .dualstack_ip_selection_threshold_in_group(self.effective_rule_group())
    }

    /// `max-reply-ip-num` 的生效值（组级 > 全局）
    #[inline]
    pub fn max_reply_ip_num(&self) -> Option<u8> {
        self.cfg
            .max_reply_ip_num_in_group(self.effective_rule_group())
    }

    // ── 📌 乙类（2026-09-26 铺开）：这三层是**域名规则 > 组级 > 全局**。
    //
    // 它们与甲类的区别：域名规则级**本来就有**对应写法，所以组级是"插在中间那一档"，
    // 而不是"新加一层"。调用方（`dns_mw_ns.rs` / `dns_mw_dualstack.rs`）保持
    // 原来的 `域名规则 → 本函数` 形状，中间那档由本函数负责。

    /// `rr-ttl` 的生效值（域名规则 > 组级 > 全局）
    ///
    /// 注意**不含**域名规则级 —— 那一级由调用方通过 `domain_rule.get(...)` 先取，
    /// 与既有写法保持一致（`dns_mw_addr.rs` / `dns_mw_ns.rs` 都是这个形状）。
    #[inline]
    pub fn rr_ttl(&self) -> Option<u64> {
        self.cfg.rr_ttl_in_group(self.effective_rule_group())
    }

    /// `response-mode` 的生效值（域名规则 > 组级 > 全局）
    #[inline]
    pub fn response_mode(&self) -> crate::config::ResponseMode {
        self.cfg.response_mode_in_group(self.effective_rule_group())
    }

    /// `speed-check-mode` 的生效值（组级 > 全局）。
    ///
    /// 与上面三个不同：它返回 `Option` 而不是"已解析的最终值"，
    /// 因为**"没写"与"写了 none"必须可区分**（问题 24），而最终解析要由
    /// `config::resolve_speed_check_mode` 统一完成（它同时管默认值）。
    #[inline]
    pub fn speed_check_mode(&self) -> Option<crate::config::SpeedCheckModeList> {
        self.cfg
            .speed_check_mode_in_group(self.effective_rule_group())
    }

    // ── 📌 丙-1（2026-09-26 补齐组级支持）：都只在**逐查询**那一侧生效。
    //
    // ⚠️ 这三个各有一份"同名但属于后台任务"的用途，**不跟组级走**：
    //   · `prefetch-domain`：这里只管"这条应答要不要安排预取"；
    //     后台预取任务的启停仍读 `ctx.cfg().prefetch_domain()`（进程级）。
    //   · `serve-expired`：这里只管"这次查询要不要喂过期数据"；
    //     缓存后台清理仍读缓存对象上的全局快照。

    /// `serve-expired` 的生效值（组级 > 全局）—— 逐查询
    #[inline]
    pub fn serve_expired(&self) -> bool {
        self.cfg.serve_expired_in_group(self.effective_rule_group())
    }

    /// `serve-expired-reply-ttl` 的生效值（组级 > 全局）—— 逐查询
    #[inline]
    pub fn serve_expired_reply_ttl(&self) -> u64 {
        self.cfg
            .serve_expired_reply_ttl_in_group(self.effective_rule_group())
    }

    /// `prefetch-domain` 的生效值（组级 > 全局）—— **只管"这条应答要不要安排预取"**
    ///
    /// 🔐 **不要**拿它控制后台预取任务的启停：那个任务是进程级的、
    /// 遍历所有缓存条目，不是"某个组在预取"。按组取值会让一个组把全进程的任务停掉。
    /// 后台任务启停用 `ctx.cfg().prefetch_domain()`。
    #[inline]
    pub fn prefetch_domain(&self) -> bool {
        self.cfg
            .prefetch_domain_in_group(self.effective_rule_group())
    }

    // ── 📌 丙-2a / 丙-2b（2026-09-26 补齐组级支持）

    /// `dns64` 前缀的生效值（组级 > 全局）
    ///
    /// `None` = 这次查询**不做 DNS64**（全局与本组都没配）。
    #[inline]
    pub fn dns64_prefix(&self) -> Option<ipnet::Ipv6Net> {
        self.cfg.dns64_prefix_in_group(self.effective_rule_group())
    }

    /// `edns-client-subnet` 的**组级**值
    ///
    /// ⚠️ 它**不是**取值链的终点：全局那一档存在 `NameServer` 里（启动期定型的
    /// 默认值），由 `dns_client` 兜底。调用方应把它插在"域名规则级"与
    /// "全局默认值"之间。
    #[inline]
    pub fn edns_client_subnet(&self) -> Option<ipnet::IpNet> {
        self.cfg
            .edns_client_subnet_in_group(self.effective_rule_group())
    }

    #[inline]
    pub fn server_opts(&self) -> &ServerOpts {
        &self.server_opts
    }

    pub fn server_group_name(&self) -> &str {
        match self.server_opts().group() {
            Some(n) => n,
            None => {
                let mut node = self.domain_rule.as_ref();

                while let Some(rule) = node {
                    if let Some(name) = rule.nameserver.as_deref() {
                        return name;
                    }

                    node = rule.zone();
                }

                "default"
            }
        }
    }
}

#[derive(Clone)]
pub enum LookupFrom {
    None,
    Cache,
    Static,
    Zone(String),
    Server(String),
}

impl Debug for LookupFrom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Cache => write!(f, "Cache"),
            Self::Static => write!(f, "Static"),
            Self::Zone(arg0) => write!(f, "Zone: {arg0}"),
            Self::Server(arg0) => write!(f, "Server: {arg0}"),
        }
    }
}

impl Default for LookupFrom {
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

mod serial_message {

    use crate::dns_error::LookupError;
    use crate::libdns::Protocol;
    use crate::libdns::proto::{ProtoError, op::Query};
    use crate::{config::ServerOpts, libdns::proto::op::Message};
    use bytes::Bytes;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::{DnsRequest, DnsResponse};

    pub enum SerialMessage {
        Raw(Box<Message>, SocketAddr, Protocol, GroupingAddr),
        // 🌟 核心修复：升级底层载体，支持引用计数内存池指针，消除堆拷贝
        Bytes(bytes::Bytes, SocketAddr, Protocol, GroupingAddr),
    }

    /// 🔐 13-⑥：随报文一起走的「**归组地址**」。
    ///
    /// ## 它和 `SerialMessage` 里的 `addr` 有什么区别
    ///
    /// * `addr` 是**真实对端地址**（内核给出的，不可伪造）—— ACL 与审计用它；
    /// * 本值是**可信反向代理**通过 `X-Forwarded-For` 报上来的真实客户端地址 ——
    ///   **可被伪造**，所以**只用于归组**（选 `client-rules` 的规则组）。
    ///
    /// ## 为什么用 `Default` 而不是把两个地址都塞进 `addr`
    ///
    /// 因为绝大多数路径（UDP/TCP/DoT/DoQ，以及所有应答回填）**根本没有 HTTP 头**，
    /// 这个值恒为 `None`。用 `Default` 让那些路径**零改动、行为逐字节不变**。
    ///
    /// ## ⚠️ 用途约束
    ///
    /// **只能用于归组，绝不可用于 ACL 放行**。理由见 `src/trusted_proxy.rs`
    /// 模块文档的"三条铁律"第 3 条：伪造一个能匹配白名单的头就绕过了 ACL。
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct GroupingAddr(pub Option<SocketAddr>);

    impl GroupingAddr {
        /// 没有转发信息（默认）—— 归组就用真实对端地址。
        pub const NONE: Self = Self(None);

        pub fn new(addr: SocketAddr) -> Self {
            Self(Some(addr))
        }
    }

    impl SerialMessage {
        // 🌟 巧用 impl Into 泛型，向下完美兼容其余所有还在传 Vec<u8> 的协议，避免改动全局产生连锁报错！
        pub fn binary(
            bytes: impl Into<bytes::Bytes>,
            addr: SocketAddr,
            protocol: Protocol,
        ) -> Self {
            Self::Bytes(bytes.into(), addr, protocol, GroupingAddr::NONE)
        }
        pub fn raw(message: Message, addr: SocketAddr, protocol: Protocol) -> Self {
            Self::Raw(message.into(), addr, protocol, GroupingAddr::NONE)
        }

        /// 🔐 13-⑥：带上「归组地址」（只有 DoH 那条路径需要，见 [`GroupingAddr`]）。
        ///
        /// 用 `with_` 形式而不是给构造器加参数 —— 这样**其它 40 余处调用点零改动**。
        pub fn with_grouping_addr(mut self, grouping: SocketAddr) -> Self {
            match &mut self {
                Self::Raw(_, _, _, g) => *g = GroupingAddr::new(grouping),
                Self::Bytes(_, _, _, g) => *g = GroupingAddr::new(grouping),
            }
            self
        }

        /// 🔐 13-⑥：归组用的地址（没有转发信息时为 `None`）。
        ///
        /// ⚠️ **只能用于归组**（选规则组），**不可用于 ACL 放行** —— 见 [`GroupingAddr`]。
        pub fn grouping_addr(&self) -> Option<SocketAddr> {
            match self {
                Self::Raw(_, _, _, g) => g.0,
                Self::Bytes(_, _, _, g) => g.0,
            }
        }

        pub fn is_binray(&self) -> bool {
            matches!(self, SerialMessage::Bytes(..))
        }

        pub fn protocol(&self) -> Protocol {
            match self {
                SerialMessage::Raw(_, _, p, _) => *p,
                SerialMessage::Bytes(_, _, p, _) => *p,
            }
        }

        pub fn addr(&self) -> SocketAddr {
            match self {
                SerialMessage::Raw(_, a, _, _) => *a,
                SerialMessage::Bytes(_, a, _, _) => *a,
            }
        }
    }

    impl From<Query> for SerialMessage {
        fn from(query: Query) -> Self {
            let mut message = Message::query();
            message.add_query(query);
            message.into()
        }
    }

    impl From<Message> for SerialMessage {
        fn from(message: Message) -> Self {
            Self::raw(
                message,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0)),
                Protocol::Udp,
            )
        }
    }

    impl TryFrom<SerialMessage> for crate::libdns::proto::xfer::SerialMessage {
        type Error = ProtoError;
        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            Ok(match value {
                // 只有在真正需要发往外网 DNS 服务器时（Cache 未命中），才发生一次克隆提取，保全了 99% 命中缓存的热路径性能！
                SerialMessage::Bytes(bytes, addr, ..) => Self::new(bytes.to_vec(), addr),
                SerialMessage::Raw(message, addr, ..) => Self::new(message.to_vec()?, addr),
            })
        }
    }

    impl TryFrom<SerialMessage> for Vec<u8> {
        type Error = ProtoError;
        #[inline]
        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            Ok(crate::libdns::proto::xfer::SerialMessage::try_from(value)?
                .into_parts()
                .0)
        }
    }

    impl TryFrom<SerialMessage> for Bytes {
        type Error = ProtoError;
        #[inline]
        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            Ok(crate::libdns::proto::xfer::SerialMessage::try_from(value)?
                .into_parts()
                .0
                .into())
        }
    }

    impl TryFrom<SerialMessage> for Message {
        type Error = ProtoError;

        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            match value {
                SerialMessage::Raw(message, _, ..) => Ok(message.as_ref().clone()),
                SerialMessage::Bytes(bytes, _, ..) => Message::from_vec(&bytes),
            }
        }
    }
}

mod request {

    use std::{fmt::Debug, net::SocketAddr, ops::Deref, sync::Arc};

    use crate::libdns::{
        Protocol,
        proto::{
            ProtoError,
            op::{LowerQuery, Message, Query},
            rr::{Name, RecordType},
        },
    };

    use super::{DnsError, SerialMessage};

    #[derive(Clone)]
    pub struct DnsRequest {
        id: u16,
        /// Message with the associated query or update data
        query: LowerQuery,
        message: Arc<Message>,
        /// Source address of the Client
        src: SocketAddr,
        /// Protocol of the request
        protocol: Protocol,
        /// 🔐 13-⑥：可信代理**转发来**的真实客户端地址（仅 HTTP 类协议可能带上）。
        ///
        /// ## 这个字段的用途被**严格限制**在"归组"上
        ///
        /// 它来自 `X-Forwarded-For`，而那是**调用方可以伪造的普通 HTTP 头**。
        /// 因此：
        ///
        /// * ✅ **可以**用它选 `client-rules` 里的**规则组**（`dns_mw.rs` 的归组路径）
        ///   —— 猜错组最坏是"用了别人的策略"，不是安全边界；
        /// * ❌ **绝不可以**用它做**放行/拒绝**判定（ACL）。
        ///   否则攻击者伪造一个能匹配白名单的头，就**绕过了 ACL** ——
        ///   那会把"限流问题"升级成"安全问题"。
        ///
        /// 所以 ACL 那条路径仍然只读 [`DnsRequest::src`]（内核给出的真实对端，不可伪造）。
        /// 详见 `src/trusted_proxy.rs` 模块文档的"三条铁律"。
        forwarded_client: Option<std::net::IpAddr>,
    }

    impl DnsRequest {
        pub fn new(message: Message, src_addr: SocketAddr, protocol: Protocol) -> Self {
            let id = message.id();
            let query = message.queries().first().cloned().unwrap_or_default();
            Self {
                id,
                query: query.into(),
                message: Arc::new(message),
                src: src_addr,
                protocol,
                // 默认没有转发地址 —— 即"不信任任何代理头"，与改动前完全一致。
                forwarded_client: None,
            }
        }

        /// 🔐 13-⑥：带上"可信代理转发来的真实客户端地址"。
        ///
        /// 调用方（DoH / `bind-http` 的请求处理）已经用
        /// [`crate::trusted_proxy::resolve_client_ip`] 判定过"对端是否可信"，
        /// 只有**确认可信**时才应当设置它 —— 本方法**不做校验**，
        /// 因为它只是个数据通道（判定逻辑集中在 `trusted_proxy` 模块，便于单测）。
        pub fn with_forwarded_client(mut self, ip: Option<std::net::IpAddr>) -> Self {
            self.forwarded_client = ip;
            self
        }

        /// 🔐 13-⑥：可信代理转发来的真实客户端地址（没有则为 `None`）。
        ///
        /// ⚠️ **调用方必须自己判断用途**：只能用于**归组**，不能用于**放行判定**。
        /// 见本结构体 `forwarded_client` 字段的说明。
        #[inline]
        pub fn forwarded_client(&self) -> Option<std::net::IpAddr> {
            self.forwarded_client
        }

        /// see `Header::id()`
        pub fn id(&self) -> u16 {
            self.id
        }

        /// ```text
        /// Question        Carries the query name and other query parameters.
        /// ```
        #[inline]
        pub fn query(&self) -> &LowerQuery {
            &self.query
        }

        /// The IP address from which the request originated.
        #[inline]
        pub fn src(&self) -> SocketAddr {
            self.src
        }

        /// The protocol that was used for the request
        #[inline]
        pub fn protocol(&self) -> Protocol {
            self.protocol
        }

        pub fn with_cname(&self, name: Name) -> Self {
            Self {
                id: self.id,
                query: LowerQuery::from(Query::query(name, self.query().query_type())),
                message: self.message.clone(),
                src: self.src,
                protocol: self.protocol,
                // 🔐 13-⑥：CNAME 重写只是换个域名，来源身份必须**原样保留**
                forwarded_client: self.forwarded_client,
            }
        }

        pub fn set_query_type(&mut self, query_type: RecordType) {
            let mut query = self.query.original().clone();
            query.set_query_type(query_type);
            self.query = LowerQuery::from(query)
        }

        pub fn is_dnssec(&self) -> bool {
            let rtype = self.query().query_type();
            self.extensions()
                .as_ref()
                .map(|e| e.flags().dnssec_ok)
                .unwrap_or(rtype.is_dnssec())
        }
    }

    impl Debug for DnsRequest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let id = self.id();
            let src_addr = self.src();
            let protocol = self.protocol();
            let query = self.query();
            let query_name = query.name();
            let query_type = query.query_type();
            let query_class = query.query_class();

            let message_type = self.message_type();
            let is_dnssec = self.is_dnssec();
            let qop_code = self.op_code();
            let qflags = self.flags();

            write!(
                f,
                "{id} src:{proto}://{addr}#{port} type:{message_type} dnssec:{is_dnssec} {op}:{query}:{qtype}:{class} qflags:{qflags}",
                id = id,
                proto = protocol,
                addr = src_addr.ip(),
                port = src_addr.port(),
                message_type = message_type,
                is_dnssec = is_dnssec,
                op = qop_code,
                query = query_name,
                qtype = query_type,
                class = query_class,
                qflags = qflags,
            )
        }
    }

    impl std::ops::Deref for DnsRequest {
        type Target = Message;

        fn deref(&self) -> &Self::Target {
            self.message.as_ref()
        }
    }

    impl From<Query> for DnsRequest {
        fn from(query: Query) -> Self {
            use std::net::{Ipv4Addr, SocketAddrV4};

            let mut message = Message::query();
            message.add_query(query.clone());

            Self {
                id: message.id(),
                query: query.into(),
                message: Arc::new(message),
                src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
                protocol: Protocol::Udp,
                // 内部构造的请求没有转发来源 —— 归组就用 `src`（本机）。
                forwarded_client: None,
            }
        }
    }

    impl TryFrom<SerialMessage> for DnsRequest {
        type Error = ProtoError;

        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            // 🔐 13-⑥：把「归组地址」一路带到 `DnsRequest` 上。
            //
            // 它来自 `SerialMessage::with_grouping_addr`（目前只有 DoH 那条路径会设）。
            // 其余路径恒为 `None` ⇒ 归组仍用真实对端地址，行为与改动前一致。
            //
            // ⚠️ 这个值**只用于归组**（选规则组），**不可用于 ACL 放行** ——
            // 它是反向代理自报的、可被伪造。见 `GroupingAddr` 的说明。
            let grouping = value.grouping_addr();

            let (message, src_addr, protocol) = match value {
                SerialMessage::Raw(message, src_addr, protocol, _) => {
                    (message.as_ref().clone(), src_addr, protocol)
                }
                SerialMessage::Bytes(bytes, src_addr, protocol, _) => {
                    use crate::libdns::proto::serialize::binary::{BinDecodable, BinDecoder};
                    let mut decoder = BinDecoder::new(&bytes);
                    (Message::read(&mut decoder)?, src_addr, protocol)
                }
            };

            Ok(DnsRequest::new(message, src_addr, protocol)
                .with_forwarded_client(grouping.map(|sa| sa.ip())))
        }
    }
}

mod response {

    use crate::dns_client::MAX_TTL;
    use crate::libdns::proto::{
        op::{self, Header, Message, MessageType, Query},
        rr::{RData, Record},
    };
    use crate::libdns::resolver::TtlClip as _;

    use std::net::IpAddr;
    use std::ops::Deref;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::DnsRequest;

    static DEFAULT_QUERY: once_cell::sync::Lazy<Query> = once_cell::sync::Lazy::new(Query::default);

    #[derive(Debug, Clone, Eq)]
    pub struct DnsResponse {
        message: Message,
        valid_until: Instant,
        name_server_group: Option<String>,
    }

    impl PartialEq for DnsResponse {
        fn eq(&self, other: &Self) -> bool {
            self.message == other.message && self.name_server_group == other.name_server_group
        }
    }

    impl DnsResponse {
        pub fn new_with_max_ttl<R, I>(query: Query, records: R) -> Self
        where
            R: IntoIterator<Item = Record, IntoIter = I>,
            I: Iterator<Item = Record>,
        {
            let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
            Self::new_with_deadline(query, records, valid_until)
        }

        pub fn new_with_deadline<R, I>(query: Query, records: R, valid_until: Instant) -> Self
        where
            R: IntoIterator<Item = Record, IntoIter = I>,
            I: Iterator<Item = Record>,
        {
            use op::message::{HeaderCounts, update_header_counts};
            let mut message = Message::query().to_response();
            message.add_query(query.clone());
            message.add_answers(records);

            let header = update_header_counts(
                message.header(),
                message.truncated(),
                HeaderCounts {
                    query_count: message.queries().len(),
                    answer_count: message.answers().len(),
                    authority_count: message.authorities().len(),
                    additional_count: message.additionals().len(),
                },
            );

            message.set_header(header);

            Self {
                message,
                valid_until,
                name_server_group: None,
            }
        }

        pub fn empty() -> Self {
            Self {
                message: Message::query(),
                valid_until: Instant::now(),
                name_server_group: None,
            }
        }

        /// Return new instance with given rdata and the maximum TTL.
        pub fn from_rdata(query: Query, rdata: RData) -> Self {
            let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
            Self::new_with_max_ttl(query, vec![record])
        }

        pub fn query(&self) -> &Query {
            self.deref().queries().first().unwrap_or(&DEFAULT_QUERY)
        }

        pub fn message(&self) -> &Message {
            &self.message
        }

        pub fn valid_until(&self) -> Instant {
            self.valid_until
        }

        pub fn with_valid_until(mut self, valid_until: Instant) -> Self {
            self.valid_until = valid_until;
            self
        }

        pub fn name_server_group(&self) -> Option<&str> {
            self.name_server_group.as_deref()
        }

        pub fn with_name_server_group(mut self, group_name: String) -> Self {
            self.name_server_group = Some(group_name);
            self
        }

        pub fn records(&self) -> &[Record] {
            self.answers()
        }

        pub fn record_iter(&self) -> std::slice::Iter<'_, Record> {
            self.answers().iter()
        }

        pub fn ip_addrs(&self) -> Vec<IpAddr> {
            self.ip_addrs_iter().collect()
        }

        pub fn ip_addrs_iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
            self.message()
                .answers()
                .iter()
                .flat_map(|r| r.data().ip_addr())
        }

        pub fn set_valid_until_max(&mut self) {
            self.set_valid_until(MAX_TTL)
        }

        pub fn set_valid_until(&mut self, ttl: u32) {
            let valid_until = Instant::now() + Duration::from_secs(ttl as u64);
            self.valid_until = valid_until
        }

        // 🌟 核心修复（治理影响 B）：在报文最终出站的必经之路上，严格核对实际装箱数量。
        // 无论外部传入了什么 Header，都将其 QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT
        // 严格同步为当前报文体内真正携带的记录数！
        pub fn into_message(self, header: Option<Header>) -> Message {
            use op::message::{HeaderCounts, update_header_counts};
            let mut message = self.message;

            // 提取基准 Header（若有外部传入的新 Header 则以它为准，否则使用自身 Header）
            let base_header = header.as_ref().unwrap_or(message.header());

            // 统计当前报文体内实际装载的真实记录数量
            let actual_counts = HeaderCounts {
                query_count: message.queries().len(),
                answer_count: message.answers().len(),
                authority_count: message.authorities().len(), // 👈 准确获取实际塞入的 SOA 权威记录数
                additional_count: message.additionals().len(),
            };

            // 生成数量严格对齐的新 Header 并覆写
            let synced_header =
                update_header_counts(base_header, message.truncated(), actual_counts);
            message.set_header(synced_header);

            message
        }

        // 🌟 核心重写：追加权威记录与附加记录时，同步刷新内存中的 Header 计数
        pub fn add_authority(&mut self, record: Record) {
            self.message.add_authority(record);
            self.sync_header_counts();
        }

        pub fn add_additional(&mut self, record: Record) {
            self.message.add_additional(record);
            self.sync_header_counts();
        }

        pub fn sync_header_counts(&mut self) {
            use op::message::{HeaderCounts, update_header_counts};
            let counts = HeaderCounts {
                query_count: self.message.queries().len(),
                answer_count: self.message.answers().len(),
                authority_count: self.message.authorities().len(),
                additional_count: self.message.additionals().len(),
            };
            let header =
                update_header_counts(self.message.header(), self.message.truncated(), counts);
            self.message.set_header(header);
        }
    }

    impl std::ops::Deref for DnsResponse {
        type Target = Message;

        fn deref(&self) -> &Self::Target {
            &self.message
        }
    }

    impl std::ops::DerefMut for DnsResponse {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.message
        }
    }

    impl From<Message> for DnsResponse {
        fn from(message: Message) -> Self {
            let valid_until = Instant::now()
                + Duration::from_secs(
                    message
                        .answers()
                        .iter()
                        .map(|r| r.ttl())
                        .min()
                        .unwrap_or(MAX_TTL) as u64,
                );
            Self {
                message,
                valid_until,
                name_server_group: None,
            }
        }
    }

    impl DnsResponse {
        // 🌟 终极全景雷达：找寿命时，绝不放过包裹的任何一个角落！
        pub fn max_ttl(&self) -> Option<u32> {
            let ans = self.answers().iter().map(|r| r.ttl()).max();
            let auth = self.authorities().iter().map(|r| r.ttl()).max();
            let add = self.additionals().iter().map(|r| r.ttl()).max();

            // 将三个区的最大值放在一起，再求一个最终的最大值
            [ans, auth, add].into_iter().flatten().max()
        }

        pub fn min_ttl(&self) -> Option<u32> {
            let ans = self.answers().iter().map(|r| r.ttl()).min();
            let auth = self.authorities().iter().map(|r| r.ttl()).min();
            let add = self.additionals().iter().map(|r| r.ttl()).min();

            // 将三个区的最小值放在一起，再求一个最终的最小值
            [ans, auth, add].into_iter().flatten().min()
        }

        // 🌟 终极修复：让 TTL 涂改覆盖所有的三个区域，彻底解决 SOA 倒计时冻结！
        pub fn set_new_ttl(&mut self, ttl: u32) {
            for record in self.answers_mut() {
                record.set_ttl(ttl);
            }
            for record in self.authorities_mut() {
                record.set_ttl(ttl);
            } // 👈 换成了正确的 authorities_mut
            for record in self.additionals_mut() {
                record.set_ttl(ttl);
            }
        }

        pub fn set_max_ttl(&mut self, ttl: u32) {
            for record in self.answers_mut() {
                record.set_max_ttl(ttl);
            }
            for record in self.authorities_mut() {
                record.set_max_ttl(ttl);
            }
            for record in self.additionals_mut() {
                record.set_max_ttl(ttl);
            }
        }

        pub fn set_min_ttl(&mut self, ttl: u32) {
            for record in self.answers_mut() {
                record.set_min_ttl(ttl);
            }
            for record in self.authorities_mut() {
                record.set_min_ttl(ttl);
            }
            for record in self.additionals_mut() {
                record.set_min_ttl(ttl);
            }
        }
    }
}

pub type DnsRequest = request::DnsRequest;
pub type DnsResponse = response::DnsResponse;
pub type DnsError = LookupError;
use ipnet::IpAdd;
pub use serial_message::SerialMessage;

#[derive(Debug, Clone, Copy, Default)]
pub enum LookupResponseStrategy {
    #[default]
    FirstPing, // query + ping
    FastestIp,       // ping
    FastestResponse, // query
}

pub trait DefaultSOA {
    fn default_soa() -> Self;
}

/// 🔐 问题 27-2：合成 SOA 的**序列号**。
///
/// ## 原来错在哪
///
/// 两处构造 SOA 的地方**各自写死了一个序列号，而且值完全不同**：
///
/// | 位置 | 原来的序列号 | 问题 |
/// |---|---|---|
/// | `SOA::default_soa()` | `1800` | 它是**照抄的"刷新时间"**，与序列号无关；而且是个极小的固定值 |
/// | `forge_soa_record()` | `2026032400` | 一个**未来时间戳**（写这段代码时是未来） |
///
/// 两个后果：
///   1. **序列号是"比大小"用的**（RFC 1982 的序列号算术）。一个未来时间戳
///      会让部分客户端/解析器认为"这份 SOA 比我知道的更新"，从而**刷新否定缓存**；
///   2. 两处取值不一致，同一个进程对"同一件事"（合成否定应答）给出互相矛盾的版本号。
///
/// ## 现在怎么取
///
/// 用**构建时刻的 Unix 秒**：
///   * **确定**：同一份二进制内恒定 —— 绝不会出现"同一个客户端两次查询拿到不同序列号"
///     （那会让客户端缓存反复失效，比固定值更糟）；
///   * **与时序一致**：升级到新版本时序列号必然更大，符合"越新的构建版本越新"的直觉；
///   * **不再是未来时间戳**：构建时刻本身就是当时的真实时间。
///
/// 返回值被裁剪到 `u32` 范围内（Unix 秒到 2106 年才会溢出，超出时饱和处理）。
#[inline]
fn synthetic_soa_serial() -> u32 {
    let secs = crate::BUILD_DATE.timestamp();
    // 负值理论上不可能（构建时间不会是 1970 之前），防御性处理成 0
    u32::try_from(secs).unwrap_or(u32::MAX)
}

impl DefaultSOA for SOA {
    #[inline]
    fn default_soa() -> Self {
        Self::new(
            Name::from_str("a.gtld-servers.net").unwrap(),
            Name::from_str("nstld.verisign-grs.com").unwrap(),
            synthetic_soa_serial(), // 🔐 问题 27-2：不再是抄来的 1800
            1800,
            900,
            604800,
            86400,
        )
    }
}

impl DefaultSOA for RData {
    fn default_soa() -> Self {
        Self::SOA(SOA::default_soa())
    }
}

// ==========================================
// 🌟 统一兵工厂：规范化 SOA 萝卜章制造机
// ==========================================
pub fn forge_soa_record(name: Name, ttl: u32) -> Record {
    let mname: Name = "a.root-servers.net.".parse().unwrap();
    let rname: Name = "admin.smartdns.local.".parse().unwrap();

    // 构造合法的 SOA 证书内容，核心是将 ttl 同步写入最小缓存时间字段！
    let soa_data = RData::SOA(crate::libdns::proto::rr::rdata::SOA::new(
        mname,
        rname,
        synthetic_soa_serial(), // 🔐 问题 27-2：与 `default_soa()` 统一（原来是 2026032400）
        1800,                   // 刷新时间
        900,                    // 重试时间
        259200,                 // 极限过期时间
        ttl,                    // 【核心】最小否定缓存时间：与外部寿命严格同步
    ));

    Record::from_rdata(name, ttl, soa_data)
}

#[cfg(test)]
mod jia_class_wiring_tests {
    use super::*;
    use std::str::FromStr;

    /// 📌 甲类铺开的**贯通性测试**：组级值必须真的走到 `DnsContext` 的取值入口。
    ///
    /// 为什么单靠配置层测试不够：本次要动三处（`GroupParams` 装值、`config_unchecked`
    /// 分流、`DnsContext` 取值）。配置层测试只证明了前两处，**第三处（取值入口）
    /// 完全没被覆盖** —— 而那正是"配了不生效"最常发生的地方。
    ///
    /// 这里直接构造一个带规则组的 `DnsContext`，验证两条路径得出不同答案。
    /// 判据**成对**：组内取到组的值（正向） **且** 其它组取到全局的值（反向）。
    #[test]
    fn group_level_params_reach_the_context_accessor() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                // 全局：故意与组级设成**不同的值**，否则两条路径答案相同、测不出接线
                .with("local-ttl 60")
                .with("max-reply-ip-num 3")
                .with("group-begin office")
                .with("local-ttl 999")
                .with("max-reply-ip-num 9")
                .with("rr-ttl-reply-max 77")
                .with("group-end")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();

        // ① 落在 office 组的查询 → 取到**组级**值
        let office = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("office".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(office.local_ttl(), 999, "office 组必须取到组级 local-ttl");
        assert_eq!(
            office.max_reply_ip_num(),
            Some(9),
            "office 组必须取到组级 max-reply-ip-num"
        );
        assert_eq!(
            office.rr_ttl_reply_max(),
            Some(77),
            "office 组必须取到组级 rr-ttl-reply-max"
        );

        // ② 默认组（未匹配任何 client-rule 的普通查询）→ 取到**全局**值
        let default_ctx = DnsContext::new(&name, cfg.clone(), ServerOpts::default());
        assert_eq!(
            default_ctx.local_ttl(),
            60,
            "默认组必须取到全局 local-ttl，不能拿到 office 的 999"
        );
        assert_eq!(
            default_ctx.max_reply_ip_num(),
            Some(3),
            "默认组必须取到全局 max-reply-ip-num"
        );
        assert_eq!(
            default_ctx.rr_ttl_reply_max(),
            None,
            "全局没写 rr-ttl-reply-max，默认组就该是 None（不能漏到 office 的 77）"
        );

        // ③ 组不存在 → 安全回落全局，不能 panic
        let missing = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("no-such-group".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(missing.local_ttl(), 60, "组不存在必须回落全局");
    }

    /// 📌 乙类铺开的**贯通性测试**：`rr-ttl` / `response-mode` / `speed-check-mode`
    /// 的组级值必须走到 `DnsContext` 的取值入口。
    ///
    /// 与甲类那条同理：配置层测试只覆盖"值有没有进组"，
    /// **取值入口**（"配了不生效"最常发生的地方）必须单独覆盖。
    #[test]
    fn yi_class_group_params_reach_the_context_accessor() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                // 全局与组级故意不同值，否则两条路径答案相同、测不出接线
                .with("rr-ttl 60")
                .with("response-mode fastest-response")
                .with("group-begin office")
                .with("rr-ttl 777")
                .with("response-mode first-ping")
                .with("speed-check-mode none")
                .with("group-end")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();

        let office = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("office".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(office.rr_ttl(), Some(777), "office 组取到组级 rr-ttl");
        assert_eq!(
            office.response_mode(),
            crate::config::ResponseMode::FirstPing,
            "office 组取到组级 response-mode"
        );
        assert!(
            office
                .speed_check_mode()
                .as_ref()
                .is_some_and(|m| m.iter().any(|x| x.is_none())),
            "office 组取到组级 speed-check-mode none（且是 Some([None]) 形状）"
        );

        let default_ctx = DnsContext::new(&name, cfg.clone(), ServerOpts::default());
        assert_eq!(
            default_ctx.rr_ttl(),
            Some(60),
            "默认组必须取到全局 rr-ttl（不能拿到 office 的 777）"
        );
        assert_eq!(
            default_ctx.response_mode(),
            crate::config::ResponseMode::FastestResponse,
            "默认组必须取到全局 response-mode"
        );
        assert!(
            default_ctx
                .speed_check_mode()
                .as_ref()
                .is_none_or(|m| !m.iter().any(|x| x.is_none())),
            "默认组没写 speed-check-mode ⇒ 不能变成『写了 none』"
        );

        // 🔐 端到端解析：office 组必须解析成"不测速"
        let resolved =
            crate::config::resolve_speed_check_mode(None, office.speed_check_mode().as_ref());
        assert!(
            resolved.iter().any(|m| m.is_none()),
            "office 组的 speed-check-mode none 必须能让共用解析函数得出『不测速』"
        );
    }

    /// 顶层写这些参数时必须照常生效（组级支持**不得**破坏顶层用法）。
    ///
    /// 这是本改动最需要防的副作用：把落点从"全局"改成"分流"时，
    /// 很容易写成"只有组内才认"，于是所有写在顶层的既有配置**全部失效**。
    #[test]
    fn top_level_still_works_after_group_support() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                .with("local-ttl 123")
                .with("ipset-timeout yes")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();
        let ctx = DnsContext::new(&name, cfg.clone(), ServerOpts::default());

        assert_eq!(ctx.local_ttl(), 123, "顶层 local-ttl 必须照常生效");
        assert!(ctx.ipset_timeout(), "顶层 ipset-timeout 必须照常生效");
    }
}

#[cfg(test)]
mod soa_serial_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn synthetic_soa_serial_matches_build_time() {
        let s = synthetic_soa_serial();
        assert_eq!(s, synthetic_soa_serial(), "同一构建内必须恒定");
        assert_eq!(
            s as i64,
            crate::BUILD_DATE.timestamp(),
            "序列号应当取自构建时刻"
        );
    }

    #[test]
    fn both_soa_builders_share_the_same_serial() {
        let a = SOA::default_soa().serial();
        let rec = forge_soa_record(Name::from_str("x.test").unwrap(), 60);
        let b = match rec.data() {
            RData::SOA(s) => s.serial(),
            other => panic!("应当产出 SOA: {other:?}"),
        };
        assert_eq!(a, b, "两处必须用同一个序列号");
    }
}

/// 📌 丙-1 的**贯通**测试：三个参数的组级值必须走到 `DnsContext` 的取值入口，
/// 且**进程级用途不得被组级带偏**。
#[cfg(test)]
mod bing1_wiring_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn bing1_group_params_reach_the_context_accessor() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                // 全局与组级故意不同值，否则两条路径答案相同、测不出接线
                .with("serve-expired yes")
                .with("serve-expired-reply-ttl 5")
                .with("prefetch-domain yes")
                .with("group-begin office")
                .with("serve-expired no")
                .with("serve-expired-reply-ttl 42")
                .with("prefetch-domain no")
                .with("group-end")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();

        let office = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("office".to_string()),
                ..Default::default()
            },
        );
        assert!(!office.serve_expired(), "office 组：不喂过期数据");
        assert_eq!(
            office.serve_expired_reply_ttl(),
            42,
            "office 组：回给客户端的过期 TTL 取 42"
        );
        assert!(!office.prefetch_domain(), "office 组：不安排预取");

        let default_ctx = DnsContext::new(&name, cfg.clone(), ServerOpts::default());
        assert!(default_ctx.serve_expired(), "默认组：沿用全局的 yes");
        assert_eq!(
            default_ctx.serve_expired_reply_ttl(),
            5,
            "默认组：沿用全局的 5（不能漏成 office 的 42）"
        );
        assert!(default_ctx.prefetch_domain(), "默认组：沿用全局的 yes");
    }

    /// 🔐 丙-1 的边界在**取值层**也要成立：`DnsContext` 上那个按组取值的
    /// `prefetch_domain()` **只表示"这条应答要不要安排预取"**，
    /// 进程级任务开关读的始终是 `cfg` 上的全局访问器。
    #[test]
    fn context_prefetch_is_per_query_while_the_task_switch_stays_global() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                .with("prefetch-domain yes")
                .with("group-begin quiet")
                .with("prefetch-domain no")
                .with("group-end")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();
        let quiet = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("quiet".to_string()),
                ..Default::default()
            },
        );

        // ① 逐查询：这个组不发预取通知
        assert!(!quiet.prefetch_domain());
        // ② 进程级：后台任务照旧要开（读的是全局访问器，与组无关）
        assert!(
            cfg.prefetch_domain(),
            "某个组写了 no，绝不能把进程级后台预取任务关掉"
        );
    }

    /// 📌 丙-2a 的**贯通**测试：`dns64` 前缀必须走到 `DnsContext` 取值入口，
    /// 且"只有某个组配了"时该组生效、其它组不做。
    ///
    /// 真机上这里最难验证（要造 AAAA 空答案 + A 有条目的场景），
    /// 所以这一层用单元测试把"接线通了"钉住。
    #[test]
    fn bing2_group_params_reach_the_context_accessor() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                .with("edns-client-subnet 1.1.1.0/24")
                .with("group-begin v6only")
                .with("dns64 64:ff9b::/96")
                .with("edns-client-subnet 9.9.9.0/24")
                .with("group-end")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();

        let v6 = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("v6only".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(
            v6.dns64_prefix(),
            Some("64:ff9b::/96".parse().unwrap()),
            "v6only 组取到组级 dns64 前缀"
        );
        assert_eq!(
            v6.edns_client_subnet(),
            Some("9.9.9.0/24".parse().unwrap()),
            "v6only 组取到组级 ECS"
        );

        // 默认组：全局没配 dns64 ⇒ 不做 DNS64；ECS 回落……组级没写就是 None
        let default_ctx = DnsContext::new(&name, cfg.clone(), ServerOpts::default());
        assert_eq!(
            default_ctx.dns64_prefix(),
            None,
            "默认组没配 dns64 ⇒ 必须不做 DNS64（这正是旧实现会连累的场景）"
        );
        assert_eq!(
            default_ctx.edns_client_subnet(),
            None,
            "默认组没写组级 ECS ⇒ 交给 NameServer 的全局默认值兜底（这里应为 None）"
        );
    }
}

/// 📌 丙-2c 的**贯通**测试：`dualstack-ip-selection` 的组级值必须走到
/// `DnsContext` 取值入口，且**域名规则级仍然压过组级**。
///
/// 与甲/乙/丙-1/丙-2a 的那几条同理：配置层测试只证明"值进组了"，
/// **取值入口**（"配了不生效"最常发生的地方）必须单独覆盖。
#[cfg(test)]
mod bing2c_wiring_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn dualstack_group_value_reaches_the_context_accessor() {
        let cfg = std::sync::Arc::new(
            RuntimeConfig::builder()
                .with("server 8.8.8.8")
                // 全局与组级故意不同值，否则两条路径答案相同、测不出接线
                .with("dualstack-ip-selection yes")
                .with("group-begin office")
                .with("dualstack-ip-selection no")
                .with("group-end")
                .build()
                .unwrap(),
        );

        let name = Name::from_str("example.com").unwrap();

        // ① 命中 office 组 ⇒ 组级 no 生效
        let office = DnsContext::new(
            &name,
            cfg.clone(),
            ServerOpts {
                rule_group: Some("office".to_string()),
                ..Default::default()
            },
        );
        assert!(
            !cfg.dualstack_ip_selection_in_group("office"),
            "office 组写了 no，组级入口必须给出 false"
        );
        assert!(
            !office.server_opts().no_dualstack_selection(),
            "本用例没有 bind 级总闸，不该被误判"
        );

        // ② 默认组 ⇒ 回落全局 yes
        let default_ctx = DnsContext::new(&name, cfg.clone(), ServerOpts::default());
        assert!(
            cfg.dualstack_ip_selection_in_group(default_ctx.effective_rule_group()),
            "默认组没写 ⇒ 回落全局的 yes"
        );

        // ③ 端到端按调用点的算法复算一遍（总闸在外、链在内）
        let enabled_office = !office.server_opts().no_dualstack_selection()
            && crate::config::resolve_dualstack_selection(
                office
                    .domain_rule
                    .as_ref()
                    .map(|r| r.dualstack_ip_selection),
                cfg.group_params(office.effective_rule_group())
                    .dualstack_ip_selection,
                cfg.dualstack_ip_selection,
            );
        assert!(
            !enabled_office,
            "office 组的双栈优选应当被关掉（组级 no 生效）"
        );

        let enabled_default = !default_ctx.server_opts().no_dualstack_selection()
            && crate::config::resolve_dualstack_selection(
                default_ctx
                    .domain_rule
                    .as_ref()
                    .map(|r| r.dualstack_ip_selection),
                cfg.group_params(default_ctx.effective_rule_group())
                    .dualstack_ip_selection,
                cfg.dualstack_ip_selection,
            );
        assert!(enabled_default, "默认组应当保持开启");
    }
}
