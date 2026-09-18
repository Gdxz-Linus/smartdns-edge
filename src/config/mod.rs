use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use crate::{
    infra::file_mode::FileMode,
    libdns::proto::rr::{
        Name, RecordType,
        rdata::{HTTPS, SRV},
    },
    log::Level,
    proxy::ProxyConfig,
    third_ext::serde_str,
};

use byte_unit::Byte;
use ipnet::{IpNet, Ipv6Net};
use serde::{self, Deserialize, Serialize};

/// DNS 规范里的 TTL 上限：RFC 2181 §8 —— TTL 是 31 位，最高位必须为 0。
pub const TTL_MAX: u64 = 0x7FFF_FFFF;

/// 把配置里的 TTL 秒数收进合法范围。
///
/// 🔐 P2：原实现把值当 `u64` 收下、下游再 `as u32` 截断 —— 写 `rr-ttl 4294967297`
/// 会**静默**变成 1 秒（没有任何告警）。这里改成"夹到规范上限 + 告警"：
/// 既不静默出错，也不会因为一个手误就让服务起不来。
pub fn sanitize_ttl(name: &str, v: u64) -> u64 {
    if v > TTL_MAX {
        crate::log::warn!("配置项 {name} 的值 {v} 超出 DNS 规范上限 {TTL_MAX} 秒，已按上限生效");
        TTL_MAX
    } else {
        v
    }
}

mod acl;
mod audit;
mod bind_addr;
mod cache;
mod client_rule;
mod conf_file;
mod domain;
mod domain_rule;
mod domain_set;
mod group_match;
mod ip_set;
mod log;
mod nameserver;
pub mod parser;
mod response_mode;
mod rule_group;
mod server_opts;
mod set_cache;
mod speed_mode;

pub use acl::*;
pub use audit::*;
pub use bind_addr::*;
pub use cache::*;
pub use client_rule::*;
pub use conf_file::*;
pub use domain::*;
pub use domain_rule::*;
pub use domain_set::*;
pub use group_match::*;
pub use ip_set::*;
pub use log::*;
pub use nameserver::*;
pub use response_mode::*;
pub use rule_group::*;
pub use server_opts::*;
pub use speed_mode::*;

use self::parser::NomParser;

pub type DomainSets = HashMap<String, HashSet<WildcardName>>;
pub type ForwardRules = Vec<ForwardRule>;
pub type AddressRules = Vec<AddressRule>;
pub type DomainRules = Vec<ConfigForDomain<DomainRule>>;
pub type CNameRules = Vec<ConfigForDomain<CNameRule>>;
pub type SrvRecords = Vec<ConfigForDomain<SRV>>;
pub type HttpsRecords = Vec<ConfigForDomain<HttpsRecordRule>>;

#[derive(Default)]
pub struct Config {
    /// 管理后台（WebAPI / 网页控制台）的口令。
    ///
    /// 配置里写了 `api-token <口令>` 就用它；没写则退回环境变量
    /// `SMARTDNS_API_TOKEN`；两者都没有时，进程启动后第一次用到会随机生成一个
    /// 并打印出来（**代码里不再保留任何写死的默认口令**）。
    pub api_token: Option<String>,

    /// dns server name, default is host namepub struct Config {
    /// dns server name, default is host name
    ///
    /// ```
    /// server-name,
    ///
    /// example:
    ///   server-name smartdns
    /// ```
    pub server_name: Option<Name>,

    /// The number of worker threads
    pub num_workers: Option<usize>,

    pub mdns_lookup: Option<bool>,

    /// whether resolv local hostname to ip address
    pub resolv_hostname: Option<bool>,

    pub hosts_file: Option<glob::Pattern>,

    pub expand_ptr_from_address: Option<bool>,

    /// dns server run user
    ///
    /// ```
    /// user [username]
    ///
    /// exmaple:
    ///   user nobody
    /// ```
    pub user: Option<String>,

    /// Local domain suffix appended to DHCP names and hosts file entries.
    pub domain: Option<Name>,

    /// List of bind addresses
    pub binds: Vec<BindAddrConfig>,

    /// SSL Certificate file path
    pub bind_cert_file: Option<PathBuf>,
    /// SSL Certificate key file path
    pub bind_cert_key_file: Option<PathBuf>,
    /// SSL Certificate key file password
    pub bind_cert_key_pass: Option<String>,

    /// tcp connection idle timeout
    ///
    /// tcp-idle-time [second]
    pub tcp_idle_time: Option<u64>,

    /// max-connections [number]
    ///
    /// 所有 DNS 监听合计允许的**同时连接数**上限（0 或未配置 = 按物理内存自动推算）。
    /// 超限时拒绝新连接（不影响已有连接），并计入统计。
    pub max_connections: Option<usize>,

    /// max-connections-per-ip [number]
    ///
    /// 单一来源允许的同时连接数上限（IPv6 按 /64 前缀聚合计数；0 或未配置 = 自动）。
    /// 企业环境里 NAT/代理后面的客户端共用一个 IP，所以默认值取得比较宽。
    pub max_connections_per_ip: Option<usize>,

    /// first-packet-timeout [second]
    ///
    /// 连接建立后、"读到一个完整 DNS 报文之前"允许等待的秒数（默认 5，0 表示不限制）。
    /// 用途：把"只发长度前缀就不发正文"的慢速攻击窗口从空闲超时（默认 120 秒）压到几秒，
    /// 同时对正常客户端（握手后立刻发查询）没有任何影响，也不影响长连接复用。
    pub first_packet_timeout: Option<u64>,

    pub cache: CacheConfig,

    /// List of hosts that supply bogus NX domain results
    pub bogus_nxdomain: Vec<IpOrSet>,

    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    pub blacklist_ip: Vec<IpOrSet>,

    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    pub whitelist_ip: Vec<IpOrSet>,

    /// List of IPs that will be ignored
    pub ignore_ip: Vec<IpOrSet>,

    /// speed check mode
    ///
    /// speed-check-mode [ping|tcp:port|http:port|https:port|none|,]
    /// ```ini
    /// example:
    ///   speed-check-mode ping,tcp:8080,http:80,https
    ///   speed-check-mode tcp:443,ping
    ///   speed-check-mode none
    /// ```
    pub speed_check_mode: Option<SpeedCheckModeList>,

    /// force AAAA query return SOA
    ///
    /// force-AAAA-SOA [yes|no]
    pub force_aaaa_soa: Option<bool>,

    /// force HTTPS query return SOA
    ///
    /// force-HTTPS-SOA [yes|no]
    pub force_https_soa: Option<bool>,

    /// force specific qtype return soa
    ///
    /// force-qtype-SOA [qtypeid |...]
    ///
    /// qtypeid: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    /// ```ini
    /// example:
    ///   force-qtype-SOA 65 28
    /// ```
    pub force_qtype_soa: HashSet<RecordType>,

    /// Enable IPV4, IPV6 dual stack IP optimization selection strategy
    ///
    /// dualstack-ip-selection [yes|no]
    pub dualstack_ip_selection: Option<bool>,
    /// dualstack-ip-selection-threshold [num] (0~1000)
    pub dualstack_ip_selection_threshold: Option<u64>,
    /// dualstack-ip-allow-force-AAAA [yes|no]
    pub dualstack_ip_allow_force_aaaa: Option<bool>,

    /// DNS64 prefix
    ///
    /// dns64 ip-prefix/mask
    pub dns64_prefix: Option<Ipv6Net>,

    /// edns client subnet
    ///
    /// ```
    /// example:
    ///   edns-client-subnet [ip/subnet]
    ///   edns-client-subnet 192.168.1.1/24
    ///   edns-client-subnet 8::8/56
    /// ```
    pub edns_client_subnet: Option<IpNet>,

    /// ttl for all resource record
    pub rr_ttl: Option<u64>,
    /// minimum ttl for resource record
    pub rr_ttl_min: Option<u64>,
    /// maximum ttl for resource record
    pub rr_ttl_max: Option<u64>,
    /// maximum reply ttl for resource record
    pub rr_ttl_reply_max: Option<u64>,

    /// ttl for local address and host (default: rr-ttl-min)
    pub local_ttl: Option<u64>,

    /// Maximum number of IPs returned to the client|8|number of IPs, 1~16
    pub max_reply_ip_num: Option<u8>,

    /// response mode
    ///
    /// response-mode [first-ping|fastest-ip|fastest-response]
    pub response_mode: Option<ResponseMode>,

    pub log: LogConfig,

    pub audit: AuditConfig,

    /// 访问控制（`acl-enable`）：开启后没匹配到任何 `client-rules` 的客户端一律 REFUSED。
    pub acl: AclConfig,

    /// Support reading dnsmasq dhcp file to resolve local hostname
    pub dnsmasq_lease_file: Option<PathBuf>,

    /// certificate file
    pub ca_file: Option<PathBuf>,
    /// certificate path
    pub ca_path: Option<PathBuf>,

    /// remote dns server list
    pub nameservers: Vec<NameServerInfo>,

    /// The proxy server for upstream querying.
    pub proxy_servers: HashMap<String, ProxyConfig>,

    pub nftsets: Vec<ConfigForDomain<Vec<ConfigForIP<NFTsetConfig>>>>,

    /// 🔐 Q1：`ipset /域名/#4:集合名,#6:集合名` —— 把解析结果写进 Linux 的 ipset
    pub ipsets: Vec<ConfigForDomain<Vec<ConfigForIP<IpsetConfig>>>>,

    /// 🔐 Q2：写进 ipset 的条目要不要带过期时间（`ipset-timeout [yes|no]`）。
    /// 开着 = 用"应答 TTL × 3 秒"（C 版 `ds_context.c:668` 的算法）；默认关 = 永不过期。
    pub ipset_timeout: Option<bool>,

    /// 🔐 Q4：同上，nftables 那一半（`nftset-timeout`）
    pub nftset_timeout: Option<bool>,

    /// 🔐 Q3：`ipset-no-speed`。**本实现一律把解析出的地址全部写入集合**，
    /// 也就是"本来就等于开着这个开关"（C 版默认是"先测速、只写最快那一个"）。
    /// 存下来只为"这行配置我认了"，运行时不改变行为 —— 启动时会明确说明一次，不让用户以为白配。
    pub ipset_no_speed: Option<bool>,

    /// 🔐 Q5：同上，nftables 那一半（`nftset-no-speed`）
    pub nftset_no_speed: Option<bool>,

    /// 🔐 Q6：`nftset-debug` —— 打开往防火墙集合写地址时的详细日志
    pub nftset_debug: Option<bool>,

    /// 🔐 Q7 `log-syslog [yes|no]`：运行日志**同时**送系统日志（Linux 的 syslog）。
    ///
    /// 与 C 版对齐（`src/smartdns.c:525` + `openlog("smartdns", LOG_CONS, LOG_USER)`）：
    /// 级别映射成 syslog 优先级；是"追加一路"，文件/控制台照旧。
    /// **只在 Linux 上有效**，其它平台启动时会明确提示"不会生效"。
    pub log_syslog: Option<bool>,

    /// 🔐 Q11 `local-domain <域名>`：把该域名（含子域名）交给 **mDNS** 那一组解析。
    ///
    /// 语义对齐 C 版 `src/dns_conf/local_domain.c:50`（`_conf_domain_rule_nameserver(域, "mdns")`）：
    /// 等价于"这个域名用本地 mDNS 找"，用于局域网里的 `.lan` / `.home` 这类名字。
    ///
    /// 比 C 版多两点：① C 版是全局变量，**只支持一条**（写第二条会把第一条顶掉）；我们支持多条。
    /// ② 配了它却把 `mdns-lookup` 关着时，启动时会**明确告警**（否则就是"配了像没配"）。
    pub local_domains: Vec<String>,

    /// 🔐 Q10 `max-query-limit`：整机**同时处理**的查询数上限（不是"每客户端"，也不是"每秒"）。
    ///
    /// 超过就回 `REFUSED`（不查上游、不进缓存），日志每 120 秒最多告警一次；`0` = 不限。
    /// 默认 65535（与 C 版 `DNS_MAX_QUERY_LIMIT` 及本仓库文档一致）。
    pub max_query_limit: Option<usize>,

    pub resolv_file: Option<PathBuf>,
    pub domain_set_providers: HashMap<String, Vec<DomainSetProvider>>,

    /// ip set
    pub ip_sets: HashMap<String, Vec<IpNet>>,

    /// 🔐 IP 集合的来源清单（`-url` / `-file` / `-interval` 等），与 `domain_set_providers` 对称。
    /// 集合内容在解析时就已经展开进 `ip_sets`，这里留一份供定时刷新判断周期用。
    pub ip_set_providers: HashMap<String, Vec<IpSetProvider>>,

    pub ip_alias: Vec<IpAlias>,

    pub client_rules: Vec<ClientRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAlias {
    pub ip: IpOrSet,
    pub to: Arc<[IpAddr]>,
}

/// 🔐 Q18 `group-begin <组名> [-inherit <另一组|none|parent|default>]`
///
/// 语义对齐 C 版 `src/dns_conf/dns_conf_group.c:228-302`：
/// * `none` = 不继承；`parent` = 继承**外层**组；`default` = 继承 `default` 组；写别的组名 = 继承那个组；
/// * **被继承的组必须已经定义过**（继承在推入该组时解析）—— 不支持前向引用，写错会明确告警；
/// * 不写这个选项时：**嵌套组默认继承外层组**（C 版如此），顶层组不继承。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupBegin {
    pub name: String,
    pub inherit: Option<String>,
}

/// 🔐 Q12 `ip-rules <IP/CIDR 或 ip-set:名字> [-blacklist-ip] [-whitelist-ip] [-bogus-nxdomain] [-ignore-ip] [-ip-alias <IP 列表|ip-set:名字>]`
///
/// 语义与 C 版一致（`src/dns_conf/ip_rule.c:104`）：**这就是"按 IP 段"版的那几个开关** ——
/// 顶层的 `blacklist-ip 1.2.3.0/24`、`bogus-nxdomain 1.2.3.4` 是"一个开关一行"，
/// `ip-rules` 是"一段 IP 一行，后面挂多个开关"，落到的是同一批表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRules {
    /// 这条规则作用在哪段 IP（也可以是一命名集合 `ip-set:名字`）
    pub key: IpOrSet,
    pub blacklist: bool,
    pub whitelist: bool,
    pub bogus: bool,
    pub ignore: bool,
    /// `-ip-alias`：把这段 IP 映射成这些 IP
    pub alias: Option<Arc<[IpAddr]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpOrSet {
    Net(IpNet),
    Set(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedProxyConfig {
    pub name: String,
    pub config: ProxyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigForDomain<T: Sized + parser::NomParser> {
    pub domain: Domain,
    pub config: T,
}

impl<T: Sized + parser::NomParser> std::ops::Deref for ConfigForDomain<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

// 🔐 Q19/Q20：加 `Serialize` 是为了让监听级的集合配置能出现在 API 的配置回显里（只序列化，不反序列化）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ConfigForIP<T: Sized + parser::NomParser> {
    V4(T),
    V6(T),
    None,
}

/// 🔐 Q1：`ipset /域名/#4:集合名,#6:集合名` 里的"集合名"。
///
/// 与 nftables 那套（`NFTsetConfig`）的区别是：ipset 的集合是**全局的**，
/// 没有 family/table 的层级，所以这里只有一个名字。
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct IpsetConfig {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct NFTsetConfig {
    pub family: &'static str,
    pub table: String,
    pub name: String,
}

pub type Options<'a> = Vec<(&'a str, Option<&'a str>)>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct SslConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_key_pass: Option<String>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum AddressRuleValue {
    SOA,
    SOAv4,
    SOAv6,
    IGN,
    IGNv4,
    IGNv6,
    Addr {
        v4: Option<Arc<[Ipv4Addr]>>,
        v6: Option<Arc<[Ipv6Addr]>>,
    },
}

impl std::fmt::Display for AddressRuleValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AddressRuleValue::*;
        match self {
            SOA => write!(f, "#"),
            SOAv4 => write!(f, "#4"),
            SOAv6 => write!(f, "#6"),
            IGN => write!(f, "-"),
            IGNv4 => write!(f, "-4"),
            IGNv6 => write!(f, "-6"),
            Addr { v4, v6 } => {
                let mut first = true;
                if let Some(v4) = v4 {
                    for ip in v4.iter() {
                        if first {
                            first = false;
                        } else {
                            write!(f, ",")?;
                        }
                        write!(f, "{ip}")?;
                    }
                }
                if let Some(v6) = v6 {
                    for ip in v6.iter() {
                        if first {
                            first = false;
                        } else {
                            write!(f, ",")?;
                        }
                        write!(f, "{ip}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
#[allow(clippy::upper_case_acronyms)]
pub enum Ignorable<T> {
    #[default]
    Ignore,
    Value(T),
}

pub type CNameRule = Ignorable<Name>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, crate::api::ToSchema)]
pub struct AddressRule {
    #[serde(with = "serde_str")]
    #[schema(value_type = String)]
    pub domain: Domain,
    #[serde(with = "serde_str")]
    #[schema(value_type = String)]
    pub address: AddressRuleValue,
}

impl std::fmt::Display for AddressRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}/{}", self.domain, self.address)
    }
}

/// alias: nameserver rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRule {
    #[serde(with = "serde_str")]
    pub domain: Domain,
    pub nameserver: String,
}

impl std::fmt::Display for ForwardRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}/{}", self.domain, self.nameserver)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpsRecordRule {
    SOA,
    Ignore,
    Filter {
        no_ipv4_hint: bool,
        no_ipv6_hint: bool,
    },
    RecordData(HTTPS),
}

macro_rules! impl_from_str {
    ($($type:ty),*) => {
        $(
            impl FromStr for $type {
                type Err=nom::Err<nom::error::Error<String>>;

                /// 🔐 P2：**必须吃完整个输入**，尾部还有非空白内容就报错。
                ///
                /// 旧实现是 `Ok((_, v)) => Ok(v)` —— 把 nom 的"剩余输入"直接扔掉，
                /// 于是 `"example.com<垃圾>"` 会被**静默截断**成 `example.com` 并当成
                /// 合法值使用（接口入参走 `serde_str` → 这里），DELETE/PUT 就会操作到
                /// 一个调用方根本没点名的域名。宁可报错，也不能改写用户写下的名字。
                ///
                /// 先 `trim()`：`"example.com "` 这类首尾空白仍应被接受。
                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    match NomParser::parse(s.trim()) {
                        Ok((rest, v)) => {
                            if rest.trim().is_empty() {
                                Ok(v)
                            } else {
                                Err(nom::Err::Error(nom::error::Error::new(
                                    rest.to_string(),
                                    nom::error::ErrorKind::Eof,
                                )))
                            }
                        }
                        Err(err) => Err(err.to_owned()),
                    }
                }
            }
        )*
    };
}

impl_from_str!(AddressRule, Domain, AddressRuleValue, BindAddr);
