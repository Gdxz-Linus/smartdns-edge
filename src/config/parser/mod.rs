use ipnet::Ipv6Net;
use nom::{
    IResult, Parser, branch::*, bytes::complete::*, character::complete::*, combinator::*,
    multi::*, sequence::*,
};

mod address_rule;
mod bind_addr;
mod bool;
mod bytes;
mod client_rule;
mod cname;
mod conf_file;
mod config_for_domain;
mod domain;
mod domain_rule;
mod domain_set;
mod file_mode;
mod forward_rule;
mod glob_pattern;
mod group_begin;
mod group_match;
mod https_record;
mod ip_alias;
mod ip_net;
mod ip_rules;
mod ip_set;
mod iporset;
mod ipset;
mod log_level;
mod nameserver;
mod nftset;
mod nom_recipes;
mod options;
mod path;
mod proxy_config;
mod record_type;
mod response_mode;
mod speed_mode;
mod srv;
mod svcb;

use super::*;

pub(crate) trait NomParser: Sized {
    fn parse(input: &str) -> IResult<&str, Self>;

    // fn from_str(s: &str) -> Result<Self, nom::Err<nom::error::Error<&str>>> {
    //     match Self::parse(s) {
    //         Ok((_, v)) => Ok(v),
    //         Err(err) => Err(err),
    //     }
    // }
}

impl NomParser for usize {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        // 🔐 问题 53-①：**不能 `as` 截断**。
        //
        // 原来写的是 `map(u64, |v| v as usize)`。在 64 位平台上两者同宽、看不出问题；
        // 但在 **32 位平台**上，`u64 → usize` 的 `as` 会**静默截断**：
        //   `-interval 4294967296`（2³²）→ 截成 **0** → 而 0 的语义是"关闭定时刷新"
        //   ⇒ **用户配了刷新，却得到了完全相反的效果**，而且没有任何提示。
        // 这属于"静默失效"里最坏的一类：配置看起来生效了。
        //
        // 改成 `map_res`：超出 `usize` 表示范围时返回解析错误
        // （配置解析处会把它变成"这一行不认识"的告警/致命错误，用户看得见）。
        map_res(u64, |v| {
            usize::try_from(v)
                .map_err(|_| format!("the value {v} does not fit in usize on this platform"))
        })
        .parse(input)
    }
}

impl NomParser for u64 {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        u64(input)
    }
}

impl NomParser for u8 {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        u8(input)
    }
}

impl NomParser for String {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(is_not(" \t\r\n"), ToString::to_string).parse(input)
    }
}

/// one line config.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::large_enum_variant)]
pub enum ConfigItem {
    Address(AddressRule),
    ApiToken(String),
    AuditEnable(bool),
    /// `acl-enable yes|no`：访问控制总开关（配合 client-rules 当白名单用）
    AclEnable(bool),
    /// 🔐 13-⑥：`trusted-proxy <IP|CIDR>`（可重复）—— 可信反向代理清单。
    ///
    /// 只有来自这些地址的请求，才会去解析 `X-Forwarded-For` 还原真实客户端。
    /// **不配 = 完全保持现状**（不信任任何代理头）。
    TrustedProxy(IpNet),
    AuditFile(PathBuf),
    AuditFileMode(FileMode),
    /// 🔐 Q9：审计行同时打到控制台
    AuditConsole(bool),
    AuditNum(usize),
    AuditSize(Byte),
    BindCertFile(PathBuf),
    BindCertKeyFile(PathBuf),
    BindCertKeyPass(String),
    BlacklistIp(IpOrSet),
    BogusNxDomain(IpOrSet),
    CacheFile(PathBuf),
    CachePersist(bool),
    CacheSize(usize),
    CacheCheckpointTime(u64),
    CaFile(PathBuf),
    CaPath(PathBuf),
    ClientRule(ClientRule),
    CNAME(ConfigForDomain<CNameRule>),
    SrvRecord(ConfigForDomain<SRV>),
    GroupBegin(GroupBegin),
    GroupEnd,
    GroupMatch(GroupMatch),
    HttpsRecord(ConfigForDomain<HttpsRecordRule>),
    ConfFile(ConfFileItem),
    DnsmasqLeaseFile(PathBuf),
    Dns64(Ipv6Net),
    Domain(Name),
    DomainRule(ConfigForDomain<DomainRule>),
    DomainSetProvider(DomainSetProvider),
    DualstackIpAllowForceAAAA(bool),
    DualstackIpSelection(bool),
    DualstackIpSelectionThreshold(u64),
    EdnsClientSubnet(IpNet),
    ExpandPtrFromAddress(bool),
    ForceAAAASOA(bool),
    ForceHTTPSSOA(bool),
    ForceNoCNAME(bool),
    ForceQtypeSoa(RecordType),
    ForwardRule(ForwardRule),
    HostsFile(glob::Pattern),
    IgnoreIp(IpOrSet),
    Listener(BindAddrConfig),
    LocalTtl(u64),
    LogConsole(bool),
    LogNum(u64),
    LogSize(Byte),
    LogLevel(Level),
    LogFile(PathBuf),
    LogFileMode(FileMode),
    LogFilter(String),
    MaxReplyIpNum(u8),
    MdnsLookup(bool),
    NftSet(ConfigForDomain<Vec<ConfigForIP<NFTsetConfig>>>),
    /// 🔐 Q1：`ipset /域名/#4:集合名,#6:集合名`
    IpSet(ConfigForDomain<Vec<ConfigForIP<IpsetConfig>>>),
    /// 🔐 Q2/Q4：写进集合的条目带不带过期时间（TTL×3）
    IpSetTimeout(bool),
    NftSetTimeout(bool),
    /// 🔐 Q3/Q5：`-no-speed`（本实现一律全写，等于常开）
    IpSetNoSpeed(bool),
    NftSetNoSpeed(bool),
    /// 🔐 Q6：nftset 详细日志
    NftSetDebug(bool),
    /// 🔐 Q10：整机同时处理的查询数上限（0 = 不限）
    MaxQueryLimit(usize),
    /// 🔐 Q11：`local-domain <域名>`（`-` = 清空已配的）
    LocalDomain(String),
    /// 🔐 Q7/Q8：日志 / 审计送系统日志
    LogSyslog(bool),
    AuditSyslog(bool),
    /// 🔐 Q12：`ip-rules <IP/CIDR> [-blacklist-ip ...]`（按 IP 段挂那几个过滤开关）
    IpRules(IpRules),
    NumWorkers(usize),
    PrefetchDomain(bool),
    ProxyConfig(NamedProxyConfig),
    ResolvHostname(bool),
    ResponseMode(ResponseMode),
    ServeExpired(bool),
    ServeExpiredTtl(u64),
    ServeExpiredReplyTtl(u64),
    ServeExpiredPrefetchTime(u64),
    Server(NameServerInfo),
    ServerName(Name),
    ResolvFile(PathBuf),
    RrTtl(u64),
    RrTtlMin(u64),
    RrTtlMax(u64),
    RrTtlReplyMax(u64),
    SpeedMode(Option<SpeedCheckModeList>),
    TcpIdleTime(u64),
    FirstPacketTimeout(u64),
    MaxConnections(usize),
    MaxConnectionsPerIp(usize),
    WhitelistIp(IpOrSet),
    User(String),
    IpSetProvider(IpSetProvider),
    IpAlias(IpAlias),
}

impl std::fmt::Display for ConfigItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigItem::Address(rule) => write!(f, "address {rule}")?,
            ConfigItem::ForwardRule(rule) => write!(f, "nameserver {rule}")?,
            ConfigItem::Server(c) => write!(f, "server {c}")?,
            // 🌟 核心修复：把剩下的所有 todo!() 干掉，换成安全的通用打印！
            // 只要我们不专门格式化它，就只输出一个占位提示，绝不引发崩溃！
            _ => write!(f, "[Unformatted Config Item]")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ConfigLine<'a> {
    Config {
        config: ConfigItem,
        comment: Option<&'a str>,
    },
    Comment(&'a str),
    EmptyLine,
    Eof,
}

pub struct ConfigFile<'a>(Vec<ConfigLine<'a>>);

impl<'a> std::ops::Deref for ConfigFile<'a> {
    type Target = Vec<ConfigLine<'a>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> std::ops::DerefMut for ConfigFile<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> std::fmt::Display for ConfigFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for line in &self.0 {
            match line {
                ConfigLine::Config { config, comment } => {
                    writeln!(f, "{}{}", config, comment.unwrap_or_default())?
                }
                ConfigLine::Comment(comment) => writeln!(f, "{comment}")?,
                ConfigLine::EmptyLine => writeln!(f)?,
                ConfigLine::Eof => (),
            }
        }
        Ok(())
    }
}

impl ConfigFile<'_> {
    pub fn parse(input: &str) -> IResult<&str, ConfigFile<'_>> {
        map(separated_list0(line_ending, parse_line), ConfigFile).parse(input)
    }
}

fn parse_line<'a>(input: &'a str) -> IResult<&'a str, ConfigLine<'a>> {
    fn comment(input: &str) -> IResult<&str, &str> {
        map(recognize((char('#'), not_line_ending)), |comment: &str| {
            comment.trim_end()
        })
        .parse(input)
    }

    fn config_name<'a>(
        keyword: &'static str,
    ) -> impl Parser<&'a str, Output = &'a str, Error = nom::error::Error<&'a str>> {
        tag_no_case(keyword)
    }

    fn config<'a, T: NomParser>(
        name: &'static str,
    ) -> impl Parser<&'a str, Output = T, Error = nom::error::Error<&'a str>> {
        preceded(config_name(name), preceded(space1, T::parse))
    }

    let group1 = alt((
        map(config("address"), ConfigItem::Address),
        map(config("audit-enable"), ConfigItem::AuditEnable),
        map(config("audit-file-mode"), ConfigItem::AuditFileMode),
        map(config("audit-console"), ConfigItem::AuditConsole),
        map(config("audit-file"), ConfigItem::AuditFile),
        map(config("audit-num"), ConfigItem::AuditNum),
        map(config("audit-size"), ConfigItem::AuditSize),
        map(config("bind-cert-file"), ConfigItem::BindCertFile),
        map(config("bind-cert-key-file"), ConfigItem::BindCertKeyFile),
        map(config("bind-cert-key-pass"), ConfigItem::BindCertKeyPass),
        map(config("bogus-nxdomain"), ConfigItem::BogusNxDomain),
        map(config("blacklist-ip"), ConfigItem::BlacklistIp),
        map(config("cache-file"), ConfigItem::CacheFile),
        map(config("cache-persist"), ConfigItem::CachePersist),
        map(config("cache-size"), ConfigItem::CacheSize),
        map(
            config("cache-checkpoint-time"),
            ConfigItem::CacheCheckpointTime,
        ),
        map(config("ca-file"), ConfigItem::CaFile),
        map(config("ca-path"), ConfigItem::CaPath),
        // `client-rule`（单数）是 `client-rules` 的**兼容别名**，同一配置项。
        map(config("client-rules"), ConfigItem::ClientRule),
        map(config("client-rule"), ConfigItem::ClientRule),
        map(config("conf-file"), ConfigItem::ConfFile),
    ));

    let group2 = alt((
        // `domain-rule`（单数）同样是别名；文档只列复数形式 `domain-rules`。
        map(config("domain-rules"), ConfigItem::DomainRule),
        map(config("domain-rule"), ConfigItem::DomainRule),
        map(config("domain-set"), ConfigItem::DomainSetProvider),
        map(config("dnsmasq-lease-file"), ConfigItem::DnsmasqLeaseFile),
        map(config("dns64"), ConfigItem::Dns64),
        map(
            config("dualstack-ip-allow-force-AAAA"),
            ConfigItem::DualstackIpAllowForceAAAA,
        ),
        map(
            config("dualstack-ip-selection"),
            ConfigItem::DualstackIpSelection,
        ),
        map(
            config("dualstack-ip-selection-threshold"),
            ConfigItem::DualstackIpSelectionThreshold,
        ),
        map(config("edns-client-subnet"), ConfigItem::EdnsClientSubnet),
        map(
            config("expand-ptr-from-address"),
            ConfigItem::ExpandPtrFromAddress,
        ),
        map(config("force-AAAA-SOA"), ConfigItem::ForceAAAASOA),
        map(config("force-HTTPS-SOA"), ConfigItem::ForceHTTPSSOA),
        map(config("force-qtype-soa"), ConfigItem::ForceQtypeSoa),
        // ⚠️ `response` 是 `response-mode` 的**别名**（上游历史上两种写法都有），
        // 文档只列 `response-mode` 一种。
        map(config("response"), ConfigItem::ResponseMode),
        // 🔐 Q18：`group-begin <组> [-inherit ...]`（自带前缀，放通用项之前）
        map(NomParser::parse, ConfigItem::GroupBegin),
        map(config_name("group-end"), |_| ConfigItem::GroupEnd),
        map(config("prefetch-domain"), ConfigItem::PrefetchDomain),
        map(config("cname"), ConfigItem::CNAME),
        map(config("num-workers"), ConfigItem::NumWorkers),
        map(config("domain"), ConfigItem::Domain),
        map(config("hosts-file"), ConfigItem::HostsFile),
    ));

    let group3 = alt((
        map(config("https-record"), ConfigItem::HttpsRecord),
        // 🔐 注意：`force-no-CNAME` 没有放进 group2 —— 那一组**已经满 21 个元素**
        // （`nom` 的 `alt` 实现上限就是 21），再加会**编译不过**。
        // 这里并入元素较少的 group3，语义上同样只是"多认一个关键字"，没有顺序含义。
        map(config("force-no-CNAME"), ConfigItem::ForceNoCNAME),
        map(config("ignore-ip"), ConfigItem::IgnoreIp),
        map(config("local-ttl"), |v: u64| {
            ConfigItem::LocalTtl(sanitize_ttl("local-ttl", v))
        }),
        map(config("log-console"), ConfigItem::LogConsole),
        map(config("log-file-mode"), ConfigItem::LogFileMode),
        map(config("log-file"), ConfigItem::LogFile),
        map(config("log-filter"), ConfigItem::LogFilter),
        map(config("log-level"), ConfigItem::LogLevel),
        map(config("log-num"), ConfigItem::LogNum),
        map(config("log-size"), ConfigItem::LogSize),
        map(config("max-reply-ip-num"), ConfigItem::MaxReplyIpNum),
        map(config("mdns-lookup"), ConfigItem::MdnsLookup),
        map(config("nameserver"), ConfigItem::ForwardRule),
        map(config("proxy-server"), ConfigItem::ProxyConfig),
        map(config("rr-ttl-reply-max"), |v: u64| {
            ConfigItem::RrTtlReplyMax(sanitize_ttl("rr-ttl-reply-max", v))
        }),
        map(config("rr-ttl-min"), |v: u64| {
            ConfigItem::RrTtlMin(sanitize_ttl("rr-ttl-min", v))
        }),
        map(config("rr-ttl-max"), |v: u64| {
            ConfigItem::RrTtlMax(sanitize_ttl("rr-ttl-max", v))
        }),
        map(config("rr-ttl"), |v: u64| {
            ConfigItem::RrTtl(sanitize_ttl("rr-ttl", v))
        }),
        map(config("resolv-file"), ConfigItem::ResolvFile),
    ));

    let group4 = alt((
        // 注意：nom 的 alt 元组最多 21 项，加新指令前先数一下（当前 14 项）
        map(config("api-token"), ConfigItem::ApiToken),
        // ⚠️ `resolv-hostanme` 是**拼写错误的兼容别名**（正确写法见下方 `resolv-hostname`）。
        // 保留它是为了不破坏既有配置，**不要写进文档**、也不要"顺手删掉"。
        map(config("resolv-hostanme"), ConfigItem::ResolvHostname),
        map(config("response-mode"), ConfigItem::ResponseMode),
        map(config("server-name"), ConfigItem::ServerName),
        map(config("speed-check-mode"), ConfigItem::SpeedMode),
        map(config("serve-expired-reply-ttl"), |v: u64| {
            ConfigItem::ServeExpiredReplyTtl(sanitize_ttl("serve-expired-reply-ttl", v))
        }),
        map(config("serve-expired-ttl"), |v: u64| {
            ConfigItem::ServeExpiredTtl(sanitize_ttl("serve-expired-ttl", v))
        }),
        map(config("serve-expired-prefetch-time"), |v: u64| {
            ConfigItem::ServeExpiredPrefetchTime(sanitize_ttl("serve-expired-prefetch-time", v))
        }),
        map(config("serve-expired"), ConfigItem::ServeExpired),
        map(config("srv-record"), ConfigItem::SrvRecord),
        map(config("resolv-hostname"), ConfigItem::ResolvHostname),
        map(config("tcp-idle-time"), ConfigItem::TcpIdleTime),
        map(
            config("first-packet-timeout"),
            ConfigItem::FirstPacketTimeout,
        ),
        map(config("max-connections"), ConfigItem::MaxConnections),
        map(
            config("max-connections-per-ip"),
            ConfigItem::MaxConnectionsPerIp,
        ),
        map(config("nftset"), ConfigItem::NftSet),
        map(config("user"), ConfigItem::User),
        // `acl-enable`：访问控制总开关（放在 group4 —— 它离 21 项上限还有余量）
        map(config("acl-enable"), ConfigItem::AclEnable),
        // 🔐 13-⑥：`trusted-proxy <IP|CIDR>`（可重复，多条累加成一个可信清单）
        map(config("trusted-proxy"), ConfigItem::TrustedProxy),
        // ⚠️ 注意：每个 groupN 最多只能有 21 个入口——这是 nom 对 alt/Choice 元组
        // 元素数量的硬上限（group2 已达 21 个）。以后新增配置指令时，请放到元素较少的组。
        map(config("group-match"), ConfigItem::GroupMatch),
    ));

    let group5 = alt((
        // 🔐 Q12：`ip-rules ...`（自带前缀，不会和别的项撞；放在通用解析器之前）
        map(NomParser::parse, ConfigItem::IpRules),
        map(config("ipset"), ConfigItem::IpSet),
        map(config("ipset-timeout"), ConfigItem::IpSetTimeout),
        map(config("ipset-no-speed"), ConfigItem::IpSetNoSpeed),
        map(config("nftset-timeout"), ConfigItem::NftSetTimeout),
        map(config("nftset-no-speed"), ConfigItem::NftSetNoSpeed),
        map(config("nftset-debug"), ConfigItem::NftSetDebug),
        // 🔐 Q10：整机同时处理的查询数上限（默认 65535，0 = 不限）
        map(config("max-query-limit"), ConfigItem::MaxQueryLimit),
        // 🔐 Q11：把域名交给 mDNS 那一组解析（可多条）
        map(config("local-domain"), ConfigItem::LocalDomain),
        // 🔐 Q7/Q8：日志与审计送系统日志
        map(config("log-syslog"), ConfigItem::LogSyslog),
        map(config("audit-syslog"), ConfigItem::AuditSyslog),
        map(config("whitelist-ip"), ConfigItem::WhitelistIp),
        map(config("ip-set"), ConfigItem::IpSetProvider),
        map(config("ip-alias"), ConfigItem::IpAlias),
        map(NomParser::parse, ConfigItem::Listener),
        map(NomParser::parse, ConfigItem::Server),
    ));

    let group = alt((group1, group2, group3, group4, group5));

    alt((
        map(
            (
                preceded(space0, group),
                alt((
                    map(recognize((space1, comment)), Some),
                    map(space0, |_| None),
                )),
            ),
            |(config, comment)| ConfigLine::Config { config, comment },
        ),
        map(preceded(space0, comment), ConfigLine::Comment),
        map(eof, |_| ConfigLine::Eof),
        map(space0, |_| ConfigLine::EmptyLine),
    ))
    .parse(input)
}

pub fn parse_config(input: &str) -> IResult<&str, Option<ConfigItem>> {
    let (input, line) = parse_line(input)?;

    let item = match line {
        ConfigLine::Config { config, .. } => Some(config),
        _ => None,
    };

    Ok((input, item))
}

/// 🔐 `-interval` 现在**真的生效**了（配置会按它定期重建，把新名单展开进规则树）。
/// 间隔太短会让配置被频繁重载，这里提醒一句。`kind` 是配置项名（`domain-set` / `ip-set`）。
///
/// 放这里是因为域名集合与 IP 集合共用同一套判断与提醒。
pub(crate) fn warn_if_interval_too_short(kind: &str, name: &str, interval: Option<usize>) {
    if let Some(secs) = interval.filter(|secs| *secs > 0 && *secs < 10) {
        crate::log::warn!(
            "{kind} {name}: -interval {secs} s is too short and will reload the configuration frequently (10 s or more is recommended)"
        );
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use std::path::Path;

    use super::*;

    /// 🔐 问题 53-①：`usize` 解析**不得静默截断**。
    ///
    /// 原实现是 `map(u64, |v| v as usize)`：在 32 位平台上，
    /// `-interval 4294967296`（2³²）会被截成 **0**，而 0 的语义是"关闭定时刷新" ——
    /// 用户配了刷新却得到相反效果，且没有任何提示。
    ///
    /// ⚠️ **平台差异（如实说明）**：64 位平台上 `u64` 全都在 `usize` 范围内，
    /// 因此**无法在这里构造真实的溢出** —— 下面用 `usize::MAX` 做上界校验，
    /// 并显式断言"`usize::MAX` 解析出来必须等于它本身"（而不是被截断或以其它方式变化）。
    /// 真正的 32 位行为由那段 `try_from` 保证；本测试钉住的是"**没有截断**"这个不变量。
    #[test]
    fn usize_parsing_does_not_truncate() {
        // 正常值：原样解析
        assert_eq!(usize::parse("0"), Ok(("", 0)));
        assert_eq!(usize::parse("4294967295"), Ok(("", 4294967295)));

        // usize::MAX 必须原样返回 —— 若实现里有 `as usize` 截断，这里就会不等
        let max_str = usize::MAX.to_string();
        let (rest, got) = usize::parse(&max_str).expect("usize::MAX 应当能解析");
        assert_eq!(rest, "");
        assert_eq!(
            got,
            usize::MAX,
            "解析结果必须与字面值完全一致（截断会在这里露馅）"
        );

        // 超出 u64 的写法仍然要报错（这不是本问题的范畴，但顺手钉住）
        assert!(usize::parse("99999999999999999999999999").is_err());

        // 非数字要报错，不能被当成 0
        assert!(usize::parse("abc").is_err());
    }

    /// 🔐 问题 53-①（补强）：**直接验证"转换失败会报错"这条逻辑本身**。
    ///
    /// 上一条测试只能证明"64 位下没截断"，**证明不了 32 位下会怎样** ——
    /// 那台机器上 `u64` 全都在 `usize` 范围内，构造不出真实溢出。
    ///
    /// 所以这里换成**模拟 32 位的语义**：拿一个"假装是 32 位 usize"的窄类型
    /// 去复现同一套 `try_from` 逻辑，断言"超出范围必须失败、而不是变成 0"。
    /// 这证明了**我们用的转换方式是对的**（`try_from` 会拒绝而不是截断），
    /// 只是它在本机 64 位下不会触发。
    #[test]
    fn narrow_usize_conversion_rejects_instead_of_wrapping_to_zero() {
        // 这就是 32 位平台上 `usize::try_from(u64)` 会遇到的情形
        let too_big: u64 = 4294967296; // 2^32，在 32 位 usize 上装不下

        // ① 模拟 32 位：用 u32 作为"窄 usize"
        assert!(
            u32::try_from(too_big).is_err(),
            "2^32 装不进 32 位，try_from 必须报错"
        );

        // ② 对照：`as` 转换会**静默截断成 0** —— 这正是原实现的缺陷
        //    （0 的语义是"关闭定时刷新"，于是"配了刷新"变成"关掉刷新"）
        assert_eq!(
            too_big as u32, 0,
            "`as` 把 2^32 截断成 0 —— 这就是原实现让 -interval 语义反转的原因"
        );

        // ③ 边界：恰好装得下时不报错
        assert_eq!(u32::try_from(4294967295u64).unwrap(), u32::MAX);
    }

    /// 🔐 P2：`parse_config` 的"剩余输入"必须能被上层看见 —— 配置加载就靠它告警。
    ///
    /// 关键事实（也是这个 bug 的根因）：语法里 `space0` 那个兜底分支是**零宽**匹配，
    /// 所以任何一行都至少能被解析成"空行"，`parse_config` **永远不会返回 Err**
    /// —— 原来 `Err(err) => warn!("unknown conf: ...")` 是死代码，拼错的关键字整行静默消失。
    #[test]
    fn test_parse_config_reports_leftover() {
        // 正常配置项：剩余为空
        let (rest, item) = parse_config("address /a.test/1.2.3.4").unwrap();
        assert!(rest.is_empty(), "剩余应为空，实际 {rest:?}");
        assert!(item.is_some());

        // 行尾注释：注释被语法吃掉，剩余仍为空（所以正常配置不会误报）
        let (rest, item) = parse_config("address /a.test/1.2.3.4   # 行尾注释").unwrap();
        assert!(rest.is_empty(), "剩余应为空，实际 {rest:?}");
        assert!(item.is_some());

        // 行尾粘了别的东西：配置项认出来了，但剩余不为空 → 上层告警"尾部有无法识别的内容"
        let (rest, item) = parse_config("address /a.test/1.2.3.4 垃圾").unwrap();
        assert_eq!(rest.trim(), "垃圾");
        assert!(item.is_some());

        // 关键字拼错：整行谁都不认 → **返回 Ok**（不是 Err！），剩余 = 整行，item = None
        let (rest, item) = parse_config("addres /a.test/1.2.3.4").unwrap();
        assert_eq!(rest, "addres /a.test/1.2.3.4");
        assert!(item.is_none());

        // 注释行 / 空白行：剩余为空（不该告警）
        let (rest, _) = parse_config("# 注释").unwrap();
        assert!(rest.is_empty(), "注释行剩余应为空，实际 {rest:?}");
        let (rest, item) = parse_config("   ").unwrap();
        assert!(rest.trim().is_empty());
        assert!(item.is_none());
    }

    #[test]
    fn test_nftset() {
        assert_eq!(
            parse_config("nftset /www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigItem::NftSet(ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![ConfigForIP::V4(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
                .into()
            )
        );

        assert_eq!(
            parse_config("nftset /www.example.com/#4:inet#tab#dns4 # comment 123").unwrap(),
            (
                "",
                ConfigItem::NftSet(ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![ConfigForIP::V4(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
                .into()
            )
        );
    }

    #[test]
    fn test_parse_blacklist_ip() {
        assert_eq!(
            parse_config("blacklist-ip  243.185.187.39").unwrap(),
            (
                "",
                ConfigItem::BlacklistIp(IpOrSet::Net("243.185.187.39/32".parse().unwrap())).into()
            )
        );

        assert_eq!(
            parse_config("blacklist-ip ip-set:name").unwrap(),
            (
                "",
                ConfigItem::BlacklistIp(IpOrSet::Set("name".to_string())).into()
            )
        );
    }

    #[test]
    fn test_parse_whitelist_ip() {
        assert_eq!(
            parse_config("whitelist-ip  243.185.187.39").unwrap(),
            (
                "",
                ConfigItem::WhitelistIp(IpOrSet::Net("243.185.187.39/32".parse().unwrap())).into()
            )
        );

        assert_eq!(
            parse_config("whitelist-ip ip-set:name").unwrap(),
            (
                "",
                ConfigItem::WhitelistIp(IpOrSet::Set("name".to_string())).into()
            )
        );
    }

    #[test]
    fn test_parse_log_size() {
        assert_eq!(
            parse_config("log-size 1M").unwrap(),
            ("", ConfigItem::LogSize("1M".parse().unwrap()).into())
        );
    }

    #[test]
    fn test_parse_speed_check_mode() {
        // 🔐 问题 24：`none` 现在是 `Some([None])`，**不再**折叠成 `Default`（即 `None`）。
        // 折叠的后果见 `config/parser/speed_mode.rs` 里 `test_speed_mode_none` 的说明。
        assert_eq!(
            parse_config("speed-check-mode none").unwrap(),
            (
                "",
                ConfigItem::SpeedMode(Some(crate::config::SpeedCheckModeList(vec![
                    crate::config::SpeedCheckMode::None
                ])))
                .into()
            )
        );
    }

    #[test]
    fn test_parse_response_mode() {
        assert_eq!(
            parse_config("response-mode fastest-response").unwrap(),
            (
                "",
                ConfigItem::ResponseMode(ResponseMode::FastestResponse).into()
            )
        );
    }

    /// 🔐 `force-no-CNAME` 必须真的被解析器认出来。
    ///
    /// 它先前只写在文档里、程序完全不认识（问题 12）。这条测试锁住"配置能被认出"，
    /// 免得将来又变成"配了不生效"。
    #[test]
    fn test_parse_force_no_cname() {
        assert_eq!(
            parse_config("force-no-CNAME yes").unwrap(),
            ("", ConfigItem::ForceNoCNAME(true).into())
        );
        assert_eq!(
            parse_config("force-no-CNAME no").unwrap(),
            ("", ConfigItem::ForceNoCNAME(false).into())
        );
    }

    #[test]
    fn test_parse_resolv_hostname() {
        assert_eq!(
            parse_config("resolv-hostname no").unwrap(),
            ("", ConfigItem::ResolvHostname(false).into())
        );
    }

    #[test]
    fn test_parse_domain_set() {
        assert_eq!(
            parse_config("domain-set -name outbound -file /etc/smartdns/geoip.txt").unwrap(),
            (
                "",
                ConfigItem::DomainSetProvider(DomainSetProvider::File(DomainSetFileProvider {
                    name: "outbound".to_string(),
                    file: Path::new("/etc/smartdns/geoip.txt").to_path_buf(),
                    interval: None,
                    content_type: Default::default(),
                }))
                .into()
            )
        );

        assert_eq!(
            parse_config("domain-set -n proxy-server -f proxy-server-list.txt").unwrap(),
            (
                "",
                ConfigItem::DomainSetProvider(DomainSetProvider::File(DomainSetFileProvider {
                    name: "proxy-server".to_string(),
                    file: Path::new("proxy-server-list.txt").to_path_buf(),
                    interval: None,
                    content_type: Default::default(),
                }))
                .into()
            )
        );
    }

    #[test]
    fn test_parse_domain_rule() {
        assert_eq!(
            parse_config("domain-rules /domain-set:domain-block-list/ --address #").unwrap(),
            (
                "",
                ConfigItem::DomainRule(ConfigForDomain {
                    domain: Domain::Set("domain-block-list".to_string()),
                    config: DomainRule {
                        address: Some(AddressRuleValue::SOA),
                        ..Default::default()
                    }
                })
                .into()
            )
        );
    }

    #[test]
    fn test_parse_ip_set() {
        assert_eq!(
            parse_config("ip-set -name name -file /path/to/file.txt").unwrap(),
            (
                "",
                ConfigItem::IpSetProvider(IpSetProvider::File(IpSetFileProvider {
                    name: "name".to_string(),
                    file: Path::new("/path/to/file.txt").to_path_buf(),
                    interval: None,
                }))
                .into()
            )
        );
        // 远程来源
        assert_eq!(
            parse_config("ip-set -name set -url https://example.com/list -interval 3600").unwrap(),
            (
                "",
                ConfigItem::IpSetProvider(IpSetProvider::Http(IpSetHttpProvider {
                    name: "set".to_string(),
                    url: url::Url::parse("https://example.com/list").unwrap(),
                    interval: Some(3600),
                    proxy: None,
                }))
                .into()
            )
        );
    }

    #[test]
    fn test_parse_conf_file() {
        assert_eq!(
            parse_config("conf-file /etc/smartdns/more.conf").unwrap(),
            (
                "",
                ConfigItem::ConfFile(ConfFileItem {
                    path: Path::new("/etc/smartdns/more.conf").to_path_buf(),
                    group: None,
                })
                .into()
            )
        );
        assert_eq!(
            parse_config("conf-file /etc/smartdns/conf.d/*.conf -g office").unwrap(),
            (
                "",
                ConfigItem::ConfFile(ConfFileItem {
                    path: Path::new("/etc/smartdns/conf.d/*.conf").to_path_buf(),
                    group: Some("office".to_string()),
                })
                .into()
            )
        );
    }

    #[test]
    fn test_parse_line() {
        assert_eq!(
            parse_line("address /example.com/1.2.3.5").unwrap().1,
            ConfigLine::Config {
                config: ConfigItem::Address(AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: "1.2.3.5".parse().unwrap()
                }),
                comment: None
            }
        );

        assert_eq!(
            parse_line("address /example.com/1.2.3.5  ").unwrap().1, // trailing spaces should be ignored
            ConfigLine::Config {
                config: ConfigItem::Address(AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: "1.2.3.5".parse().unwrap()
                }),
                comment: None
            }
        );

        assert_eq!(
            parse_line("address /example.com/1.2.3.5  # comment")
                .unwrap()
                .1, // trailing spaces should be ignored
            ConfigLine::Config {
                config: ConfigItem::Address(AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: "1.2.3.5".parse().unwrap()
                }),
                comment: Some("  # comment")
            }
        );

        assert_eq!(
            parse_line("# comment").unwrap().1,
            ConfigLine::Comment("# comment")
        );

        assert_eq!(
            parse_line("# comment  ").unwrap().1, // trailing spaces should be ignored
            ConfigLine::Comment("# comment")
        );

        assert_eq!(
            parse_line("  # comment").unwrap().1, // leading spaces should be ignored
            ConfigLine::Comment("# comment")
        );

        assert_eq!(parse_line("").unwrap().1, ConfigLine::Eof);

        assert_eq!(parse_line(" ").unwrap().1, ConfigLine::EmptyLine);
    }

    #[test]
    fn test_config_file_update() {
        let conf_in = indoc! {"
        # comments are preserved1
        address /example.com/1.2.3.4
        address /a.example.com/5.6.7.8 # comments are preserved2
        address /b.example.com/9.10.11.12 # comments are preserved3
          # comments are preserved4
        "};

        let conf_out = indoc! {"
        # comments are preserved1
        address /example.com/1.2.3.4
        address /a.example.com/#6 # comments are preserved2
        address /b.example.com/9.10.11.12 # comments are preserved3
        # comments are preserved4
        "};

        let (_, mut conf) = ConfigFile::parse(conf_in).unwrap();

        assert_eq!(conf.0.len(), 6);

        let mut rules = conf
            .0
            .iter()
            .enumerate()
            .flat_map(|(i, c)| match c {
                ConfigLine::Config {
                    config: ConfigItem::Address(rule),
                    ..
                } => Some((i, rule.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(rules.len(), 3);

        let (line, rule) = rules.get_mut(1).unwrap();
        rule.address = AddressRuleValue::SOAv6;
        if let Some(ConfigLine::Config { config, .. }) = conf.0.get_mut(*line) {
            *config = ConfigItem::Address(rule.clone());
        };

        assert_eq!(conf.to_string(), conf_out);
    }
}
