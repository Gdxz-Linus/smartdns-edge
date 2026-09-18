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
mod group_match;
mod https_record;
mod ip_alias;
mod ip_rules;
mod group_begin;
mod ip_net;
mod ip_set;
mod ipset;
mod iporset;
// mod line;
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
        map(u64, |v| v as usize).parse(input)
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
        map(config("client-rules"), ConfigItem::ClientRule),
        map(config("client-rule"), ConfigItem::ClientRule),
        map(config("conf-file"), ConfigItem::ConfFile),
    ));

    let group2 = alt((
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
        map(config("first-packet-timeout"), ConfigItem::FirstPacketTimeout),
        map(config("max-connections"), ConfigItem::MaxConnections),
        map(config("max-connections-per-ip"), ConfigItem::MaxConnectionsPerIp),
        map(config("nftset"), ConfigItem::NftSet),
        map(config("user"), ConfigItem::User),
        // `acl-enable`：访问控制总开关（放在 group4 —— 它离 21 项上限还有余量）
        map(config("acl-enable"), ConfigItem::AclEnable),
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
            "{kind} {name}: -interval {secs} 秒太短，会频繁重载配置（建议 ≥ 10 秒）"
        );
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use std::path::Path;

    use super::*;

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
        assert_eq!(
            parse_config("speed-check-mode none").unwrap(),
            ("", ConfigItem::SpeedMode(Default::default()).into())
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
