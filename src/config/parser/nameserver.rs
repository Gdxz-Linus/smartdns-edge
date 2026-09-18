use std::str::FromStr;

use crate::dns_url::{DnsUrl, ProtocolConfig};
use crate::log;
use crate::third_ext::FromStrOrHex;

use super::*;

impl NomParser for NameServerInfo {
    fn parse(input: &str) -> IResult<&str, Self> {
        let dns_url = |default_proto| {
            map_res(take_till1(|c: char| c.is_whitespace()), move |url: &str| {
                let (a, b) = match (url.split_once("://"), url) {
                    (Some(parts), _) => parts,
                    (None, "system" | "dhcp") => return DnsUrl::from_str(url),
                    (None, _) => (default_proto, url),
                };
                let url: String = [a, "://", b].concat();
                DnsUrl::from_str(&url).or_else(|err| {
                    let url: String = [a, "://", "[", b, "]"].concat();
                    DnsUrl::from_str(&url).map_err(|_| err)
                })
            })
        };

        let (input, url) = alt((
            preceded(tag_no_case("server-udp"), preceded(space1, dns_url("udp"))),
            preceded(tag_no_case("server-tcp"), preceded(space1, dns_url("tcp"))),
            #[cfg(feature = "dns-over-tls")]
            preceded(tag_no_case("server-tls"), preceded(space1, dns_url("tls"))),
            #[cfg(feature = "dns-over-https")]
            preceded(
                tag_no_case("server-https"),
                preceded(space1, dns_url("https")),
            ),
            #[cfg(feature = "dns-over-h3")]
            preceded(tag_no_case("server-h3"), preceded(space1, dns_url("h3"))),
            #[cfg(feature = "dns-over-quic")]
            preceded(
                tag_no_case("server-quic"),
                preceded(space1, dns_url("quic")),
            ),
            preceded(tag_no_case("server"), preceded(space1, dns_url("udp"))),
        ))
        .parse(input)?;

        let (input, options) = opt(preceded(space1, options::parse)).parse(input)?;

        let mut nameserver: NameServerInfo = url.into();

        if let Some(options) = options {
            for (k, v) in options {
                match k.to_lowercase().as_str() {
                    "e" | "exclude-default-group" => nameserver.exclude_default_group = true,
                    "blacklist-ip" => nameserver.blacklist_ip = true,
                    // 后备服务器：平时不用，正常那批不灵了才上场
                    "fallback" => nameserver.fallback = true,
                    "whitelist-ip" => nameserver.whitelist_ip = true,
                    "check-edns" => nameserver.check_edns = true,
                    "b" | "bootstrap-dns" => nameserver.bootstrap_dns = true,
                    "set-mark" => match v {
                        Some(m) => {
                            match u32::from_str_or_hex(m) {
                                Ok(mark) => nameserver.so_mark = Some(mark),
                                Err(_) => log::error!("Invalid set-mark value: '{}', ignored!", m), // 🌟 拒绝静默吞错
                            }
                        }
                        None => { log::warn!("expect mark") }
                    },
                    "g" | "group" => match v {
                        Some(g) => nameserver.group.push(g.to_string()),
                        None => {
                            log::warn!("expect group name")
                        }
                    },
                    "p" | "proxy" => {
                        nameserver.proxy = v.map(|p| p.to_string());
                    }
                    "interface" => {
                        nameserver.interface = v.map(|p| p.to_string());
                    }
                    "subnet" => match v {
                        Some(s) => {
                            match IpNet::parse(s) {
                                Ok(net) => nameserver.subnet = Some(net.1),
                                Err(_) => log::error!("Invalid subnet value: '{}', ignored!", s), // 🌟 拒绝静默吞错
                            }
                        }
                        None => { log::warn!("expect edns client subnet") }
                    },
                    "host-name" => match v {
                        Some(host_name) => {
                            if host_name == "-" {
                                nameserver.server.set_sni_off(true);
                            } else {
                                nameserver.server.set_host(host_name);
                            }
                        }
                        None => {
                            log::warn!("expect host-name")
                        }
                    },
                    "k" | "no-check-certificate" => {
                        nameserver.server.set_ssl_verify(false);
                    }
                    "tls-host-verify" => match v {
                        Some(tls_host_verify) => match nameserver.server.host() {
                            url::Host::Ipv4(ipv4_addr) => {
                                nameserver.server.set_ip(IpAddr::V4(*ipv4_addr));
                                nameserver.server.set_host(tls_host_verify);
                            }
                            url::Host::Ipv6(ipv6_addr) => {
                                nameserver.server.set_ip(IpAddr::V6(*ipv6_addr));
                                nameserver.server.set_host(tls_host_verify);
                            }
                            url::Host::Domain(_) => {
                                log::warn!("tls-host-verify expects an ip address host");
                            }
                        },
                        None => {
                            log::warn!("expect tls-host-verify")
                        }
                    },
                    // 🔐 第三部分第 2 条（`-spki-pin`）：证书公钥（SPKI）DER 的 SHA-256，base64 编码
                    "spki-pin" => match v {
                        Some(pin) => match crate::dns_url::decode_spki_pin(pin) {
                            Ok(_) => nameserver.server.set_spki_pin(pin),
                            Err(err) => log::error!(
                                "Invalid spki-pin value: '{}', ignored! ({})",
                                pin,
                                err
                            ), // 🌟 拒绝静默吞错
                        },
                        None => {
                            log::warn!("expect spki-pin")
                        }
                    },
                    // 🔐 Q15 `-http-host <主机名>`：DoH 请求头里的 Host（与 TLS 的 SNI 是两件事）。
                    // 只对 https / h3 有意义 —— 其它协议上写了要明确告警，不能"配了像没配"。
                    "http-host" => match v {
                        Some(host) => match nameserver.server.proto() {
                            ProtocolConfig::Https { .. } | ProtocolConfig::H3 { .. } => {
                                nameserver.server.set_http_host(host)
                            }
                            _ => log::warn!(
                                "`-http-host` 只对 DoH 上游（https / h3）有效：这条是 {}，已忽略",
                                nameserver.server
                            ),
                        },
                        None => log::warn!("expect http-host"),
                    },
                    // 🔐 Q16 `-tcp-keepalive <值>`：带一个 EDNS 的 TCP keepalive 选项（RFC 7828）
                    // 值 = 100 毫秒为单位（见 `NameServerInfo::tcp_keepalive` 的说明）。
                    "tcp-keepalive" => match v {
                        Some(value) => match value.parse::<u16>() {
                            Ok(seconds_100ms) => nameserver.tcp_keepalive = Some(seconds_100ms),
                            Err(err) => log::error!(
                                "Invalid tcp-keepalive value: '{}', ignored! ({})",
                                value,
                                err
                            ),
                        },
                        None => log::warn!("expect tcp-keepalive"),
                    },
                    // 🔐 Q17 `-subnet-all-query-types`：不带值，是个开关
                    "subnet-all-query-types" => {
                        nameserver.subnet_all_query_types = true;
                    }
                    // 🔐 Q14 `-host-ip <ip>`：**连接**就用这个地址，域名照旧（TLS 校验、SNI 仍用域名）。
                    //
                    // 场景：上游地址写的是域名，但不想（或不能）本机去解析它 —— 比如域名解析要靠
                    // 一个还没起来的 bootstrap、或者要固定连某个特定节点。
                    // 与 C 版一致（`dc_server.c:306`：`server->server = host_ip`，域名留着做验证），
                    // 也和 `-tls-host-verify` 用同一个机制（两者只是"谁跟着谁"相反）。
                    "host-ip" => match v {
                        Some(ip) => match ip.parse::<IpAddr>() {
                            Ok(addr) => match nameserver.server.host() {
                                url::Host::Domain(_) => nameserver.server.set_ip(addr),
                                url::Host::Ipv4(_) | url::Host::Ipv6(_) => log::warn!(
                                    "`-host-ip` 只对「地址写的是域名」的上游有意义：这条上游本身就写的 IP，已忽略"
                                ),
                            },
                            Err(err) => log::error!(
                                "Invalid host-ip value: '{}', ignored! ({})",
                                ip,
                                err
                            ), // 🌟 与 spki-pin 一样：拒绝静默吞错
                        },
                        None => {
                            log::warn!("expect host-ip")
                        }
                    },
                    _ => {
                        log::warn!("unknown server options: {}, {:?}", k, v);
                    }
                }
            }
        }

        Ok((input, nameserver))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_server_default() -> NameServerInfo {
        DnsUrl::from_str("udp://127.0.0.1:53").unwrap().into()
    }

    /// 🔐 第三部分第 3 条（上游 `-fallback`）：写得对就记下来，不写就是普通上游
    #[test]
    fn test_fallback_flag() {
        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8 -fallback"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("udp://8.8.8.8").unwrap(),
                    fallback: true,
                    ..name_server_default()
                }
            ))
        );

        assert!(
            !NameServerInfo::parse("server 8.8.8.8")
                .unwrap()
                .1
                .fallback,
            "不写 -fallback 就是普通上游（默认 false）"
        );
    }

    /// 🔐 Q15 `-http-host`：DoH 请求头里的 Host（与 TLS 的 SNI 是两件事）
    #[test]
    fn test_parse_http_host() {
        let (_, server) = NameServerInfo::parse(
            "server-https https://doh.example.com/dns-query -http-host gw.example.com",
        )
        .unwrap();
        assert_eq!(server.server.http_host().as_deref(), Some("gw.example.com"));
        // SNI 名字不受影响（仍来自地址）
        assert_eq!(server.server.host().to_string(), "doh.example.com");

        // 非 DoH 上游上写了要忽略（不能"配了像没配"）
        let (_, server) = NameServerInfo::parse("server udp://1.1.1.1 -http-host gw.example.com").unwrap();
        assert_eq!(server.server.http_host(), None);

        // 没配就是 None（原行为：Host 与 SNI 一致）
        let (_, server) = NameServerInfo::parse("server-https https://doh.example.com/dns-query").unwrap();
        assert_eq!(server.server.http_host(), None);
    }

    /// 🔐 Q16/Q17：两个上游选项要能解析进 NameServerInfo
    #[test]
    fn test_parse_tcp_keepalive_and_subnet_all_query_types() {
        let (_, server) =
            NameServerInfo::parse("server udp://1.1.1.1 -tcp-keepalive 300").unwrap();
        assert_eq!(server.tcp_keepalive, Some(300));

        let (_, server) = NameServerInfo::parse("server udp://1.1.1.1 -tcp-keepalive 0").unwrap();
        assert_eq!(server.tcp_keepalive, Some(0), "0 是合法值（空选项 = 问上游）");

        // 写错的值 → 忽略，不改变默认
        let (_, server) =
            NameServerInfo::parse("server udp://1.1.1.1 -tcp-keepalive abc").unwrap();
        assert_eq!(server.tcp_keepalive, None);

        let (_, server) =
            NameServerInfo::parse("server udp://1.1.1.1 -subnet-all-query-types").unwrap();
        assert!(server.subnet_all_query_types);

        let (_, server) = NameServerInfo::parse("server udp://1.1.1.1").unwrap();
        assert!(!server.subnet_all_query_types, "默认关");
        assert_eq!(server.tcp_keepalive, None, "默认不带");
    }

    /// 🔐 Q14 `-host-ip`：地址写域名时，连接改用指定的 IP，域名照旧（TLS 校验/SNI 用域名）
    #[test]
    fn test_parse_server_host_ip() {
        let (_, server) = NameServerInfo::parse("server tls://dot.example.com -host-ip 1.2.3.4").unwrap();

        assert_eq!(server.server.ip(), Some("1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(server.server.has_ip(), "配了 host-ip 就算\"有地址\"，不该再要求 bootstrap 解析");
        assert_eq!(
            server.server.host().to_string(),
            "dot.example.com",
            "域名必须留着 —— TLS 校验和 SNI 都靠它"
        );
    }

    /// `-host-ip` 写错（不是 IP）→ 忽略并告警，不改变原行为
    #[test]
    fn test_parse_server_host_ip_invalid() {
        let (_, server) = NameServerInfo::parse("server tls://dot.example.com -host-ip 不是IP").unwrap();
        assert_eq!(server.server.ip(), None);
    }

    /// 上游本身就写的 IP 时，`-host-ip` 无意义 → 保持原地址（不覆盖）
    #[test]
    fn test_parse_server_host_ip_ignored_when_host_is_ip() {
        let (_, server) = NameServerInfo::parse("server tls://9.9.9.9 -host-ip 1.2.3.4").unwrap();
        assert_eq!(server.server.ip(), Some("9.9.9.9".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_simple() {
        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8:53 -interface Net"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("udp://8.8.8.8:53").unwrap(),
                    interface: Some("Net".to_string()),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("udp://8.8.8.8").unwrap(),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8 -subnet 192.168.1.1"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("udp://8.8.8.8").unwrap(),
                    subnet: Some("192.168.1.1/32".parse().unwrap()),
                    ..name_server_default()
                }
            ))
        );

        fn proto<'a>(input: &'a str, default_proto: &'static str) -> IResult<&'a str, &'a str> {
            map(
                opt(alt((
                    tag_no_case("tcp://"),
                    tag_no_case("tls://"),
                    tag_no_case("https://"),
                    tag_no_case("quic://"),
                    tag_no_case("h3://"),
                ))),
                move |p| p.unwrap_or(default_proto),
            )
            .parse(input)
        }

        assert_eq!(
            NameServerInfo::parse("server-tls 8.8.8.8:853"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("tls://8.8.8.8:853").unwrap(),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server-tls 8.8.8.8:853"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("tls://8.8.8.8:853").unwrap(),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server-tls 2606:4700:4700::1111"),
            Ok((
                "",
                NameServerInfo {
                    name: None,
                    server: DnsUrl::from_str("tls://[2606:4700:4700::1111]").unwrap(),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server system"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("system").unwrap(),
                    ..name_server_default()
                }
            ))
        );
    }

    #[test]
    fn test_server_https() {
        assert_eq!(
            NameServerInfo::parse(
                "server-https https://223.5.5.5/dns-query -g bootstrap -exclude-default-group"
            ),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap(),
                    group: vec!["bootstrap".to_string()],
                    exclude_default_group: true,
                    ..name_server_default()
                }
            ))
        );
    }

    #[test]
    fn test_server_https_1() {
        assert_eq!(
            NameServerInfo::parse(
                "server https://dns.alidns.com/dns-query -group alidns -e # -proxy proxy"
            ),
            Ok((
                " # -proxy proxy",
                NameServerInfo {
                    server: DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap(),
                    group: vec!["alidns".to_string()],
                    exclude_default_group: true,
                    ..name_server_default()
                }
            ))
        );
    }

    #[test]
    fn test_server_dhcp() {
        assert_eq!(
            NameServerInfo::parse("server dhcp"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("dhcp").unwrap(),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server dhcp://eth0"),
            Ok((
                "",
                NameServerInfo {
                    server: DnsUrl::from_str("dhcp://eth0").unwrap(),
                    ..name_server_default()
                }
            ))
        );
    }
}
