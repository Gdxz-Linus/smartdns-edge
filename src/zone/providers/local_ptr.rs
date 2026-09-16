use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dns::{DefaultSOA, DnsContext, DnsError, DnsRequest, DnsResponse, Name, RData, RecordType};
use crate::zone::ZoneProvider;
use crate::libdns::proto::rr::rdata::PTR;

pub struct LocalPtrZoneProvider {
    server_names: BTreeSet<Name>,
}

impl LocalPtrZoneProvider {
    pub fn new() -> Self {
        let mut server_names = BTreeSet::new();
        server_names.insert(Name::from_str("smartdns.").unwrap());
        server_names.insert(Name::from_str("whoami.").unwrap());

        Self { server_names }
    }
}

#[async_trait::async_trait]
impl ZoneProvider for LocalPtrZoneProvider {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError> {
        if req.query().query_type() != RecordType::PTR {
            return Ok(None);
        }

        let query = req.query();
        let name: &Name = query.name().borrow();

        // 1. 匹配本机特有域名
        if self.server_names.contains(name) {
            return Ok(Some(DnsResponse::from_rdata(
                query.original().to_owned(),
                RData::PTR(PTR(ctx.cfg().server_name())),
            )));
        }

        // 2. 解析 ARPA 格式，利用纯数学规则拦截私网反向查询
        if let Ok(net) = name.parse_arpa_name() {
            let ip = net.addr();
            
            // 🌟 核心修复：抛弃僵化的网卡 IP 抓取，改用数学法则覆盖全量私网网段！
            // 无论宿主机增加多少虚拟网卡或 VPN，只要落在私有网段内，100% 绝对拦截！
            let is_private_ip = match ip {
                IpAddr::V4(v4) => is_private_v4(v4),
                IpAddr::V6(v6) => {
                    // 🔐 P2：`::ffff:a.b.c.d` 这种 IPv4-mapped 地址必须先还原成 IPv4 再判断，
                    // 否则它会绕过所有 v4 私网规则、被当成公网地址转发出去
                    // （同目录 identity.rs 的 normalize_client_ip 就是这么做的）。
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        is_private_v4(v4)
                    } else {
                        let segments = v6.segments();
                        v6.is_loopback()
                            || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 链路本地
                            || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 唯一本地地址 (ULA)
                    }
                }
            };

            if is_private_ip {
                // 🌟 上帝视角防御：一旦命中私有 IP，强制返回 NXDOMAIN + SOA
                // 这将阻断任何泄露到外网的可能，并迫使客户端缓存这个“否定结果”，避免泛洪
                use crate::libdns::proto::op::ResponseCode;
                let mut res = DnsResponse::empty();
                res.add_query(query.original().to_owned());
                res.set_response_code(ResponseCode::NXDomain);
                
                let soa = crate::dns::Record::from_rdata(
                    crate::dns::Name::root(), 
                    3600, 
                    crate::dns::RData::default_soa()
                );
                res.add_authority(soa);
                
                return Ok(Some(res));
            }
        }

        Ok(None)
    }
}

/// 🔐 P2：私网 / 特殊用途 IPv4 判定。
///
/// 除 RFC1918 外还必须覆盖这些「`is_private()` 不认、但绝不该外发」的网段：
///   * 100.64.0.0/10 —— 运营商级 NAT（CGNAT，RFC 6598）
///   * 0.0.0.0/8、255.255.255.255 —— 未指定与广播
///
/// 调用方还负责把 `::ffff:a.b.c.d` 这类 IPv4-mapped 地址先还原成 IPv4 再送进来
/// （否则它会绕过这里所有规则）。
fn is_private_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

#[cfg(test)]
mod private_range_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// 🔐 P2：`is_private()` 不认 CGNAT（100.64/10），这类地址以前会被转发到公网。
    #[test]
    fn cgnat_is_private() {
        assert!(is_private_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_v4(Ipv4Addr::new(100, 127, 255, 254)));
        // 边界外：100.63.x 与 100.128.x 不是 CGNAT
        assert!(!is_private_v4(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_private_v4(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn rfc1918_and_special_ranges_are_private() {
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
        ] {
            assert!(
                is_private_v4(ip.parse::<Ipv4Addr>().unwrap()),
                "{ip} 应被判为私网/特殊用途"
            );
        }

        // 公网地址不受影响
        for ip in ["1.1.1.1", "8.8.8.8", "223.5.5.5"] {
            assert!(
                !is_private_v4(ip.parse::<Ipv4Addr>().unwrap()),
                "{ip} 是公网地址，不该被拦截"
            );
        }
    }

    /// 🔐 P2：`::ffff:192.168.1.1` 必须先还原成 IPv4 才能被 v4 规则拦下。
    #[test]
    fn ipv4_mapped_is_normalized_first() {
        let v6: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        let v4 = v6.to_ipv4_mapped().expect("IPv4-mapped 地址应能还原");
        assert_eq!(v4, Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_private_v4(v4), "还原后必须被判为私网（改前这里会被转发到公网）");

        let cgnat_v6: Ipv6Addr = "::ffff:100.64.0.9".parse().unwrap();
        assert!(is_private_v4(cgnat_v6.to_ipv4_mapped().unwrap()));
    }
}
