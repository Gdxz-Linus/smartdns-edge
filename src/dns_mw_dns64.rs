use crate::dns::*;
use crate::middleware::*;
use ipnet::Ipv6Net;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

pub struct Dns64Middleware {
    ipv6_net: Ipv6Net,
}

impl Dns64Middleware {
    pub fn new(ipv6_net: Ipv6Net) -> Self {
        Self { ipv6_net }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for Dns64Middleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query().original();
        let query_type = query.query_type();
        match query_type {
            RecordType::AAAA => {
                let res = next.clone().run(ctx, req).await;

                // 🌟 修复：无论上游是返回 NXDOMAIN(Err) 还是返回了纯 IPv4 的空包(Ok但没AAAA记录)，都必须启动 DNS64 合成！
                let fallback_needed = match &res {
                    Err(_) => true,
                    Ok(lookup) => !lookup.records().iter().any(|r| r.record_type() == RecordType::AAAA),
                };

                if !fallback_needed {
                    return res;
                }

                let mut msg: op::Message = req.deref().clone();
                let Some(q) = msg.queries_mut().first_mut() else {
                    return res; // 无 query，直接退还原响应
                };
                q.set_query_type(RecordType::A);

                let req = DnsRequest::new(msg, req.src(), req.protocol());

                let Ok(mut lookup) = next.run(ctx, &req).await else {
                    return res;
                };

                for record in lookup.answers_mut() {
                    let Some(IpAddr::V4(ipv4)) = record.data().ip_addr() else {
                        continue;
                    };
                    let Some(ipv6) = to_dns64(self.ipv6_net, ipv4) else {
                        continue;
                    };
                    // 🌟 核心修复：不能只改数据，我们直接用原域名和寿命生成一条全新的 AAAA 记录，整体覆盖旧的 A 记录，从根本上保证包头类型与数据绝对匹配！
                    *record = Record::from_rdata(record.name().clone(), record.ttl(), RData::AAAA(ipv6.into()));
                }
                if let Some(q) = lookup.queries_mut().first_mut() {
                    q.set_query_type(query_type);
                }
                Ok(lookup)
            }
            _ => next.run(ctx, req).await,
        }
    }
}

fn to_dns64(ipv6_net: Ipv6Net, ipv4: Ipv4Addr) -> Option<Ipv6Addr> {
    let v4_bits = std::mem::size_of::<Ipv4Addr>() as u8 * 8;
    let v6_bits = std::mem::size_of::<Ipv6Addr>() as u8 * 8;

    let prefix = ipv6_net.prefix_len();
    let suffix = v6_bits - prefix;

    let mut v6 = u128::from_be_bytes(ipv6_net.addr().octets());
    let mut v4 = u32::from_be_bytes(ipv4.octets()) as u128;

    v6 = v6 >> suffix << suffix;
    v4 <<= suffix - v4_bits;

    let octets = (v4 + v6).to_be_bytes();

    Some(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_dns64_1() {
        let ipv6_net = Ipv6Net::from_str("64:ff9b::/96").unwrap();
        let ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let ipv6 = to_dns64(ipv6_net, ipv4);
        assert_eq!(ipv6, Ipv6Addr::from_str("64:ff9b::c0a8:1").ok());
    }

    #[test]
    fn test_dns64_2() {
        let ipv6_net = Ipv6Net::from_str("3000::/64").unwrap();
        let ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let ipv6 = to_dns64(ipv6_net, ipv4);
        assert_eq!(ipv6, Ipv6Addr::from_str("3000::c0a8:1:0:0").ok());
    }
}
