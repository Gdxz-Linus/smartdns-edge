//! DNS64：把 A 记录**合成**成 AAAA，让只有 IPv6 的客户端也能访问 IPv4-only 的站点。
//!
//! ## 📌 丙-2a（2026-09-26）：中间件改为**无条件挂载**，前缀**逐查询**取
//!
//! 原先这个中间件是"配了才挂"（`app.rs` 里 `if let Some(prefix) = cfg.dns64_prefix`），
//! 前缀在构造时存进实例。支持组级后那样就不成立了：
//! **全局没配、某个组配了**的时候，中间件压根没挂，那个组配了也不生效。
//!
//! 所以现在**无条件挂上**，改由 [`DnsContext::dns64_prefix`] 逐查询判断
//! "这次要不要做 DNS64、用哪个前缀"。代价是每个查询多过一层极轻的判断
//! （多半直接 `None` 就放行）。
//!
//! ## 为什么它不涉及缓存串答案
//!
//! 本中间件在中间件链里位于**缓存的外层**（见 `app.rs` 的注册顺序）：
//! 它先 `next.run()` 拿到（可能是缓存来的）上游答案，再决定要不要合成 AAAA。
//! **合成结果不写入缓存**，所以组与组之间不会互相污染缓存内容。
//! （组级参数会进缓存键这件事由 `dns_mw_cache.rs` 的 `AnswerAffectingOpts` 负责，
//! 与本文件无关。）

use crate::dns::*;
use crate::middleware::*;
use ipnet::Ipv6Net;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

/// DNS64 合成中间件。
///
/// **无状态**：前缀不再存在实例里（那会把它钉死在构造那一刻），
/// 每次查询从 [`DnsContext::dns64_prefix`] 取当前生效值。
pub struct Dns64Middleware;

impl Dns64Middleware {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Dns64Middleware {
    fn default() -> Self {
        Self::new()
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
        // 📌 丙-2a：先取本次查询生效的前缀。
        // 没配（全局与本组都没写）⇒ 完全不做 DNS64，直接放行 ——
        // 这与"中间件没挂"的旧行为**逐字节一致**，不是新增分支。
        let Some(ipv6_net) = ctx.dns64_prefix() else {
            return next.run(ctx, req).await;
        };

        let query = req.query().original();
        let query_type = query.query_type();
        match query_type {
            RecordType::AAAA => {
                let res = next.clone().run(ctx, req).await;

                // 🌟 修复：无论上游是返回 NXDOMAIN(Err) 还是返回了纯 IPv4 的空包(Ok但没AAAA记录)，都必须启动 DNS64 合成！
                let fallback_needed = match &res {
                    Err(_) => true,
                    Ok(lookup) => !lookup
                        .records()
                        .iter()
                        .any(|r| r.record_type() == RecordType::AAAA),
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
                    let Some(ipv6) = to_dns64(ipv6_net, ipv4) else {
                        continue;
                    };
                    // 🌟 核心修复：不能只改数据，我们直接用原域名和寿命生成一条全新的 AAAA 记录，整体覆盖旧的 A 记录，从根本上保证包头类型与数据绝对匹配！
                    *record = Record::from_rdata(
                        record.name().clone(),
                        record.ttl(),
                        RData::AAAA(ipv6.into()),
                    );
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
