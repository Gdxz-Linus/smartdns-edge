use std::ops::Deref;

use crate::dns::*;

use crate::middleware::*;

pub struct DnsBogusMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsBogusMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let res = next.run(ctx, req).await;

        let bogus_nxdomain = ctx.cfg().bogus_nxdomain();

        if req.query().query_type().is_ip_addr() {
            // 🌟 核心修复 1：在 Ok 的状态下进行拦截，不再抛出 Err
            if let Ok(mut lookup) = res {
                let is_bogus = lookup.records().iter().any(|record| match record.data() {
                    RData::A(ip) if bogus_nxdomain.contains(ip.deref()) => true,
                    RData::AAAA(ip) if bogus_nxdomain.contains(ip.deref()) => true,
                    _ => false,
                });

                if is_bogus {
                    // 🌟 核心修复 2：剥离被污染的脏 IP
                    lookup.take_answers();
                    // 强制修改状态码为域名不存在
                    use crate::libdns::proto::op::ResponseCode;
                    lookup.set_response_code(ResponseCode::NXDomain);
                    
                    // 🌟 核心修复 3：补发 SOA 记录，激活系统的“否定缓存 (Negative Caching)”机制，阻断查询风暴！
                    if lookup.authorities().is_empty() {
                        // 1. 提取用户真实查询的域名
                        let domain_name = req.query().original().name().clone();
                        // 2. 统一调用 dns.rs 中的“萝卜章制造机”，生成有效期为 3600 秒的标准 SOA 记录
                        let soa = crate::dns::forge_soa_record(domain_name, 3600);
                        lookup.add_authority(soa);
                    }
                    return Ok(lookup);
                }
                return Ok(lookup);
            }
        }
        res
    }
}
