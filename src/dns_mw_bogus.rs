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
                        // 2. 🔐 P3-4：TTL 不再写死 3600 —— 与 dns_mw_addr / dualstack 的伪造 SOA
                        //    同一条取值链（组级 rr-ttl → rr-ttl-min → 300 兜底）。
                        //    写死 3600 的后果：用户调低 rr-ttl 后，bogus 否定缓存仍压制一小时；
                        //    名单移除后，客户端/缓存最长一小时内继续认定该域名不存在。
                        let rr_ttl = ctx.rr_ttl().map(|t| t as u32);
                        let rr_ttl_min = rr_ttl
                            .or_else(|| ctx.rr_ttl_min().map(|t| t as u32))
                            .unwrap_or(300);
                        let soa = crate::dns::forge_soa_record(domain_name, rr_ttl_min);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_conf::RuntimeConfig;
    use crate::dns_mw::*;
    use crate::libdns::proto::rr::{DNSClass, RecordType};

    /// 🔐 P3-4：bogus 命中后伪造 SOA 的 TTL 必须跟随 rr-ttl 链（组级 → 全局 → 兜底 300），
    /// 不能写死 3600 —— 否则用户调低 rr-ttl 后，否定缓存仍被压制一小时。

    async fn search_with_query(
        mw: &DnsMiddlewareHandler,
        name: &str,
        query_type: RecordType,
        query_class: DNSClass,
        src: std::net::SocketAddr,
    ) -> Result<DnsResponse, crate::dns::DnsError> {
        use crate::libdns::proto::op;
        let mut query = op::Query::query(name.parse().unwrap(), query_type);
        query.set_query_class(query_class);
        let mut message = op::Message::query();
        message.add_query(query);
        let req = DnsRequest::new(message, src, Protocol::Udp);
        mw.search(&req, &Default::default()).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_bogus_soa_ttl_follows_rr_ttl() {
        let cfg = RuntimeConfig::builder()
            .with("bogus-nxdomain 192.0.2.1")
            .with("rr-ttl 123")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(DnsBogusMiddleware)
            .with_a_record("bogus.test", "192.0.2.1".parse().unwrap())
            .build(cfg);
        let result = search_with_query(
            &mock,
            "bogus.test.",
            RecordType::A,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await;
        // bogus 命中后：Answer 剥离、回 NXDomain + SOA。下游 search 会把否定应答折叠成
        // NoRecordsFound 错误（SOA 挂在错误里），两种形态都接受，关键校验 SOA 的 TTL。
        let soa_ttl = match result {
            Ok(response) => {
                assert!(
                    response.answers().is_empty(),
                    "bogus 命中后 Answer 应被剥离"
                );
                response
                    .authorities()
                    .iter()
                    .find(|r| r.data().as_soa().is_some())
                    .map(|r| r.ttl())
            }
            Err(crate::dns::DnsError::Proto(e)) => match e.kind() {
                crate::libdns::proto::ProtoErrorKind::NoRecordsFound(no_records) => {
                    no_records.soa.as_ref().map(|s| s.ttl())
                }
                other => panic!("unexpected proto error kind: {other:?}"),
            },
            Err(e) => panic!("unexpected error: {e:?}"),
        };
        assert_eq!(
            soa_ttl,
            Some(123),
            "伪造 SOA 的 TTL 必须取 rr-ttl 生效值（修复前写死 3600）"
        );
    }
}
