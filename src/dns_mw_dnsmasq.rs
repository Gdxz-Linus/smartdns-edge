use crate::dns::*;
use crate::dnsmasq::LanClientStore;
use crate::middleware::*;
use std::borrow::Borrow;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct DnsmasqMiddleware {
    client_store: LanClientStore,
}

impl DnsmasqMiddleware {
    pub fn new<P: AsRef<Path>>(lease_file: P, domain: Option<Name>) -> Self {
        Self {
            client_store: LanClientStore::new(lease_file, domain),
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsmasqMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        // 🌟 接收后厨传来的数组（可能是[IP]，也可能是强行拦截的空包[]）
        if let Some(rdatas) = self
            .client_store
            .lookup(req.query().name().borrow(), req.query().query_type())
            .await
        {
            let local_ttl = ctx.cfg().local_ttl();

            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + Duration::from_secs(local_ttl);

            // 🌟 将后厨给的数据，批量转换成标准 DNS 记录。
            // 如果 rdatas 是空的，这里自然就生成空的 records，完美变身合法空包退给手机！
            let records: Vec<Record> = rdatas
                .into_iter()
                .map(|rdata| Record::from_rdata(name.clone(), local_ttl as u32, rdata))
                .collect();

            let mut lookup = DnsResponse::new_with_deadline(
                query,
                records,
                valid_until,
            );

            // 🌟 终极修复：如果是空包（如查 AAAA 但设备只有 IPv4），
            // 必须在权威区盖上 SOA 戳！否则苹果/Windows 设备会拒绝缓存并疯狂发起重试风暴！
            if lookup.answers().is_empty() {
                use crate::dns::DefaultSOA;
                let soa = crate::dns::Record::from_rdata(
                    crate::dns::Name::root(),
                    local_ttl as u32,
                    crate::dns::RData::default_soa()
                );
                lookup.add_authority(soa);
            }

            ctx.source = LookupFrom::Static;
            return Ok(lookup);
        }

        next.run(ctx, req).await
    }
}
