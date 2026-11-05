use crate::dns::{DnsContext, DnsError, DnsRequest, DnsResponse};

#[async_trait::async_trait]
#[allow(clippy::double_must_use)] // async_trait 宏会为返回 Result 的方法重复加 #[must_use]
pub trait ZoneProvider: Send + Sync {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError>;
}
