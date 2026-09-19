use std::{borrow::Borrow, net::IpAddr, sync::Arc};

use crate::libdns::proto::{
    op::Query,
    rr::{IntoName, RecordType},
};

use crate::{
    config::ServerOpts,
    dns::{DnsContext, DnsError, DnsRequest, DnsResponse},
    dns_conf::RuntimeConfig,
    middleware::{Middleware, MiddlewareBuilder, MiddlewareDefaultHandler, MiddlewareHost},
};

pub type DnsMiddlewareHost = MiddlewareHost<DnsContext, DnsRequest, DnsResponse, DnsError>;

pub struct DnsMiddlewareHandler {
    cfg: Arc<RuntimeConfig>,
    host: DnsMiddlewareHost,
}

impl DnsMiddlewareHandler {
    /// 只读访问运行时配置。app 层组装客户端答复时要用到（例如给自造的否定 SOA 取 TTL）。
    #[inline]
    pub fn cfg(&self) -> &Arc<RuntimeConfig> {
        &self.cfg
    }

    pub async fn search(
        &self,
        req: &DnsRequest,
        server_opts: &ServerOpts,
    ) -> Result<DnsResponse, DnsError> {
        let cfg = self.cfg.clone();

        let mut server_opts = server_opts.clone();

        let client_rules = cfg.client_rules();
        // 🌟 修复：坚决剥夺 ECS 参与本地 ACL 控制的权利，只认真实的请求来源物理 IP
        let mut client_ip = req.src().ip();
        if let IpAddr::V6(addr) = client_ip
            && let Some(addr) = addr.to_ipv4_mapped()
        {
            client_ip = addr.into();
        }

        // 🔐 Q10 `max-query-limit`：整机**同时处理**的查询数上限。
        //
        // 语义对齐 C 版 `src/dns_server/dns_server.c:483`：超过上限直接回 REFUSED
        // （不查上游、不进缓存），日志每 120 秒最多告警一次；`0` = 不限。
        // 放在 ACL 判定**之前** —— C 版也是先过这道闸门再看客户端规则。
        //
        // 后台请求（预取、双栈探针、过期刷新）不占这个额度：它们不是"客户端在查"，
        // 让它们被自己的闸门拒掉只会让缓存永远刷不新。
        let _query_guard = match crate::server::limit::enter_query(
            cfg.max_query_limit(),
            server_opts.is_background,
        ) {
            crate::server::limit::QueryAdmission::Allowed(guard) => guard,
            crate::server::limit::QueryAdmission::Refused => {
                crate::log::debug!("the number of concurrent queries has reached its limit; replying REFUSED");
                return Err(crate::libdns::proto::op::ResponseCode::Refused.into());
            }
        };

        // 🔐 第三部分第 1 条（文档说了、代码没有）：`acl-enable` / `bind ... -acl`。
        //
        // 语义对齐 C 版 `src/dns_server/client_rule.c:22-32`：**开启后，没匹配到任何
        // `client-rules` 的客户端一律 REFUSED（且不缓存）**；匹配到的照常服务（仍按规则分组）。
        // 默认关闭时这里什么都不做 —— 默认行为零变化。
        //
        // 后台请求（预取、双栈探针、过期刷新）不是"某个客户端"，不参与 ACL 判定：
        // 否则一开 ACL，预取会被自己拒掉（来源是程序自己，永远匹配不到客户端规则）。
        let matched_rule = client_rules.iter().find(|s| s.match_ip(&client_ip));
        if !server_opts.is_background
            && (cfg.acl_enable() || server_opts.acl())
            && matched_rule.is_none()
        {
            crate::log::debug!(
                "ACL is enabled: client {client_ip} matched no client-rules; replying REFUSED"
            );
            return Err(crate::libdns::proto::op::ResponseCode::Refused.into());
        }

        // 🔐 P2（用户定策）：两条护栏，缺一不可 ——
        //   ① 调用方**已经指定**规则组就尊重它（预取会把"这条缓存属于哪组"带回来）；
        //      原来这里是无条件覆盖，等于把调用方的意图直接抹掉。
        //   ② 后台请求（预取、双栈探针、过期刷新）不是"某个人"，不参与按来源 IP 判组
        //      （它的来源是程序自己，匹配不到任何客户端规则，硬判只会把组抹成默认）。
        // 只有"调用方没指定 + 不是后台请求"时，才按来源 IP 从客户端规则里推断。
        if server_opts.rule_group.is_none() && !server_opts.is_background {
            server_opts.rule_group = matched_rule.map(|s| s.group.clone());
        }

        let mut ctx = DnsContext::new(req.query().name().borrow(), cfg, server_opts.clone());
        self.host.execute(&mut ctx, req).await
    }

    pub async fn lookup<N: IntoName>(
        &self,
        name: N,
        query_type: RecordType,
    ) -> Result<DnsResponse, DnsError> {
        let query = Query::query(name.into_name()?, query_type);
        self.search(&query.into(), &Default::default()).await
    }
}

pub struct DnsMiddlewareBuilder {
    builder: MiddlewareBuilder<DnsContext, DnsRequest, DnsResponse, DnsError>,
}

impl DnsMiddlewareBuilder {
    pub fn new() -> Self {
        Self {
            builder: MiddlewareBuilder::new(DnsDefaultHandler),
        }
    }

    pub fn with<M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static>(
        mut self,
        middleware: M,
    ) -> Self {
        self.builder = self.builder.with(middleware);
        self
    }

    pub fn build(self, cfg: Arc<RuntimeConfig>) -> DnsMiddlewareHandler {
        DnsMiddlewareHandler {
            host: self.builder.build(),
            cfg,
        }
    }
}

#[derive(Default)]
struct DnsDefaultHandler;

#[async_trait::async_trait]
impl MiddlewareDefaultHandler<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsDefaultHandler {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
    ) -> Result<DnsResponse, DnsError> {
        Err(DnsError::no_records_found(
            req.query().original().to_owned(),
            ctx.cfg().rr_ttl().unwrap_or_default() as u32,
        ))
    }
}

#[cfg(test)]
pub use tests::*;

#[cfg(test)]
mod tests {

    use crate::libdns::proto::rr::{RData, Record};
    use std::{
        collections::HashMap,
        fmt::Debug,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use super::*;
    use crate::infra::middleware::*;

    pub struct DnsMockMiddleware {
        map: HashMap<Query, Result<DnsResponse, DnsError>>,
    }

    impl DnsMockMiddleware {
        #[inline]
        pub fn builder() -> DnsMockMiddlewareBuilder {
            DnsMockMiddlewareBuilder::new()
        }

        pub fn mock<M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static>(
            middleware: M,
        ) -> DnsMockMiddlewareBuilder {
            Self::builder().with_extra_middleware(middleware)
        }
    }

    #[async_trait::async_trait]
    impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsMockMiddleware {
        async fn handle(
            &self,
            ctx: &mut DnsContext,
            req: &DnsRequest,
            next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
        ) -> Result<DnsResponse, DnsError> {
            match self.map.get(req.query().original()) {
                Some(res) => res.clone(),
                None => next.run(ctx, req).await,
            }
        }
    }

    pub struct DnsMockMiddlewareBuilder {
        map: HashMap<Query, Result<DnsResponse, DnsError>>,
        builder: DnsMiddlewareBuilder,
    }

    impl DnsMockMiddlewareBuilder {
        fn new() -> Self {
            Self {
                map: Default::default(),
                builder: DnsMiddlewareBuilder::new(),
            }
        }

        pub fn with_extra_middleware<
            M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static,
        >(
            mut self,
            middleware: M,
        ) -> Self {
            self.builder = self.builder.with(middleware);
            self
        }

        pub fn build<T: Into<Arc<RuntimeConfig>>>(self, cfg: T) -> DnsMiddlewareHandler {
            let Self { map, builder } = self;

            builder.with(DnsMockMiddleware { map }).build(cfg.into())
        }

        pub fn with_a_record<N: IntoName>(self, name: N, ip: Ipv4Addr) -> Self {
            self.with_rdata(name, RData::A(ip.into()), 10 * 60)
        }

        pub fn with_a_record_and_ttl<N: IntoName>(self, name: N, ip: Ipv4Addr, ttl: u32) -> Self {
            self.with_rdata(name, RData::A(ip.into()), ttl)
        }

        pub fn with_aaaa_record<N: IntoName>(self, name: N, ip: Ipv6Addr) -> Self {
            self.with_rdata(name, RData::AAAA(ip.into()), 10 * 60)
        }

        pub fn with_aaaa_record_and_ttl<N: IntoName>(
            self,
            name: N,
            ip: Ipv6Addr,
            ttl: u32,
        ) -> Self {
            self.with_rdata(name, RData::AAAA(ip.into()), ttl)
        }

        pub fn with_rdata<N: IntoName>(self, name: N, rdata: RData, ttl: u32) -> Self {
            let name = match name.into_name() {
                Ok(name) => name,
                Err(err) => panic!("invalid Name {err}"),
            };

            self.with_record(Record::from_rdata(name, ttl, rdata))
        }

        pub fn with_record(self, record: Record) -> Self {
            self.with_multi_records(record.name().clone(), record.record_type(), vec![record])
        }

        pub fn with_multi_records<Name: IntoName + Debug>(
            mut self,
            name: Name,
            record_type: RecordType,
            records: Vec<Record>,
        ) -> Self {
            let name = match name.into_name() {
                Ok(name) => name,
                Err(err) => panic!("invalid Name {err}"),
            };

            let query = Query::query(name, record_type);

            self.map.insert(
                query.clone(),
                Ok(DnsResponse::new_with_max_ttl(query, records)),
            );

            self
        }
    }

    impl DnsMiddlewareHandler {
        pub async fn lookup_rdata<N: IntoName>(
            &self,
            name: N,
            query_type: RecordType,
        ) -> Result<Vec<RData>, DnsError> {
            self.lookup(name, query_type)
                .await
                .map(|lookup| lookup.record_iter().map(|s| s.data()).cloned().collect())
        }
    }

    /// 造一条"带指定来源地址"的请求（用来测按来源 IP 的判定）
    fn req_from(name: &str, src: &str) -> DnsRequest {
        use crate::libdns::proto::op::Message;

        let mut msg = Message::query();
        msg.add_query(Query::query(
            crate::libdns::proto::rr::Name::from_ascii(name).unwrap(),
            RecordType::A,
        ));
        DnsRequest::new(msg, src.parse().unwrap(), crate::libdns::Protocol::Udp)
    }

    /// 🔐 第三部分第 1 条（`acl-enable` / `bind ... -acl`）：
    /// 默认关闭时一切照旧；开启后**只有没匹配到 client-rules 的客户端**被 REFUSED（不是 SERVFAIL）；
    /// 匹配到的照常服务；后台请求（预取/探针）不受影响；监听级 `-acl` 与全局开关是"或"的关系。
    #[tokio::test(flavor = "multi_thread")]
    async fn acl_enable_refuses_only_unmatched_clients() {
        use crate::config::ServerOpts;
        use crate::libdns::proto::op::ResponseCode;

        let name = "acltest.example.com";
        let matching_rule = "client-rules 127.0.0.0/8";
        let other_rule = "client-rules 192.168.0.0/16";

        // ① 默认（不开 ACL）+ 规则不匹配 → 照常解析（默认行为零变化）
        let cfg = RuntimeConfig::builder().with(other_rule).build().unwrap();
        let mw = DnsMockMiddleware::builder()
            .with_a_record(name, "10.1.1.1".parse().unwrap())
            .build(cfg);
        let res = mw
            .search(&req_from(name, "127.0.0.1:55001"), &ServerOpts::default())
            .await;
        assert!(
            res.is_ok(),
            "不开 ACL 时，匹配不上规则也必须照常解析：{res:?}"
        );

        // ② 全局打开 + 规则不匹配 → REFUSED（且是"明确状态码"，不是 SERVFAIL）
        let cfg = RuntimeConfig::builder()
            .with("acl-enable yes")
            .with(other_rule)
            .build()
            .unwrap();
        assert!(cfg.acl_enable(), "acl-enable yes 必须解析成 true");
        let mw = DnsMockMiddleware::builder()
            .with_a_record(name, "10.1.1.1".parse().unwrap())
            .build(cfg);
        let err = mw
            .search(&req_from(name, "127.0.0.1:55002"), &ServerOpts::default())
            .await
            .expect_err("开了 ACL、又不匹配规则，必须拒绝");
        assert_eq!(
            err.explicit_response_code(),
            Some(ResponseCode::Refused),
            "必须是 REFUSED（不许抹成 SERVFAIL）：{err:?}"
        );

        // ③ 全局打开 + 规则匹配 → 照常拿到答案（白名单里的客户端不受影响）
        let cfg = RuntimeConfig::builder()
            .with("acl-enable yes")
            .with(matching_rule)
            .build()
            .unwrap();
        let mw = DnsMockMiddleware::builder()
            .with_a_record(name, "10.1.1.1".parse().unwrap())
            .build(cfg);
        let res = mw
            .search(&req_from(name, "127.0.0.1:55003"), &ServerOpts::default())
            .await;
        assert!(res.is_ok(), "匹配到规则的客户端必须照常服务：{res:?}");

        // ④ 只有监听级 `-acl`（全局没开）+ 不匹配 → 也要拒绝（"或"的关系，对齐 C 版的 bind 标志）
        let cfg = RuntimeConfig::builder().with(other_rule).build().unwrap();
        assert!(!cfg.acl_enable());
        let mw = DnsMockMiddleware::builder()
            .with_a_record(name, "10.1.1.1".parse().unwrap())
            .build(cfg);
        let err = mw
            .search(
                &req_from(name, "127.0.0.1:55004"),
                &ServerOpts {
                    acl: Some(true),
                    ..Default::default()
                },
            )
            .await
            .expect_err("监听级 -acl 打开时，不匹配的客户端也要拒绝");
        assert_eq!(err.explicit_response_code(), Some(ResponseCode::Refused));

        // ⑤ 后台请求（预取/双栈探针）不是"某个客户端" → 不受 ACL 影响，
        //    否则一开 ACL 预取会被自己拒掉
        let cfg = RuntimeConfig::builder()
            .with("acl-enable yes")
            .with(other_rule)
            .build()
            .unwrap();
        let mw = DnsMockMiddleware::builder()
            .with_a_record(name, "10.1.1.1".parse().unwrap())
            .build(cfg);
        let res = mw
            .search(
                &req_from(name, "127.0.0.1:55005"),
                &ServerOpts {
                    is_background: true,
                    ..Default::default()
                },
            )
            .await;
        assert!(
            res.is_ok(),
            "后台请求不许被 ACL 拒掉（否则预取会自己废掉）：{res:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mock_middleware_ip() {
        let mw = DnsMockMiddleware::builder()
            .with_a_record("qq.com", "1.5.6.7".parse().unwrap())
            .build(RuntimeConfig::default());

        let res = mw.lookup_rdata("qq.com", RecordType::A).await.unwrap();

        assert_eq!(res, vec![RData::A("1.5.6.7".parse().unwrap())]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mock_middleware_soa() {
        let mw = DnsMockMiddleware::builder()
            .with_a_record("qq.com", "1.5.6.7".parse().unwrap())
            .build(RuntimeConfig::default());

        let res = mw.lookup_rdata("baidu.com", RecordType::A).await;

        assert!(res.is_err());

        let err = res.unwrap_err();

        assert!(err.is_soa());
    }
}
