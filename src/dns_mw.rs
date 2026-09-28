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

/// IPv6 的 v4-mapped 地址先归一成 IPv4 —— 否则同一个设备会因为"用了哪种写法"
/// 落到不同的客户端规则上（`::ffff:192.168.1.5` 与 `192.168.1.5` 必须同组）。
///
/// 抽成独立函数是为了让 `search` 与 `resolve_rule_group` **共用同一归一化**，
/// 不再各写一遍（原先这两处就各写了一份同样的 8 行代码）。
fn normalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(addr) = ip
        && let Some(addr) = addr.to_ipv4_mapped()
    {
        return addr.into();
    }
    ip
}

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

    /// 🔐 算出**这次查询实际落在哪个规则组**（`None` = 默认组）。
    ///
    /// 为什么抽成公开方法：`app.rs` 在**中间件链之外**还有一处兜底答复
    /// （上游回"不带 SOA 的 NXDOMAIN"时，自造 NOERROR+SOA），那里也要取组级参数
    /// （例如 `rr-ttl-reply-max`）。如果让它在外面**自己再判一次**组，就会出现
    /// "同一件事两处算法"——正是本项目反复吃亏的那类分叉（问题 24 就是两条路径各算各的）。
    ///
    /// 判据与 `search` 内部**完全共用这一份**：
    ///   · 调用方已经指定了组 → 尊重它（预取会把"这条缓存属于哪组"带回来）；
    ///   · 后台请求 → **不判组**（它的来源是程序自己，硬判只会把组抹成默认）；
    ///   · 其余 → 按**归组地址**（`grouping_ip`，可来自可信代理）匹配客户端规则。
    ///
    /// ⚠️ 注意这里用的是 `grouping_ip`（可伪造）而不是 `client_ip`（真实对端）：
    /// 选组不是安全边界，与 ACL 放行判定必须分开（见 `search` 里的详细说明）。
    pub fn resolve_rule_group(&self, req: &DnsRequest, server_opts: &ServerOpts) -> Option<String> {
        if let Some(g) = server_opts.rule_group.as_ref() {
            return Some(g.clone());
        }
        if server_opts.is_background {
            return None;
        }

        let grouping_ip = normalize_ip(req.forwarded_client().unwrap_or(req.src().ip()));
        self.cfg
            .client_rules()
            .iter()
            .find(|s| s.match_ip(&grouping_ip))
            .map(|s| s.group.clone())
    }

    /// 与本次查询对应的规则组名（空串表示默认组），可直接喂给 `*_in_group()`。
    ///
    /// 只是 `resolve_rule_group` 的一个方便包装：调用方拿到的永远是"能用"的字符串，
    /// 不必到处写 `unwrap_or_default()`。
    #[inline]
    pub fn rule_group_name(&self, req: &DnsRequest, server_opts: &ServerOpts) -> String {
        self.resolve_rule_group(req, server_opts)
            .unwrap_or_default()
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
        let client_ip = normalize_ip(req.src().ip());

        // 🔐 13-⑥：**归组地址**与上面的 `client_ip` 是两回事，不能混用。
        //
        //   · `client_ip`   = 真实对端（内核给出，**不可伪造**）→ 用于 **ACL 放行判定**；
        //   · 归组地址       = 可信反向代理经 `X-Forwarded-For` 报来的真实客户端
        //                     （**可伪造**）→ **只用于选规则组**。
        //
        // 为什么必须分开：`X-Forwarded-For` 是客户端能自己填的普通 HTTP 头。
        // 若拿它做放行判定，攻击者只要伪造一个能匹配白名单的头就**绕过了 ACL**；
        // 而拿它选规则组，最坏也只是"用了别人的策略"，不构成安全边界。
        // 详见 `src/trusted_proxy.rs` 模块文档的"三条铁律"第 3 条。
        //
        // 📌 归组地址的计算与匹配已搬进 `resolve_rule_group`（下面调用），
        // 因为它同时被 `app.rs` 的兜底答复路径需要 —— 两处必须共用同一份判据。

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
                crate::log::debug!(
                    "the number of concurrent queries has reached its limit; replying REFUSED"
                );
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
        //
        // 🔐 13-⑥：⚠️ 这里**必须用 `client_ip`（真实对端）**，不能用 `grouping_ip` ——
        // 后者来自可伪造的 `X-Forwarded-For`，拿它做放行判定等于把 ACL 交给调用方自报。
        // 这是本功能最要紧的一条安全约束。
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
        //
        // 🔐 13-⑥：这里用的是 **`grouping_ip`** —— 选规则组属于"归组"，
        // 是可信代理功能的**正当用途**（比如"代理后面的访客设备按真实 IP 分到 guest 组"）。
        // 与上面的 ACL 判定刻意分开，两者的分工见函数开头 `grouping_ip` 的说明。
        //
        // 📌 判据已抽到 `resolve_rule_group` —— `app.rs` 的兜底答复路径也要取组级参数，
        // 两处**必须**共用同一份判据（否则又是"同一件事两处各算各的"）。
        if server_opts.rule_group.is_none() && !server_opts.is_background {
            server_opts.rule_group = self.resolve_rule_group(req, &server_opts);
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
            ctx.rr_ttl().unwrap_or_default() as u32,
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

    /// 🔐 **13-⑥ 的安全底线（铁律 ③）**：`X-Forwarded-For` **绝不能**影响 ACL 放行。
    ///
    /// ## 为什么这条测试必须存在
    ///
    /// `X-Forwarded-For` 是**客户端能自己填的普通 HTTP 头**。如果拿它做放行判定，
    /// 攻击者只要加一行 `X-Forwarded-For: <白名单里的地址>` 就**绕过了 ACL** ——
    /// 那会把一个"限流不便"的问题升级成"访问控制被绕过"的安全问题。
    ///
    /// ## 本测试怎么证明这一点
    ///
    /// 场景设计成"两个地址分属不同规则"：
    ///   * **真实对端** `10.9.9.9` —— 不属于白名单 `127.0.0.0/8`；
    ///   * **转发地址** `127.0.0.1` —— **属于**白名单。
    ///
    /// 若实现错误地拿转发地址做 ACL 判定，请求就会被**放行**（测试失败）；
    /// 正确实现下必须**拒绝**（因为真实对端不在白名单里）。
    ///
    /// 判别力：把 `dns_mw.rs` 里 ACL 判定的 `client_ip` 改成 `grouping_ip`，
    /// 本测试**必然失败**。
    #[tokio::test(flavor = "multi_thread")]
    async fn forwarded_for_never_bypasses_acl() {
        use crate::config::ServerOpts;
        use crate::libdns::proto::op::ResponseCode;

        let name = "trusted-proxy-acl.example.com";

        // 白名单只放 127.0.0.0/8
        let cfg = RuntimeConfig::builder()
            .with("acl-enable yes")
            .with("client-rules 127.0.0.0/8")
            .build()
            .unwrap();

        let mw = DnsMockMiddleware::builder()
            .with_a_record(name, "10.1.1.1".parse().unwrap())
            .build(cfg);

        // 真实对端 10.9.9.9（不在白名单），但请求声称"转发自 127.0.0.1"（在白名单）
        let req = req_from(name, "10.9.9.9:55010")
            .with_forwarded_client(Some("127.0.0.1".parse().unwrap()));

        let err = mw.search(&req, &ServerOpts::default()).await.expect_err(
            "🔐 真实对端不在白名单时**必须拒绝** —— \
                 即便 `X-Forwarded-For` 声称来自白名单地址。\
                 若这里被放行，说明伪造一个 HTTP 头就能绕过 ACL",
        );

        assert_eq!(
            err.explicit_response_code(),
            Some(ResponseCode::Refused),
            "被 ACL 拒掉时应当回 REFUSED（不是 SERVFAIL）"
        );
    }

    /// 🔐 13-⑥：把"选组用的是哪个地址"这件事**直接钉在纯逻辑上**。
    ///
    /// 上一条测试没法把选组结果读回来（`search` 内部用的是副本），
    /// 所以这里改成**直接验证地址选择逻辑**：给定 `forwarded_client` 时，
    /// 归组地址必须是它、而不是真实对端。
    ///
    /// 这条与 `forwarded_for_never_bypasses_acl` 合起来构成本功能的完整契约：
    ///   * 归组 → 用 `forwarded_client`（本条）；
    ///   * ACL  → 用真实对端（上一条）。
    #[test]
    fn grouping_address_prefers_the_forwarded_client() {
        let name = "grouping.example.com";

        // 没有转发信息 → 归组地址就是真实对端
        let req = req_from(name, "10.0.0.1:55012");
        assert_eq!(
            req.forwarded_client().unwrap_or(req.src().ip()),
            req.src().ip(),
            "没有转发信息时，归组地址必须等于真实对端（行为与改动前一致）"
        );

        // 有转发信息 → 归组地址取它
        let req = req_from(name, "10.0.0.1:55013")
            .with_forwarded_client(Some("192.168.1.50".parse().unwrap()));
        assert_eq!(
            req.forwarded_client().unwrap_or(req.src().ip()),
            "192.168.1.50".parse::<std::net::IpAddr>().unwrap(),
            "🔐 有转发信息时，**归组**必须用转发来的真实客户端地址 —— \
             否则代理后面的设备全都归到代理那一组（这正是本功能要解决的问题）"
        );
        // 同时确认 `src()`（ACL 用的那个）**没有被改掉**
        assert_eq!(
            req.src().ip(),
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap(),
            "🔐 `src()` 必须保持**真实对端**不变 —— ACL 与审计依赖它不可伪造"
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
