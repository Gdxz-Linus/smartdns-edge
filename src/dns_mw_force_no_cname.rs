//! `force-no-CNAME`：强制不向客户端返回 CNAME 记录。
//!
//! ## 为什么做成独立中间件
//!
//! 项目里**已经**有一处 CNAME 展平逻辑（`dns_mw_cache.rs` 的 `flatten_cname`），
//! 但它有两个限制：
//!   1. 它挂在**缓存中间件**里 —— 而 `cache-size 0` 时缓存中间件**根本不在解析链上**，
//!      那时就不存在展平；
//!   2. 它**只对 A/AAAA** 生效，且有"答案里必须含目标类型"的前置条件。
//!
//! 本开关是**用户显式要求的行为**，不该依赖缓存是否开启，所以单独成一个中间件。
//! 这样也避免去改动那段已经在线上跑通的缓存逻辑（改动风险最小）。
//!
//! ## 行为
//!
//! 开启后，应答里的 CNAME 记录会被移除：
//!   * **A/AAAA 查询**：与缓存那套展平口径一致 —— 移除 CNAME 后，把剩余记录的
//!     名字改写成用户最初查询的域名、并把 TTL 对齐到原来最短的那条。
//!     这样客户端拿到的就是"直接答案"，少一跳、也不会因为中间 CNAME 域名的
//!     TTL 不一致而产生割裂。
//!   * **其它查询类型**：只移除 CNAME，不动剩余记录（例如 MX 应答里的 MX 记录保持原样）。
//!
//! ## 一个刻意的保守取舍
//!
//! 如果**移除 CNAME 后答案区会变空**（例如应答里只有 CNAME 记录、或查询类型本身就是 CNAME），
//! 就**不做移除**、原样返回。
//!
//! 理由：那种应答是"链路还没走完"的中间产物 —— 把它变成空答案，
//! 会让客户端收到 NODATA 而不是它真正需要的解析结果，属于**把功能改坏**。
//! 「不返回 CNAME」的意图是"别让客户端多做一次查询"，不是"把有效信息删成空"。

use crate::dns::*;
use crate::middleware::*;

pub struct DnsForceNoCNameMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsForceNoCNameMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        // 必须在 `next.run` 之前把开关读出来（之后 ctx 会被移交给下游）。
        // 取值口径：bind 级 > 组级 > 全局（组级即 `group-begin` 块里写的值）。
        let enabled = ctx.force_no_cname();
        let query = req.query().original().to_owned();

        let mut res = next.run(ctx, req).await?;

        if enabled {
            strip_cname(&mut res, &query);
        }

        Ok(res)
    }
}

/// 移除应答里的 CNAME 记录。见本文件头部对行为与取舍的说明。
fn strip_cname(resp: &mut DnsResponse, query: &crate::libdns::proto::op::Query) {
    use crate::libdns::proto::rr::RecordType as RT;

    let has_cname = resp.answers().iter().any(|r| r.record_type() == RT::CNAME);
    if !has_cname {
        return;
    }

    let is_ip_query = query.query_type().is_ip_addr();

    // A/AAAA：只有拿到了目标类型的记录才动手（与缓存那套展平口径一致）。
    // 否则说明链路还没走完（应答里只有 CNAME），此时移除会让客户端收到空答案。
    if is_ip_query {
        let target_type = query.query_type();
        let has_target = resp
            .answers()
            .iter()
            .any(|r| r.record_type() == target_type);
        if !has_target {
            return;
        }

        // 在丢掉 CNAME 之前，先取整份答案里最短的 TTL，
        // 避免底层 IP 记录寿命过长、变成"僵尸地址"。
        let real_min_ttl = resp.answers().iter().map(|r| r.ttl()).min().unwrap_or(60);

        let original_name = query.name().clone();
        resp.answers_mut()
            .retain(|record| record.record_type() == target_type);
        for record in resp.answers_mut() {
            if record.name() != &original_name {
                record.set_name(original_name.clone());
            }
            record.set_ttl(real_min_ttl);
        }
        return;
    }

    // 其它类型：移除 CNAME，但**保证移除后答案区不为空**。
    let remaining = resp
        .answers()
        .iter()
        .filter(|r| r.record_type() != RT::CNAME)
        .count();
    if remaining == 0 {
        return;
    }
    resp.answers_mut()
        .retain(|record| record.record_type() != RT::CNAME);
}

/// 便于单测：从 CNAME 链应答里按配置剥离 CNAME。
#[cfg(test)]
mod tests {
    use super::strip_cname;
    use crate::dns::DnsResponse;
    use crate::libdns::proto::{
        op::{Message, Query},
        rr::{Name, RData, Record, RecordType, rdata::CNAME},
    };

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// 组装一份"主域名 → CNAME → 目标地址"的应答
    fn cname_chain_response(
        query_type: RecordType,
        cname_target: &str,
        target_record: Option<(RecordType, RData)>,
        cname_ttl: u32,
        target_ttl: u32,
    ) -> DnsResponse {
        let mut msg = Message::query();
        let qname = name("www.example.test");
        msg.add_query(Query::query(qname.clone(), query_type));
        let mut message: Message = msg;

        message.add_answer(Record::from_rdata(
            qname.clone(),
            cname_ttl,
            RData::CNAME(CNAME(name(cname_target))),
        ));

        if let Some((rtype, rdata)) = target_record {
            message.add_answer(Record::from_rdata(name(cname_target), target_ttl, rdata));
            let _ = rtype;
        }

        DnsResponse::from(message)
    }

    fn a_rdata(ip: &str) -> RData {
        RData::A(ip.parse::<std::net::Ipv4Addr>().unwrap().into())
    }

    /// 🔐 A 查询：CNAME 被移除，地址记录被改写为「用户最初查询的域名」。
    ///
    /// 这样客户端拿到的就是直接答案，不必再为 CNAME 目标多发一次查询。
    #[test]
    fn a_query_cname_is_flattened_to_the_queried_name() {
        let mut resp = cname_chain_response(
            RecordType::A,
            "cdn.example.test",
            Some((RecordType::A, a_rdata("192.0.2.1"))),
            300,
            600,
        );

        strip_cname(
            &mut resp,
            &Query::query(name("www.example.test"), RecordType::A),
        );

        assert_eq!(resp.answers().len(), 1, "应当只剩地址记录");
        let rec = &resp.answers()[0];
        assert_eq!(rec.record_type(), RecordType::A);
        assert_eq!(
            rec.name(),
            &name("www.example.test"),
            "地址记录必须改写成用户最初查询的域名"
        );
    }

    /// TTL 对齐到原来最短的那条（防止底层地址寿命过长）
    #[test]
    fn flattened_answer_uses_the_shortest_original_ttl() {
        let mut resp = cname_chain_response(
            RecordType::A,
            "cdn.example.test",
            Some((RecordType::A, a_rdata("192.0.2.1"))),
            60,
            3600,
        );

        strip_cname(
            &mut resp,
            &Query::query(name("www.example.test"), RecordType::A),
        );

        assert_eq!(
            resp.answers()[0].ttl(),
            60,
            "应当取原答案里最短的 TTL，而不是地址记录自己的长 TTL"
        );
    }

    /// 🔐 保守取舍：应答里只有 CNAME、没有目标记录时，**不做移除**。
    ///
    /// 强行剥离会让客户端收到空答案（NODATA），把功能改坏。
    #[test]
    fn cname_only_response_is_left_intact() {
        let mut resp = cname_chain_response(RecordType::A, "cdn.example.test", None, 300, 0);
        let before = resp.answers().len();

        strip_cname(
            &mut resp,
            &Query::query(name("www.example.test"), RecordType::A),
        );

        assert_eq!(
            resp.answers().len(),
            before,
            "链路还没走完时不能剥离，否则客户端会收到空答案"
        );
        assert_eq!(resp.answers()[0].record_type(), RecordType::CNAME);
    }

    /// 非 A/AAAA 查询：移除 CNAME，保留其它记录且不改名。
    #[test]
    fn non_ip_query_drops_cname_but_keeps_other_records() {
        let mut resp = cname_chain_response(
            RecordType::TXT,
            "target.example.test",
            Some((
                RecordType::TXT,
                RData::TXT(crate::libdns::proto::rr::rdata::TXT::new(vec![
                    "hello".to_string(),
                ])),
            )),
            300,
            300,
        );

        strip_cname(
            &mut resp,
            &Query::query(name("www.example.test"), RecordType::TXT),
        );

        assert_eq!(resp.answers().len(), 1);
        let rec = &resp.answers()[0];
        assert_eq!(rec.record_type(), RecordType::TXT);
        assert_eq!(
            rec.name(),
            &name("target.example.test"),
            "非 IP 查询不改名（改名会让记录的语义变味）"
        );
    }

    /// 应答里没有 CNAME 时，什么都不做（不得误伤正常应答）。
    #[test]
    fn response_without_cname_is_untouched() {
        let mut msg = Message::query();
        msg.add_query(Query::query(name("plain.example.test"), RecordType::A));
        let mut message: Message = msg;
        message.add_answer(Record::from_rdata(
            name("plain.example.test"),
            300,
            a_rdata("192.0.2.9"),
        ));
        let mut resp = DnsResponse::from(message);

        strip_cname(
            &mut resp,
            &Query::query(name("plain.example.test"), RecordType::A),
        );

        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].ttl(), 300, "TTL 不该被动过");
    }

    // ─────────────────────── 中间件层测试 ───────────────────────
    //
    // 🔐 上面那些测试只验证了 `strip_cname` 这个函数本身。
    // 但"函数正确"不等于"中间件真的调用了它" —— 我实测验证时发现：
    // 把中间件里那行调用注释掉，上面所有测试**照样通过**。
    // 所以这里必须再补一层「中间件是否真的接通」的测试。

    use crate::dns::{DnsContext, DnsRequest};
    use crate::infra::middleware::{MiddlewareBuilder, MiddlewareDefaultHandler};
    use crate::libdns::Protocol;
    use std::sync::Arc;

    /// 下游桩：原样返回一个预置的应答（模拟"上游查完了"）
    struct StubHandler {
        resp: DnsResponse,
    }

    #[async_trait::async_trait]
    impl MiddlewareDefaultHandler<DnsContext, DnsRequest, DnsResponse, crate::dns::DnsError>
        for StubHandler
    {
        async fn handle(
            &self,
            _ctx: &mut DnsContext,
            _req: &DnsRequest,
        ) -> Result<DnsResponse, crate::dns::DnsError> {
            Ok(self.resp.clone())
        }
    }

    /// 跑一遍「中间件 → 下游桩」的完整链路
    async fn run_middleware(force_no_cname: bool) -> DnsResponse {
        // 用真实配置构造 DnsContext：开关值就写在这一行里
        let conf = if force_no_cname {
            "force-no-CNAME yes"
        } else {
            "force-no-CNAME no"
        };
        run_middleware_with_conf(conf, Default::default()).await
    }

    /// 同上传一遍链路，但配置内容与 `ServerOpts`（bind 级）都由调用方给定。
    ///
    /// ⚠️ 配置内容会**写成真实文件**再加载，而不是走 `RuntimeConfig::builder().with()`。
    /// 原因：`with()` 把整块字符串当成**一行**交给解析器，而解析器遇到换行只会吃掉第一行、
    /// 余下的按"未识别内容"丢弃 —— 于是 `group-begin/group-end` 这类**跨行**结构
    /// 在 `with()` 下根本不会成立（实测：`office` 组里的参数落不进去）。
    /// 用真实文件加载才是与生产一致的逐行路径。
    async fn run_middleware_with_conf(
        conf: &str,
        server_opts: crate::config::ServerOpts,
    ) -> DnsResponse {
        // 目录名只用序号：配置内容里有 `/`、换行等字符，直接拼进路径在 Windows 上是非法文件名。
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("force-no-cname-mw-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conf_file = dir.join("smartdns.conf");
        std::fs::write(&conf_file, conf).unwrap();

        let cfg = Arc::new(
            crate::dns_conf::RuntimeConfig::builder()
                .with_conf_dir(&dir)
                .with_conf_file(&conf_file)
                .build()
                .unwrap(),
        );

        let stub_resp = cname_chain_response(
            RecordType::A,
            "cdn.example.test",
            Some((RecordType::A, a_rdata("192.0.2.1"))),
            300,
            600,
        );

        let handler =
            MiddlewareBuilder::<DnsContext, DnsRequest, DnsResponse, crate::dns::DnsError>::new(
                StubHandler { resp: stub_resp },
            )
            .with(super::DnsForceNoCNameMiddleware)
            .build();

        let mut ctx = DnsContext::new(&name("www.example.test"), cfg, server_opts);

        let mut msg = Message::query();
        msg.add_query(Query::query(name("www.example.test"), RecordType::A));
        let req = DnsRequest::new(msg, "127.0.0.1:12345".parse().unwrap(), Protocol::Udp);

        let out = handler.execute(&mut ctx, &req).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    /// 🔐 核心：**中间件真的调用了展平逻辑**。
    ///
    /// 这条测试专门覆盖"实现是否接通" —— 把中间件里对 `strip_cname` 的调用去掉，
    /// 它就会失败（上面那些只测函数的用例不会）。
    #[test]
    fn middleware_actually_strips_cname_when_enabled() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let resp = rt.block_on(run_middleware(true));

        assert_eq!(
            resp.answers().len(),
            1,
            "开启 force-no-CNAME 后，中间件必须把 CNAME 剥掉，实际答案: {:?}",
            resp.answers()
                .iter()
                .map(|r| r.record_type())
                .collect::<Vec<_>>()
        );
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(
            resp.answers()[0].name(),
            &name("www.example.test"),
            "地址记录应当改写成用户最初查询的域名"
        );
    }

    /// 反向：开关关闭时，中间件**不得**改动应答。
    #[test]
    fn middleware_leaves_cname_alone_when_disabled() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let resp = rt.block_on(run_middleware(false));

        assert_eq!(
            resp.answers().len(),
            2,
            "关闭时应当保留 CNAME 与地址两条记录"
        );
        assert_eq!(resp.answers()[0].record_type(), RecordType::CNAME);
    }

    /// 下游桩：**直接短路返回，绝不调用更深一层**。
    ///
    /// 这就是缓存命中时 `DnsCacheMiddleware` 的真实行为 —— 它在 `CacheStatus::Valid`
    /// 分支里直接 `return Ok(res)`，根本不会 `next.run()`。
    struct ShortCircuitHandler;

    /// 反向验证专用：一个"内层缓存命中"式的短路中间件。
    /// 它直接返回应答、**不调 `next.run()`**，与缓存的命中分支行为一致。
    struct ShortCircuitStub;

    #[async_trait::async_trait]
    impl
        crate::infra::middleware::Middleware<
            DnsContext,
            DnsRequest,
            DnsResponse,
            crate::dns::DnsError,
        > for ShortCircuitStub
    {
        async fn handle(
            &self,
            _ctx: &mut DnsContext,
            _req: &DnsRequest,
            _next: crate::infra::middleware::Next<
                '_,
                DnsContext,
                DnsRequest,
                DnsResponse,
                crate::dns::DnsError,
            >,
        ) -> Result<DnsResponse, crate::dns::DnsError> {
            Ok(cname_chain_response(
                RecordType::TXT,
                "target.example.test",
                Some((
                    RecordType::TXT,
                    RData::TXT(crate::libdns::proto::rr::rdata::TXT::new(vec![
                        "hello".to_string(),
                    ])),
                )),
                300,
                300,
            ))
        }
    }

    #[async_trait::async_trait]
    impl MiddlewareDefaultHandler<DnsContext, DnsRequest, DnsResponse, crate::dns::DnsError>
        for ShortCircuitHandler
    {
        async fn handle(
            &self,
            _ctx: &mut DnsContext,
            _req: &DnsRequest,
        ) -> Result<DnsResponse, crate::dns::DnsError> {
            Ok(cname_chain_response(
                RecordType::TXT,
                "target.example.test",
                Some((
                    RecordType::TXT,
                    RData::TXT(crate::libdns::proto::rr::rdata::TXT::new(vec![
                        "hello".to_string(),
                    ])),
                )),
                300,
                300,
            ))
        }
    }

    /// 🔐 位置属性回归：`force-no-CNAME` 必须挂在**最外层**。
    ///
    /// 这条测试存在的唯一理由：本开关第一次实现时被误挂在**缓存内层**，
    /// 而缓存命中路径是**直接返回、不走 `next.run()`** 的 —— 结果就是
    /// 非 A/AAAA 类型（MX/TXT/SRV 等）在缓存命中时会把 CNAME 漏给客户端，
    /// 开关形同虚设。当时已有的测试**全部通过**，抓不到这个问题。
    ///
    /// 这里用"短路桩"复现该场景：把本中间件放在最外层，它就一定能看到并处理
    /// 内层短路返回的应答。**若把它移回缓存内层，这条测试会失败。**
    #[test]
    fn outer_position_covers_short_circuiting_inner_middleware() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let cfg = Arc::new(
            crate::dns_conf::RuntimeConfig::builder()
                .with("force-no-CNAME yes")
                .build()
                .unwrap(),
        );

        // 洋葱模型：注册顺序 = 从外到内。本中间件注册在最外层。
        let handler =
            MiddlewareBuilder::<DnsContext, DnsRequest, DnsResponse, crate::dns::DnsError>::new(
                ShortCircuitHandler,
            )
            .with(super::DnsForceNoCNameMiddleware)
            .with(ShortCircuitStub)
            .build();

        let mut ctx = DnsContext::new(&name("www.example.test"), cfg, Default::default());
        let mut msg = Message::query();
        msg.add_query(Query::query(name("www.example.test"), RecordType::TXT));
        let req = DnsRequest::new(msg, "127.0.0.1:12345".parse().unwrap(), Protocol::Udp);

        let resp = rt.block_on(handler.execute(&mut ctx, &req)).unwrap();

        assert_eq!(
            resp.answers().len(),
            1,
            "即使内层缓存命中直接短路返回，最外层的 force-no-CNAME 也必须剥掉 CNAME；\
             实际答案: {:?}",
            resp.answers()
                .iter()
                .map(|r| r.record_type())
                .collect::<Vec<_>>()
        );
        assert_eq!(resp.answers()[0].record_type(), RecordType::TXT);
    }

    // ───────────── 三层优先级（bind 级 > 组级 > 全局）的运行时验证 ─────────────
    //
    // 🔐 上面那些测试验证的是"开关本身生效"。这一组验证**取值口径**：
    // 同一个中间件、同一份应答，只改配置的层级，结果必须不同。
    // 如果 `DnsContext::force_no_cname()` 退回成只看全局（改坏了），
    // 下面 `group_level_beats_global_at_runtime` 与 `bind_level_beats_group_at_runtime` 会失败。

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// 组级写 yes、全局不写 → 该组查询必须展平。
    #[test]
    fn group_level_beats_global_at_runtime() {
        let conf = "group-begin office\nforce-no-CNAME yes\ngroup-end\n";

        // ① 查询不带规则组（走 default）→ 全局没开 → 不展平
        let resp = rt().block_on(run_middleware_with_conf(conf, Default::default()));
        assert_eq!(
            resp.answers().len(),
            2,
            "没指定 office 组时全局是关的，不应当展平：{:?}",
            resp.answers()
                .iter()
                .map(|r| r.record_type())
                .collect::<Vec<_>>()
        );

        // ② 同一条查询挂到 office 组 → 组级 yes 生效 → 展平
        let opts = crate::config::ServerOpts {
            rule_group: Some("office".to_string()),
            ..Default::default()
        };
        let resp = rt().block_on(run_middleware_with_conf(conf, opts));
        assert_eq!(
            resp.answers().len(),
            1,
            "office 组里写了 yes，该组的查询必须展平：{:?}",
            resp.answers()
                .iter()
                .map(|r| r.record_type())
                .collect::<Vec<_>>()
        );
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
    }

    /// bind 级（`-force-no-CNAME`）压过组级与全局。
    #[test]
    fn bind_level_beats_group_at_runtime() {
        // 全局关、组里也不写；只靠 bind 级打开
        let conf = "server 8.8.8.8\n";
        let opts = crate::config::ServerOpts {
            force_no_cname: Some(true),
            ..Default::default()
        };
        let resp = rt().block_on(run_middleware_with_conf(conf, opts));
        assert_eq!(
            resp.answers().len(),
            1,
            "bind 级显式打开时，即使全局与组级都是关的也必须展平：{:?}",
            resp.answers()
                .iter()
                .map(|r| r.record_type())
                .collect::<Vec<_>>()
        );
    }

    /// 三层都没写 → 必须关闭（保持既有行为，不能因为引入三层就默认打开）。
    #[test]
    fn all_layers_unset_means_disabled() {
        let resp = rt().block_on(run_middleware_with_conf(
            "server 8.8.8.8\n",
            Default::default(),
        ));
        assert_eq!(
            resp.answers().len(),
            2,
            "三层都没配时必须保持关闭，CNAME 原样返回"
        );
    }
}
