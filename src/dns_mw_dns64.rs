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

        // 🔐 P2-5 补齐：`ipv4only.arpa` 特判（RFC 7050，对齐 C 版 dns64.c 的内置处理）。
        //
        // 这是 IPv6-only 网络里客户端做 NAT64 探测的标准域名：
        //   * A 查询 → 固定返回 IANA 保留地址 192.0.0.170 / 192.0.0.171（不查上游、不进缓存，
        //     TTL 取 local-ttl——与 C 版 `_dns_server_get_local_ttl` 一致）；
        //   * AAAA 查询 → 回空 NOERROR，交给下面的 DNS64 合成逻辑（合成的地址指向 NAT64 前缀，
        //     客户端据此判断"在 NAT64 后面"）。
        // 缺了它，部分系统（Windows/手机）的 IPv6 连通性探测会异常或超时变慢。
        // 仅在配了 dns64 前缀的组生效（与 C 版 is_dns64_request 的第一道判定一致）。
        const IPV4ONLY_ARPA: &str = "ipv4only.arpa.";
        if req.query().name().to_string().eq_ignore_ascii_case(IPV4ONLY_ARPA) {
            let query = req.query().original().clone();
            let name = query.name().to_owned();
            match query.query_type() {
                RecordType::A => {
                    let ttl = ctx.local_ttl() as u32;
                    let mut resp = DnsResponse::empty();
                    resp.add_query(query);
                    for ip in ["192.0.0.170", "192.0.0.171"] {
                        resp.add_answer(crate::dns::Record::from_rdata(
                            name.clone(),
                            ttl,
                            crate::dns::RData::A(ip.parse().unwrap()),
                        ));
                    }
                    return Ok(resp);
                }
                RecordType::AAAA => {
                    // 空应答：不查上游，让客户端的探测流程走 AAAA 语义
                    // （C 版 has_ip=0 + do_reply；这里同样回 NOERROR 空 AAAA）
                    let mut resp = DnsResponse::empty();
                    resp.add_query(query);
                    return Ok(resp);
                }
                _ => (), // 其它类型照常走原链路
            }
        }

        let query = req.query().original();
        let query_type = query.query_type();
        match query_type {
            RecordType::AAAA => {
                let res = next.clone().run(ctx, req).await;

                // 🌟 修复：无论上游是返回 NXDOMAIN(Err) 还是返回了纯 IPv4 的空包(Ok但没AAAA记录)，都必须启动 DNS64 合成！
                // 🔐 P2-5：**压制标记优先于合成**。应答带 aaaa_suppressed 标记说明
                // "没有 AAAA"是内层链路的主动决策（双栈优选测速 A 胜出压掉 AAAA、
                // force-AAAA-SOA / address /域/#6 把 AAAA 回成 SOA）——
                // 补救不得推翻指令，跳过合成。只对"上游真没有 AAAA"的情况出手。
                // 参考 C 版：双栈优选子查询与 DNS64 互相隔离，force-AAAA-SOA 在
                // 请求预处理阶段直接回 SOA，查询根本到不了 DNS64。
                let fallback_needed = match &res {
                    Err(_) => true,
                    Ok(lookup) => {
                        !lookup.aaaa_suppressed()
                            && !lookup
                                .records()
                                .iter()
                                .any(|r| r.record_type() == RecordType::AAAA)
                    }
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

/// 合成 IPv4-embedded IPv6 地址（RFC 6052 §2.2）。
///
/// 合法前缀长度只有 32/40/48/56/64/96 六种（配置层已拦截，这里是对运行期的第二道防线），
/// 其它长度返回 None。u 字节（保留位）强制为 0。
fn to_dns64(ipv6_net: Ipv6Net, ipv4: Ipv4Addr) -> Option<Ipv6Addr> {
    let prefix = ipv6_net.prefix_len();
    let mut octets = ipv6_net.addr().octets();
    let v4 = ipv4.octets();

    // RFC 6052 §2.2 表格：按前缀长度决定 IPv4 的嵌入位置与 u 字节位置
    match prefix {
        32 => {
            octets[4..8].copy_from_slice(&v4);
            octets[8] = 0;
        }
        40 => {
            octets[5..8].copy_from_slice(&v4[0..3]);
            octets[9] = v4[3];
            octets[8] = 0;
        }
        48 => {
            octets[6..8].copy_from_slice(&v4[0..2]);
            octets[9..11].copy_from_slice(&v4[2..4]);
            octets[8] = 0;
        }
        56 => {
            // 字节 7 为 8 位保留，字节 8 为 u（两者都必须为 0）
            octets[9..12].copy_from_slice(&v4[0..3]);
            octets[13] = v4[3];
            octets[7] = 0;
            octets[8] = 0;
            octets[13] = 0;
        }
        64 => {
            octets[9..13].copy_from_slice(&v4);
            octets[8] = 0;
        }
        96 => {
            octets[12..16].copy_from_slice(&v4);
        }
        _ => return None,
    }

    Some(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;
    use crate::dns_conf::RuntimeConfig;
    use crate::dns_mw::*;
    use crate::libdns::proto::rr::DNSClass;

    /// 🔐 P2-5：应答带 aaaa_suppressed 标记时，DNS64 不合成（压制优先于补救）。
    /// 内层 FlagSetter 中间件模拟"双栈优选/force-AAAA-SOA 压制了 AAAA"的应答。

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

    /// 🔐 P2-5 补齐：ipv4only.arpa 特判（RFC 7050 / C 版 dns64.c 对齐）。
    /// A 查询固定回 192.0.0.170/171；AAAA 查询回空 NOERROR；不查上游。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ipv4only_arpa_a_query() {
        struct FailResponder;
        use crate::middleware::Middleware as _;

        #[async_trait::async_trait]
        impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for FailResponder {
            async fn handle(
                &self,
                _ctx: &mut DnsContext,
                _req: &DnsRequest,
                _next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
            ) -> Result<DnsResponse, DnsError> {
                panic!("ipv4only.arpa must be answered locally, never forwarded upstream");
            }
        }

        let cfg = RuntimeConfig::builder()
            .with("dns64 64:ff9b::/96")
            .with("local-ttl 77")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(Dns64Middleware::new())
            .with_extra_middleware(FailResponder)
            .build(cfg);

        let response = search_with_query(
            &mock,
            "ipv4only.arpa.",
            RecordType::A,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut ips: Vec<_> = response
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                crate::dns::RData::A(ip) => Some(ip.to_string()),
                _ => None,
            })
            .collect();
        ips.sort();
        assert_eq!(
            ips,
            vec!["192.0.0.170", "192.0.0.171"],
            "ipv4only.arpa 的 A 查询必须固定返回 RFC 7050 保留地址"
        );
        assert_eq!(response.answers()[0].ttl(), 77, "TTL 应取 local-ttl（对齐 C 版）");
    }

    /// 🔐 P2-5 补齐：ipv4only.arpa 的 AAAA 查询回空 NOERROR，且不查上游。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ipv4only_arpa_aaaa_query() {
        struct FailResponder;
        use crate::middleware::Middleware as _;

        #[async_trait::async_trait]
        impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for FailResponder {
            async fn handle(
                &self,
                _ctx: &mut DnsContext,
                _req: &DnsRequest,
                _next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
            ) -> Result<DnsResponse, DnsError> {
                panic!("ipv4only.arpa AAAA must not be forwarded upstream");
            }
        }

        let cfg = RuntimeConfig::builder()
            .with("dns64 64:ff9b::/96")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(Dns64Middleware::new())
            .with_extra_middleware(FailResponder)
            .build(cfg);
        let response = search_with_query(
            &mock,
            "ipv4only.arpa.",
            RecordType::AAAA,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await
        .unwrap();
        assert!(response.answers().is_empty(), "AAAA 应返回空（RFC 7050）");
        assert_eq!(
            response.response_code(),
            crate::libdns::proto::op::ResponseCode::NoError
        );
    }

    /// 🔐 P2-5 补齐：未配 dns64 前缀的组不拦截 ipv4only.arpa（原样穿透到内层）。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ipv4only_arpa_not_intercepted_without_dns64() {
        struct PassthroughChecker;
        use crate::middleware::Middleware as _;

        #[async_trait::async_trait]
        impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for PassthroughChecker {
            async fn handle(
                &self,
                _ctx: &mut DnsContext,
                req: &DnsRequest,
                _next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
            ) -> Result<DnsResponse, DnsError> {
                assert!(
                    req.query().name().to_string().eq_ignore_ascii_case("ipv4only.arpa."),
                    "未配 dns64 时该查询应原样穿透"
                );
                let mut resp = DnsResponse::empty();
                resp.add_query(req.query().original().to_owned());
                Ok(resp)
            }
        }

        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(Dns64Middleware::new())
            .with_extra_middleware(PassthroughChecker)
            .build(cfg);
        let response = search_with_query(
            &mock,
            "ipv4only.arpa.",
            RecordType::A,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await
        .unwrap();
        assert!(response.answers().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dns64_skipped_when_suppressed() {
        struct SuppressedResponder;
        use crate::middleware::Middleware as _;

        #[async_trait::async_trait]
        impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for SuppressedResponder {
            async fn handle(
                &self,
                _ctx: &mut DnsContext,
                req: &DnsRequest,
                _next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
            ) -> Result<DnsResponse, DnsError> {
                // 模拟内层：AAAA 查询被压制，回 SOA（force-AAAA-SOA 的形态）
                let mut resp = DnsResponse::empty();
                resp.add_query(req.query().original().to_owned());
                use crate::libdns::proto::op::ResponseCode;
                resp.set_response_code(ResponseCode::NoError);
                resp.add_authority(crate::dns::Record::from_rdata(
                    req.query().original().name().clone(),
                    300,
                    crate::dns::RData::default_soa(),
                ));
                resp.set_aaaa_suppressed(true);
                Ok(resp)
            }
        }

        let cfg = RuntimeConfig::builder()
            .with("dns64 64:ff9b::/96")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(Dns64Middleware::new())
            .with_extra_middleware(SuppressedResponder)
            .build(cfg);
        let response = search_with_query(
            &mock,
            "suppressed.test.",
            RecordType::AAAA,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await
        .unwrap();
        // 压制标记下：不合成——应答保持 SOA 形态（无合成 AAAA、无二次 A 查询的地址）
        assert!(
            response
                .answers()
                .iter()
                .all(|r| r.record_type() != RecordType::AAAA),
            "被压制的 AAAA 查询不得被 DNS64 合成（P2-5 修复点）"
        );
        assert!(
            response
                .authorities()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA),
            "压制应答应保持 SOA 否定形态"
        );
    }

    /// 🔐 P2-5：无压制标记时，DNS64 照常合成（主场行为不受修复影响）。
    #[tokio::test(flavor = "multi_thread")]
    async fn test_dns64_synthesizes_when_not_suppressed() {
        struct AOnlyResponder;
        use crate::middleware::Middleware as _;

        #[async_trait::async_trait]
        impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for AOnlyResponder {
            async fn handle(
                &self,
                _ctx: &mut DnsContext,
                req: &DnsRequest,
                _next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
            ) -> Result<DnsResponse, DnsError> {
                if req.query().query_type() == RecordType::A {
                    let mut resp = DnsResponse::empty();
                    resp.add_query(req.query().original().to_owned());
                    resp.add_answer(crate::dns::Record::from_rdata(
                        req.query().original().name().clone(),
                        300,
                        crate::dns::RData::A("1.2.3.4".parse().unwrap()),
                    ));
                    Ok(resp)
                } else {
                    // AAAA 查询：上游真没有（NOERROR 空应答，无压制标记）
                    let mut resp = DnsResponse::empty();
                    resp.add_query(req.query().original().to_owned());
                    Ok(resp)
                }
            }
        }

        let cfg = RuntimeConfig::builder()
            .with("dns64 64:ff9b::/96")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::builder()
            .with_extra_middleware(Dns64Middleware::new())
            .with_extra_middleware(AOnlyResponder)
            .build(cfg);
        let response = search_with_query(
            &mock,
            "v4only.test.",
            RecordType::AAAA,
            DNSClass::IN,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await
        .unwrap();
        let synthesized: Vec<_> = response
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::AAAA)
            .collect();
        assert_eq!(
            synthesized.len(),
            1,
            "上游真没有 AAAA 时必须照常合成（主场行为）"
        );
        assert_eq!(
            synthesized[0].data().ip_addr(),
            Some("64:ff9b::102:304".parse().unwrap())
        );
    }

    #[test]
    fn test_dns64_1() {
        let ipv6_net = Ipv6Net::from_str("64:ff9b::/96").unwrap();
        let ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let ipv6 = to_dns64(ipv6_net, ipv4);
        assert_eq!(ipv6, Ipv6Addr::from_str("64:ff9b::c0a8:1").ok());
    }

    #[test]
    fn test_dns64_2() {
        // 🔐 P3-3：/64 前缀按 RFC 6052 §2.2 布局——前缀 8 字节 + u 字节(0) + IPv4 4 字节 + 3 字节 suffix
        // 旧期望 3000::c0a8:1:0:0 是非标准布局（v4 从字节 10 开始），与标准 NAT64 网关不互通
        let ipv6_net = Ipv6Net::from_str("3000::/64").unwrap();
        let ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        let ipv6 = to_dns64(ipv6_net, ipv4);
        // RFC 6052 /64 布局：字节 0-7 = 前缀，字节 8 = u(0)，字节 9-12 = IPv4，字节 13-15 = suffix
        let mut expected = [0u8; 16];
        expected[0..8].copy_from_slice(&[0x30, 0, 0, 0, 0, 0, 0, 0]);
        expected[9..13].copy_from_slice(&[192, 168, 0, 1]);
        assert_eq!(
            ipv6,
            Some(Ipv6Addr::from(expected)),
            "/64 前缀必须按 RFC 6052 §2.2 布局（u 字节在字节 8，IPv4 在字节 9-12）"
        );
    }

    /// 🔐 P2-4：非法前缀长度返回 None（配置层已拦截，这里是运行期防线）
    #[test]
    fn test_dns64_invalid_prefix_returns_none() {
        let ipv6_net = Ipv6Net::from_str("3000::/128").unwrap();
        let ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        assert_eq!(to_dns64(ipv6_net, ipv4), None, "/128 必须返回 None");

        let ipv6_net = Ipv6Net::from_str("3000::/100").unwrap();
        let ipv4 = Ipv4Addr::from_str("192.168.0.1").unwrap();
        assert_eq!(to_dns64(ipv6_net, ipv4), None, "/100 必须返回 None");
    }
}
