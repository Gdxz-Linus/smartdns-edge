use std::time::{Duration, Instant};

use crate::dns::*;
use crate::libdns::proto::rr::{RData, RecordType};
use crate::middleware::*;

#[derive(Debug)]
pub struct AddressMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for AddressMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query_type = req.query().query_type();

        if let Some(rdatas) = handle_rule_addr(query_type, ctx) {
            let local_ttl = ctx.cfg().local_ttl() as u32;

            // 🌟 提取 rr-ttl 和 rr-ttl-min，为合成否定缓存 (SOA 拦截) 提供规范的兜底寿命
            let rr_ttl = ctx.domain_rule.get(|r| r.rr_ttl).map(|i| i as u32)
                .or_else(|| ctx.cfg().rr_ttl().map(|i| i as u32));
            let rr_ttl_min = ctx.domain_rule.get(|r| r.rr_ttl_min).map(|i| i as u32)
                .unwrap_or_else(|| ctx.cfg().rr_ttl_min().unwrap_or(300) as u32);
            // 如果没配 rr_ttl，就用 min 兜底
            let intercept_soa_ttl = rr_ttl.unwrap_or(rr_ttl_min);

            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + Duration::from_secs(local_ttl as u64);

            // 🌟 核心修复 2：严格遵守 DNS RFC 规范，SOA 萝卜章必须放入 Authority 区，IP 记录放入 Answer 区！
            let mut answers = Vec::new();
            let mut authorities = Vec::new();

            for d in rdatas {
                match d {
                    RData::SOA(_) => {
                        // 🌟 使用全局统一兵工厂，配上受外网规则管控的拦截 TTL
                        let soa_record = crate::dns::forge_soa_record(name.clone(), intercept_soa_ttl);
                        authorities.push(soa_record);
                    }
                    _ => {
                        // 静态 IP 记录依然乖乖使用 local_ttl
                        let record = Record::from_rdata(name.clone(), local_ttl, d);
                        answers.push(record);
                    }
                }
            }

            let mut lookup = DnsResponse::new_with_deadline(query, answers, valid_until);
            for auth in authorities {
                lookup.add_authority(auth);
            }

            // 🔐 B3：本地 address 规则 / 强制 SOA 的应答走的是这条**早返回**分支，
            // 以前完全不经过 `rr-ttl-reply-max` —— 于是 `rr-ttl-min 600` + `rr-ttl-reply-max 60`
            // 时，这类应答照样带 600 秒返回给客户端，与"允许返回给客户端的最大 TTL"对不上。
            if let Some(reply_max) = ctx.cfg().rr_ttl_reply_max().map(|i| i as u32) {
                clamp_reply_ttl(&mut lookup, reply_max);
            }

            ctx.source = LookupFrom::Static;
            return Ok(lookup);
        }

        let res = next.run(ctx, req).await;

        match res {
            Ok(mut lookup) => {
                // 🔐 P2 修复：这里是"给客户端看的最终修饰"，必须**原地修改**，
                // 不能再像原来那样用 new_with_deadline 重建响应体 —— 重建只搬运 Answer 区，
                // 会把 Authority 区的 SOA（否定缓存的关键）、附加区的胶水记录、rcode 以及 EDNS 全丢掉。
                // 症状：只要配置了 rr-ttl-reply-max，所有 NXDOMAIN/NODATA 的 SOA 就消失，
                // 客户端的否定缓存随之失效。

                // 1) max-reply-ip-num：截断 Answer 区的 IP 记录
                if query_type.is_ip_addr()
                    && let Some(mut max_reply_ip_num) = ctx.cfg().max_reply_ip_num()
                        && max_reply_ip_num > 0 {
                            let mut truncate = None;
                            for (i, r) in lookup.answers().iter().enumerate() {
                                if matches!(r.data(), RData::A(_) | RData::AAAA(_)) {
                                    max_reply_ip_num -= 1;
                                    if max_reply_ip_num == 0 {
                                        truncate = Some(i + 1);
                                        break;
                                    }
                                }
                            }

                            if let Some(truncate) = truncate
                                && lookup.answers().len() > truncate {
                                    lookup.answers_mut().truncate(truncate);
                                    lookup.sync_header_counts();
                                }
                        }

                // 2) rr-ttl-reply-max：把"给客户端看的 TTL"统一压到上限以内（B3：三个区都压）。
                if let Some(reply_max) = ctx.cfg().rr_ttl_reply_max().map(|i| i as u32) {
                    clamp_reply_ttl(&mut lookup, reply_max);
                }

                Ok(lookup)
            }
            Err(err) => Err(err),
        }
    }
}

/// 把"给客户端看的 TTL"统一压到 `rr-ttl-reply-max` 以内。
///
/// 🔐 B3 的两个要点：
/// ① **三个区都压**（Answer / Authority(SOA) / Additional(胶水)）—— 这个配置的承诺是
///    "允许返回给客户端的最大 TTL 值"，而客户端会把三个区都缓存下来；只压前两个区时，
///    胶水记录的 TTL 仍会超过用户设定的上限。
/// ② 本地 address 规则命中的**早返回**分支以前完全不经过这里（见上面的调用点）。
fn clamp_reply_ttl(lookup: &mut DnsResponse, reply_max: u32) {
    for record in lookup.answers_mut() {
        if record.ttl() > reply_max {
            record.set_ttl(reply_max);
        }
    }
    for record in lookup.authorities_mut() {
        if record.ttl() > reply_max {
            record.set_ttl(reply_max);
        }
    }
    for record in lookup.additionals_mut() {
        if record.ttl() > reply_max {
            record.set_ttl(reply_max);
        }
    }
}

fn handle_rule_addr(query_type: RecordType, ctx: &DnsContext) -> Option<Vec<RData>> {
    use RecordType::{A, AAAA, HTTPS};

    let cfg = ctx.cfg();
    let server_opts = ctx.server_opts();
    let rule = ctx.domain_rule.as_ref();

    let no_rule_soa = server_opts.no_rule_soa();

    // handle force SOA
    if !no_rule_soa {
        match query_type {
            // force AAAA query return SOA
            AAAA if server_opts.force_aaaa_soa() || cfg.force_aaaa_soa() => {
                return Some(vec![RData::default_soa()]);
            }
            // force HTTPS query return SOA
            HTTPS if server_opts.force_https_soa() || cfg.force_https_soa() => {
                return Some(vec![RData::default_soa()]);
            }
            _ => (),
        }

        // force specific qtype return SOA
        if cfg.force_qtype_soa().contains(&query_type) {
            return Some(vec![RData::default_soa()]);
        }
    }

    // skip address rule.
    if server_opts.no_rule_addr() || !query_type.is_ip_addr() {
        return None;
    }

    let mut node = rule;

    while let Some(rule) = node {
        use crate::dns_conf::AddressRuleValue::*;

        if let Some(address) = rule.address.as_ref() {
            match address {
                Addr { v4, v6 } => {
                    match query_type {
                        A => {
                            if let Some(v4) = v4 {
                                return Some(v4.iter().map(|ip| RData::A((*ip).into())).collect());
                            }
                        }
                        AAAA => {
                            if let Some(v6) = v6 {
                                return Some(
                                    v6.iter().map(|ip| RData::AAAA((*ip).into())).collect(),
                                );
                            }

                            if let Some(v4) = v4 {
                                return Some(
                                    v4.iter()
                                        .map(|ip| RData::AAAA(ip.to_ipv6_mapped().into()))
                                        .collect(),
                                );
                            }
                        }
                        other => {
                            // 🔐 P0-2：理论上到不了（外层只进 A/AAAA 分支），
                            // 但也绝不 panic —— 远程可触发的 panic 等于一个拒绝服务入口。
                            crate::log::warn!(
                                "handle_rule_addr: unexpected record type {other:?}, skip address rule"
                            );
                            return None;
                        }
                    }
                    if !no_rule_soa {
                        return Some(vec![RData::default_soa()]);
                    }
                }
                SOA if !no_rule_soa => return Some(vec![RData::default_soa()]),
                SOAv4 if !no_rule_soa && query_type == A => {
                    return Some(vec![RData::default_soa()]);
                }
                SOAv6 if !no_rule_soa && query_type == AAAA => {
                    return Some(vec![RData::default_soa()]);
                }
                IGN => return None, // ignore rule
                IGNv4 if query_type == A => return None,
                IGNv6 if query_type == AAAA => return None,
                _ => (),
            };
        }

        node = rule.zone(); // find parent rule
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        dns_conf::{AddressRuleValue, RuntimeConfig},
        dns_mw::*,
        libdns::proto::{
            op::{self, Query},
            rr::rdata,
        },
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn test_address_rule_soa_v6() {
        let cfg = RuntimeConfig::builder()
            .with("domain-rule /google.com/ -address #6")
            .build()
            .unwrap();

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"google.com".parse().unwrap())
                .cloned()
                .unwrap()
                .address,
            Some(AddressRuleValue::SOAv6)
        );

        let mock = DnsMockMiddleware::mock(AddressMiddleware)
            .with_a_record("google.com", "8.8.8.8".parse().unwrap())
            .with_aaaa_record("google.com", "2001:4860:4860::8888".parse().unwrap())
            .build(cfg);

        // 修复：合成 SOA 按 RFC 规范放在 Authority 区（不再放 Answer 区），
        // 所以要用 lookup() 取完整响应后断言 authorities()，
        // 不能再用只能看 Answer 区的 lookup_rdata()（那是修复前的写法）。
        let res = mock.lookup("google.com", RecordType::AAAA).await.unwrap();
        assert!(
            res.answers().is_empty(),
            "-address #6 表示 AAAA 查询返回 SOA，Answer 区应为空"
        );
        assert!(matches!(
            res.authorities().first().unwrap().data(),
            RData::SOA(_)
        ));

        // A 查询不受该规则影响，仍返回真实地址
        assert_eq!(
            mock.lookup_rdata("google.com", RecordType::A)
                .await
                .unwrap()[0],
            RData::A("8.8.8.8".parse().unwrap())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_address_rule_soa2() {
        let cfg = RuntimeConfig::builder()
            .with(r#"domain-rule /google.com/ -address 1.2.3.4"#)
            .build()
            .unwrap();

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"google.com".parse().unwrap())
                .cloned()
                .unwrap()
                .address,
            Some(AddressRuleValue::Addr {
                v4: Some(["1.2.3.4".parse().unwrap()].into()),
                v6: None
            })
        );

        let mock = DnsMockMiddleware::mock(AddressMiddleware)
            .with_a_record("google.com", "8.8.8.8".parse().unwrap())
            .with_aaaa_record("google.com", "2001:4860:4860::8888".parse().unwrap())
            .build(cfg);

        assert_eq!(
            mock.lookup_rdata("google.com", RecordType::A)
                .await
                .unwrap()[0],
            RData::A("1.2.3.4".parse().unwrap())
        );

        assert_eq!(
            mock.lookup_rdata("google.com", RecordType::AAAA)
                .await
                .unwrap()[0],
            RData::AAAA("::ffff:1.2.3.4".parse().unwrap())
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_rule_without_explicit_group_returns_group_address() {
        let cfg = RuntimeConfig::builder()
            .with("address /wiki.lan/192.168.1.5")
            .with("group-begin group-a")
            .with("client-rules 192.168.100.0/24")
            .with("address /wiki.lan/192.168.100.5")
            .with("group-end")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(AddressMiddleware).build(cfg);

        let mut query = Query::query("wiki.lan".parse().unwrap(), RecordType::A);
        query.set_query_class(crate::libdns::proto::rr::DNSClass::IN);

        let mut message = op::Message::query();
        message.add_query(query.clone());
        let req_group_a = DnsRequest::new(
            message,
            "192.168.100.23:5300".parse().unwrap(),
            crate::libdns::Protocol::Udp,
        );

        let mut message = op::Message::query();
        message.add_query(query);
        let req_lan = DnsRequest::new(
            message,
            "192.168.1.23:5300".parse().unwrap(),
            crate::libdns::Protocol::Udp,
        );

        let res_group_a = mock
            .search(&req_group_a, &Default::default())
            .await
            .unwrap();
        let res_lan = mock.search(&req_lan, &Default::default()).await.unwrap();

        assert_eq!(
            res_group_a.records().first().unwrap().data(),
            &RData::A("192.168.100.5".parse().unwrap())
        );
        assert_eq!(
            res_lan.records().first().unwrap().data(),
            &RData::A("192.168.1.5".parse().unwrap())
        );
    }

    // 已删除 test_client_rule_uses_edns_client_subnet_for_group_matching。
    // 它断言用 EDNS Client Subnet 参与 client-rules 的规则组匹配（且 ECS 覆盖来源 IP），
    // 但该语义是错的：ECS 是客户端可自报的"声明"，而 client-rules 的分流/ACL 必须基于
    // 不可伪造的真实来源 IP 或 MAC。参考实现（pymumu 的 C 版 smartdns）没有这个功能——
    // 官方文档明确 ECS 的定位是"向上游声明客户端子网、以优化上游返回的 IP"，
    // client-rules / group-match 的匹配依据只有 ip-set / ip/subnet / mac / domain。
    // 按客户端子网分流请使用 group-match -client-ip（或原有的 client-rules）。

    // 说明：原先这里有 test_ttl_clip_ttl_min / _max / _min_max 三个测试，
    // 它们断言 AddressMiddleware 会按 rr-ttl-min/max 裁剪 TTL。
    // 但该逻辑后来被有意搬到了 NS 中间件（dns_mw_ns.rs，注释："在刚拿到上游包裹时，
    // 立刻用配置的界限去约束它"），文档 docs/zh/configuration.md 也写明 rr-ttl-min/max
    // 作用于「远程查询结果」。因此这三个测试测错了层，一直失败。
    // 对应的裁剪语义已由 dns_mw_ns.rs 的 clamp_ttl_tests 直接覆盖。

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ttl_clip_ttl_max_reply() -> Result<(), DnsError> {
        let cfg = RuntimeConfig::builder()
            .with("rr-ttl-max 66")
            .with("rr-ttl-min 55")
            .with("rr-ttl-reply-max 30")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(AddressMiddleware)
            .with_multi_records(
                "dns.google",
                RecordType::A,
                vec![
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        96,
                        RData::A("8.8.8.8".parse().unwrap()),
                    ),
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        48,
                        RData::A("8.8.4.4".parse().unwrap()),
                    ),
                ],
            )
            .build(cfg);

        let lookup = mock.lookup("dns.google", RecordType::A).await?;

        assert!(lookup.record_iter().all(|r| r.ttl() == 30));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ttl_clip_ttl_max_reply_ip_num() -> Result<(), DnsError> {
        let cfg = RuntimeConfig::builder()
            .with("rr-ttl-max 66")
            .with("rr-ttl-min 55")
            .with("rr-ttl-reply-max 30")
            .with("max-reply-ip-num 2")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(AddressMiddleware)
            .with_multi_records(
                "dns.google",
                RecordType::A,
                vec![
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        96,
                        RData::A("8.8.8.8".parse().unwrap()),
                    ),
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        48,
                        RData::A("8.8.4.4".parse().unwrap()),
                    ),
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        48,
                        RData::A("8.8.4.3".parse().unwrap()),
                    ),
                ],
            )
            .build(cfg);

        let lookup = mock.lookup("dns.google", RecordType::A).await?;

        assert_eq!(lookup.records().len(), 2);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ttl_clip_ttl_max_reply_ip_num_1() -> Result<(), DnsError> {
        let cfg = RuntimeConfig::builder()
            .with("rr-ttl-max 66")
            .with("rr-ttl-min 55")
            .with("rr-ttl-reply-max 30")
            .with("max-reply-ip-num 1")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(AddressMiddleware)
            .with_multi_records(
                "dns.google",
                RecordType::A,
                vec![Record::from_rdata(
                    "dns.google".parse().unwrap(),
                    96,
                    RData::A("8.8.8.8".parse().unwrap()),
                )],
            )
            .build(cfg);

        let lookup = mock.lookup("dns.google", RecordType::A).await?;

        assert_eq!(lookup.records().len(), 1);

        Ok(())
    }

    // 已删除 test_ttl_clip_ttl_max_reply_ip_num_2：
    // 它的正文与 test_ttl_clip_ttl_max_reply_ip_num 逐字节相同（只有函数名不同），
    // 是纯粹的重复，删掉不损失任何覆盖。


    #[tokio::test(flavor = "multi_thread")]
    async fn test_ttl_clip_ttl_cname_max_reply_ip_num_2() -> Result<(), DnsError> {
        let cfg = RuntimeConfig::builder()
            .with("rr-ttl-max 66")
            .with("rr-ttl-min 55")
            .with("rr-ttl-reply-max 30")
            .with("max-reply-ip-num 2")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(AddressMiddleware)
            .with_multi_records(
                "dns.google",
                RecordType::A,
                vec![
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        96,
                        RData::CNAME(rdata::CNAME("dns.google".parse::<Name>().unwrap())),
                    ),
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        96,
                        RData::A("8.8.8.8".parse().unwrap()),
                    ),
                    Record::from_rdata(
                        "dns.google".parse().unwrap(),
                        48,
                        RData::A("8.8.4.4".parse().unwrap()),
                    ),
                ],
            )
            .build(cfg);

        let lookup = mock.lookup("dns.google", RecordType::A).await?;

        let ip_count: u8 = lookup
            .record_iter()
            .map(|r| matches!(r.data(), RData::A(_) | RData::AAAA(_)) as u8)
            .sum();

        assert_eq!(ip_count, 2);

        Ok(())
    }
}
