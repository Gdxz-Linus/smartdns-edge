use std::net::IpAddr;
use std::time::Duration;
use std::sync::LazyLock;
use tokio::sync::Semaphore;

// 🌟 双栈测速专用限流关卡，保护系统底层不受 ICMP/TCP 测速风暴冲击
static PING_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1500));

use futures::FutureExt;

use crate::config::SpeedCheckMode;
use crate::dns::*;
use crate::middleware::*;

// 🌟 回归最原始的纯粹状态：没有 Mutex，没有 HashMap，没有频道！就是一个无状态的并发分发器！
pub struct DnsDualStackIpSelectionMiddleware {}

impl DnsDualStackIpSelectionMiddleware {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError>
    for DnsDualStackIpSelectionMiddleware
{
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        use RecordType::{A, AAAA};

        let query_type = req.query().query_type();

        if !query_type.is_ip_addr() {
            return next.run(ctx, req).await;
        }
		
        // 如果被强制要求返回 SOA（行政禁赛），则不分裂，直接放行本尊
        if ctx.server_opts.force_aaaa_soa() || ctx.cfg().force_aaaa_soa() {
            return next.run(ctx, req).await;
        }

        let dualstack_enabled = !ctx.server_opts.no_dualstack_selection() && ctx
            .domain_rule
            .as_ref()
            .map(|rule| rule.dualstack_ip_selection)
            .unwrap_or_default()
            .unwrap_or(ctx.cfg().dualstack_ip_selection());

        let allow_force_aaaa = ctx.cfg().dualstack_ip_allow_force_aaaa();
        let selection_threshold = Duration::from_millis(ctx.cfg().dualstack_ip_selection_threshold());
        let speed_check_mode = ctx.domain_rule.get_ref(|r| r.speed_check_mode.as_ref()).cloned().unwrap_or_default();
		
        // 🌟 提取 name，供后续的探针 SNI 测速使用
        let name = req.query().original().name().to_string();

        let that_type = match query_type {
            A => AAAA,
            AAAA => A,
            typ => typ,
        };

        // 🌟 原汁原味的并发分裂：强行克隆兄弟类型，用 join! 缝合平行宇宙
        let mut that_ctx = ctx.clone();
        let that_req = {
            let mut req = req.clone();
            req.set_query_type(that_type);
            req
        };

        let that_fut = next.clone().run(&mut that_ctx, &that_req);
        let this_fut = next.run(ctx, req);
        
        // 两个请求同时向下层 (NS模块) 并发，NS模块会负责它们的安全流转
        let (this_res, that_res) = tokio::join!(this_fut, that_fut);

        // 🌟 智能半包容错 (Best-Effort) 与 宁缺毋滥 (Fail-Fast)
        let (mut this_resp, mut that_resp) = match (this_res, that_res) {
            (Ok(this), Ok(that)) => (this, that),
            
            // 单边容错 1：this 报错，that 拿到了真实 IP
            (Err(_), Ok(that)) if that.records().iter().any(|r| r.record_type().is_ip_addr()) => {
                crate::log::debug!("dual stack IP selection: {} , partial failure tolerated ({} survived)", req.query().original().name(), that_req.query().query_type());
                let mut empty = DnsResponse::empty();
                empty.add_query(req.query().original().clone());
                (empty, that)
            }
            
            // 单边容错 2：that 报错，this 拿到了真实 IP
            (Ok(this), Err(_)) if this.records().iter().any(|r| r.record_type().is_ip_addr()) => {
                crate::log::debug!("dual stack IP selection: {} , partial failure tolerated ({} survived)", req.query().original().name(), req.query().query_type());
                let mut empty = DnsResponse::empty();
                empty.add_query(that_req.query().original().clone());
                (this, empty)
            }

            // 宁缺毋滥：双双 Err，或者一死一空包。直接把底层报错抛出给用户，促使其重试！
            (Err(e), _) | (_, Err(e)) => {
                return Err(e);
            }
        };

        let (aaaa_resp_ref, a_resp_ref) = match query_type {
            AAAA => (&this_resp, &that_resp),
            A => (&that_resp, &this_resp),
            _ => unreachable!(),
        };

        let mut aaaa_blocked = false;
        let mut a_blocked = false;

        // 🌟 TTL 夹逼对齐逻辑保留
        let cfg_min_ttl = ctx.domain_rule.get(|r| r.rr_ttl_min)
            .map(|i| i as u32)
            .unwrap_or_else(|| ctx.cfg().rr_ttl_min().unwrap_or(60) as u32);

        let aaaa_ttl = aaaa_resp_ref.max_ttl();
        let a_ttl = a_resp_ref.max_ttl();

        let final_ttl = match (aaaa_ttl, a_ttl) {
            (Some(t1), Some(t2)) => t1.min(t2), 
            (Some(t), None) => t,               
            (None, Some(t)) => t,
            (None, None) => cfg_min_ttl,        
        };

        if dualstack_enabled {
            // 🌟 测速对决
            let race_result = which_faster(&name, aaaa_resp_ref, a_resp_ref, &speed_check_mode, selection_threshold).await;

            if race_result == Some(false) {
                aaaa_blocked = true;
                crate::log::debug!("dual stack IP selection: {} , A wins, block AAAA", req.query().original().name());
            } else if race_result == Some(true) {
                if allow_force_aaaa {
                    a_blocked = true;
                    crate::log::debug!("dual stack IP selection: {} , AAAA wins, block A", req.query().original().name());
                } else {
                    crate::log::debug!("dual stack IP selection: {} , AAAA wins, but force-AAAA is no, keep both", req.query().original().name());
                }
            } else {
                crate::log::debug!("dual stack IP selection: {} , Tie, keep both", req.query().original().name());
            }
        }


        // 🌟 智能安全洗包机
        let process_resp = |resp: &mut DnsResponse, blocked: bool, ttl: u32| {
            if blocked {
                resp.take_answers();
            }

            resp.set_new_ttl(ttl);

            let has_soa = resp.authorities().iter().any(|r| r.record_type() == RecordType::SOA) ||
                          resp.answers().iter().any(|r| r.record_type() == RecordType::SOA) ||
                          resp.additionals().iter().any(|r| r.record_type() == RecordType::SOA);

            let is_empty = resp.answers().is_empty()
                && resp.authorities().is_empty()
                && resp.additionals().is_empty();

            if !has_soa && (blocked || is_empty) {
                resp.take_answers();
                let soa_record = crate::dns::forge_soa_record(resp.query().name().clone(), ttl);
                resp.add_authority(soa_record);
            }
        };

        if query_type == RecordType::AAAA {
            process_resp(&mut this_resp, aaaa_blocked, final_ttl);
            process_resp(&mut that_resp, a_blocked, final_ttl);
        } else {
            process_resp(&mut this_resp, a_blocked, final_ttl);
            process_resp(&mut that_resp, aaaa_blocked, final_ttl);
        }

        // 🌟 结果入库：把兄弟记录打包推给上层 Cache 冰柜
        ctx.extra_cache_records.push((that_resp.query().clone(), that_resp));

        Ok(this_resp)
    }
}

// 🌟 测速大裁判（保持带有 name 的透传参数，实现 SNI 支持）
async fn which_faster(
    name: &str, 
    aaaa_resp: &DnsResponse,
    a_resp: &DnsResponse,
    modes: &[SpeedCheckMode],
    selection_threshold: Duration,
) -> Option<bool> {
    let aaaa_ips = aaaa_resp.ip_addrs();
    let a_ips = a_resp.ip_addrs();

    for mode in modes {
        let mut aaaa_fut = Box::pin(single_mode_ping_fastest(name, &aaaa_ips, mode));
        let mut a_fut = Box::pin(single_mode_ping_fastest(name, &a_ips, mode));

        let (first_res, is_aaaa_first) = tokio::select! {
            res = &mut aaaa_fut => (res, true),
            res = &mut a_fut => (res, false),
        };

        if let Some((_, _first_time)) = first_res {
            let grace_period = tokio::time::sleep(selection_threshold);
            tokio::pin!(grace_period);

            let second_res = tokio::select! {
                res = if is_aaaa_first { a_fut } else { aaaa_fut } => res,
                _ = &mut grace_period => None,
            };

            if let Some(_) = second_res {
                return None;
            } else {
                return Some(is_aaaa_first);
            }
        } else {
            let second_res = if is_aaaa_first { a_fut.await } else { aaaa_fut.await };
            if second_res.is_some() {
                return Some(!is_aaaa_first);
            }
            continue;
        }
    }
    None
}

// 🌟 测速引擎（保持 600ms 死线防挂起）
async fn single_mode_ping_fastest(
    domain: &str,
    ip_addrs: &[IpAddr],
    mode: &SpeedCheckMode,
) -> Option<(IpAddr, Duration)> {
    if ip_addrs.is_empty() { return None; }

    let dests = mode.to_ping_addrs(ip_addrs);
    if dests.is_empty() {
        return None;
    }

    let _permit = match PING_SEMAPHORE.acquire().await {
        Ok(p) => p,
        Err(_) => return None,
    };

    use crate::infra::ping::{PingOptions, ping_fastest};
    let duration = Duration::from_millis(600);

    let ping_ops = PingOptions::default().with_timeout(duration);

    let ping_task = ping_fastest(dests, Some(domain), ping_ops).boxed();
    let timeout_task = tokio::time::sleep(duration).boxed();

    match futures_util::future::select(ping_task, timeout_task).await {
        futures::future::Either::Left((Ok(ping_out), _)) => {
            Some((ping_out.dest().ip_addr(), ping_out.elapsed()))
        }
        _ => {
            None
        }
    }
}