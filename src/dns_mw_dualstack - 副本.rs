use std::net::IpAddr;
use std::time::Duration;
use std::sync::LazyLock;
use tokio::sync::Semaphore;

// 🌟 双栈测速共享同一个级别的限流关卡，防止测速风暴耗尽系统线程
static PING_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1500));

use futures::FutureExt;

use crate::config::SpeedCheckMode;
use crate::dns::*;
use crate::middleware::*;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

pub struct DnsDualStackIpSelectionMiddleware {
    // 🌟 等候室登记册：域名+分组 -> 广播频道 (返回处理好的 A 和 AAAA)
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<Option<(DnsResponse, DnsResponse)>>>>>,
}

impl DnsDualStackIpSelectionMiddleware {
    pub fn new() -> Self {
        Self { inflight: Arc::new(Mutex::new(HashMap::new())) }
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
		
		// 🌟 核心防御前置熔断：如果上面已经下达了行政禁赛令（强制 SOA），
        // 双栈模块立即解散，禁止克隆！禁止测速！原封不动放行本尊去查外网！
        if ctx.server_opts.force_aaaa_soa() || ctx.cfg().force_aaaa_soa() {
            return next.run(ctx, req).await;
        }

        // 🌟 核心统一：无论双栈优选开关是否打开，只要查 IP，必须强制拉起兄弟类型统筹入库！
        let dualstack_enabled = !ctx.server_opts.no_dualstack_selection() && ctx
            .domain_rule
            .as_ref()
            .map(|rule| rule.dualstack_ip_selection)
            .unwrap_or_default()
            .unwrap_or(ctx.cfg().dualstack_ip_selection());

        let allow_force_aaaa = ctx.cfg().dualstack_ip_allow_force_aaaa();
        let selection_threshold = Duration::from_millis(ctx.cfg().dualstack_ip_selection_threshold());
        let speed_check_mode = ctx.domain_rule.get_ref(|r| r.speed_check_mode.as_ref()).cloned().unwrap_or_default();
		
		// 👇=== 核心手术：双栈等候室 ===👇
        let group_name = ctx.server_group_name().to_string();
        let name = req.query().original().name().to_string();
        let cache_key = format!("{}:{}", name, group_name);

        let rx = {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.get(&cache_key) {
                Some(tx.subscribe()) // 大哥在干活，领个号码牌
            } else {
                let (tx, _) = broadcast::channel(1);
                map.insert(cache_key.clone(), tx);
                None // 我是第一个，我当大哥
            }
        };

        if let Some(mut receiver) = rx {
            return match receiver.recv().await {
                Ok(Some((a_resp, aaaa_resp))) => {
                    // 大哥干完活了！拿走属于我自己的那份返回即可！
                    if query_type == RecordType::A { Ok(a_resp) } else { Ok(aaaa_resp) }
                }
                _ => next.run(ctx, req).await, // 大哥阵亡，自己去跑
            };
        }

        let mut inflight_guard = InflightDualStackGuard {
            inflight: self.inflight.clone(),
            key: cache_key.clone(),
            done: false,
        };
        // 👆=== 手术结束 ===👆

        let that_type = match query_type {
            A => AAAA,
            AAAA => A,
            typ => typ,
        };

        // 🌟 并发分裂：强行克隆兄弟类型，用 join! 缝合平行宇宙
        let mut that_ctx = ctx.clone();
        let that_req = {
            let mut req = req.clone();
            req.set_query_type(that_type);
            req
        };

        let that_fut = next.clone().run(&mut that_ctx, &that_req);
        let this_fut = next.run(ctx, req);
        let (this_res, that_res) = tokio::join!(this_fut, that_fut);

        // 🌟 核心修正：智能半包容错 (Best-Effort) 与 宁缺毋滥 (Fail-Fast)
        // 1. 如果双双成功 (Ok)，完美放行。
        // 2. 如果单边超时 (Err)，且另一边拿到了【真实的 IP 记录】，为了保住用户的秒开体验，
        //    我们极其克制地容忍这个 Err，把它降级为合法空包，交由后续洗包机盖萝卜章。
        // 3. 如果单边超时 (Err)，但另一边是个空包 (NXDOMAIN/NoData)，或者双双超时，
        //    这极大概率是严重的网络断流！我们果断直接抛出真实错误，逼迫客户端重试！
        let (mut this_resp, mut that_resp) = match (this_res, that_res) {
            (Ok(this), Ok(that)) => (this, that),
            
            // 单边容错分支 1：this 报错了，但 that 拿到了真金白银的 IP
            (Err(_), Ok(that)) if that.records().iter().any(|r| r.record_type().is_ip_addr()) => {
                crate::log::debug!("dual stack IP selection: {} , partial failure tolerated ({} survived)", req.query().original().name(), that_req.query().query_type());
                let mut empty = DnsResponse::empty();
                empty.add_query(req.query().original().clone());
                (empty, that) // 强行把报错的 this 降级为空包，保全 that
            }
            
            // 单边容错分支 2：that 报错了，但 this 拿到了真金白银的 IP
            (Ok(this), Err(_)) if this.records().iter().any(|r| r.record_type().is_ip_addr()) => {
                crate::log::debug!("dual stack IP selection: {} , partial failure tolerated ({} survived)", req.query().original().name(), req.query().query_type());
                let mut empty = DnsResponse::empty();
                empty.add_query(that_req.query().original().clone());
                (this, empty) // 强行把报错的 that 降级为空包，保全 this
            }

            // 宁缺毋滥分支：包含双双 Err，以及一死(Err)一空包(NXDOMAIN)的绝对毒化场景
            (Err(e), _) | (_, Err(e)) => {
                inflight_guard.done = true; // 宣告本次并发折叠阵亡
                {
                    let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tx) = map.remove(&cache_key) {
                        let _ = tx.send(None); // 通知所有等候的小弟：大哥拿的是假数据或被车撞了，大家散了吧去重试！
                    }
                }
                return Err(e); // 绝不伪造残疾包污染缓存，把真实的底层超时错误扔出去！
            }
        };

        // 剥离繁琐的 Option，由于上述逻辑兜底，它们现在 100% 存在！
        let (aaaa_resp_ref, a_resp_ref) = match query_type {
            AAAA => (&this_resp, &that_resp),
            A => (&that_resp, &this_resp),
            _ => unreachable!(),
        };

        let mut aaaa_blocked = false;
        let mut a_blocked = false;

        // 🌟 救命的底裤：必须保留！专为“上游绝对空包”准备的萝卜章兜底寿命！
        let cfg_min_ttl = ctx.domain_rule.get(|r| r.rr_ttl_min)
            .map(|i| i as u32)
            .unwrap_or_else(|| ctx.cfg().rr_ttl_min().unwrap_or(60) as u32);

        let aaaa_ttl = aaaa_resp_ref.max_ttl();
        let a_ttl = a_resp_ref.max_ttl();

        let final_ttl = match (aaaa_ttl, a_ttl) {
            (Some(t1), Some(t2)) => t1.min(t2), // 双方都有，取最小同步
            (Some(t), None) => t,               // 只有一方有
            (None, Some(t)) => t,
            (None, None) => cfg_min_ttl,        // 🌟 极端兜底：上游啥也没给，用配置的 min_ttl 伪造空包寿命！
        };

        // 🌟 核心恢复：原封不动地还原你最初的、完美的规则状态机！
        if dualstack_enabled {
            // 🌟 修复：由于前面必定生成兜底空包，这里 100% 存在，无需再用 Option 拆包！直接传进去测速！
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


        // 🌟 辅助闭包：智能安全洗包机（强制同步双栈寿命 + 兜底空包萝卜章）
        let process_resp = |resp: &mut DnsResponse, blocked: bool, ttl: u32| {
            if blocked {
                resp.take_answers(); // 剥夺被淘汰者的 IP 记录
            }

            // 无差别强制同步该响应包内所有剩余记录的 TTL！
            resp.set_new_ttl(ttl);

            // 🌟 核心恢复：严格判断是否存在原有 SOA！绝不覆盖上游的真实权威记录！
            let has_soa = resp.authorities().iter().any(|r| r.record_type() == RecordType::SOA) ||
                          resp.answers().iter().any(|r| r.record_type() == RecordType::SOA) ||
                          resp.additionals().iter().any(|r| r.record_type() == RecordType::SOA);

            let is_empty = resp.answers().is_empty()
                && resp.authorities().is_empty()
                && resp.additionals().is_empty();

            // 只有在没有 SOA，并且是被剥夺了 IP 的残包或是纯空包时，才盖萝卜章
            if !has_soa && (blocked || is_empty) {
                resp.take_answers(); // 防御性清空
                // 🌟 调用公共的统一兵工厂
                let soa_record = crate::dns::forge_soa_record(resp.query().name().clone(), ttl);
                resp.add_authority(soa_record);
            }
        };

        // 🌟 目标达成：双栈记录 100% 被双双洗包并带回冰柜，彻底消灭幽灵击穿风暴！
        if query_type == RecordType::AAAA {
            process_resp(&mut this_resp, aaaa_blocked, final_ttl);
            process_resp(&mut that_resp, a_blocked, final_ttl);
        } else {
            process_resp(&mut this_resp, a_blocked, final_ttl);
            process_resp(&mut that_resp, aaaa_blocked, final_ttl);
        }

        // 👇=== 发送复印件 ===👇
        let (final_a, final_aaaa) = match query_type {
            RecordType::A => (this_resp.clone(), that_resp.clone()),
            RecordType::AAAA => (that_resp.clone(), this_resp.clone()),
            _ => unreachable!(),
        };

        {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.remove(&cache_key) {
                let _ = tx.send(Some((final_a, final_aaaa)));
            }
        }
        inflight_guard.done = true; // 广播完成，解除护卫队
        // 👆=== 分发结束 ===👆

        ctx.extra_cache_records.push((that_resp.query().clone(), that_resp));

        Ok(this_resp)
    }
}

// 🌟 终极大裁判：智能抢跑赛制（先比 TCP，双双失败再比 ICMP）
// 🌟 加入 name 参数
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
        // 🌟 把 name 传进去
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
                // 🌟 核心恢复：只要第二名在宽限期（threshold）内跑完冲线了，
                // 大裁判不看具体数值，直接宣布平局 (Tie)！
                // 这将完美触发上层的 “平局双双保留并同步 TTL” 的预期逻辑！
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

// 🌟 单一回合测速函数：保留 600ms 绝对死线，防止双黑洞导致内存泄漏死等！
async fn single_mode_ping_fastest(
    domain: &str, // 🌟 接收 domain
    ip_addrs: &[IpAddr],
    mode: &SpeedCheckMode,
) -> Option<(IpAddr, Duration)> {
    if ip_addrs.is_empty() { return None; }

    let dests = mode.to_ping_addrs(ip_addrs);
    if dests.is_empty() {
        return None;
    }

    // 🌟 智能熔断：拿不到令牌当场判负！连死线都不等，瞬间结束！
    let _permit = match PING_SEMAPHORE.try_acquire() {
        Ok(p) => p,
        Err(_) => return None,
    };

    use crate::infra::ping::{PingOptions, ping_fastest};
    let duration = Duration::from_millis(600);

    // 🌟 核心修复：消除超时倒挂陷阱！
    // 将底层 OS Socket (如 ICMP Tracker 或 TCP SYN 定时器) 的物理死亡时间，
    // 精准对齐上层 Tokio 裁判吹哨的时间。当系统判定超时，底层内核资源也会在同一毫秒被释放，杜绝僵尸端口！
    let ping_ops = PingOptions::default().with_timeout(duration);

    // 🌟 将 domain 转化为 Option<&str> 喂给底层引擎
    let ping_task = ping_fastest(dests, Some(domain), ping_ops).boxed();
    let timeout_task = tokio::time::sleep(duration).boxed();

    match futures_util::future::select(ping_task, timeout_task).await {
        futures::future::Either::Left((Ok(ping_out), _)) => {
            // 在 600ms 内测通了，返回真实耗时
            Some((ping_out.dest().ip_addr(), ping_out.elapsed()))
        }
        _ => {
            // 超时或者报错被拦截了，当场判负！
            None
        }
    }
}

// ==========================================
// 🌟 制造对讲机工牌：防止大哥半路阵亡导致小弟死等
// ==========================================
struct InflightDualStackGuard {
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<Option<(DnsResponse, DnsResponse)>>>>>,
    key: String,
    done: bool,
}

impl Drop for InflightDualStackGuard {
    fn drop(&mut self) {
        if !self.done {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = map.remove(&self.key) {
                let _ = tx.send(None);
            }
        }
    }
}
