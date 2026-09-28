use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Semaphore;

// 🌟 双栈测速专用限流关卡，保护系统底层不受 ICMP/TCP 测速风暴冲击
static PING_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1500));

use futures::FutureExt;

use crate::config::{SpeedCheckMode, SpeedCheckModeList};
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

        // 如果**本次查的就是 AAAA**、且被强制要求返回 SOA（行政禁赛），则不分裂，直接放行本尊。
        //
        // 🔐 问题 27-1：这里**必须限定 `query_type == AAAA`**。
        //
        // `force-AAAA-SOA` 的定义域是"**AAAA 查询**直接回 SOA"（见 `dns_mw_addr.rs` 的守卫，
        // 那里写的就是 `AAAA if ctx.force_aaaa_soa()`）。而原先这里只判 `ctx.force_aaaa_soa()`、
        // 不带类型条件，于是**打开了这个开关的用户，连 A 查询也不再分裂**。
        //
        // 后果不是"少压一族"（那是报告原先的描述），而是两条：
        //   ① A 查询不再顺带刷新 AAAA 记录 —— `ctx.extra_cache_records` 那条通道整个断掉，
        //      缓存里的 AAAA 条目失去唯一的顺带刷新来源；
        //   ② 与 `dns_mw_addr` 的口径不一致：同一个开关，两处定义域不同。
        //
        // 改回限定 AAAA 之后，A 查询恢复分裂；而分裂出来的那条 AAAA 兄弟查询**仍会**被
        // 内层的 `dns_mw_addr` 换成 SOA（它自己就是 AAAA 查询，照旧命中那条守卫），
        // 所以"别给客户端 AAAA"的意图**不受影响**。
        // 🔐 问题 27-1：本中间件是做 A/AAAA **双栈选择**的，所以只有在
        // "本次查的就是 AAAA"时才让 `force-AAAA-SOA` 短路它。
        if should_bypass_for_force_aaaa_soa(query_type, ctx.force_aaaa_soa()) {
            return next.run(ctx, req).await;
        }

        // 📌 丙-2c：双栈优选的取值链补成 **域名规则 > 组级 > 全局**（三层，正向布尔）。
        //
        // ⚠️ **bind 级那个 `-no-dualstack-selection` 不在链上**，它是**单向总闸**
        // （只能关、不能开）：语义是"这个监听整体不做双栈优选"，
        // 与"某一层把开关配成什么"是两件事。所以它保持在外面的 `&&` 上。
        //
        // 判据抽成纯函数 `resolve_dualstack_selection`（与 `resolve_speed_check_mode` 同形），
        // 让"域名规则压过组级、组级压过全局"能被直接单测 ——
        // 原先这三层是嵌套的 `unwrap_or_default().unwrap_or(...)`，埋在 async 里测不到。
        let dualstack_enabled = !ctx.server_opts.no_dualstack_selection()
            && crate::config::resolve_dualstack_selection(
                ctx.domain_rule
                    .as_ref()
                    .map(|rule| rule.dualstack_ip_selection),
                ctx.cfg()
                    .group_params(ctx.effective_rule_group())
                    .dualstack_ip_selection,
                ctx.cfg().dualstack_ip_selection,
            );

        let allow_force_aaaa = ctx.dualstack_ip_allow_force_aaaa();
        let selection_threshold = Duration::from_millis(ctx.dualstack_ip_selection_threshold());

        // 🔐 问题 24：测速模式的取值口径必须与上游选 IP **完全一致**。
        //
        // ## 原缺陷
        //
        // 这里原来写的是：
        //
        //     ctx.domain_rule.get_ref(|r| r.speed_check_mode.as_ref())
        //         .cloned().unwrap_or_default()
        //
        // 两个问题叠在一起，结果是**用户配了也不生效**：
        //
        // ① **不回落到全局**：全局 `speed-check-mode` 对双栈完全不可见。上游那条路径
        //    （`dns_mw_ns.rs`）写的是"域名规则没写就取 `cfg.speed_check_mode()`"，
        //    两条路径对同一个配置项给出不同答案。
        //
        // ② **`none` 被当成"没配"**：解析器把 `speed-check-mode none` 解析成
        //    `Option::None`（见 `config/parser/speed_mode.rs`），而 `.unwrap_or_default()`
        //    的范围是 `SpeedCheckModeList::default()` = `[Ping, Tcp(443)]`。
        //    于是用户写 `none` 想关掉测速，双栈这边反而**拿默认值去探测** ——
        //    与意图正好相反，而且没有任何提示。
        //
        // 上游 C 版是**两级回落**（`dns_server/rules.c` 的 `_dns_server_process_speed_rule`：
        // 域名规则命中就用，否则用 `request->conf` 的组级/全局值），本实现对齐它。
        //
        // ## 现在的口径（与上游 C 版一致，用户定调）
        //
        //   1. 域名规则写了自己的测速模式 → 用它（含 `-c none`）；
        //   2. 否则取全局 `speed-check-mode`（含全局 `none`）；
        //   3. 两者都没写 → **默认模式**（`ping` + `tcp:443`）⇒ **要测速**。
        //
        // ⚠️ 第 3 条是"要测速"、**不是**"不测速" —— 这与上游 C 版一致：
        // C 版在 `_dns_conf_default_value_init()` 里把默认 `check_orders` 显式填成
        // `ping,tcp:80,tcp:443`，即"没写这一行"从来不等于"关掉测速"。
        //
        // 这一条口径由 `config::resolve_speed_check_mode` **统一提供**，
        // 上游选 IP 与双栈两条路径**共用同一个函数** —— 问题 24 的本质就是
        // 这两条路径各自算各自的、口径不一，共用之后就**不可能再分叉**。
        //
        // ⚠️ 为什么"不测速"就等于"跳过族对决"、而不是"用别的模式兜底"：
        // 族对决的**唯一输入**就是测速结果（`which_faster` 靠 ping 探针判谁快）。
        // 没有测速就没有判据，此时唯一诚实的做法是**不压制任何一族**，
        // 而不是替用户另选一个模式去探测。这与上游在 `none` 时置
        // `FastestResponse`（跳过按延迟挑选）是同一取向。
        //
        // ⚠️ 判"关"必须用 `any(|m| m.is_none())` 而不是 `is_none()`：
        // 前者覆盖"用户写了 `none`"（`Some([None])`），后者覆盖的是"没写"。
        // 上游那条路径（`dns_mw_ns.rs`）用的正是 `any(...)`，两处保持一致。
        let speed_check_mode = crate::config::resolve_speed_check_mode(
            ctx.domain_rule.get_ref(|r| r.speed_check_mode.as_ref()),
            ctx.speed_check_mode().as_ref(),
        );

        // 🌟 提取 name：后面既用于探针的 SNI 测速，也用于各条诊断日志。
        let name = req.query().original().name().to_string();

        // 🔐 问题 24：`none` / `-no-speed-check` 时**显式跳过族对决**。
        //
        // 判据有三个来源，任一成立即"不测速"：
        //   ① 配置里写了 `speed-check-mode none`（全局或域名规则级）；
        //   ② **本监听**写了 `bind ... -no-speed-check`（bind 级，优先级最高）；
        //   ③ （"未配置"**不**算——见下面 `resolve_speed_check_mode` 的说明：
        //      按用户定调，未配置与 C 版一致，视为**要用默认模式测速**）。
        //
        // ⚠️ 第 ② 条是**后补的**：原先双栈只读了 `no_dualstack_selection`，
        // **完全没有读 `no_speed_check`** —— 于是 `bind ... -no-speed-check` 在上游选 IP
        // 那条路径上生效（`dns_mw_ns.rs`），在双栈这条路径上**被静默忽略**。
        // 同一个"关测速"意图，两条路径表现不一致，属同一族问题。
        //
        // ⚠️ 这里只算标志位、**不打日志**：本段代码在**每个查询**上都会执行，
        // 而"测速被关、双栈优选失效"是一条**配置层面**的事，说一次就够 ——
        // 提示已放在配置摘要里（`dns_conf.rs` 的 `summary()`，启动与热重载各一次）。
        let speed_check_off =
            should_skip_speed_race(ctx.server_opts.no_speed_check(), &speed_check_mode);

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
                crate::log::debug!(
                    "dual-stack IP selection: {}; partial failure tolerated ({} survived)",
                    req.query().original().name(),
                    that_req.query().query_type()
                );
                let mut empty = DnsResponse::empty();
                empty.add_query(req.query().original().clone());
                (empty, that)
            }

            // 单边容错 2：that 报错，this 拿到了真实 IP
            (Ok(this), Err(_)) if this.records().iter().any(|r| r.record_type().is_ip_addr()) => {
                crate::log::debug!(
                    "dual-stack IP selection: {}; partial failure tolerated ({} survived)",
                    req.query().original().name(),
                    req.query().query_type()
                );
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
            other => {
                // 🔐 P0-2：本中间件只做 A/AAAA 双栈选择；遇到别的类型直接旁路
                // （原样返回本次查询对应的响应），不 panic。
                crate::log::warn!("dualstack: unexpected record type {other:?}, bypass");
                return Ok(this_resp);
            }
        };

        let mut aaaa_blocked = false;
        let mut a_blocked = false;

        // 🌟 TTL 夹逼对齐逻辑保留
        let cfg_min_ttl = ctx
            .domain_rule
            .get(|r| r.rr_ttl_min)
            .map(|i| i as u32)
            .unwrap_or_else(|| ctx.rr_ttl_min().unwrap_or(60) as u32);

        let final_ttl = aligned_ttl_for(aaaa_resp_ref, a_resp_ref, cfg_min_ttl);

        if dualstack_enabled && !speed_check_off {
            // 🌟 测速对决
            let race_result = which_faster(
                &name,
                aaaa_resp_ref,
                a_resp_ref,
                &speed_check_mode,
                selection_threshold,
            )
            .await;

            if race_result == Some(false) {
                aaaa_blocked = true;
                crate::log::debug!(
                    "dual stack IP selection: {} , A wins, block AAAA",
                    req.query().original().name()
                );
            } else if race_result == Some(true) {
                if allow_force_aaaa {
                    a_blocked = true;
                    crate::log::debug!(
                        "dual stack IP selection: {} , AAAA wins, block A",
                        req.query().original().name()
                    );
                } else {
                    crate::log::debug!(
                        "dual stack IP selection: {} , AAAA wins, but force-AAAA is no, keep both",
                        req.query().original().name()
                    );
                }
            } else {
                crate::log::debug!(
                    "dual stack IP selection: {} , Tie, keep both",
                    req.query().original().name()
                );
            }
        }

        // 🌟 智能安全洗包机
        let process_resp = |resp: &mut DnsResponse, blocked: bool, ttl: u32| {
            if blocked {
                resp.take_answers();
            }

            resp.set_new_ttl(ttl);

            let has_soa = resp
                .authorities()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA)
                || resp
                    .answers()
                    .iter()
                    .any(|r| r.record_type() == RecordType::SOA)
                || resp
                    .additionals()
                    .iter()
                    .any(|r| r.record_type() == RecordType::SOA);

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
        ctx.extra_cache_records
            .push((that_resp.query().clone(), that_resp));

        Ok(this_resp)
    }
}

/// 双栈对齐时用的 TTL：从两族的应答里各取**最短**记录，再取两族中**较短**的那个。
///
/// 🔐 为什么必须取短的（这是本次修复的核心）：
/// 双栈优选会把 A 与 AAAA 两族记录的 TTL **统一改写成同一个值**，
/// 取值方向一旦偏大，就会**把原本短命的记录拉长**：
/// 例如 A 族有 60 秒和 3600 秒两条、AAAA 族是 3600 秒，
/// 若按「较长的」对齐就得到 3600，那条 60 秒的 A 记录会被静默改成 3600 ——
/// 上游用短 TTL 表达的意图（容灾切换、灰度、快速轮转）就此失效。
///
/// 更麻烦的是连带效应：缓存是按「最短 TTL」计算这条记录能存多久的，
/// 而它看到的响应**已经被抹平成同一个值**，于是缓存寿命跟着一起变长。
///
/// 取短的代价是缓存寿命偏保守、回源略多；这是刻意的取舍：
/// **宁可多查一次，也不拿过期数据糊弄客户端。**
///
/// 口径说明：
///   * 两族各自用 `min_ttl()`（整份响应里最短的一条）；
///   * 两边都有 → 取较小；只有一边有 → 取那一边（另一边是单边失败时补的空包）；
///   * 都没有 → 用配置下限 `rr-ttl-min`（与 `set_new_ttl` 的其它分支保持一致）。
fn aligned_ttl_for(aaaa_resp: &DnsResponse, a_resp: &DnsResponse, cfg_min_ttl: u32) -> u32 {
    let aaaa_ttl = aaaa_resp.min_ttl();
    let a_ttl = a_resp.min_ttl();

    match (aaaa_ttl, a_ttl) {
        (Some(t1), Some(t2)) => t1.min(t2),
        (Some(t), None) => t,
        (None, Some(t)) => t,
        (None, None) => cfg_min_ttl,
    }
}

/// 🔐 问题 24：**该不该跳过族对决**（即"这次不做测速"）。
///
/// 两个来源，任一成立即跳过：
///
/// ① **bind 级 `-no-speed-check`**（`bind 127.0.0.1:53 -no-speed-check`）——
///    这是**逐监听**的开关，优先级最高。
///    ⚠️ 本条是**后补的**：原先双栈只读了 `no_dualstack_selection`，
///    **完全没有读 `no_speed_check`**，于是同一个"关测速"意图在上游选 IP
///    那条路径上生效、在双栈这条路径上被静默忽略。属同一族问题。
/// ② **配置里写了 `none`**（域名规则级或全局）——`any(|m| m.is_none())`。
///
/// ⚠️ **"未配置"不在此列**：没写 `speed-check-mode` 时
/// `resolve_speed_check_mode` 会给出**默认模式列表**（不含 `None`），
/// 本函数因此返回 `false` ⇒ 照常测速。这与上游 C 版一致（用户定调）。
///
/// 抽成纯函数是为了让"两种关法都算数、而未配置不算"这条边界**可被单测钉住**。
fn should_skip_speed_race(no_speed_check: bool, modes: &SpeedCheckModeList) -> bool {
    no_speed_check || modes.iter().any(|m| m.is_none())
}

/// 🔐 问题 24：`force-AAAA-SOA` 该不该让双栈**整个旁路**？（与 27-1 同节，见下）
///
/// 只在该开关**开着**、且**本次查的就是 AAAA** 时为真。
///
/// ## 为什么要限定 AAAA（原缺陷）
///
/// `force-AAAA-SOA` 的定义域是"**AAAA 查询**直接回 SOA"——
/// 证据是地址规则里那条守卫写的就是 `AAAA if ctx.force_aaaa_soa()`
/// （`dns_mw_addr.rs`）。而本中间件原先只判开关、不带类型条件，于是
/// **打开了这个开关的用户，连 A 查询也不再分裂**。
///
/// 后果不是报告原先说的"少压一族"，而是两条真实影响：
///   ① A 查询不再顺带查询兄弟 AAAA 记录 —— `ctx.extra_cache_records` 那条通道整个断掉，
///      缓存里的 AAAA 条目因此失去唯一的顺带刷新来源；
///   ② 同一个开关在两处定义域不同，属一致性问题。
///
/// ## 限定 AAAA 之后，"别给客户端 AAAA"的意图**不受影响**
///
/// A 查询恢复分裂后，那条 AAAA 兄弟查询会**自己**走到地址规则，
/// 而它本身就是 AAAA 查询，照旧命中 `AAAA if ctx.force_aaaa_soa()` ⇒ 被换成 SOA。
/// 也就是说：客户端**仍然拿不到 AAAA 的地址**，只是缓存里那条 AAAA 得到了正常维护。
///
/// 抽成纯函数是为了**可被单测钉住**（原先没有任何测试覆盖这条分支，
/// 撤掉修复时全部测试照样通过 —— 已如实记录在《实施记录》）。
fn should_bypass_for_force_aaaa_soa(
    query_type: crate::libdns::proto::rr::RecordType,
    force_soa: bool,
) -> bool {
    force_soa && query_type == crate::libdns::proto::rr::RecordType::AAAA
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

            if second_res.is_some() {
                return None;
            } else {
                return Some(is_aaaa_first);
            }
        } else {
            let second_res = if is_aaaa_first {
                a_fut.await
            } else {
                aaaa_fut.await
            };
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
    if ip_addrs.is_empty() {
        return None;
    }

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
        _ => None,
    }
}

#[cfg(test)]
mod aligned_ttl_tests {
    use super::aligned_ttl_for;
    use crate::dns::DnsResponse;
    use crate::libdns::proto::{
        op::{Message, Query},
        rr::{Name, RData, Record, RecordType},
    };

    /// 造一个带若干条 A 记录（各自不同 TTL）的响应
    fn resp_with_ttls(ttls: &[u32]) -> DnsResponse {
        let mut msg = Message::query();
        let name: Name = "example.test".parse().unwrap();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        let mut message: Message = msg;
        for (i, ttl) in ttls.iter().enumerate() {
            let ip: std::net::Ipv4Addr = format!("192.0.2.{}", i + 1).parse().unwrap();
            message.add_answer(Record::from_rdata(name.clone(), *ttl, RData::A(ip.into())));
        }
        DnsResponse::from(message)
    }

    /// 空响应（模拟单边失败时补的占位包）
    fn empty_resp() -> DnsResponse {
        DnsResponse::empty()
    }

    /// 🔐 核心回归：双栈对齐必须取「较短」的那个，而不是较长的。
    ///
    /// 这个测试直接调用中间件使用的那条路径（`aligned_ttl_for`），
    /// 所以若把实现改回 `max_ttl()`，它**一定会失败**。
    #[test]
    fn alignment_takes_the_shorter_side() {
        // A 族有 60 与 3600 两条（最短 60），AAAA 族 3600 → 结果必须是 60
        let a = resp_with_ttls(&[60, 3600]);
        let aaaa = resp_with_ttls(&[3600]);

        assert_eq!(
            aligned_ttl_for(&aaaa, &a, 30),
            60,
            "必须取较短的一族，不能把短 TTL 拉长（修复前会得到 3600）"
        );

        // 顺序无关
        assert_eq!(aligned_ttl_for(&a, &aaaa, 30), 60);
    }

    /// 两族各自取最短，再对齐 —— 等价于「两族所有记录里的最小值」。
    #[test]
    fn alignment_equals_the_global_minimum_across_both_families() {
        let a = resp_with_ttls(&[60, 120]);
        let aaaa = resp_with_ttls(&[300, 600]);
        assert_eq!(aligned_ttl_for(&aaaa, &a, 30), 60);
    }

    /// 单边失败（另一边拿不到任何记录）时，取有值的那一边。
    #[test]
    fn alignment_falls_back_to_the_available_side() {
        let a = resp_with_ttls(&[120]);
        let empty = empty_resp();

        assert_eq!(aligned_ttl_for(&a, &empty, 30), 120);
        assert_eq!(aligned_ttl_for(&empty, &a, 30), 120);
    }

    /// 两边都拿不到 TTL 时用配置下限（与 `set_new_ttl` 的其它分支口径一致）。
    #[test]
    fn alignment_uses_config_min_when_both_missing() {
        let empty = empty_resp();
        assert_eq!(aligned_ttl_for(&empty, &empty, 45), 45);
    }

    /// 用 `rr-ttl-min` 抬起下限后，对齐结果不会低于它 —— 说明配置能兜住地板。
    #[test]
    fn config_min_provides_a_floor() {
        // 上游给了 3 秒，配置下限是 60：模拟 NS 中间件先把 TTL 抬到 60 之后的情形
        let a = resp_with_ttls(&[60]);
        let aaaa = resp_with_ttls(&[60]);
        assert_eq!(aligned_ttl_for(&aaaa, &a, 60), 60);
    }

    // ───────────────── 🔐 问题 24：测速模式的取值口径 ─────────────────
    //
    // 这一组直接测中间件用到的那条路径（`resolve_speed_check_mode`），
    // 因此把实现改回「只读域名规则 + `unwrap_or_default()`」，前两条**一定会失败**。

    // 🔐 问题 24：取值口径由 `config::resolve_speed_check_mode` 统一提供
    // （上游选 IP 与双栈**共用同一个函数**，见该函数的说明）。
    use crate::config::resolve_speed_check_mode;
    use crate::config::{SpeedCheckMode, SpeedCheckModeList};

    fn modes(list: &[SpeedCheckMode]) -> SpeedCheckModeList {
        SpeedCheckModeList(list.to_vec())
    }

    /// 🔐 核心：**域名规则没写时，必须回落到全局**（原实现完全不看全局）。
    ///
    /// 这是问题 24 的第一层：用户把 `speed-check-mode` 写在顶层，
    /// 双栈那条路径却当作"没配"，于是拿自己的默认值去探测。
    #[test]
    fn global_speed_check_mode_is_visible_to_the_dualstack_path() {
        let global = modes(&[SpeedCheckMode::Tcp(5353)]);
        let resolved = resolve_speed_check_mode(None, Some(&global));

        assert_eq!(
            resolved, global,
            "域名规则没写时必须回落到全局（修复前会得到默认的 ping+tcp:443，全局被完全忽略）"
        );
    }

    /// 🔐 核心：**全局配了 `none` 时，双栈也必须"不测速"**。
    ///
    /// ⚠️ 这条正是问题 24 的要害：原实现用 `.unwrap_or_default()`，
    /// 而 `SpeedCheckModeList::default()` 是 `[Ping, Tcp(443)]` ——
    /// 于是用户写 `none` 想关掉测速，双栈反而**拿默认值去探测**，与意图正好相反。
    ///
    /// 判别力说明：若把 `resolve_speed_check_mode` 改回 `.unwrap_or_default()`，
    /// 本测试会拿到 `[Ping, Tcp(443)]`、`any(is_none)` 为 false ⇒ **必然失败**。
    #[test]
    fn explicit_none_turns_the_race_off() {
        let global = modes(&[SpeedCheckMode::None]);
        let resolved = resolve_speed_check_mode(None, Some(&global));

        assert!(
            resolved.iter().any(|m| m.is_none()),
            "全局 `speed-check-mode none` 必须被双栈看到并判为'不测速'；\
             实际得到 {:?} —— 这正是修复前会拿默认值去测速的那个分支",
            resolved
        );
    }

    /// 域名规则写了就用它，**压过全局**（三层口径里最内层优先）。
    #[test]
    fn domain_rule_beats_global() {
        let global = modes(&[SpeedCheckMode::None]);
        let domain = modes(&[SpeedCheckMode::Ping]);

        let resolved = resolve_speed_check_mode(Some(&domain), Some(&global));
        assert_eq!(
            resolved, domain,
            "域名规则显式写了测速模式时，应当压过全局的 none"
        );
    }

    /// 域名规则的 `-c none` 同样生效（解析器给的是 `Some([None])`）。
    #[test]
    fn domain_rule_none_also_turns_the_race_off() {
        let domain = modes(&[SpeedCheckMode::None]);
        let resolved = resolve_speed_check_mode(Some(&domain), None);
        assert!(
            resolved.iter().any(|m| m.is_none()),
            "域名规则写 `-c none` 时双栈也应当不测速"
        );
    }

    /// 🔐 **用户定调（2026-09-26）**：两层都没写时，**得到默认模式 = 要测速**。
    ///
    /// 口径与**上游 C 版一致**：C 版在 `_dns_conf_default_value_init()` 里把默认
    /// `check_orders` 显式填成 `ping,tcp:80,tcp:443`，即"没写这一行"**从不等于**
    /// "关掉测速"。
    ///
    /// 这条测试钉住的是"**未配置 ≠ 不测速**"这个**关键区分**：
    ///   · 没写        → 默认模式列表（不含 `None`）⇒ 照常族对决；
    ///   · 写了 `none` → `Some([None])` ⇒ 跳过族对决（见 `explicit_none_turns_the_race_off`）。
    ///
    /// ⚠️ 判据必须同时看两件事：**既非空、也不含 `None`** ——
    /// 只判"`any(is_none)` 为假"是不够的，一个**空列表**也能满足它。
    #[test]
    fn unset_means_default_modes_not_off() {
        let resolved = resolve_speed_check_mode(None, None);

        assert!(
            !resolved.iter().any(|m| m.is_none()),
            "未配置**不等于**不测速 —— 应当是默认模式"
        );
        assert!(
            !resolved.is_empty(),
            "未配置时不能得到空列表（空列表会让下面所有模式都不探测，等价于悄悄关掉测速）"
        );
        assert_eq!(
            resolved,
            SpeedCheckModeList::default(),
            "未配置时应当等于默认模式（ping + tcp:443，与上游 C 版一致的取向）"
        );
    }

    // ───────────── 🔐 问题 24 补充：bind 级 `-no-speed-check` ─────────────

    use super::should_skip_speed_race;

    /// 🔐 **bind 级 `-no-speed-check` 必须让双栈也跳过族对决**。
    ///
    /// 原缺陷：双栈只读了 `no_dualstack_selection`，**完全没读 `no_speed_check`** ——
    /// 于是 `bind ... -no-speed-check` 在上游选 IP 那条路径上生效
    /// （`dns_mw_ns.rs` 用它强制 `FastestResponse`），在双栈这条路径上**被静默忽略**。
    /// 用户加了这个选项本该"这条监听不测速"，实际只生效了一半。
    ///
    /// 判别力：撤掉 `should_skip_speed_race` 里的 `no_speed_check ||`，本测试必然失败。
    #[test]
    fn bind_level_no_speed_check_skips_the_race() {
        // 模式是"要测速"的默认值，但 bind 级显式关掉了 → 仍应跳过
        let modes = SpeedCheckModeList::default();
        assert!(
            should_skip_speed_race(true, &modes),
            "bind 级 `-no-speed-check` 必须让双栈跳过族对决（原先被静默忽略）"
        );
    }

    /// 与上一条成对：**没有 bind 级开关、模式也不是 `none` 时，不该跳过**。
    ///
    /// 这条防止"修复方向反了"—— 例如把判据写成恒真，就会让族对决彻底失效。
    #[test]
    fn race_runs_when_neither_bind_nor_none_disables_it() {
        let modes = SpeedCheckModeList::default();
        assert!(
            !should_skip_speed_race(false, &modes),
            "两层都没要求关测速时，族对决必须照常进行"
        );

        // 显式给了普通模式（非 none）也一样
        let modes = SpeedCheckModeList(vec![SpeedCheckMode::Ping]);
        assert!(
            !should_skip_speed_race(false, &modes),
            "配了 ping 时应当照常族对决"
        );
    }

    /// 两种"关测速"的来源**都可以**触发跳过（`none` 与 bind 级）。
    #[test]
    fn both_none_and_bind_disable_the_race() {
        let none_modes = SpeedCheckModeList(vec![SpeedCheckMode::None]);

        assert!(
            should_skip_speed_race(false, &none_modes),
            "配置写了 none → 跳过"
        );
        assert!(
            should_skip_speed_race(true, &none_modes),
            "两者同时成立 → 仍然跳过（不应互相抵消）"
        );
    }

    // ───────────── 🔐 问题 27-1：`force-AAAA-SOA` 的旁路范围 ─────────────

    use super::should_bypass_for_force_aaaa_soa;

    /// 🔐 核心：`force-AAAA-SOA` 开着时，**只有 AAAA 查询**才旁路双栈。
    ///
    /// ⚠️ 这条测试是**必需的**：修复前本文件对这条分支**没有任何覆盖**，
    /// 撤掉修复时全部测试照样通过（反向验证当场暴露了这个缺口）。
    #[test]
    fn force_aaaa_soa_only_bypasses_the_aaaa_query() {
        assert!(
            should_bypass_for_force_aaaa_soa(RecordType::AAAA, true),
            "AAAA 查询 + 开关打开 → 旁路（这正是'AAAA 直接回 SOA'的语义）"
        );

        assert!(
            !should_bypass_for_force_aaaa_soa(RecordType::A, true),
            "⚠️ A 查询**不得**被旁路 —— 修复前正是这里把 A 查询也短路了，\
             导致 A 查询不再分裂、缓存里的 AAAA 失去顺带刷新"
        );
    }

    /// 开关关着时，任何类型都不旁路（默认行为零变化）。
    #[test]
    fn force_aaaa_soa_off_never_bypasses() {
        for qt in [RecordType::A, RecordType::AAAA] {
            assert!(
                !should_bypass_for_force_aaaa_soa(qt, false),
                "开关没开时 {qt:?} 不该被旁路"
            );
        }
    }
}
