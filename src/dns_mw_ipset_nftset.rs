//! 把解析结果写进内核的"集合"—— nftables 的 set（nftset）与 Linux 的 ipset。
//!
//! 两个后端共用同一条流水线：**取这条回答里的 IP → 按地址族分开 → 丢给阻塞池去写内核**，
//! 并用同一个信号量保护阻塞线程池（内核调用是同步的，`max_blocking_threads` 那点容量要省着用）。
//!
//! 🔐 Q1（本次新增 ipset）的三处关键取舍：
//!   1. **不复制一份中间件**：ipset 与 nftset 只差"往哪儿写"，取 IP、分区、限流、降载、
//!      失败可见这些逻辑一模一样，复制一份必然出现"以后改一处忘另一处"。
//!   2. **写失败要看得见**：nftset 走的是 C 版那套（只写不读回执），ipset 这边我们带
//!      `NLM_F_ACK` 读回执，失败按"集合名 + 原因"限流告警一次 —— 集合名写错、权限不足、
//!      内核没编 ipset 支持，用户都能在日志里看到，而不是"配了像没配"。
//!   3. **接上 `-no-rule-ipset`**：文档写着"跳过 ipset/nftset 规则"，但代码里这个开关
//!      **从来没人消费**（配在监听上完全不起作用）。这里两条路径都按它跳过。

use std::net::IpAddr;
use std::sync::LazyLock;
use tokio::sync::Semaphore;

use crate::config::{ConfigForIP, IpsetConfig, NFTsetConfig, ServerOpts};
use crate::dns::*;
use crate::ffi::ipset;
// nftset 那半边走 C 版那份 C 文件，只在 `nft` 特性 + Linux 下编进来；
// ipset 这半边是我们自己的纯 Rust 实现，**不依赖 `nft` 特性**（只需要 Linux 内核）。
#[cfg(all(feature = "nft", target_os = "linux"))]
use crate::ffi::nftset;
use crate::middleware::*;

// 🌟 核心防御阵列：全局专属限流关卡
// 限制同时只能有 512 个任务排队等待内核（netlink）锁。
// 将剩下的 blocking 线程容量留给 文件 I/O 和配置重载，防止系统被单一模块饿死！
static KERNEL_SET_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(512));

pub struct DnsIpsetNftsetMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsIpsetNftsetMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let res = next.run(ctx, req).await;

        // 非 Linux 平台没有内核集合可写：什么都不做，直接放行。
        // （配置照样认，启动时会明确提示"这些规则不会生效"，见 `dns_conf::summary()`。
        //   用运行期分支而不是把整段代码 `#[cfg]` 掉，是为了让本文件在所有平台都能编译、
        //   从而让"过期时间怎么算"这类纯逻辑能在本机单测。）
        if !cfg!(target_os = "linux") {
            return res;
        }

        // 后台请求（预取、双栈探针、过期刷新）不是"某个客户端在查"，不写集合：
        // 否则预取会把一堆本来没人访问的域名也塞进防火墙集合。
        if ctx.server_opts.is_background {
            return res;
        }

        // 🔐 文档写了但一直没人消费的开关：`bind ... -no-rule-ipset` = 这个监听不写 ipset/nftset
        if ctx.server_opts.no_rule_ipset() {
            return res;
        }

        let Ok(lookup) = res.as_ref() else {
            return res;
        };

        // 域名规则里配的集合（`nftset /域/...`、`domain-rules /域/ -nftset ...`）
        let (rule_nftsets, rule_ipsets) = match &ctx.domain_rule {
            Some(rule) => (
                rule.get(|n| n.nftset.as_ref().cloned()).unwrap_or_default(),
                rule.get(|n| n.ipset.as_ref().cloned()).unwrap_or_default(),
            ),
            None => (Vec::new(), Vec::new()),
        };

        // 再并上"监听上配的"（Q19/Q20）
        let (nftsets, ipsets) = merge_kernel_sets(rule_nftsets, rule_ipsets, &ctx.server_opts);

        if nftsets.is_empty() && ipsets.is_empty() {
            return res;
        }

        let ip_addrs = lookup
            .records()
            .iter()
            .filter_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();

        if ip_addrs.is_empty() {
            return res;
        }

        // 🔐 Q2/Q4：写进集合的条目带不带过期时间（`ipset-timeout` / `nftset-timeout`）
        let ipset_expiry = set_expiry_seconds(lookup, ctx.cfg().ipset_timeout(), ctx.cfg().rr_ttl());
        // 非 Linux 或不带 nft 特性的构建里，下面那两个写入块不参与编译，这个值也就没人用
        #[cfg_attr(not(all(feature = "nft", target_os = "linux")), allow(unused_variables))]
        let nftset_expiry = set_expiry_seconds(lookup, ctx.cfg().nftset_timeout(), ctx.cfg().rr_ttl());
        #[cfg_attr(not(all(feature = "nft", target_os = "linux")), allow(unused_variables))]
        let debug = ctx.cfg().nftset_debug();

        // 🌟 尝试获取通行证，获取不到说明内核那一侧已经严重拥堵！
        // 此时直接当场丢弃任务（Load Shedding），绝不让 spawn_blocking 无限制堆积导致 OOM！
        let Ok(permit) = KERNEL_SET_SEMAPHORE.try_acquire() else {
            // 降载保护触发！记录一笔极轻量的 Trace 日志，防止被攻击时连日志 I/O 也被打爆。
            crate::log::trace!(
                "Kernel set concurrency limit reached, dropped IP update to prevent OOM."
            );
            return res;
        };

        tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                // 🌟 智能工牌：将生命周期绑定在这个闭包上。
                // 一旦底层调用完成，闭包结束，立刻将通行证还给全局信号量池。
                let _guard = permit;

                let (ipv4_addrs, ipv6_addrs): (Vec<_>, Vec<_>) =
                    ip_addrs.into_iter().partition(|ip| ip.is_ipv4());

                // ── nftables 的 set（行为与改动前完全一致；没有 `nft` 特性时这段不编译）──
                #[cfg(all(feature = "nft", target_os = "linux"))]
                if !ipv4_addrs.is_empty() {
                    for nftset in &nftsets {
                        if let ConfigForIP::V4(cfg) = nftset {
                            report_nftset_result(
                                cfg.family,
                                &cfg.table,
                                &cfg.name,
                                &ipv4_addrs,
                                nftset_expiry,
                                debug,
                            );
                        }
                    }
                }

                #[cfg(all(feature = "nft", target_os = "linux"))]
                if !ipv6_addrs.is_empty() {
                    for nftset in &nftsets {
                        if let ConfigForIP::V6(cfg) = nftset {
                            report_nftset_result(
                                cfg.family,
                                &cfg.table,
                                &cfg.name,
                                &ipv6_addrs,
                                nftset_expiry,
                                debug,
                            );
                        }
                    }
                }

                // ── 🔐 Q1：Linux 的 ipset ──
                if !ipv4_addrs.is_empty() {
                    for ipset_cfg in &ipsets {
                        if let ConfigForIP::V4(cfg) = ipset_cfg {
                            report_ipset_result(&cfg.name, &ipv4_addrs, ipset_expiry);
                        }
                    }
                }

                if !ipv6_addrs.is_empty() {
                    for ipset_cfg in &ipsets {
                        if let ConfigForIP::V6(cfg) = ipset_cfg {
                            report_ipset_result(&cfg.name, &ipv6_addrs, ipset_expiry);
                        }
                    }
                }
            })
            .await
            .unwrap_or_default();
        });

        res
    }
}

/// 写一个 ipset，并把结果整理成人能看的话。
///
/// `timeout` 传 0 = 不设过期时间（与没写 `ipset-timeout` 时的语义一致）。
/// 失败按"集合名 + 原因"限流告警一次：集合名写错、权限不足、内核没 ipset 支持，
/// 都会在这里明确说出来 —— 这正是 C 版缺的那一环（它只发不读回执）。
fn report_ipset_result(setname: &str, addrs: &[IpAddr], timeout: u64) {
    let result = ipset::add_batch(setname, addrs, timeout);

    if result.is_ok() {
        crate::log::debug!(
            "ipset: 已把 {} 个地址写入集合 {}（过期时间 {} 秒，0 = 不过期）",
            result.added,
            setname,
            timeout
        );
        return;
    }

    let (addr, err) = match result.first_error.as_ref() {
        Some(v) => v,
        None => return,
    };

    let key = format!(
        "ipset-write-fail:{}:{}",
        setname,
        err.raw_os_error().unwrap_or(-1)
    );

    if crate::log::warn_once(&key) {
        crate::log::warn!(
            "ipset: 写入集合 `{}` 失败（成功 {} 条、失败 {} 条，例如 {}）：{}。\
             请检查集合是否存在（`ipset list {}`）、进程权限是否足够；本行只提示一次。",
            setname,
            result.added,
            result.failed,
            addr,
            err,
            setname
        );
    }
}

/// 这次查询要写哪些内核集合：**域名规则里配的**与**监听上配的**合在一起。
///
/// 🔐 Q19/Q20（监听级 `-ipset`/`-nftset`）的语义来自 C 版 `dns_conf/bind.c:216`：
/// 监听上配的集合对该监听的**每个**查询都生效，与该域名有没有规则无关；
/// 与域名规则里配的集合是**并列**关系（各写各的集合），不是谁覆盖谁。
///
/// 🔐 Q21：`domain-rules /域/ -nftset ...` 与顶层的 `nftset /域/...` 落到同一个字段，
/// 所以这里不需要区分它们从哪儿来。
fn merge_kernel_sets(
    mut rule_nftsets: Vec<ConfigForIP<NFTsetConfig>>,
    mut rule_ipsets: Vec<ConfigForIP<IpsetConfig>>,
    server_opts: &ServerOpts,
) -> (Vec<ConfigForIP<NFTsetConfig>>, Vec<ConfigForIP<IpsetConfig>>) {
    rule_nftsets.extend(server_opts.nftset.clone().unwrap_or_default());
    rule_ipsets.extend(server_opts.ipset.clone().unwrap_or_default());

    (rule_nftsets, rule_ipsets)
}

/// 🔐 Q2/Q4：写进集合的条目该什么时候过期（秒），0 = 不带过期时间（永不过期）。
///
/// 算法照 C 版 `ds_context.c:668` 的 `timeout_value = request->ip_ttl * 3`：**应答 TTL 的三倍**。
/// 多条应答时取**最小**的那个 TTL —— 宁可整批早点重写一遍，也不让已经过期的地址留在集合里把分流带偏。
///
/// 没开开关（`ipset-timeout` / `nftset-timeout` 默认关）就返回 0：条目永不过期，与改动前一致。
/// TTL 算不出来（应答里全是 0）时退回配置里的 `rr-ttl`，都没有就还是 0。
fn set_expiry_seconds(lookup: &DnsResponse, enabled: bool, config_ttl: Option<u64>) -> u64 {
    if !enabled {
        return 0;
    }

    let min_ttl = lookup
        .records()
        .iter()
        .map(|r| r.ttl() as u64)
        .min()
        .unwrap_or(0);

    let ttl = if min_ttl == 0 {
        config_ttl.unwrap_or(0)
    } else {
        min_ttl
    };

    ttl.saturating_mul(3)
}

/// 写 nftables 的 set（只在 Linux + `nft` 特性下参与编译）。
///
/// 开了 `nftset-debug` 时把"写了多少条、过期多久"打出来；失败则按"集合名"限流告警一次
/// —— 与 ipset 那一半同样的道理：写不进去要让用户看得见。
#[cfg(all(feature = "nft", target_os = "linux"))]
fn report_nftset_result(
    family: &str,
    table: &str,
    set_name: &str,
    addrs: &[IpAddr],
    timeout: u64,
    debug: bool,
) {
    match nftset::add_batch(family, table, set_name, addrs, timeout) {
        Ok(n) => {
            if debug {
                crate::log::debug!(
                    "nftset: 已把 {} 个地址写入 {}/{} 的集合 {}（过期时间 {} 秒，0 = 不过期）",
                    n,
                    family,
                    table,
                    set_name,
                    timeout
                );
            }
        }
        Err(err) => {
            let key = format!("nftset-write-fail:{family}:{table}:{set_name}");
            if crate::log::warn_once(&key) {
                crate::log::warn!(
                    "nftset: 往 {family}/{table} 的集合 {set_name} 写不了地址：{err}（表或集合可能不存在、或权限不足；本行只提示一次）"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;
    use crate::config::parser::NomParser;
    use crate::libdns::proto::{op::Query, rr::{Name, RData, Record}};

    fn lookup_with_ttls(ttls: &[u32]) -> DnsResponse {
        let name = Name::from_str("ips.example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);

        let records = ttls
            .iter()
            .enumerate()
            .map(|(i, ttl)| {
                let ip = Ipv4Addr::new(10, 0, 0, i as u8 + 1);
                Record::from_rdata(name.clone(), *ttl, RData::A(ip.into()))
            })
            .collect::<Vec<_>>();

        DnsResponse::new_with_max_ttl(query, records)
    }

    /// 没开开关 → 不带过期时间（与改动前一致）
    #[test]
    fn set_expiry_disabled_means_never_expire() {
        let lookup = lookup_with_ttls(&[300]);
        assert_eq!(set_expiry_seconds(&lookup, false, Some(600)), 0);
    }

    /// 开着 → TTL × 3（C 版算法）
    #[test]
    fn set_expiry_is_three_times_ttl() {
        let lookup = lookup_with_ttls(&[300]);
        assert_eq!(set_expiry_seconds(&lookup, true, None), 900);
    }

    /// 多条应答取最小的那个 TTL（宁可早点重写，也不留过期地址）
    #[test]
    fn set_expiry_uses_smallest_ttl_of_all_answers() {
        let lookup = lookup_with_ttls(&[600, 60, 300]);
        assert_eq!(set_expiry_seconds(&lookup, true, None), 180);
    }

    /// 应答 TTL 全是 0（有些上游不填）→ 退回配置里的 rr-ttl
    #[test]
    fn set_expiry_falls_back_to_config_ttl() {
        let lookup = lookup_with_ttls(&[0, 0]);

        assert_eq!(set_expiry_seconds(&lookup, true, Some(120)), 360);
        // 配置里也没有 → 0（不过期），不编一个数字出来
        assert_eq!(set_expiry_seconds(&lookup, true, None), 0);
    }

    /// 🔐 Q19/Q20：监听上配的集合对该监听的**每个**查询都生效 —— 即使这个域名没有任何规则
    #[test]
    fn listener_sets_apply_without_any_domain_rule() {
        let mut opts = ServerOpts::default();
        opts.nftset = Some(Vec::<ConfigForIP<NFTsetConfig>>::parse("#4:inet#filter#set4").unwrap().1);
        opts.ipset = Some(Vec::<ConfigForIP<IpsetConfig>>::parse("#4:dns4").unwrap().1);

        let (nft, ip) = merge_kernel_sets(Vec::new(), Vec::new(), &opts);

        assert_eq!(nft.len(), 1, "没有域名规则时，监听上的 nftset 仍要写");
        assert_eq!(ip.len(), 1, "没有域名规则时，监听上的 ipset 仍要写");
    }

    /// 🔐 Q19-21：域名规则里配的 + 监听上配的，**两处都要写**（并列，不是谁覆盖谁）
    #[test]
    fn domain_rule_and_listener_sets_are_merged() {
        let rule_nft = Vec::<ConfigForIP<NFTsetConfig>>::parse("#4:inet#filter#ruleset")
            .unwrap()
            .1;
        let rule_ip = Vec::<ConfigForIP<IpsetConfig>>::parse("#6:dns6").unwrap().1;

        let mut opts = ServerOpts::default();
        opts.nftset = Some(Vec::<ConfigForIP<NFTsetConfig>>::parse("#4:inet#filter#set4").unwrap().1);
        opts.ipset = Some(Vec::<ConfigForIP<IpsetConfig>>::parse("#4:dns4").unwrap().1);

        let (nft, ip) = merge_kernel_sets(rule_nft, rule_ip, &opts);

        assert_eq!(nft.len(), 2, "规则里的 + 监听上的 nftset 都要在");
        assert_eq!(ip.len(), 2, "规则里的 + 监听上的 ipset 都要在");
    }

    /// 两处都没配 → 空（中间件据此提前返回，不做无用的内核调用）
    #[test]
    fn no_sets_configured_means_empty() {
        let opts = ServerOpts::default();
        let (nft, ip) = merge_kernel_sets(Vec::new(), Vec::new(), &opts);
        assert!(nft.is_empty() && ip.is_empty());
    }

    /// 极大的 TTL 不 panic、不溢出（乘 3 用饱和运算）
    #[test]
    fn set_expiry_saturates_on_huge_ttl() {
        let lookup = lookup_with_ttls(&[u32::MAX]);
        assert_eq!(set_expiry_seconds(&lookup, true, None), u32::MAX as u64 * 3);
    }
}
