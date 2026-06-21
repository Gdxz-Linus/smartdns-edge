use std::sync::LazyLock;
use tokio::sync::Semaphore;

use crate::config::ConfigForIP;
use crate::dns::*;
use crate::ffi::nftset;
use crate::middleware::*;

// 🌟 核心防御阵列：全局 Nftset 专属限流关卡
// 限制同时只能有 512 个线程排队等待 Netlink 内核锁。
// 将剩下的 1500+ 个 blocking 线程容量死死留给 文件 I/O 和配置重载，防止系统被单一模块饿死！
static NFTSET_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(512));

pub struct DnsNftsetMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsNftsetMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let res = next.run(ctx, req).await;

        if !ctx.server_opts.is_background {
            if let (Ok(lookup), Some(rule)) = (res.as_ref(), &ctx.domain_rule) {
                let nftsets = rule.get(|n| n.nftset.as_ref().cloned());
                if let Some(nftsets) = nftsets {
                    let ip_addrs = lookup
                        .records()
                        .iter()
                        .filter_map(|r| r.data().ip_addr())
                        .collect::<Vec<_>>();

                    if !ip_addrs.is_empty() {
                        // 🌟 核心修复：尝试获取通行证，获取不到说明内核 Netlink 已经严重拥堵！
                        // 此时直接当场丢弃任务（Load Shedding），绝不让 spawn_blocking 无限制堆积导致 OOM！
                        if let Ok(permit) = NFTSET_SEMAPHORE.try_acquire() {
                            tokio::spawn(async move {
                                tokio::task::spawn_blocking(move || {
                                    // 🌟 智能工牌：将生命周期绑定在这个闭包上。
                                    // 一旦底层 C 语言的 FFI 调用完成，闭包结束，立刻将通行证还给全局信号量池。
                                    let _guard = permit;

                                    let (ipv4_addrs, ipv6_addrs): (Vec<_>, Vec<_>) =
                                        ip_addrs.into_iter().partition(|ip| ip.is_ipv4());

                                    if !ipv4_addrs.is_empty() {
                                        for nftset in &nftsets {
                                            if let ConfigForIP::V4(cfg) = nftset {
                                                // 🌟 直接调用新武器！一次调用，内核搞定所有 IP！
                                                let _ = nftset::add_batch(
                                                    cfg.family, &cfg.table, &cfg.name, &ipv4_addrs, 0,
                                                );
                                            }
                                        }
                                    }

                                    if !ipv6_addrs.is_empty() {
                                        for nftset in &nftsets {
                                            if let ConfigForIP::V6(cfg) = nftset {
                                                // 🌟 IPv6 同样享受批量红利！
                                                let _ = nftset::add_batch(
                                                    cfg.family, &cfg.table, &cfg.name, &ipv6_addrs, 0,
                                                );
                                            }
                                        }
                                    }
									
                                }).await.unwrap_or_default();
                            });
                        } else {
                            // 降载保护触发！记录一笔极轻量的 Trace 日志，防止被攻击时连日志 I/O 也被打爆。
                            crate::log::trace!("Nftset concurrency limit reached, dropped IP update to prevent OOM.");
                        }
                    }
                }
            }
        }
        res
    }
}
