//! 连接数上限与统计（P0-5 的第二道防线）
//!
//! 为什么需要它：DoQ/TCP/DoT 的读路径原本按客户端"声明的长度"分配内存，而连接数没有上限，
//! 攻击者可以用极小的成本占住大量内存（治本修复见 hickory 的分块读取 + 首包超时）。
//! 这里再加一道"总预算"闸门：连接总数与单一来源的连接数都有上限，超限就拒绝新连接。
//!
//! 默认值不再写死，而是**按机器内存自动推算**，同时照顾两端：
//! - 家庭环境（软路由/NAS，内存可能只有 256 MB）→ 自动收紧，避免自己把自己压垮；
//! - 企业环境（大内存服务器 + NAT/代理后面成千上万客户端）→ 自动放宽，不误伤正常用户。
//!
//! 计算方式（可在配置里用 `max-connections` / `max-connections-per-ip` 覆盖，0 = 自动）：
//!   内存预算 = clamp(物理内存 / 8, 16 MiB, 512 MiB)
//!   每连接保守估计 32 KiB（含 socket 缓冲、任务与协议状态）
//!   总上限   = clamp(内存预算 / 32 KiB, 512, 16384)
//!   单来源上限 = clamp(总上限 / 8, 64, 2048)
//!
//! 以 256 MB 的软路由为例：预算 32 MiB → 总上限 1024、单来源 128（家庭设备数远低于此）；
//! 以 8 GB 以上的服务器为例：预算 512 MiB → 总上限 16384、单来源 2048（企业级 NAT 也不误伤）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// 单一来源的计数键：IPv4 按地址、IPv6 按 /64 前缀
/// （IPv6 必须按前缀聚合：攻击者拿到一个 /64 就等于拥有海量源地址，按单地址计数形同虚设）
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum SourceKey {
    V4(Ipv4Addr),
    V6([u8; 8]),
}

impl SourceKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                let o = v6.octets();
                Self::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
            }
        }
    }
}

pub struct ConnectionLimiter {
    max_connections: usize,
    max_per_source: usize,
    current: AtomicUsize,
    rejected: AtomicUsize,
    per_source: Mutex<HashMap<SourceKey, usize>>,
}

/// 每条连接的凭据：连接结束时自动归还计数
pub struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    key: SourceKey,
    /// 是否真的占用了配额（环回来源为 false，不参与计数）
    counted: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        self.limiter.current.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut map) = self.limiter.per_source.lock() {
            if let Some(n) = map.get_mut(&self.key) {
                *n -= 1;
                if *n == 0 {
                    map.remove(&self.key);
                }
            }
        }
    }
}

fn auto_max_connections() -> usize {
    // sysinfo 在 Linux/Windows/macOS 上都能拿到物理内存
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    let total = system.total_memory(); // 字节
    let budget = (total / 8).clamp(16 * 1024 * 1024, 512 * 1024 * 1024);
    (budget as usize / (32 * 1024)).clamp(512, 16384)
}

fn auto_max_per_source(max_connections: usize) -> usize {
    (max_connections / 8).clamp(64, 2048)
}

impl ConnectionLimiter {
    fn new(configured_max: Option<usize>, configured_per_source: Option<usize>) -> Self {
        let max_connections = match configured_max {
            Some(n) if n > 0 => n,
            _ => auto_max_connections(),
        };
        let max_per_source = match configured_per_source {
            Some(n) if n > 0 => n,
            _ => auto_max_per_source(max_connections),
        };

        crate::log::info!(
            "连接数上限：总计 {}、单一来源 {}（可用 max-connections / max-connections-per-ip 调整）",
            max_connections,
            max_per_source
        );

        Self {
            max_connections,
            max_per_source,
            current: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            per_source: Mutex::new(HashMap::new()),
        }
    }

    /// 申请一条连接的配额。返回 None 表示超限（已计入统计并打日志）。
    ///
    /// ⚠️ 本机环回地址（127.0.0.1 / ::1）**不占配额**：管理后台通常就是通过本机或
    /// SSH 隧道访问的，如果它也被算进限额，一旦被人用连接洪泛打满，
    /// 运维就再也进不去后台看情况了——那是最需要它的时候。
    pub fn acquire(self: &Arc<Self>, addr: IpAddr) -> Option<ConnectionGuard> {
        if addr.is_loopback() {
            return Some(ConnectionGuard {
                limiter: self.clone(),
                key: SourceKey::from_ip(addr),
                counted: false,
            });
        }

        let key = SourceKey::from_ip(addr);

        {
            let mut map = self.per_source.lock().unwrap();
            let entry = map.entry(key).or_insert(0);
            if *entry >= self.max_per_source
                || self.current.load(Ordering::Relaxed) >= self.max_connections
            {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                // 日志限流：每累计 32 次才打一条，避免被刷爆
                if self.rejected.load(Ordering::Relaxed) % 32 == 1 {
                    crate::log::warn!(
                        "连接数达到上限，拒绝来自 {} 的连接（当前 {}，上限 {}；累计超限 {}）",
                        addr,
                        self.current.load(Ordering::Relaxed),
                        self.max_connections,
                        self.rejected.load(Ordering::Relaxed)
                    );
                }
                return None;
            }
            *entry += 1;
        }

        self.current.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionGuard {
            limiter: self.clone(),
            key,
            counted: true,
        })
    }

    /// (当前连接数, 累计拒绝数, 总上限)
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.current.load(Ordering::Relaxed),
            self.rejected.load(Ordering::Relaxed),
            self.max_connections,
        )
    }
}

static GLOBAL: OnceLock<Arc<ConnectionLimiter>> = OnceLock::new();

/// 由启动流程按配置初始化；未初始化时按自动值创建（测试等场景也能用）
pub fn init(max_connections: Option<usize>, max_per_source: Option<usize>) {
    let _ = GLOBAL.set(Arc::new(ConnectionLimiter::new(
        max_connections,
        max_per_source,
    )));
}

pub fn global() -> Arc<ConnectionLimiter> {
    GLOBAL
        .get_or_init(|| Arc::new(ConnectionLimiter::new(None, None)))
        .clone()
}

// ================= 逐监听上限 =================
//
// 全局上限保护的是整机内存；但不同监听的风险不同：内网 53 端口可以宽松，
// 对公网的 DoH 端口（443）往往需要单独收紧。做法是给带覆盖选项的监听登记一个
// 独立的限额实例，accept 时与全局限额**同时**生效。
static LISTENERS: OnceLock<Mutex<HashMap<std::net::SocketAddr, Arc<ConnectionLimiter>>>> =
    OnceLock::new();

fn listeners() -> &'static Mutex<HashMap<std::net::SocketAddr, Arc<ConnectionLimiter>>> {
    LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 启动时为某个监听登记独立限额（只有配置了覆盖选项才会登记）
pub fn register_listener(
    addr: std::net::SocketAddr,
    max_connections: Option<usize>,
    max_per_source: Option<usize>,
) {
    if max_connections.is_none() && max_per_source.is_none() {
        return;
    }
    crate::log::info!(
        "监听 {addr} 单独设置了连接上限：总计 {:?}、单一来源 {:?}",
        max_connections,
        max_per_source
    );
    listeners().lock().unwrap().insert(
        addr,
        Arc::new(ConnectionLimiter::new(max_connections, max_per_source)),
    );
}

/// 取某个监听的独立限额（没登记就返回 None，表示只受全局限制）
pub fn for_listener(addr: std::net::SocketAddr) -> Option<Arc<ConnectionLimiter>> {
    listeners().lock().unwrap().get(&addr).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_key_groups_ipv6_by_64() {
        // IPv6 必须按 /64 聚合：同一个 /64 内的不同地址算同一个来源
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(SourceKey::from_ip(a), SourceKey::from_ip(b));
        assert_ne!(SourceKey::from_ip(a), SourceKey::from_ip(c));
    }

    #[test]
    fn test_limit_rejects_over_cap_and_releases() {
        let limiter = Arc::new(ConnectionLimiter::new(Some(2), Some(2)));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();

        let g1 = limiter.acquire(ip).expect("第 1 条应通过");
        let g2 = limiter.acquire(ip).expect("第 2 条应通过");
        assert!(limiter.acquire(ip).is_none(), "第 3 条应被拒绝");

        drop(g1);

        // 注意：必须把 guard 绑到变量上——临时值在语句结束就被丢弃，
        // 那样计数会立刻回落，断言就会看错。
        let g3 = limiter.acquire(ip).expect("释放后应能再接入");

        let (current, rejected, max) = limiter.stats();
        assert_eq!((current, rejected, max), (2, 1, 2));

        drop(g3);
        drop(g2);
        assert_eq!(limiter.stats().0, 0, "全部释放后当前连接数应回到 0");
    }

    #[test]
    fn test_loopback_is_exempt() {
        // 本机访问不该被连接洪泛挡在门外（管理后台要靠它）
        let limiter = Arc::new(ConnectionLimiter::new(Some(1), Some(1)));
        let wan: IpAddr = "203.0.113.9".parse().unwrap();
        let _hold = limiter.acquire(wan).unwrap();
        assert!(limiter.acquire(wan).is_none(), "外部来源第 2 条应被拒");

        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.acquire(lo).is_some(), "环回应始终放行");
        assert!(
            limiter.acquire(lo).is_some(),
            "环回应始终放行（且不占配额）"
        );
        assert_eq!(limiter.stats().0, 1, "环回不应计入当前连接数");
    }

    #[test]
    fn test_per_listener_limits_registry() {
        // 逐监听限额：只有配置过覆盖选项的监听才会登记
        let addr: std::net::SocketAddr = "127.0.0.1:65533".parse().unwrap();
        assert!(
            for_listener(addr).is_none(),
            "未登记时应返回 None（只受全局限制）"
        );

        register_listener(addr, Some(1), Some(1));
        let l = for_listener(addr).expect("登记后应能取到");
        assert_eq!(l.stats().2, 1, "该监听应使用自己的上限");

        // 常见地址不应被误伤
        assert!(for_listener("127.0.0.1:65534".parse().unwrap()).is_none());
    }

    #[test]
    fn test_auto_defaults_are_sane() {
        // 自动推算必须落在"家庭够小、企业够大"的区间内，且不能是 0
        let limiter = ConnectionLimiter::new(None, None);
        let (_, _, max) = limiter.stats();
        assert!(
            (512..=16384).contains(&max),
            "自动上限应在 512~16384，实际 {max}"
        );
        assert!(limiter.max_per_source >= 64);
    }
}

// ───────────────────────── 🔐 Q10：`max-query-limit`（整机同时处理的查询数） ─────────────────────────
//
// 语义对齐 C 版 `src/dns_server/dns_server.c:483`：
//   * 计数**已进入处理、还没结束**的查询（C 版是 `server.request_num`）；
//   * 超过上限 → 直接回 `REFUSED`（不查上游、不进缓存），日志**每 120 秒最多告警一次**（避免被打爆时刷屏）；
//   * `0` = 不限（C 版也是 `> 0` 才判）。
//
// 与连接数上限的分工：连接数管的是"socket 占着不放"，这里管的是"查询堆在流水线里"，
// 两道闸门互相独立 —— 一条连接上可以堆很多条查询。

/// 查询数闸门。做成结构体（而不是一堆全局静态量）是为了能在单测里各建各的，互不干扰。
#[derive(Debug, Default)]
pub struct QueryLimiter {
    in_flight: AtomicUsize,
    /// 上次告警的时间戳（秒），用于"120 秒最多告警一次"
    last_warn: AtomicU64,
}

/// 进入查询的凭据：查询结束时自动归还计数（RAII，出错也一样会归还）
pub struct QueryGuard {
    limiter: &'static QueryLimiter,
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 进程内共用的一份计数器（`max-query-limit` 是整机级别的）
static QUERY_LIMITER: QueryLimiter = QueryLimiter {
    in_flight: AtomicUsize::new(0),
    last_warn: AtomicU64::new(0),
};

/// 放行结果
pub enum QueryAdmission {
    /// 放行：凭据丢掉时自动归还计数
    Allowed(QueryGuard),
    /// 超上限：调用方应当直接回 REFUSED
    Refused,
}

/// 尝试放行一条查询。
///
/// `limit` = 配置里的 `max-query-limit`（0 = 不限）；`is_background` = 内部后台请求（预取、
/// 双栈探针、过期刷新）**不占这个额度** —— 它们不是"client 在查"，不该被自己的闸门拒掉。
pub fn enter_query(limit: usize, is_background: bool) -> QueryAdmission {
    admit(&QUERY_LIMITER, limit, is_background, unix_now())
}

/// 单测入口：可以传入自己的闸门与"当前时间"
fn admit(
    limiter: &'static QueryLimiter,
    limit: usize,
    is_background: bool,
    now: u64,
) -> QueryAdmission {
    if is_background || limit == 0 {
        // 不计数但要保持成对：这里也走一次加/减，靠 guard 归还，语义最简单
        limiter.in_flight.fetch_add(1, Ordering::Relaxed);
        return QueryAdmission::Allowed(QueryGuard { limiter });
    }

    let in_flight = limiter.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
    if in_flight > limit {
        // 超了：把刚加的那次还回去（这条查询不会继续处理）
        limiter.in_flight.fetch_sub(1, Ordering::Relaxed);
        limiter.warn_once_in_window(now);
        return QueryAdmission::Refused;
    }

    QueryAdmission::Allowed(QueryGuard { limiter })
}

impl QueryLimiter {
    /// 当前在处理的查询数（单测与日志用）
    #[inline]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// 每 120 秒最多告警一次（与 C 版的 `last_log_time` 同思路）
    fn warn_once_in_window(&self, now: u64) {
        let last = self.last_warn.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 120 {
            return;
        }
        if self
            .last_warn
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            crate::log::warn!(
                "同时处理的查询数已达上限（`max-query-limit`），新的查询会被直接拒绝（REFUSED）。\n\
                 这说明有异常流量或上游太慢导致查询堆积；确认是正常业务量就调大这个值，或查一下上游。"
            );
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod query_limit_tests {
    use super::*;

    fn limiter() -> &'static QueryLimiter {
        Box::leak(Box::new(QueryLimiter::default()))
    }

    /// 0 = 不限：来多少放多少
    #[test]
    fn zero_limit_means_unlimited() {
        let l = limiter();
        let mut guards = Vec::new();
        for _ in 0..100 {
            match admit(l, 0, false, 0) {
                QueryAdmission::Allowed(g) => guards.push(g),
                QueryAdmission::Refused => panic!("0 = 不限，不该拒"),
            }
        }
        assert_eq!(l.in_flight(), 100, "100 条同时处理中");

        guards.clear();
        assert_eq!(l.in_flight(), 0, "全部结束后计数归零");
    }

    /// 超过上限就拒（C 版也是"大于"才拒）
    #[test]
    fn refuses_only_above_limit() {
        let l = limiter();

        let g1 = admit(l, 2, false, 0);
        let g2 = admit(l, 2, false, 0);
        assert!(matches!(g1, QueryAdmission::Allowed(_)));
        assert!(matches!(g2, QueryAdmission::Allowed(_)));

        // 第 3 条超上限
        assert!(matches!(admit(l, 2, false, 0), QueryAdmission::Refused));
        // 被拒的那条不该把计数留高
        assert_eq!(l.in_flight(), 2);

        drop(g1);
        drop(g2);
        assert_eq!(l.in_flight(), 0, "凭据丢掉后计数要归还（含出错路径）");
    }

    /// 后台请求不占额度（否则预取会被自己的闸门拦下）
    #[test]
    fn background_queries_do_not_consume_quota() {
        let l = limiter();

        let _g = admit(l, 1, false, 0);
        // 额度已满，但后台请求照样放行
        assert!(matches!(admit(l, 1, true, 0), QueryAdmission::Allowed(_)));
        // 普通请求仍然被拒
        assert!(matches!(admit(l, 1, false, 0), QueryAdmission::Refused));
    }

    /// 告警 120 秒内只发一次
    #[test]
    fn warn_window_is_120_seconds() {
        let l = limiter();
        let _g = admit(l, 1, false, 0);

        l.warn_once_in_window(1000);
        assert_eq!(l.last_warn.load(Ordering::Relaxed), 1000, "第一次要记下来");

        l.warn_once_in_window(1100);
        assert_eq!(
            l.last_warn.load(Ordering::Relaxed),
            1000,
            "120 秒内不重复告警"
        );

        l.warn_once_in_window(1121);
        assert_eq!(
            l.last_warn.load(Ordering::Relaxed),
            1121,
            "过了 120 秒可以再告警"
        );
    }
}
