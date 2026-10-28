use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

use lru::LruCache;
use mac_addr::MacAddr;
use tokio::sync::broadcast;

const ARP_CACHE_CAPACITY: usize = 4096;
const ARP_CACHE_TTL: Duration = Duration::from_secs(60);

pub type ArpLookupFn = fn(IpAddr) -> Option<String>;
static TEST_ARP_LOOKUP: RwLock<Option<ArpLookupFn>> = RwLock::new(None);
#[cfg(test)]
static TEST_ARP_UNCACHED_LOOKUP: RwLock<Option<ArpLookupFn>> = RwLock::new(None);

pub fn test_lookup_hook() -> Option<ArpLookupFn> {
    *TEST_ARP_LOOKUP.read().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
pub fn set_test_arp_lookup(lookup: Option<ArpLookupFn>) {
    *TEST_ARP_LOOKUP.write().unwrap_or_else(|e| e.into_inner()) = lookup;
}

#[cfg(test)]
pub(crate) fn set_test_arp_uncached_lookup(lookup: Option<ArpLookupFn>) {
    *TEST_ARP_UNCACHED_LOOKUP
        .write()
        .unwrap_or_else(|e| e.into_inner()) = lookup;
}

#[cfg(test)]
fn test_uncached_lookup_hook() -> Option<ArpLookupFn> {
    *TEST_ARP_UNCACHED_LOOKUP
        .read()
        .unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
}

// 🌟 修复 1：直接去掉冗余且会引发 Panic 的 block_in_place，
// 因为在外层的 app.rs 中已经使用了 spawn_blocking！
pub fn lookup_client_mac_from_arp(client_ip: IpAddr) -> Option<String> {
    if let Some(test_lookup) = test_lookup_hook() {
        return test_lookup(client_ip);
    }

    let ipv4 = client_ipv4_for_arp(client_ip)?;

    // 缓存与并发折叠的测试需要观察“底层查询”被调用几次；这个注入口放在
    // 测试钩子之后，避免改变 ACL 测试所依赖的“测试钩子优先直返”语义。
    #[cfg(test)]
    if let Some(test_lookup) = test_uncached_lookup_hook() {
        return test_lookup(client_ip);
    }

    lookup_client_mac_from_arp_v4(ipv4)
}

pub struct ArpResolver {
    cache: Mutex<LruCache<IpAddr, (Option<String>, Instant)>>,
    inflight: Mutex<HashMap<IpAddr, broadcast::Sender<Option<String>>>>,
}

impl ArpResolver {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(ARP_CACHE_CAPACITY)
                    .expect("ARP cache capacity must be non-zero"),
            )),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub async fn lookup(&self, ip: IpAddr) -> Option<String> {
        if let Some(hook) = test_lookup_hook() {
            return hook(ip);
        }

        let now = Instant::now();
        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((mac, expires_at)) = cache.get(&ip)
                && now < *expires_at
            {
                return mac.clone();
            }
        }

        let receiver = {
            let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(sender) = inflight.get(&ip) {
                Some(sender.subscribe())
            } else {
                let (sender, _) = broadcast::channel(1);
                inflight.insert(ip, sender);
                None
            }
        };

        if let Some(mut receiver) = receiver {
            return receiver.recv().await.ok().flatten();
        }

        let mut guard = InflightGuard::new(&self.inflight, ip);
        let result = tokio::task::spawn_blocking(move || lookup_client_mac_from_arp(ip))
            .await
            .unwrap_or(None);

        {
            let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.put(ip, (result.clone(), Instant::now() + ARP_CACHE_TTL));
        }

        guard.finish(result.clone());
        result
    }
}

impl Default for ArpResolver {
    fn default() -> Self {
        Self::new()
    }
}

struct InflightGuard<'a> {
    inflight: &'a Mutex<HashMap<IpAddr, broadcast::Sender<Option<String>>>>,
    ip: IpAddr,
    done: bool,
}

impl<'a> InflightGuard<'a> {
    fn new(
        inflight: &'a Mutex<HashMap<IpAddr, broadcast::Sender<Option<String>>>>,
        ip: IpAddr,
    ) -> Self {
        Self {
            inflight,
            ip,
            done: false,
        }
    }

    fn finish(&mut self, result: Option<String>) {
        if self.done {
            return;
        }

        let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sender) = inflight.remove(&self.ip) {
            let _ = sender.send(result);
        }
        self.done = true;
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        // 领跑者 panic / 取消时也必须唤醒等待者，否则同 IP 的后续请求会永久挂起。
        self.finish(None);
    }
}

fn client_ipv4_for_arp(client_ip: IpAddr) -> Option<Ipv4Addr> {
    match client_ip {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn parse_arp_table_mac(table: &str, target_ip: Ipv4Addr) -> Option<String> {
    parse_arp_entries(table)
        .find(|entry| entry.ip == target_ip)
        .map(|entry| entry.mac.to_string())
}

fn normalize_ip_token(token: &str) -> Option<Ipv4Addr> {
    let normalized = trim_arp_token(token);
    normalized.parse().ok()
}

fn parse_arp_line_entry(line: &str) -> Option<ParsedArpEntry> {
    let mut ip = None;
    let mut mac = None;

    for token in line.split_whitespace() {
        let token = trim_arp_token(token);

        if ip.is_none() {
            ip = normalize_ip_token(token);
        }
        if mac.is_none() {
            mac = token
                .parse::<MacAddr>()
                .ok()
                .or_else(|| {
                    token
                        .contains('-')
                        .then(|| token.replace('-', ":").parse::<MacAddr>().ok())
                        .flatten()
                })
                .filter(|candidate| *candidate != MacAddr::zero());
        }
        if ip.is_some() && mac.is_some() {
            break;
        }
    }

    Some(ParsedArpEntry { ip: ip?, mac: mac? })
}

/// Lazily parses ARP-like text output line by line.
///
/// Today we extract only `(IPv4, MAC)`, which is enough for client MAC lookup.
/// This can be extended to capture interface name, flags, and entry type if needed.
fn parse_arp_entries(output: &str) -> impl Iterator<Item = ParsedArpEntry> + '_ {
    output.lines().filter_map(parse_arp_line_entry)
}

fn trim_arp_token(token: &str) -> &str {
    token.trim_matches(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',' | ';' | ':'))
}

fn parse_arp_command_output_mac(output: &str, target_ip: Ipv4Addr) -> Option<String> {
    parse_arp_entries(output)
        .find(|entry| entry.ip == target_ip)
        .map(|entry| entry.mac.to_string())
}

#[cfg(target_os = "linux")]
fn lookup_client_mac_from_arp_v4(client_ip: Ipv4Addr) -> Option<String> {
    std::fs::read_to_string("/proc/net/arp")
        .ok()
        .and_then(|table| parse_arp_table_mac(&table, client_ip))
}

#[cfg(not(target_os = "linux"))]
fn run_arp_command(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("arp").args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "linux"))]
fn lookup_mac_from_arp_command_output(client_ip: Ipv4Addr, args: &[&str]) -> Option<String> {
    run_arp_command(args).and_then(|output| parse_arp_command_output_mac(&output, client_ip))
}

// 🌟 修复 2：Windows 平台专属极速原生 API (替代 arp.exe)
#[cfg(all(not(target_os = "linux"), target_os = "windows"))]
#[repr(C, align(8))]
struct SendArpPhysicalAddress([u8; 6]);

#[cfg(all(not(target_os = "linux"), target_os = "windows"))]
impl SendArpPhysicalAddress {
    fn zeroed() -> Self {
        Self([0; 6])
    }
}

#[cfg(all(not(target_os = "linux"), target_os = "windows"))]
fn lookup_client_mac_from_arp_v4(client_ip: Ipv4Addr) -> Option<String> {
    // 动态链接 Windows 的 IP 助手 API
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn SendARP(
            dest_ip: u32,
            src_ip: u32,
            p_mac_addr: *mut SendArpPhysicalAddress,
            phy_addr_len: *mut u32,
        ) -> u32;
    }

    // 🌟 P1-2 修复：SendARP 的 DestIP 参数与 C 的 inet_addr() 返回值同序
    // （即"内存中的字节序列 = IP 的四个字节"），因此必须用 from_ne_bytes。
    // 原来用 from_be_bytes 会得到字节序颠倒的值，SendARP 返回 67 (ERROR_BAD_NET_NAME)，
    // MAC 永远取不到 → README 主推的"MAC 地址智能分流"在 Windows 上从未生效，
    // 且全程静默无报错（只有 1.2.2.1 这类回文地址偶然可用）。
    // 实测：10.118.55.8 → from_be_bytes=0x0A763708 取不到；同序值=0x0837760A 正常取到 MAC。
    let dest_ip = u32::from_ne_bytes(client_ip.octets());
    let mut physical_address = SendArpPhysicalAddress::zeroed();
    let mut mac_len = size_of::<SendArpPhysicalAddress>() as u32;

    // 🌟 极速调用，不产生任何系统子进程，微秒级返回！
    let res = unsafe { SendARP(dest_ip, 0, &mut physical_address, &mut mac_len) };

    if res == 0 && mac_len == 6 {
        let mac = &physical_address.0;
        Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ))
    } else {
        None
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn lookup_client_mac_from_arp_v4(client_ip: Ipv4Addr) -> Option<String> {
    let ip = client_ip.to_string();
    for args in [
        ["-n", ip.as_str()],
        ["-an", ip.as_str()],
        ["-a", ip.as_str()],
    ] {
        if let Some(mac) = lookup_mac_from_arp_command_output(client_ip, &args) {
            return Some(mac);
        }
    }
    None
}

#[cfg(test)]
pub(crate) fn test_arp_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_sendarp_dest_ip_byte_order() {
        // 锁定字节序：SendARP 需要 inet_addr() 同序的值 ——
        // 它的内存字节序列必须与 IP 的四个字节完全一致。
        for ip_str in ["10.118.55.8", "192.168.1.1", "1.2.2.1", "255.255.255.255"] {
            let ip: Ipv4Addr = ip_str.parse().unwrap();
            let dest_ip = u32::from_ne_bytes(ip.octets());
            assert_eq!(
                dest_ip.to_ne_bytes(),
                ip.octets(),
                "{ip_str} 传给 SendARP 的字节序错了（MAC 查询会返回 67 而静默失败）"
            );
        }

        // 本机实测基准值：C 的 inet_addr("10.118.55.8") = 0x0837760A
        #[cfg(target_endian = "little")]
        assert_eq!(
            u32::from_ne_bytes([10, 118, 55, 8]),
            0x0837_760A,
            "必须与 Windows 的 inet_addr() 保持一致"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_sendarp_buffer_contract() {
        assert_eq!(size_of::<SendArpPhysicalAddress>(), 8);
        assert_eq!(align_of::<SendArpPhysicalAddress>(), align_of::<u64>());
        let physical_address = SendArpPhysicalAddress::zeroed();
        assert_eq!(
            std::ptr::from_ref(&physical_address).addr() % align_of::<u64>(),
            0
        );
    }

    #[test]
    fn test_client_ipv4_for_arp() {
        assert_eq!(
            client_ipv4_for_arp("192.168.1.10".parse().unwrap()),
            Some("192.168.1.10".parse().unwrap())
        );
        assert_eq!(client_ipv4_for_arp("127.0.0.1".parse().unwrap()), None);
        assert_eq!(client_ipv4_for_arp("::1".parse().unwrap()), None);
    }

    #[test]
    fn test_parse_arp_table_mac() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                     192.168.1.11     0x1         0x2         00:00:00:00:00:00     *        eth0";

        assert_eq!(
            parse_arp_table_mac(table, "192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            parse_arp_table_mac(table, "192.168.1.11".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_arp_table_mac(table, "192.168.1.12".parse().unwrap()),
            None
        );
    }

    #[test]
    fn test_parse_arp_command_output_mac_unix() {
        let output = "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        assert_eq!(
            parse_arp_command_output_mac(output, "192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_arp_command_output_mac_windows() {
        let output = "Interface: 192.168.1.1 --- 0x7\n\
                      Internet Address      Physical Address      Type\n\
                      192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic";
        assert_eq!(
            parse_arp_command_output_mac(output, "192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_arp_command_output_mac_uses_exact_ip_match() {
        let output = "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        assert_eq!(
            parse_arp_command_output_mac(output, "192.168.1.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn test_parse_arp_entries_lazily() {
        let output = "Interface: 192.168.1.1 --- 0x7\n\
                     Internet Address      Physical Address      Type\n\
                     192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic\n\
                     192.168.1.11          00-00-00-00-00-00     invalid";

        let entries = parse_arp_entries(output).collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "192.168.1.10".parse::<Ipv4Addr>().unwrap());
        assert_eq!(entries[0].mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }
    struct TestArpHookGuard;

    impl TestArpHookGuard {
        fn new(uncached: ArpLookupFn) -> Self {
            set_test_arp_lookup(None);
            set_test_arp_uncached_lookup(Some(uncached));
            Self
        }
    }

    impl Drop for TestArpHookGuard {
        fn drop(&mut self) {
            set_test_arp_lookup(None);
            set_test_arp_uncached_lookup(None);
        }
    }

    static MISS_LOOKUP_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn counting_miss_lookup(ip: IpAddr) -> Option<String> {
        if ip != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)) {
            return None;
        }
        MISS_LOOKUP_CALLS.fetch_add(1, Ordering::SeqCst);
        None
    }

    #[tokio::test]
    async fn resolver_caches_a_miss() {
        let _lock = test_arp_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _hooks = TestArpHookGuard::new(counting_miss_lookup);
        MISS_LOOKUP_CALLS.store(0, Ordering::SeqCst);

        let resolver = ArpResolver::new();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        assert_eq!(resolver.lookup(ip).await, None);
        assert_eq!(resolver.lookup(ip).await, None);
        assert_eq!(
            MISS_LOOKUP_CALLS.load(Ordering::SeqCst),
            1,
            "查不到的 MAC 也必须缓存，第二次查询不能再打底层"
        );
    }

    static FOLD_LOOKUP_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn slow_lookup(ip: IpAddr) -> Option<String> {
        if ip != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)) {
            return None;
        }
        FOLD_LOOKUP_CALLS.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        Some("aa:bb:cc:dd:ee:ff".to_string())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolver_folds_concurrent_lookups_for_the_same_ip() {
        let _lock = test_arp_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _hooks = TestArpHookGuard::new(slow_lookup);
        FOLD_LOOKUP_CALLS.store(0, Ordering::SeqCst);

        let resolver = ArpResolver::new();
        let ip: IpAddr = "192.0.2.11".parse().unwrap();
        let expected = Some("aa:bb:cc:dd:ee:ff".to_string());
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));

        let (r1, r2, r3, r4, r5, r6, r7, r8) = tokio::join!(
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
            async {
                barrier.wait().await;
                resolver.lookup(ip).await
            },
        );

        for result in [r1, r2, r3, r4, r5, r6, r7, r8] {
            assert_eq!(result, expected);
        }
        assert_eq!(
            FOLD_LOOKUP_CALLS.load(Ordering::SeqCst),
            1,
            "同一 IP 的并发查询必须折叠成一次底层查询"
        );
    }

    static HIT_LOOKUP_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn counting_hit_lookup(ip: IpAddr) -> Option<String> {
        if ip != IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12)) {
            return None;
        }
        HIT_LOOKUP_CALLS.fetch_add(1, Ordering::SeqCst);
        Some("11:22:33:44:55:66".to_string())
    }

    #[tokio::test]
    async fn resolver_caches_a_hit() {
        let _lock = test_arp_lock().lock().unwrap_or_else(|e| e.into_inner());
        let _hooks = TestArpHookGuard::new(counting_hit_lookup);
        HIT_LOOKUP_CALLS.store(0, Ordering::SeqCst);

        let resolver = ArpResolver::new();
        let ip: IpAddr = "192.0.2.12".parse().unwrap();
        let expected = Some("11:22:33:44:55:66".to_string());

        assert_eq!(resolver.lookup(ip).await, expected);
        assert_eq!(resolver.lookup(ip).await, expected);
        assert_eq!(
            HIT_LOOKUP_CALLS.load(Ordering::SeqCst),
            1,
            "命中的 MAC 必须缓存，第二次查询不能再打底层"
        );
    }
}

/// 真机验证 SendARP 真的能取到 MAC（需要同网段、可 ARP 解析的目标，通常是默认网关）。
/// 与其它环境相关测试一致：环境变量缺失就打印说明并跳过，不硬编码任何地址。
#[cfg(all(not(target_os = "linux"), target_os = "windows"))]
#[test]
fn test_sendarp_real_lookup() {
    let target = match std::env::var("SMARTDNS_TEST_ARP_TARGET") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            println!(
                "跳过 test_sendarp_real_lookup：未设置 SMARTDNS_TEST_ARP_TARGET \
                     （可设为本机默认网关，例如 172.20.10.1）"
            );
            return;
        }
    };
    let ip: Ipv4Addr = target
        .trim()
        .parse()
        .expect("SMARTDNS_TEST_ARP_TARGET 要是 IPv4 地址");
    match lookup_client_mac_from_arp_v4(ip) {
        Some(mac) => println!("SendARP resolved MAC = {mac} for {ip} (byte order correct)"),
        None => panic!(
            "SendARP 取不到 {ip} 的 MAC —— 字节序可能仍然不对（只发 2 字节前缀那种静默失败）"
        ),
    }
}
