//! 🔐 13-⑥：**可信代理**（trusted proxy）—— 在"前面挂了反向代理"时，
//! 从 `X-Forwarded-For` 里还原**真实客户端地址**。
//!
//! # 这个文件解决的问题
//!
//! 本项目**刻意不信任任何代理请求头**（`X-Forwarded-For` / `X-Real-IP` 等），
//! 只认**内核给出的真实对端地址**。这是正确的安全默认 —— 报告 §四 把它列为
//! "确认没有问题"的部分，因为**用请求头判断来源就等于把安全性交给了调用方自报**。
//!
//! 但那个正确默认有一个**代价**，报告里写得很清楚：
//!
//! > 前面挂反向代理时，所有客户端**共用代理 IP**，限流变成共享额度，
//! > **一个坏人能让所有人被限**。
//!
//! 具体是三个消费者一起受影响（它们原本都只认真实对端）：
//!
//! | 消费者 | 现状 | 挂反代后的后果 |
//! |---|---|---|
//! | 连接限流（`server/limit.rs`） | 按对端 IP 归组 | 所有客户端共用一个额度，一台设备刷满 ⇒ **全网被拒连** |
//! | ACL / 按来源分组（`dns_mw.rs`） | 按对端 IP 匹配 `client-rules` | **ACL 无法按设备做策略** |
//! | 后台口令失败限流（`api/mod.rs`） | 按对端 IP 计数 | 有人故意错 10 次 ⇒ **管理员也被 429 挡住** |
//!
//! 本模块提供一个**显式的、由用户亲手写下的**代理清单：只有来自清单内的请求，
//! 才去解析 `X-Forwarded-For`。**清单为空 = 完全保持现状**（不信任任何代理头）。
//!
//! # ⚠️ 边界：只有 HTTP 类协议能做到
//!
//! | 协议 | 能否使用可信代理 |
//! |---|---|
//! | DoH / `bind-http` / 管理后台 | ✅ 有 HTTP 头，可用 |
//! | DoT / TCP | ⚠️ 需 PROXY protocol（另一套协议，本模块不涉及） |
//! | **UDP 53** | ❌ **做不到** —— UDP 报里**没有"头"这个概念**，代理只能 SNAT，真实来源无从得知 |
//!
//! 也就是说：**普通 DNS 查询（UDP 53）永远无法按真实客户端归组**，配了可信代理也一样。
//! 这不是实现缺陷，是协议事实 —— 文档必须写明，免得用户以为配了就灵。
//!
//! # ⚠️ 三条铁律（缺一不可）
//!
//! `X-Forwarded-For` 是**客户端可以自己伪造的普通 HTTP 头**。
//! 不设限地信任它，攻击者一行命令就能伪装成任意 IP、绕过所有限流：
//!
//! ```text
//! curl -H "X-Forwarded-For: 1.2.3.4" https://server/dns-query
//! ```
//!
//! 所以本模块的实现严格遵守：
//!
//! 1. **先校验对端在清单内**（[`TrustedProxies::contains`]）—— 不在清单内就**完全无视**
//!    代理头，直接用对端地址。这一步是不可省略的前提。
//! 2. **从右往左**扫描 XFF，跳过所有可信跳，取第一个**不可信**地址
//!    （见 [`resolve_client_ip`]）。**从左取是错的**：客户端可以在最左边塞任意值，
//!    只有右侧若干跳才是由真实代理逐级追加的。
//! 3. **只用于"归组"，绝不用于"放行"** —— 即用于限流计数与选择规则组，
//!    但**不参与 ACL 的是否放行判定**（见 [`ClientIpSource::is_forwarded`] 的说明）。
//!    否则"伪造头 = 绕过 ACL"，那就从限流问题升级成安全问题了。

use std::net::IpAddr;

use ipnet::IpNet;

/// 客户端真实地址的**来源**，用于区分"要不要信任它"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIpSource {
    /// 直接用**对端地址**（内核给出的、不可伪造）。
    ///
    /// 这是默认情形：没配可信代理、或对端不在清单内。
    Peer,
    /// 从 `X-Forwarded-For` **解析出来**的地址（对端在可信清单内）。
    ///
    /// ⚠️ **这个值只可用于"归组"**（限流计数、选择规则组），
    /// **绝不可用于"是否放行"的判定** —— 它是调用方自报的，可被伪造。
    /// 详见模块文档的"三条铁律"第 3 条。
    Forwarded,
}

impl ClientIpSource {
    /// 这个地址是不是**调用方自报**的？
    ///
    /// 调用方（ACL 判定、日志打标）用它来提醒自己"别拿它当权威来源"。
    #[inline]
    pub fn is_forwarded(self) -> bool {
        matches!(self, ClientIpSource::Forwarded)
    }
}

/// 可信代理清单（一组 IP / 网段）。
///
/// **空清单是默认值，表示"不信任任何代理头"** —— 与本项目原本的行为完全一致。
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        Self {
            nets: nets.into_iter().collect(),
        }
    }

    /// 清单是否为空（空 = 不信任任何代理，行为与本项目原本完全一致）。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }

    /// 对端地址是否在清单内。
    ///
    /// ⚠️ 这是"要不要解析 XFF"的**唯一前提**。跳过这一步就等于信任所有人自报的来源。
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(&ip))
    }

    /// 清单里的网段（供启动摘要打印用）。
    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }
}

/// 把"IPv4 映射到 IPv6"的地址还原成普通 IPv4。
///
/// 与 `server/limit.rs`、`api/mod.rs` 的同名处理保持一致：双栈监听（`[::]:53`）下，
/// IPv4 客户端在程序内部以 `::ffff:a.b.c.d` 出现，不还原会导致
/// 同一台设备在两条路径上算出不同的来源身份。
///
/// ⚠️ **对 DNS 记录扇出（`record.type = 请求记录的应答扇出`）无影响**，
/// 它只是让"来源身份"在两种表示下一致。
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// 🔐 **核心**：算出"这次请求该按哪个地址归组"。
///
/// # 算法（严格按"三条铁律"）
///
/// 1. 对端**不在**可信清单内（或清单为空）⇒ 返回**对端地址**、来源记为 [`ClientIpSource::Peer`]。
///    **完全不看 XFF** —— 这是防伪造的关键一步。
/// 2. 对端在清单内 ⇒ 解析 XFF，**从右往左**扫描：
///    - 跳过所有**仍落在可信清单内**的地址（那是代理链上的其它代理）；
///    - 遇到第一个**不可信**地址就返回它、来源记为 [`ClientIpSource::Forwarded`]。
/// 3. 整条 XFF 都被"跳过"完（全可信）、或 XFF 里没有合法地址 ⇒ **退回对端地址**
///    （保守：宁可按代理归组，也不凭空造一个地址出来）。
///
/// # 为什么从右往左
///
/// XFF 是"每一跳各自追加"的，格式为 `客户端, 代理1, 代理2, ...`。
/// 但**客户端自己可以预先塞入内容** —— 它可以发
/// `X-Forwarded-For: 1.2.3.4`（伪造），于是代理追加后变成
/// `1.2.3.4, 真实客户端`。
///
/// 此时**从左取**得到伪造的 `1.2.3.4`（限流被绕过），
/// **从右取**得到 `真实客户端`（正确）。所以必须从右往左。
pub fn resolve_client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &TrustedProxies,
) -> (IpAddr, ClientIpSource) {
    let peer = normalize(peer);

    // 铁律 ①：对端不在清单内 ⇒ 完全无视代理头。
    // 清单为空时 contains 恒为 false，于是**默认行为与本项目原本完全一致**。
    if !trusted.contains(peer) {
        return (peer, ClientIpSource::Peer);
    }

    let Some(raw) = forwarded_for else {
        // 对端可信，但请求没带 XFF（比如代理没配这个头）⇒ 退回对端地址。
        return (peer, ClientIpSource::Peer);
    };

    // 铁律 ②：从右往左，跳过仍可信的跳，取第一个不可信地址。
    for item in raw.split(',').rev() {
        let item = item.trim();

        // 允许 `1.2.3.4:5678` 这种带端口的写法（部分代理会带上），
        // 去掉端口再解析；解析不了就跳过这一项（继续往左找）。
        let candidate = item
            .parse::<IpAddr>()
            .ok()
            .or_else(|| item.parse::<std::net::SocketAddr>().ok().map(|sa| sa.ip()));

        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = normalize(candidate);

        if trusted.contains(candidate) {
            // 这一跳也是可信代理 → 继续往左找真实客户端
            continue;
        }

        return (candidate, ClientIpSource::Forwarded);
    }

    // 整条 XFF 全是可信代理（或全是垃圾）⇒ 退回对端地址，不凭空造一个。
    (peer, ClientIpSource::Peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(list: &[&str]) -> TrustedProxies {
        TrustedProxies::new(list.iter().map(|s| s.parse::<IpNet>().unwrap()))
    }

    /// 🔐 **默认行为零变化**：清单为空时，永远返回对端地址、且完全无视 XFF。
    ///
    /// 这是本功能最重要的性质：没配 `trusted-proxy` 的部署，
    /// 行为与改动前**逐字节一致**（安全性不被新功能削弱）。
    #[test]
    fn empty_trusted_list_never_trusts_any_header() {
        let trusted = TrustedProxies::default();
        assert!(trusted.is_empty());

        // 即使带了伪装头，也必须用对端地址
        let (resolved, source) = resolve_client_ip(
            ip("10.0.0.1"),
            Some("1.2.3.4"), // 伪造成公网地址，想绕过限流
            &trusted,
        );

        assert_eq!(
            resolved,
            ip("10.0.0.1"),
            "清单为空时必须用对端地址 —— 否则任何人都能靠加个头绕过限流"
        );
        assert_eq!(source, ClientIpSource::Peer);
        assert!(!source.is_forwarded());
    }

    /// 🔐 **铁律 ①**：对端**不在**清单内时，即使带了 XFF 也完全无视。
    #[test]
    fn peer_outside_the_list_is_never_trusted() {
        // 只信任 192.168.1.1
        let trusted = nets(&["192.168.1.1/32"]);

        // 对端是别的地址（比如攻击者直连）
        let (resolved, source) = resolve_client_ip(ip("203.0.113.9"), Some("1.2.3.4"), &trusted);

        assert_eq!(
            resolved,
            ip("203.0.113.9"),
            "对端不在可信清单内 ⇒ 必须无视 XFF（这是防伪造的前提）"
        );
        assert_eq!(source, ClientIpSource::Peer);
    }

    /// 🔐 **铁律 ②（核心）**：对端可信时，**从右往左**取第一个不可信地址。
    ///
    /// 这条直接对应"客户端预塞伪造值"的攻击：
    /// 客户端发 `XFF: 1.2.3.4`（伪造），代理追加真实地址后变成 `1.2.3.4, 真实客户端`。
    /// 从左取会拿到伪造值，从右取才拿到真实客户端。
    #[test]
    fn takes_the_rightmost_untrusted_hop() {
        let trusted = nets(&["192.168.1.1/32"]);

        let (resolved, source) = resolve_client_ip(
            ip("192.168.1.1"),             // 对端是可信代理
            Some("1.2.3.4, 198.51.100.7"), // 左边是客户端伪造的，右边是真代理追加的
            &trusted,
        );

        assert_eq!(
            resolved,
            ip("198.51.100.7"),
            "🔐 必须取最右侧那个不可信地址 —— 从左取会拿到客户端伪造的 1.2.3.4，\
             等于限流被完全绕过"
        );
        assert_eq!(source, ClientIpSource::Forwarded);
        assert!(source.is_forwarded());
    }

    /// 多级代理链：可信跳在右侧连续出现时，要**跳过它们**继续往左找真实客户端。
    #[test]
    fn skips_multiple_trusted_hops() {
        // 信任两级代理
        let trusted = nets(&["10.0.0.0/8", "192.168.1.1/32"]);

        let (resolved, source) = resolve_client_ip(
            ip("192.168.1.1"),                       // 对端（可信）
            Some("203.0.113.5, 10.0.0.9, 10.0.0.8"), // 右侧两跳都是可信代理
            &trusted,
        );

        assert_eq!(
            resolved,
            ip("203.0.113.5"),
            "应当跳过右侧所有可信跳，取第一个不可信的（真实客户端）"
        );
        assert_eq!(source, ClientIpSource::Forwarded);
    }

    /// 整条 XFF 全是可信代理（没有真实客户端）⇒ **退回对端地址**，不凭空造。
    #[test]
    fn all_trusted_hops_fall_back_to_peer() {
        let trusted = nets(&["10.0.0.0/8"]);

        let (resolved, source) =
            resolve_client_ip(ip("10.0.0.1"), Some("10.0.0.2, 10.0.0.3"), &trusted);

        assert_eq!(
            resolved,
            ip("10.0.0.1"),
            "全是可信跳时应当保守地退回对端地址，而不是构造一个不存在的客户端"
        );
        assert_eq!(source, ClientIpSource::Peer);
    }

    /// 对端可信但没有 XFF 头（代理没配该头）⇒ 退回对端地址。
    #[test]
    fn missing_header_falls_back_to_peer() {
        let trusted = nets(&["192.168.1.1/32"]);
        let (resolved, source) = resolve_client_ip(ip("192.168.1.1"), None, &trusted);

        assert_eq!(resolved, ip("192.168.1.1"));
        assert_eq!(source, ClientIpSource::Peer);
    }

    /// XFF 里的垃圾项要**跳过**并继续往左找，不能让解析失败破坏整条解析。
    #[test]
    fn malformed_entries_are_skipped() {
        let trusted = nets(&["192.168.1.1/32"]);

        let (resolved, _) = resolve_client_ip(
            ip("192.168.1.1"),
            Some("unknown, 198.51.100.7, , garbage"),
            &trusted,
        );

        assert_eq!(
            resolved,
            ip("198.51.100.7"),
            "解析不了的项应当跳过，继续往左找第一个合法且不可信的地址"
        );
    }

    /// 带端口的写法（部分代理会带）也要能解析。
    #[test]
    fn entries_with_port_are_accepted() {
        let trusted = nets(&["192.168.1.1/32"]);

        let (resolved, source) =
            resolve_client_ip(ip("192.168.1.1"), Some("198.51.100.7:5678"), &trusted);

        assert_eq!(
            resolved,
            ip("198.51.100.7"),
            "带端口的写法应当识别出 IP 部分"
        );
        assert_eq!(source, ClientIpSource::Forwarded);
    }

    /// 🔐 双栈监听下 IPv4 客户端以 `::ffff:` 出现时，必须与普通形式**归为同一来源**。
    ///
    /// 与 `server/limit.rs`、`api/mod.rs` 的同名处理保持一致 ——
    /// 否则同一台设备在"直连"和"经代理"两条路径上会算出不同身份。
    #[test]
    fn ipv4_mapped_forms_are_normalized() {
        // ① 对端是映射形式、清单里写的是普通形式 → 应当认得出来
        let trusted = nets(&["10.0.0.1/32"]);
        let (resolved, source) =
            resolve_client_ip(ip("::ffff:10.0.0.1"), Some("198.51.100.7"), &trusted);
        assert_eq!(
            resolved,
            ip("198.51.100.7"),
            "映射形式必须与普通形式一样被认作可信代理（否则双栈监听下可信代理形同虚设）"
        );
        assert_eq!(source, ClientIpSource::Forwarded);

        // ② XFF 里写映射形式 → 还原成普通 IPv4 返回
        let (resolved, _) =
            resolve_client_ip(ip("10.0.0.1"), Some("::ffff:198.51.100.7"), &trusted);
        assert_eq!(
            resolved,
            ip("198.51.100.7"),
            "XFF 里的映射形式应当还原成普通 IPv4（保持来源身份统一）"
        );
    }

    /// 网段形式的可信代理要能正常匹配（不只是单个 IP）。
    #[test]
    fn cidr_ranges_are_supported() {
        let trusted = nets(&["10.0.0.0/8", "2001:db8::/32"]);

        assert!(trusted.contains(ip("10.1.2.3")), "网段内的 IPv4 应当命中");
        assert!(
            trusted.contains(ip("2001:db8::1")),
            "网段内的 IPv6 应当命中"
        );
        assert!(!trusted.contains(ip("11.0.0.1")), "网段外的不该命中");
    }
}
