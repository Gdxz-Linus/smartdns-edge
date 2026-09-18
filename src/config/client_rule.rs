use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Client {
    // 🌟 修复 1：将 MacAddr 改为 Mac，与 app.rs 中的调用完美契合！
    Mac(String),
    IpAddr(IpNet),
}

/// 把 MAC 的常见写法归一成"12 位小写十六进制、无分隔符"，专供比较使用。
///
/// 认这几种写法：`aa:bb:cc:dd:ee:ff`（Linux / 本项目的运行时格式）、
/// `AA-BB-CC-DD-EE-FF`（Windows `arp -a` 就是这种）、`aabbccddeeff`、`aabb.ccdd.eeff`
/// （部分交换机与运维脚本这么写）。不属这几种的一律返回 None。
pub fn normalize_mac(s: &str) -> Option<String> {
    if s.chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.'))
    {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() == 12 {
            return Some(hex.to_ascii_lowercase());
        }
    }
    None
}

/// 判断"规则里写的 MAC"与"运行时拿到的那台机器的 MAC"是不是同一个。
///
/// 运行时那个值来自 `src/infra/arp.rs`：它把系统 ARP 表解析成 `mac_addr::MacAddr` 再 `to_string()`，
/// 而这个 crate 的 Display 固定是"小写 + 冒号"（其源码注释写明 "Lowercase hex with `:` separators"）。
/// 用户则可能按别的写法配规则 → 所以**两边都归一后再比**（这就是 A10 的修复）。
///
/// 有一边不是合法 MAC 写法时，退回"忽略大小写直接比"：宁可保持原来的行为，
/// 也不要因为这次改动让原本能命中的规则失效。
pub fn mac_matches(rule: &str, actual: &str) -> bool {
    match (normalize_mac(rule), normalize_mac(actual)) {
        (Some(rule), Some(actual)) => rule == actual,
        _ => rule.eq_ignore_ascii_case(actual),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRule {
    /// The client, mac address or ip address
    pub client: Client,

    /// The rule group name
    pub group: String,
}

impl ClientRule {
    pub fn match_ip(&self, ip: &IpAddr) -> bool {
        match &self.client {
            Client::Mac(_) => false, // 🌟 修复 2：同步修改为 Mac
            Client::IpAddr(ip_net) => ip_net.contains(ip),
        }
    }

    pub fn match_net(&self, net: &IpNet) -> bool {
        match &self.client {
            Client::Mac(_) => false, // 🌟 修复 3：同步修改为 Mac
            Client::IpAddr(ip_net) => ip_net.contains(net),
        }
    }

    pub fn match_mac(&self, mac: &str) -> bool {
        match &self.client {
            // 🔐 A10（2026-09-17）：以前只做"忽略大小写"的字符串比较，于是照 Windows `arp -a`
            // 写成横杠格式（`01-23-45-67-89-ab`）的规则**永远比不上**运行时那份（小写冒号）——
            // 表现是"规则写了却不生效"。比较逻辑统一收在 `mac_matches` 里，别再各写一遍。
            Client::Mac(mac_rule) => mac_matches(mac_rule, mac),
            Client::IpAddr(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_rule() {
        let rule = ClientRule {
            client: Client::IpAddr("192.168.1.0/24".parse().unwrap()),
            group: "test".to_string(),
        };

        assert!(rule.match_ip(&"192.168.1.0".parse().unwrap()));
        assert!(rule.match_ip(&"192.168.1.2".parse().unwrap()));
        assert!(rule.match_net(&"192.168.1.2/32".parse().unwrap()));
    }

    /// 🔐 A10：MAC 规则的各种常见写法都必须能命中，且不能误命中别的 MAC。
    ///
    /// 运行时那份字符串来自 `src/infra/arp.rs` —— 它把系统 ARP 表解析成 `mac_addr::MacAddr`
    /// 再 `to_string()`，而这个 crate 的 Display 固定是"小写 + 冒号"（见 crates 源码里
    /// `impl fmt::Display for MacAddr` 的注释 "Lowercase hex with `:` separators"）。
    /// 用户则常照 Windows `arp -a` 写成横杠格式，于是两边对不上 —— 这就是 A10。
    #[test]
    fn mac_rule_matches_all_common_notations() {
        // 忠实模拟运行时那一侧的取值方式（与 arp.rs 一致）
        let actual = "01:23:45:67:89:ab"
            .parse::<mac_addr::MacAddr>()
            .unwrap()
            .to_string();
        assert_eq!(actual, "01:23:45:67:89:ab", "运行时格式应是小写冒号");

        let rule = |s: &str| ClientRule {
            client: Client::Mac(s.to_string()),
            group: "test".to_string(),
        };

        for notation in [
            "01:23:45:67:89:ab", // Linux / 本项目内部格式
            "01-23-45-67-89-ab", // Windows `arp -a` —— A10 报的就是这种不生效
            "01-23-45-67-89-AB", // 大写 + 横杠
            "0123456789AB",      // 无分隔符 + 大写
            "0123.4567.89ab",    // 点分格式（部分交换机/脚本这么写）
        ] {
            assert!(
                rule(notation).match_mac(&actual),
                "规则写成 {notation} 时必须命中 {actual}"
            );
        }

        // 不能误命中：只差最后一位也不行
        for wrong in ["01:23:45:67:89:ac", "01-23-45-67-89-ac", "0123456789ac"] {
            assert!(
                !rule(wrong).match_mac(&actual),
                "规则 {wrong} 与 {actual} 不是同一个 MAC，不该命中"
            );
        }

        // 不合法/奇怪的写法不许"碰巧命中"（这里退回忽略大小写的原样比较）
        for weird in [
            "",
            "abd",
            "01:23:45:67:89",
            "01:23:45:67:89:ab:cd",
            "zz:zz:zz:zz:zz:zz",
        ] {
            assert!(
                !rule(weird).match_mac(&actual),
                "规则 {weird} 不是合法 MAC，不该命中 {actual}"
            );
        }
    }

    /// 护栏：IP 规则那条路不受影响；拿 IP 规则去比 MAC 必须为 false。
    #[test]
    fn ip_rules_are_not_affected_by_mac_matching() {
        let ip_rule = ClientRule {
            client: Client::IpAddr("10.0.0.0/8".parse().unwrap()),
            group: "test".to_string(),
        };
        assert!(!ip_rule.match_mac("01:23:45:67:89:ab"));
        assert!(ip_rule.match_ip(&"10.1.2.3".parse().unwrap()));

        let mac_rule = ClientRule {
            client: Client::Mac("01-23-45-67-89-ab".to_string()),
            group: "test".to_string(),
        };
        assert!(!mac_rule.match_ip(&"10.1.2.3".parse().unwrap()));
    }
}
