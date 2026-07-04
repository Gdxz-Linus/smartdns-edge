use std::net::{IpAddr, Ipv4Addr};

use mac_addr::MacAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
}

// 🌟 修复 1：直接去掉冗余且会引发 Panic 的 block_in_place，
// 因为在外层的 app.rs 中已经使用了 spawn_blocking！
pub fn lookup_client_mac_from_arp(client_ip: IpAddr) -> Option<String> {
    client_ipv4_for_arp(client_ip).and_then(lookup_client_mac_from_arp_v4)
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
fn lookup_client_mac_from_arp_v4(client_ip: Ipv4Addr) -> Option<String> {
    // 动态链接 Windows 的 IP 助手 API
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn SendARP(
            dest_ip: u32,
            src_ip: u32,
            p_mac_addr: *mut u8,
            phy_addr_len: *mut u32,
        ) -> u32;
    }

    let dest_ip = u32::from_be_bytes(client_ip.octets());
    let mut mac = [0u8; 6];
    let mut mac_len = 6u32;

    // 🌟 极速调用，不产生任何系统子进程，微秒级返回！
    let res = unsafe { SendARP(dest_ip, 0, mac.as_mut_ptr(), &mut mac_len) };

    if res == 0 && mac_len == 6 {
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
mod tests {
    use super::*;

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
}
