use std::net::IpAddr;
use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Client {
    // 🌟 修复 1：将 MacAddr 改为 Mac，与 app.rs 中的调用完美契合！
    Mac(String),
    IpAddr(IpNet),
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
            // 🌟 修复 4：不仅改名，而且改为 eq_ignore_ascii_case，
            // 这样无论用户配置里写大写(AA:BB)还是小写(aa:bb)，都能完美匹配！
            Client::Mac(mac_rule) => mac_rule.eq_ignore_ascii_case(mac),
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
}
