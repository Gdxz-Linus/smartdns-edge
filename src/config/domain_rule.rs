use crate::libdns::proto::rr::rdata::opt::ClientSubnet;

use super::*;

/// domain-rules /domain/ [-rules...]
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct DomainRule {
    /// The name of NameServer Group.
    pub nameserver: Option<String>,

    pub address: Option<AddressRuleValue>,

    pub cname: Option<CNameRule>,

    pub srv: Option<SRV>,

    pub https: Option<HttpsRecordRule>,

    /// The mode of speed checking.
    pub speed_check_mode: Option<SpeedCheckModeList>,

    pub dualstack_ip_selection: Option<bool>,

    pub response_mode: Option<ResponseMode>,

    pub no_cache: Option<bool>,
    pub no_serve_expired: Option<bool>,
    pub nftset: Option<Vec<ConfigForIP<NFTsetConfig>>>,

    pub rr_ttl: Option<u64>,
    pub rr_ttl_min: Option<u64>,
    pub rr_ttl_max: Option<u64>,

    pub subnet: Option<ClientSubnet>,
}

impl std::ops::AddAssign for DomainRule {
    fn add_assign(&mut self, rhs: Self) {
        if rhs.nameserver.is_some() {
            self.nameserver = rhs.nameserver;
        }

        if rhs.address.is_some() {
            self.address = rhs.address;
        }

        // 🌟 核心修复 1：合并测速模式数组，使用纯循环避免触发系统截断 Bug
        if let Some(rhs_modes) = rhs.speed_check_mode {
            if let Some(ref mut lhs_modes) = self.speed_check_mode {
                for mode in rhs_modes.0 {
                    lhs_modes.push(mode);
                }
            } else {
                self.speed_check_mode = Some(rhs_modes);
            }
        }

        if rhs.dualstack_ip_selection.is_some() {
            self.dualstack_ip_selection = rhs.dualstack_ip_selection;
        }
        if rhs.no_cache.is_some() {
            self.no_cache = rhs.no_cache;
        }
        if rhs.no_serve_expired.is_some() {
            self.no_serve_expired = rhs.no_serve_expired;
        }
        if rhs.rr_ttl.is_some() {
            self.rr_ttl = rhs.rr_ttl;
        }
        if rhs.rr_ttl_min.is_some() {
            self.rr_ttl_min = rhs.rr_ttl_min;
        }
        if rhs.rr_ttl_max.is_some() {
            self.rr_ttl_max = rhs.rr_ttl_max;
        }
        if rhs.cname.is_some() {
            self.cname = rhs.cname;
        }
        if rhs.srv.is_some() {
            self.srv = rhs.srv;
        }
        if rhs.https.is_some() {
            self.https = rhs.https;
        }
        if rhs.response_mode.is_some() {
            self.response_mode = rhs.response_mode;
        }
        // 🌟 核心修复 2：合并 nftset 数组，同样使用纯循环避免被系统截断
        if let Some(rhs_nft) = rhs.nftset {
            if let Some(ref mut lhs_nft) = self.nftset {
                for nft in rhs_nft {
                    lhs_nft.push(nft);
                }
            } else {
                self.nftset = Some(rhs_nft);
            }
        }

        if rhs.subnet.is_some() {
            self.subnet = rhs.subnet;
        }
    }
}
