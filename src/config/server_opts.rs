use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerOpts {
    /// set domain request to use the appropriate server group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// set domain request to use the appropriate rule group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_group: Option<String>,

    /// skip address rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_rule_addr: Option<bool>,

    /// skip nameserver rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_rule_nameserver: Option<bool>,

    /// skip ipset rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_rule_ipset: Option<bool>,

    /// do not check speed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_speed_check: Option<bool>,

    /// skip cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_cache: Option<bool>,

    /// Skip address SOA(#) rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_rule_soa: Option<bool>,

    /// 该监听只提供加密 DNS（DoH），不挂管理后台。
    ///
    /// 用途：对外提供 DoH 时，不必连带把 `/api` 管理接口一起暴露出去。
    /// 对应 bind 的 `-no-api` 选项。
    pub no_api: Option<bool>,

    /// 该监听单独设置的连接总数上限（对应 bind 的 `-max-connections N`）
    pub max_connections: Option<usize>,

    /// 该监听单独设置的单一来源连接数上限（对应 `-max-connections-per-ip N`）
    pub max_connections_per_ip: Option<usize>,

    /// Disable dualstack ip selection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_dualstack_selection: Option<bool>,

    /// force AAAA query return SOA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_aaaa_soa: Option<bool>,

    /// force HTTPS query return SOA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_https_soa: Option<bool>,

    /// do not serve expired
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_serve_expired: Option<bool>,

    /// Indicates whether the query task is a background task.
    #[serde(default)]
    pub is_background: bool,
}

impl ServerOpts {
    /// 该监听是否只提供 DoH、不挂管理后台（对应 bind 的 `-no-api`）
    pub fn no_api(&self) -> bool {
        self.no_api.unwrap_or_default()
    }

    /// set domain request to use the appropriate server group.
    #[inline]
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// skip address rule.
    #[inline]
    pub fn no_rule_addr(&self) -> bool {
        self.no_rule_addr.unwrap_or_default()
    }

    /// skip nameserver rule.
    #[inline]
    pub fn no_rule_nameserver(&self) -> bool {
        self.no_rule_nameserver.unwrap_or_default()
    }

    /// skip ipset rule.
    #[inline]
    pub fn no_rule_ipset(&self) -> bool {
        self.no_rule_ipset.unwrap_or_default()
    }

    ///  do not check speed.
    #[inline]
    pub fn no_speed_check(&self) -> bool {
        self.no_speed_check.unwrap_or_default()
    }

    /// skip cache.
    #[inline]
    pub fn no_cache(&self) -> bool {
        self.no_cache.unwrap_or_default()
    }

    /// Skip address SOA(#) rules.
    #[inline]
    pub fn no_rule_soa(&self) -> bool {
        self.no_rule_soa.unwrap_or_default()
    }

    /// Disable dualstack ip selection.
    #[inline]
    pub fn no_dualstack_selection(&self) -> bool {
        self.no_dualstack_selection.unwrap_or_default()
    }

    /// force AAAA query return SOA.
    #[inline]
    pub fn force_aaaa_soa(&self) -> bool {
        self.force_aaaa_soa.unwrap_or_default()
    }

    /// force HTTPS query return SOA.
    #[inline]
    pub fn force_https_soa(&self) -> bool {
        self.force_https_soa.unwrap_or_default()
    }

    /// do not serve expired.
    #[inline]
    pub fn no_serve_expired(&self) -> bool {
        self.no_serve_expired.unwrap_or_default()
    }

    pub fn apply(&mut self, other: Self) {
        let Self {
            group,
            no_rule_addr,
            no_rule_nameserver,
            no_rule_ipset,
            no_speed_check,
            no_cache,
            no_rule_soa,
            no_api: _,
            max_connections: _,
            max_connections_per_ip: _,
            no_dualstack_selection,
            force_aaaa_soa,
            force_https_soa,
            no_serve_expired,
            is_background: _,
            rule_group,
        } = other;

        if self.group.is_none() {
            self.group = group;
        }
        if self.no_rule_addr.is_none() {
            self.no_rule_addr = no_rule_addr;
        }
        if self.no_rule_nameserver.is_none() {
            self.no_rule_nameserver = no_rule_nameserver;
        }
        if self.no_rule_ipset.is_none() {
            self.no_rule_ipset = no_rule_ipset;
        }

        if self.no_speed_check.is_none() {
            self.no_speed_check = no_speed_check;
        }
        if self.no_cache.is_none() {
            self.no_cache = no_cache;
        }
        if self.no_rule_soa.is_none() {
            self.no_rule_soa = no_rule_soa;
        }

        if self.no_dualstack_selection.is_none() {
            self.no_dualstack_selection = no_dualstack_selection;
        }

        if self.force_aaaa_soa.is_none() {
            self.force_aaaa_soa = force_aaaa_soa;
        }

        if self.force_https_soa.is_none() {
            self.force_https_soa = force_https_soa;
        }

        if self.no_serve_expired.is_none() {
            self.no_serve_expired = no_serve_expired;
        }
        if self.rule_group.is_none() {
            self.rule_group = rule_group;
        }
    }
}

impl std::ops::AddAssign for ServerOpts {
    fn add_assign(&mut self, rhs: Self) {
        self.apply(rhs)
    }
}
