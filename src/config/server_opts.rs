use serde::{Deserialize, Serialize};

use super::{ConfigForIP, IpsetConfig, NFTsetConfig};

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

    /// 🔐 Q19：`bind ... -nftset [#4|#6]:family#table#set` —— **这个监听**收到的查询，
    /// 解析出来的地址都额外写进这些集合（与域名规则里配的集合是**并列**关系，各写各的）。
    ///
    /// 与 `-no-rule-ipset` 互为反面：那个是"整个不写"，这个是"总要多写几个"。
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub nftset: Option<Vec<ConfigForIP<NFTsetConfig>>>,

    /// 🔐 Q20：同上，Linux 的 ipset 那一半。
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub ipset: Option<Vec<ConfigForIP<IpsetConfig>>>,

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

    /// 该监听单独开启访问控制（对应 bind 的 `-acl`）。
    /// 与全局 `acl-enable` 是"或"的关系：任一为真，该监听就对不匹配 client-rules 的客户端回 REFUSED。
    pub acl: Option<bool>,

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

/// 📌 会影响"答案内容"的监听级（bind 级）选项。
///
/// 为什么要把它们单独拎出来：缓存是按一串标记去找答案的（域名 + 上游组 + 客户端网段 + 这里这组选项）。
/// 缓存里存的是**答案**，所以凡是能让同一次查询产出不同答案的输入，都必须进标记 —— 否则两个配得
/// 不一样的监听会互相借用对方算出来的答案，表现是"同一个域名、不同设备拿到的结果不一样，而且
/// 谁先查谁说了算"。实测（`probe_cache_proc_opts.py`）：一个监听写 `-no-speed-check`、另一个不写，
/// 结果两边都会拿到先查那次算出来的那份。
///
/// 只收**会改变答案**的项：
/// - `-no-speed-check` / `-no-dualstack-selection`：决定要不要挑最快 IP、要不要压掉某一族；
/// - `-force-aaaa-soa` / `-force-https-soa`：AAAA / HTTPS 查询直接回 SOA；
/// - `-no-rule-addr` / `-no-rule-nameserver` / `-no-rule-soa`：跳过本地地址规则 / 跳过上游组规则 / 跳过 SOA 规则；
/// - `rule_group`：这次查询用哪一套域名规则。
///
/// 特意**不收**：`-no-api`、`-max-connections*`、`-no-cache`（这类请求压根不走缓存）、
/// `-no-rule-ipset`（只决定写不写 ipset 表，答案本身不变）、`-no-serve-expired`（它管的是
/// "过期数据喂不喂"，缓存层已经按监听单独判断了）。收多了只会把同一份答案拆成好几份、白白降低命中率。
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnswerAffectingOpts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_group: Option<String>,
    pub no_speed_check: bool,
    pub no_dualstack_selection: bool,
    pub force_aaaa_soa: bool,
    pub force_https_soa: bool,
    pub no_rule_addr: bool,
    pub no_rule_nameserver: bool,
    pub no_rule_soa: bool,
}

impl AnswerAffectingOpts {
    /// 从监听选项里取出"会影响答案"的那几项。
    pub fn from_server_opts(opts: &ServerOpts) -> Self {
        Self {
            rule_group: opts.rule_group.clone(),
            no_speed_check: opts.no_speed_check(),
            no_dualstack_selection: opts.no_dualstack_selection(),
            force_aaaa_soa: opts.force_aaaa_soa(),
            force_https_soa: opts.force_https_soa(),
            no_rule_addr: opts.no_rule_addr(),
            no_rule_nameserver: opts.no_rule_nameserver(),
            no_rule_soa: opts.no_rule_soa(),
        }
    }

    /// 后台自动刷新（prefetch）用：把这些选项放回一份 ServerOpts 里。
    ///
    /// 不这么做的话，刷新会按**默认口径**去算，算出来的答案又会写到"默认口径"的标记下面，
    /// 原来那条（带选项的）永远刷不到、只会慢慢过期。
    pub fn into_server_opts(&self, group: String) -> ServerOpts {
        ServerOpts {
            is_background: true,
            group: Some(group),
            rule_group: self.rule_group.clone(),
            no_speed_check: Some(self.no_speed_check),
            no_dualstack_selection: Some(self.no_dualstack_selection),
            force_aaaa_soa: Some(self.force_aaaa_soa),
            force_https_soa: Some(self.force_https_soa),
            no_rule_addr: Some(self.no_rule_addr),
            no_rule_nameserver: Some(self.no_rule_nameserver),
            no_rule_soa: Some(self.no_rule_soa),
            ..Default::default()
        }
    }
}

impl ServerOpts {
    /// 该监听是否只提供 DoH、不挂管理后台（对应 bind 的 `-no-api`）
    pub fn no_api(&self) -> bool {
        self.no_api.unwrap_or_default()
    }

    /// 该监听是否单独开启了访问控制（对应 bind 的 `-acl`）
    #[inline]
    pub fn acl(&self) -> bool {
        self.acl.unwrap_or_default()
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
            acl: _,
            max_connections: _,
            max_connections_per_ip: _,
            no_dualstack_selection,
            force_aaaa_soa,
            force_https_soa,
            no_serve_expired,
            is_background: _,
            rule_group,
            nftset,
            ipset,
        } = other;

        // 🔐 Q19/Q20：集合不是"谁覆盖谁"，而是**两家配的都写**（各写各的集合）
        if let Some(other_sets) = nftset {
            self.nftset.get_or_insert_with(Vec::new).extend(other_sets);
        }
        if let Some(other_sets) = ipset {
            self.ipset.get_or_insert_with(Vec::new).extend(other_sets);
        }

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
