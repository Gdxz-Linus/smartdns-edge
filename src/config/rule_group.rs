use std::sync::LazyLock;

use super::{AddressRules, CNameRules, DomainRules, ForwardRule, HttpsRecords, SrvRecords};

static EMPTY: LazyLock<RuleGroup> = LazyLock::new(RuleGroup::default);

/// 📌 可以写进 `group-begin ... group-end` 块里的**开关 / 数值型**参数。
///
/// 为什么需要它：C 版有一整类参数（`_dns_conf_group_yesno` / `_dns_conf_group_int`）
/// 既能写在顶层，也能写进规则组，从而做到「同一个域名、不同组用不同策略」。
/// 本项目原先只有顶层（全局）与 bind 级两层，`RuleGroup` 又只装**规则集合**、
/// 没有任何标量字段，于是这一层整体缺失。本结构补的就是这一层。
///
/// 字段一律用 `Option<T>`：
/// * `None` = **本组没写**，生效时继续往下找（组 → 全局），这是分层语义的基础；
/// * `Some(v)` = 本组显式指定，压过更外层的值。
///
/// 生效优先级（与 C 版一致）：**bind 级 > 组级 > 全局**。
///
/// ⚠️ 新增字段时务必同步三处，漏一处就会出现「配了不生效」或「缓存串答案」：
///   1. `dns_conf.rs` 的 `config_unchecked`（决定写进组还是写全局）；
///   2. `DnsContext` 的取值入口（决定最终生效值）；
///   3. `AnswerAffectingOpts` + `from_server_opts`（决定是否进缓存键）——
///      凡是能改变答案的项，不进缓存键就会让两个配得不一样的组互相借用答案。
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct GroupParams {
    /// 强制不向客户端返回 CNAME 记录（展平为最终地址）。
    pub force_no_cname: Option<bool>,
    /// AAAA 查询直接回 SOA。
    pub force_aaaa_soa: Option<bool>,

    /// 📌 甲类（2026-09-26 铺开）：与上游一致、且**没有 bind 级对应项**的参数。
    /// 它们只有两层：**组级 > 全局**。
    /// 写进集合的条目要不要带过期时间（`ipset-timeout`）
    pub ipset_timeout: Option<bool>,
    /// 同上，nftables 那一半
    pub nftset_timeout: Option<bool>,
    /// 最小 TTL
    pub rr_ttl_min: Option<u64>,
    /// 最大 TTL
    pub rr_ttl_max: Option<u64>,
    /// 允许返回给客户端的最大 TTL
    pub rr_ttl_reply_max: Option<u64>,
    /// 本地记录（address / cname / hosts）的 TTL
    pub local_ttl: Option<u64>,
    /// 双栈优选是否允许压掉 A 记录
    pub dualstack_ip_allow_force_aaaa: Option<bool>,
    /// 双栈族对决的判定阈值（毫秒）
    pub dualstack_ip_selection_threshold: Option<u64>,
    /// 一次应答最多返回几个 IP（0 = 不限）
    pub max_reply_ip_num: Option<u8>,

    /// 📌 乙类（2026-09-26 铺开）：这些在**域名规则级本来就有**对应写法，
    /// 所以取值链是三层：**域名规则 > 组级 > 全局**。
    /// 统一 TTL（`rr-ttl`）
    ///
    /// ⚠️ 它与 `rr_ttl_min` / `rr_ttl_max` 是**同一族**，必须同层取：
    /// `rr-ttl-min` 的语义是"给 `rr-ttl` 兜底"，让 min 从组级取、而 `rr-ttl`
    /// 从全局取会自相矛盾（详见 `RuntimeConfig::rr_ttl_min_in_group` 的说明）。
    pub rr_ttl: Option<u64>,
    /// 响应模式（`response-mode`）
    pub response_mode: Option<crate::config::ResponseMode>,
    /// 测速模式（`speed-check-mode`）
    ///
    /// 用 `Option<SpeedCheckModeList>`：**必须保住"没写"（外层 `None`）与
    /// "写了 `none`"（`Some([None])`）可区分** —— 这是问题 24 的核心成果，
    /// 折叠成同一个值会让用户的 `none` 被当成"没配置"而反过来触发默认测速。
    pub speed_check_mode: Option<crate::config::SpeedCheckModeList>,

    /// 📌 丙-1（2026-09-26 补齐组级支持）：这三个只作用于**逐查询**的那一侧。
    ///
    /// ⚠️ 同名的"后台任务开关"**不**跟组级走，理由见
    /// `RuntimeConfig::prefetch_domain_in_group` 与 `serve_expired_in_group` 的说明：
    /// 后台任务是**一个进程一份**，它遍历所有缓存条目、不是"某个组在预取"；
    /// 若让组级值影响它，会出现"某个组写了关、把整个进程的后台任务停掉"这种跨组误伤。
    ///
    /// 过期数据能不能喂（`serve-expired`）—— **逐查询**
    pub serve_expired: Option<bool>,
    /// 喂过期数据时回给客户端的 TTL（`serve-expired-reply-ttl`）—— **逐查询**
    pub serve_expired_reply_ttl: Option<u64>,
    /// 这条应答要不要安排后台预取（`prefetch-domain`）—— **逐查询**
    pub prefetch_domain: Option<bool>,

    /// 📌 丙-2a（2026-09-26 补齐组级支持）：DNS64 前缀。
    ///
    /// 配了就对这个组的 AAAA 查询做 DNS64 合成（拿 A 记录合成 AAAA）。
    /// `None` = 本组没写，继续往外找。
    pub dns64_prefix: Option<ipnet::Ipv6Net>,

    /// 📌 丙-2b（2026-09-26 补齐组级支持）：EDNS Client Subnet。
    ///
    /// 取值链是 **客户端自带 > 域名规则级 > 组级 > 全局默认值**。
    /// 注意全局那一档是**启动期烧进 `NameServer` 的默认值**，不是逐查询读配置；
    /// 组级插在它前面，因此天然压过全局（见 `dns_mw_ns.rs` 里的说明）。
    pub edns_client_subnet: Option<ipnet::IpNet>,

    /// 📌 丙-2c（2026-09-26 补齐组级支持）：双栈优选开关。
    ///
    /// 取值链是 **域名规则级 > 组级 > 全局**（三层，都是**正向布尔**）。
    ///
    /// ⚠️ **bind 级不在这条链上**：`bind ... -no-dualstack-selection` 是一个
    /// **单向总闸**（只能关、不能开），语义是"这个监听整体不做双栈优选"，
    /// 与"某一层把开关配成什么"是两码事。它在调用侧用 `&&` 短路，优先于本条链。
    pub dualstack_ip_selection: Option<bool>,
}

impl GroupParams {
    /// 把「被继承组」的值填进本组的空缺位。
    ///
    /// 注意与规则集合的 `extend`（累加）**语义不同**：标量不能累加，
    /// 只有本组**没写**（`None`）的格子才接受继承值，本组写了的一律保留。
    pub fn inherit_from(&mut self, other: &GroupParams) {
        macro_rules! fill {
            ($($field:ident),* $(,)?) => {
                $( if self.$field.is_none() {
                    // ⚠️ 用 `clone()` 而不是直接赋值：并非所有字段都是 `Copy`
                    // （`speed_check_mode` 装的是 `SpeedCheckModeList`，内含 `Vec`）。
                    // 直接移动会让 `inherit_from(&GroupParams)` 借用的那侧被移走而编译失败。
                    self.$field = other.$field.clone();
                } )*
            };
        }
        fill!(
            force_no_cname,
            force_aaaa_soa,
            ipset_timeout,
            nftset_timeout,
            rr_ttl_min,
            rr_ttl_max,
            rr_ttl_reply_max,
            local_ttl,
            dualstack_ip_allow_force_aaaa,
            dualstack_ip_selection_threshold,
            max_reply_ip_num,
            rr_ttl,
            response_mode,
            speed_check_mode,
            serve_expired,
            serve_expired_reply_ttl,
            prefetch_domain,
            dns64_prefix,
            edns_client_subnet,
            dualstack_ip_selection,
        );
    }

    /// 本组是否一个参数都没写（用于诊断与测试）。
    pub fn is_empty(&self) -> bool {
        *self == GroupParams::default()
    }
}

#[derive(Default, Debug, Clone)]
pub struct RuleGroup {
    /// specific nameserver to domain
    ///
    /// nameserver /domain/[group|-]
    ///
    /// ```
    /// example:
    ///   nameserver /www.example.com/office, Set the domain name to use the appropriate server group.
    ///   nameserver /www.example.com/-, ignore this domain
    /// ```
    pub forward_rules: Vec<ForwardRule>,

    /// specific address to domain
    ///
    /// address /domain/[ip|-|-4|-6|#|#4|#6]
    ///
    /// ```
    /// example:
    ///   address /www.example.com/1.2.3.4, return ip 1.2.3.4 to client
    ///   address /www.example.com/-, ignore address, query from upstream, suffix 4, for ipv4, 6 for ipv6, none for all
    ///   address /www.example.com/#, return SOA to client, suffix 4, for ipv4, 6 for ipv6, none for all
    /// ```
    pub address_rules: AddressRules,

    /// set domain rules
    pub domain_rules: DomainRules,

    pub cnames: CNameRules,

    pub srv_records: SrvRecords,

    pub https_records: HttpsRecords,

    /// 📌 可写进本组的开关 / 数值参数（见 `GroupParams`）。
    pub params: GroupParams,
}

impl RuleGroup {
    pub fn empty() -> &'static Self {
        &EMPTY
    }

    pub fn merge(&mut self, other: RuleGroup) {
        self.forward_rules.extend(other.forward_rules);
        self.address_rules.extend(other.address_rules);
        self.domain_rules.extend(other.domain_rules);
        self.cnames.extend(other.cnames);
        self.srv_records.extend(other.srv_records);
        self.https_records.extend(other.https_records);
        // 标量：只填本组空缺的格子（不能像规则那样累加）
        self.params.inherit_from(&other.params);
    }
}
