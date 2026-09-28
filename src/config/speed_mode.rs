use std::net::{IpAddr, SocketAddr};

use crate::infra::ping::PingAddr;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum SpeedCheckMode {
    None,
    Ping,
    Tcp(u16),
    Https(u16),
}

impl SpeedCheckMode {
    pub fn is_none(&self) -> bool {
        matches!(self, SpeedCheckMode::None)
    }

    pub fn to_ping_addr(self, ip_addr: IpAddr) -> Option<PingAddr> {
        use SpeedCheckMode::*;
        Some(match self {
            None => return Default::default(),
            Ping => PingAddr::Icmp(ip_addr),
            Tcp(port) => PingAddr::Tcp(SocketAddr::new(ip_addr, port)),
            Https(port) => PingAddr::Https(SocketAddr::new(ip_addr, port)),
        })
    }

    pub fn to_ping_addrs(self, ip_addrs: &[IpAddr]) -> Vec<PingAddr> {
        ip_addrs
            .iter()
            .flat_map(|ip| self.to_ping_addr(*ip))
            .collect()
    }
}

impl std::fmt::Debug for SpeedCheckMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SpeedCheckMode::*;
        match self {
            None => write!(f, "None"),
            Ping => write!(f, "ICMP"),
            Tcp(port) => write!(f, "TCP:{port}"),
            Https(port) => {
                if *port == 443 {
                    write!(f, "HTTPS")
                } else {
                    write!(f, "HTTPS:{port}")
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SpeedCheckModeList(pub Vec<SpeedCheckMode>);

impl SpeedCheckModeList {
    pub fn push(&mut self, mode: SpeedCheckMode) -> Option<SpeedCheckMode> {
        if self.0.iter().all(|m| m != &mode) {
            self.0.push(mode);
            None
        } else {
            Some(mode)
        }
    }
}

impl From<Vec<SpeedCheckMode>> for SpeedCheckModeList {
    fn from(value: Vec<SpeedCheckMode>) -> Self {
        let mut lst = Self(Vec::with_capacity(value.len()));
        for mode in value {
            lst.push(mode);
        }
        lst
    }
}

impl std::fmt::Debug for SpeedCheckModeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, m) in self.0.iter().enumerate() {
            let last = i == self.len() - 1;
            write!(f, "{:?}{}", m, if !last { ", " } else { "" })?;
        }
        Ok(())
    }
}

impl std::ops::Deref for SpeedCheckModeList {
    type Target = Vec<SpeedCheckMode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SpeedCheckModeList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::default::Default for SpeedCheckModeList {
    fn default() -> Self {
        Self(vec![
            // 🌟 核心需求：默认改为只做 ping 和 tcp(443) 测速，减轻 HTTPS 握手开销
            SpeedCheckMode::Ping,
            SpeedCheckMode::Tcp(443),
        ])
    }
}

/// 🔐 问题 24（用户定调）：算出**本次查询实际生效**的测速模式。
///
/// **两条路径共用这一个函数**（上游选 IP 与双栈族对决），
/// 目的是让"同一个配置项"在两条路径上**不可能再给出不同答案** ——
/// 问题 24 的本质就是这两条路径各自算各自的、口径不一。
///
/// ## 取值口径（与上游 C 版一致）
///
///   1. **域名规则**写了自己的测速模式 → 用它（含 `-c none`）；
///   2. 否则用**全局** `speed-check-mode`（含全局 `none`）；
///   3. 两者都没写 → **默认模式**（`SpeedCheckModeList::default()`，
///      即 `ping` + `tcp:443`）——**是"测速"，不是"不测速"**。
///
/// ## 第 3 条为什么是"要用默认模式测速"
///
/// 这是 **2026-09-26 的用户定调**：`未配置` 的行为**与上游 C 版一致**。
/// C 版在 `_dns_conf_default_value_init()` 里会把默认的 `check_orders`
/// **显式填成** `ping,tcp:80,tcp:443`（即测速是**开**的），
/// 也就是"没写这一行"从来不等于"关掉测速"。
///
/// ⚠️ 本函数**只看"配了什么"**，不涉及 bind 级 `-no-speed-check`
/// —— 那一层是**逐监听**的，优先级最高，由调用方各自叠加
/// （见 `dns_mw_dualstack.rs` / `dns_mw_ns.rs` 里对 `no_speed_check` 的判断）。
///
/// ## `None` 与 `Some([None])` 的区别（别混）
///
///   * `None` = **没写**这一行 → 落到第 3 条，得到默认模式；
///   * `Some([None])` = **写了 `none`** → 落到第 1/2 条，原样返回，
///     由调用方用 `any(|m| m.is_none())` 判为"不测速"。
pub fn resolve_speed_check_mode(
    domain_rule: Option<&SpeedCheckModeList>,
    global: Option<&SpeedCheckModeList>,
) -> SpeedCheckModeList {
    domain_rule.or(global).cloned().unwrap_or_default()
}

/// 🔐 丙-2c：算出**双栈优选**（`dualstack-ip-selection`）按"配置分层"的生效值。
///
/// 取值链：**域名规则级 > 组级 > 全局**。三层都是**正向布尔**
/// （`yes` = 开优选），所以实现就是"取第一个有值的"。
///
/// ## ⚠️ bind 级**不**在这个函数里
///
/// `bind ... -no-dualstack-selection` 不是这条链上的一层，而是一个**单向总闸**：
/// 它只能**关**、不能**开**，语义是"**这个监听整体上不做**双栈优选"，
/// 与"某一层把开关配成什么"是两件不同的事。
///
/// 因此调用方必须写成：
///
/// ```ignore
/// let enabled = !ctx.server_opts.no_dualstack_selection()
///     && resolve_dualstack_selection(域名规则, 组级, 全局);
/// ```
///
/// 也就是**总闸在外、链在内**。若把 bind 级塞进本函数当成"最外层的一档"，
/// 就会把它**误当成"可以把优选强制打开"**——它并没有那个语义。
///
/// ## 抽成纯函数的理由
///
/// 与 [`resolve_speed_check_mode`] 相同：这段逻辑原本是三层嵌套的
/// `unwrap_or_default().unwrap_or(...)`，写在中间件的一大段 `async` 里**测不了**。
/// 抽成只依赖三个 `Option` 的纯函数后，"域名规则压过组级、组级压过全局"
/// 这个不变量才能被直接钉住。
pub fn resolve_dualstack_selection(
    domain_rule: Option<Option<bool>>,
    group: Option<bool>,
    global: Option<bool>,
) -> bool {
    // ⚠️ `domain_rule` 是**双层** `Option`：外层表示"有没有匹配到域名规则树"，
    // 内层表示"那条规则有没有写这个开关"。两层都要 `flatten` 掉才算"没写"。
    // 原先写成 `.unwrap_or_default().unwrap_or(全局)`：`unwrap_or_default()` 把外层
    // 变成 `Some(None)` 再交给 `.unwrap_or`，正好等价于"看内层"——这里显式写清楚。
    domain_rule
        .flatten()
        .or(group)
        .or(global)
        // 三层都没写 ⇒ 默认**开**（与 `RuntimeConfig::dualstack_ip_selection` 的默认一致）
        .unwrap_or(true)
}

#[cfg(test)]
mod dualstack_selection_tests {
    use super::resolve_dualstack_selection;

    /// 🔐 **三层优先级：域名规则 > 组级 > 全局**。
    ///
    /// 判据必须是"任意两层同时给出**相反**的值时，靠前那层赢" ——
    /// 只测"某层能生效"会漏掉优先级写反（那是最容易出的错）。
    #[test]
    fn domain_rule_beats_group_beats_global() {
        // ① 三层都写了：域名规则赢
        assert!(
            !resolve_dualstack_selection(Some(Some(false)), Some(true), Some(true)),
            "域名规则写了 false，即使组级/全局都是 true，也必须以域名规则为准"
        );
        assert!(
            resolve_dualstack_selection(Some(Some(true)), Some(false), Some(false)),
            "域名规则写了 true，即使组级/全局都是 false，也必须以域名规则为准"
        );

        // ② 域名规则没写：组级赢
        assert!(
            !resolve_dualstack_selection(Some(None), Some(false), Some(true)),
            "域名规则没写（内层 None）⇒ 组级 false 必须压过全局 true"
        );
        assert!(
            resolve_dualstack_selection(Some(None), Some(true), Some(false)),
            "域名规则没写 ⇒ 组级 true 必须压过全局 false"
        );

        // ③ 连域名规则树都没匹配到（外层 None）：组级仍然要起作用
        assert!(
            !resolve_dualstack_selection(None, Some(false), Some(true)),
            "没匹配到域名规则时，组级 false 仍必须压过全局 true"
        );

        // ④ 组级也没写：全局说话
        assert!(
            !resolve_dualstack_selection(None, None, Some(false)),
            "组级没写 ⇒ 用全局的 false"
        );
        assert!(
            resolve_dualstack_selection(None, None, Some(true)),
            "组级没写 ⇒ 用全局的 true"
        );
    }

    /// 🔐 **三层都没写 ⇒ 默认开**，与 `dualstack-ip-selection` 的既有默认一致。
    ///
    /// 这一条是**边界**：若默认写成 `false`，所有没配这个参数的部署会**静默失去**
    /// 双栈优选（本项目的主打能力之一）—— 那是很严重的行为倒退。
    #[test]
    fn unset_everywhere_defaults_to_enabled() {
        assert!(
            resolve_dualstack_selection(None, None, None),
            "三层都没写时，双栈优选必须默认**开**"
        );
        assert!(
            resolve_dualstack_selection(Some(None), None, None),
            "匹配到域名规则但那条没写这个开关 ⇒ 同样落到默认开"
        );
    }

    /// 🔐 **域名规则的"没写"与"写了 false"必须可区分**。
    ///
    /// `Option<Option<bool>>` 的两层各有含义：外层 = 有没有匹配到规则树，
    /// 内层 = 那条规则写没写这个开关。若把两层混为一谈，
    /// "匹配到了规则但没写此开关"会**错误地压住组级**。
    #[test]
    fn matched_rule_without_the_switch_does_not_shadow_the_group() {
        assert!(
            !resolve_dualstack_selection(Some(None), Some(false), Some(true)),
            "域名规则存在但没写此开关 ⇒ 不该压住组级的 false"
        );
        assert!(
            resolve_dualstack_selection(Some(Some(true)), Some(false), Some(false)),
            "域名规则**写了** true ⇒ 必须压住组级的 false（两层语义不能混）"
        );
    }
}
