use super::client_rule::Client;

/// `group-match` 指令的数据。
///
/// 语义对齐 pymumu 的 C 版 smartdns（`src/dns_conf/group.c` 的 `_config_group_match`）：
///
/// - 不指定 `-g` 时，使用「当前所在的规则组」，即最近一次 `group-begin` 的名字；
/// - 一行里的多个 `-c` / `-d` **各自独立生效**，不是「与」关系（C 版是逐个调用
///   `_config_client_rule_group_add` / `_conf_domain_rule_group`，并未把条件串起来）；
/// - `-c/--client-ip <ip|cidr|mac>` 与 `client-rules <值> -g <组>` **完全等价**；
/// - `-d/--domain <域名>` 表示「查询该域名时使用此规则组」。
///
/// 语法：
/// ```text
/// group-match [-g|--group|-group <名称>] [-c|--client-ip <值>]... [-d|--domain <域名>]...
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupMatch {
    /// 目标规则组；为 `None` 时表示使用当前所在的规则组
    pub group: Option<String>,

    /// `-c/--client-ip` 的匹配项（ip / cidr / mac），可重复
    pub clients: Vec<Client>,

    /// `-d/--domain` 的匹配项，可重复
    pub domains: Vec<String>,
}
