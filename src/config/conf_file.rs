use std::path::PathBuf;

/// 一条 `conf-file` 指令：要包含进来的配置文件 + 可选的规则组。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfFileItem {
    /// 要包含的配置文件路径，支持通配符（如 `/etc/smartdns/conf.d/*.conf`）。
    pub path: PathBuf,

    /// `-g|-group <组名>`：把这一段被包含进来的配置整体挂到该规则组。
    ///
    /// 用途：一份片段文件（比如"公司出口走某个上游"那几行）可以被不同的主配置引用，
    /// 由**引用方**决定它属于哪个组，片段自己不必知道 —— 这是 `group-begin`/`group-end`
    /// 做不到的（那种写法要求组名写在片段内容里，片段就没法共享了）。
    pub group: Option<String>,
}
