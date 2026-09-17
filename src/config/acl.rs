use serde::{Deserialize, Serialize};

/// 访问控制（ACL）配置 —— 对应配置项 `acl-enable`（C 版同名的全局开关）。
///
/// 语义对齐 C 版 `src/dns_server/client_rule.c:22-32` 的判定（我们在
/// `src/dns_mw.rs::DnsMiddlewareHandler::search()` 里落地）：
///
/// - **关闭（默认，不写这一项就是关闭）**：一切照旧，任何客户端都能查 —— 默认行为零变化；
/// - **开启**：**没有匹配到任何 `client-rules` 的客户端一律 REFUSED**（并且不缓存），
///   匹配到的照常服务（依旧按规则决定用哪个服务器组）。
///
/// 换句话说：`acl-enable yes` + `client-rules <你的客户端网段>` = 白名单，
/// 这正是文档里那句"和 client-rules 搭配使用"的意思。
///
/// 监听级还有 `bind ... -acl`（对应 C 版的 `BIND_FLAG_ACL`）：只对那一个监听开启同样的管控，
/// 与全局开关是"或"的关系。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclConfig {
    /// 是否启用访问控制
    pub enable: Option<bool>,
}
