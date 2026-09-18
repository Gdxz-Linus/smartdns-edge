use std::sync::Arc;

use axum::Json;
use axum::extract::State;

use crate::libdns::proto::rr::Name;
use serde::{Deserialize, Serialize};

use super::openapi::{IntoRouter, routes};
use super::{ApiError, ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![reload, config].into_router()
}

#[utoipa::path(post, path = "/config/reload", tag = "Config")]
async fn reload(State(state): State<Arc<ServeState>>) -> Result<(), ApiError> {
    state.app.reload().await?;
    Ok(())
}

#[utoipa::path(get, path = "/config", tag = "Config", operation_id = "config")]
async fn config(State(state): State<Arc<ServeState>>) -> Json<ServerConfig> {
    let cfg = state.app.cfg().await;
    let conf_dir = cfg
        .conf_dir()
        .map(|p| std::fs::canonicalize(p).unwrap_or(p.to_path_buf()))
        .map(|p| shorten_home_prefix(&p.to_string_lossy()));

    Json(ServerConfig {
        server_name: cfg.server_name(),
        conf_dir,
    })
}

/// 🔐 P3-12：把"本机用户主目录"那段前缀换成 `~`。
///
/// 配置目录本身要能被后台显示出来（用户要知道程序在读哪儿），但**不该把本机的用户目录结构、
/// 特别是用户名回显给调用方** —— 管理接口的输出可能被脚本转发、粘贴到工单里。换成 `~` 之后
/// 信息量不变（相对位置一目了然），敏感部分不再外露。
fn shorten_home_prefix(path: &str) -> String {
    shorten_with_home(path, home_dir().as_deref())
}

/// 取本机用户主目录：Windows 用 `USERPROFILE`，类 Unix 用 `HOME`；取不到就返回 None。
fn home_dir() -> Option<String> {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .ok()
        .filter(|h| !h.is_empty())
}

/// 纯函数形式，便于单测（不依赖运行测试的机器上真的存在哪些环境变量）。
fn shorten_with_home(path: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return path.to_string();
    };
    let home = home.trim_end_matches(['\\', '/']);
    if path == home {
        return "~".to_string();
    }
    // 只有"确实在主目录里面"才替换：紧随主目录之后的必须是路径分隔符。
    // （少了这道判断，`/home/tester2/x` 会被误判成 `/home/tester` 下的路径。）
    let inside = path.starts_with(&format!("{home}/")) || path.starts_with(&format!("{home}\\"));
    if !inside {
        return path.to_string();
    }
    let rest = &path[home.len() + 1..];
    if rest.is_empty() {
        return "~".to_string();
    }
    // Windows 的路径分隔符统一成正斜杠，读起来更清楚
    format!("~/{}", rest.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::shorten_with_home;

    #[test]
    fn home_prefix_becomes_tilde() {
        // Windows 风格
        assert_eq!(
            shorten_with_home(r"C:\Users\tester\smartdns\conf", Some(r"C:\Users\tester")),
            "~/smartdns/conf"
        );
        // 类 Unix 风格
        assert_eq!(
            shorten_with_home("/home/tester/smartdns/conf", Some("/home/tester")),
            "~/smartdns/conf"
        );
        // 就是主目录本身
        assert_eq!(shorten_with_home("/home/tester", Some("/home/tester")), "~");
    }

    #[test]
    fn unrelated_paths_are_kept() {
        // 不在主目录下的（例如 /etc/smartdns）原样保留 —— 那里没有任何本机用户信息
        assert_eq!(
            shorten_with_home("/etc/smartdns", Some("/home/tester")),
            "/etc/smartdns"
        );
        // 前缀只是"像"而不是真的在下面（/home/tester2 不是 /home/tester 的子路径）
        assert_eq!(
            shorten_with_home("/home/tester2/smartdns", Some("/home/tester")),
            "/home/tester2/smartdns"
        );
        // 取不到主目录时不改动
        assert_eq!(shorten_with_home("/home/tester/x", None), "/home/tester/x");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
struct ServerConfig {
    #[schema(value_type = String)]
    server_name: Name,
    conf_dir: Option<String>,
}
