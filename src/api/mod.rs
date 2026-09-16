use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
	extract::Request,
    middleware::{self, Next},
};
use cfg_if::cfg_if;
use http::{HeaderValue, header};
use openapi::Router;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::set_header::SetResponseHeaderLayer;

mod address;
mod audit;
mod cache;
mod config;
mod forward;
mod listener;
mod log;
mod nameserver;
mod openapi;
mod serve_dns;
mod system;

use crate::{app::App, server::DnsHandle};

type StatefulRouter = Router<Arc<ServeState>>;
pub use openapi::ToSchema;

pub struct ServeState {
    pub app: App,
    pub dns_handle: DnsHandle,
}

/// 只提供 DoH（`/dns-query`）、不挂管理后台的路由。
/// 给 bind 加了 `-no-api` 的监听使用：对外提供加密 DNS，但不暴露 `/api` 接口。
pub fn dns_only_routes() -> axum::Router<Arc<ServeState>> {
    let (router, _openapi) = Router::new().merge(serve_dns::routes()).split_for_parts();

    router.layer(
        ServiceBuilder::new().layer(SetResponseHeaderLayer::overriding(
            header::SERVER,
            HeaderValue::from_static(crate::NAME),
        )),
    )
}

pub fn routes() -> axum::Router<Arc<ServeState>> {
    use utoipa::openapi::InfoBuilder;
    let (router, mut openapi) = Router::new()
        .merge(serve_dns::routes())
        .nest("/api", api_routes())
        .split_for_parts();
    openapi.info = InfoBuilder::new()
        .title(crate::NAME)
        .version(crate::BUILD_VERSION)
        .build();

    let router = {
        cfg_if! {
            if #[cfg(feature = "swagger-ui-cdn")]
            {
                router.merge(
                    openapi::swagger_cdn("/api/docs", "/api/openapi.json", openapi, None)
                        .route_layer(middleware::from_fn(api_auth_middleware)),
                )
            }
            else if #[cfg(feature = "swagger-ui-embed")]
            {
                use utoipa_swagger_ui::{Config, SwaggerUi};
                router.merge(
                    (SwaggerUi::new("/api/docs")
                        .config(
                            Config::default()
                                .show_extensions(true)
                                .show_common_extensions(true)
                                .use_base_layout(),
                        )
                        .url("/api/openapi.json", openapi))
                        .route_layer(middleware::from_fn(api_auth_middleware)),
                )
            } else {
                router
            }
        }
    };

    router.layer(
        ServiceBuilder::new().layer(SetResponseHeaderLayer::overriding(
            header::SERVER,
            HeaderValue::from_static(crate::NAME),
        )),
    )
}

fn api_routes() -> StatefulRouter {
    Router::new()
        .route("/version", get(version))
        .merge(cache::routes())
        .merge(config::routes())
        .merge(nameserver::routes())
        .merge(address::routes())
        .merge(forward::routes())
        .merge(audit::routes())
        .merge(listener::routes())
        .merge(log::routes())
        .merge(system::routes())
        // 🌟 核心修复：为以上所有的后台管理 API 强制套上鉴权护盾！
        .route_layer(middleware::from_fn(api_auth_middleware))
}

async fn version() -> Json<&'static str> {
    Json(crate::BUILD_VERSION)
}

enum ApiError {
    Internal(anyhow::Error),
    /// 🔐 P2：请求本身有问题（参数缺失 / 格式非法 / 域名写错）—— 应回 400，不该回 500。
    /// 原实现把所有错误都塞进 Internal → 客户端错误被当成服务器故障，污染监控告警。
    BadRequest(String),
    /// 🔐 P2：目标已存在（例如重复的域名规则）—— 语义是 409 Conflict，不是 500。
    Conflict(String),
    NotFound(String),
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Internal(error) => {
                // 详情写给服务端日志，响应里也保留（本机管理后台，排障需要）；
                // 关键是不能把它当成"客户端错误"的状态码糊弄过去。
                crate::log::error!("API internal error: {error:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Something went wrong: {error}"),
                )
                    .into_response()
            }
            ApiError::BadRequest(err) => (StatusCode::BAD_REQUEST, err).into_response(),
            ApiError::Conflict(err) => (StatusCode::CONFLICT, err).into_response(),
            ApiError::NotFound(err) => (StatusCode::NOT_FOUND, err).into_response(),
        }
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

impl IntoResponse for crate::dns::DnsError {
    fn into_response(self) -> Response {
        // 🔐 P2：不再手工拼 JSON —— 错误文本里一旦出现引号 / 反斜杠 / 换行，
        // 拼出来的就是坏 JSON；而且细节直接回显等于把内部信息（含服务器路径）送给调用方。
        // 这里用 serde_json 生成（自动转义），详情只写服务端日志。
        crate::log::warn!("DoH 查询失败: {self:?}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[derive(Deserialize, Serialize)]
struct DataPayload<T> {
    data: T,
}

#[derive(Deserialize, Serialize)]
struct DataListPayload<T> {
    count: usize,
    data: Vec<T>,
}

impl<T> DataListPayload<T> {
    fn new(data: Vec<T>) -> Self {
        Self {
            count: data.len(),
            data,
        }
    }
}

impl<T> From<Vec<T>> for DataListPayload<T> {
    fn from(data: Vec<T>) -> Self {
        Self::new(data)
    }
}

// 🌟 核心修复：API 控制面鉴权拦截器
// 🔐 管理接口口令（token）
//
// 设计原则：**代码里绝不保留任何写死的默认口令**。取值顺序：
//   1. 配置里的 `api-token <口令>`（启动时由 set_configured_token 登记）；
//   2. 环境变量 `SMARTDNS_API_TOKEN`；
//   3. 都没有时，第一次用到就随机生成一个强口令，打印到控制台与日志，
//      并提示用户「想固定就写进配置」。
//
// 原实现在这里留了一串写死的默认口令：口令公开写在源码里，
// 等于全世界装了本项目的人共用一个管理密码。
static API_TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static API_TOKEN_FROM_USER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 生成一个 32 位十六进制的随机口令（rand 的 ThreadRng 由操作系统熵源播种）
fn generate_api_token() -> String {
    let mut token = String::with_capacity(32);
    for _ in 0..16 {
        token.push_str(&format!("{:02x}", rand::random::<u8>()));
    }
    token
}

/// 启动流程调用：把配置里写的口令先登记好（必须在任何请求之前调用）
pub fn set_configured_token(token: Option<String>) {
    if let Some(token) = token.filter(|t| !t.trim().is_empty()) {
        API_TOKEN_FROM_USER.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = API_TOKEN.set(token);
    }
}

/// 用户自己配置过口令吗？（只看配置与环境变量，**不做任何生成**——给启动检查用，
/// 免得"拒绝启动"之前还先打印出一个随机口令，让人以为服务已经起来了）
pub fn has_configured_token(config_token: Option<&str>) -> bool {
    let non_empty = |t: &str| !t.trim().is_empty();
    config_token.is_some_and(non_empty)
        || std::env::var("SMARTDNS_API_TOKEN").is_ok_and(|t| non_empty(&t))
}

/// 当前生效的口令：配置 → 环境变量 → 随机生成（并打印一次提示）
pub fn api_token() -> &'static str {
    API_TOKEN.get_or_init(|| {
        if let Ok(token) = std::env::var("SMARTDNS_API_TOKEN")
            && !token.trim().is_empty()
        {
            API_TOKEN_FROM_USER.store(true, std::sync::atomic::Ordering::Relaxed);
            return token;
        }

        let token = generate_api_token();
        crate::log::warn!(
            "管理后台没有配置口令，已随机生成：{token}（想固定下来，请在配置里加一行：api-token {token}）"
        );
        println!("[smartdns] 管理后台口令（本次运行随机生成）：{token}");
        println!("[smartdns] 想固定下来，请在配置文件里加一行：api-token {token}");
        token
    })
}

/// 口令是否来自用户自己的配置/环境变量（而不是自动生成的）
pub fn api_token_configured() -> bool {
    let _ = api_token();
    API_TOKEN_FROM_USER.load(std::sync::atomic::Ordering::Relaxed)
}

/// 口令错误次数限制（防暴力破解）：同一来源 IP 在窗口期内错太多次，就暂时拒之门外。
static AUTH_FAILS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

const AUTH_FAIL_LIMIT: u32 = 10;
const AUTH_FAIL_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

fn auth_record_failure(ip: std::net::IpAddr) -> u32 {
    let mut map = AUTH_FAILS.lock().unwrap();
    map.retain(|_, (_, since)| since.elapsed() < AUTH_FAIL_WINDOW); // 顺手清理过期记录
    let entry = map.entry(ip).or_insert((0, std::time::Instant::now()));
    entry.0 += 1;
    entry.0
}

fn auth_record_success(ip: std::net::IpAddr) {
    AUTH_FAILS.lock().unwrap().remove(&ip);
}

/// 🔐 P2：管理后台挂在**明文 HTTP** 上时，口令会在网络中明文传输。
///
/// 这里**不改功能**（容器 / 内网用户就是靠明文 HTTP 用网页控制台的，直接禁掉会把人打残），
/// 只把风险说清楚：只绑本机的不吭声，绑到非本机地址的启动时打一条醒目告警。
/// 想要更强的手段：改用 `bind-https`（TLS），或在前面加一层做 TLS 终结的反向代理。
pub fn warn_plaintext_api(binds: &[crate::config::BindAddrConfig]) {
    use crate::dns_conf::IBindConfig as _;

    for b in binds {
        if !matches!(b, crate::config::BindAddrConfig::Http(_)) {
            continue;
        }
        let addr = b.sock_addr();
        if addr.ip().is_loopback() {
            continue;
        }
        crate::log::warn!(
            "⚠️ 管理后台（网页控制台）挂在明文 HTTP 上：{addr}。口令会以明文在网络中传输 —— \
             请只在可信内网使用；需要跨网络访问请改用 bind-https（TLS）或反向代理。"
        );
    }
}

/// 启动前检查：管理后台是否"绑到了非本机地址、却又没有配置口令"。
/// 返回 Err(中文说明) 表示这种组合必须拒绝启动（启动时与 `smartdns test` 都调用它）。
pub fn check_exposure(
    binds: &[crate::config::BindAddrConfig],
    config_token: Option<&str>,
) -> Result<(), String> {
    use crate::dns_conf::IBindConfig;

    let exposed: Vec<String> = binds
        .iter()
        .filter(|b| match b {
            crate::config::BindAddrConfig::Http(_) => true,
            #[cfg(feature = "dns-over-https")]
            crate::config::BindAddrConfig::Https(_) => true,
            #[cfg(feature = "dns-over-h3")]
            crate::config::BindAddrConfig::H3(_) => true,
            _ => false,
        })
        .map(|b| b.sock_addr())
        .filter(|addr| !addr.ip().is_loopback())
        .map(|addr| addr.to_string())
        .collect();

    if exposed.is_empty() || has_configured_token(config_token) {
        return Ok(());
    }

    Err(format!(
        "拒绝启动：管理后台绑定了非本机地址 [{}]，但没有设置口令。\n\
         这会让同网络（甚至整个互联网）上的任何人登录你的管理后台，改掉 DNS 解析结果。\n\
         请二选一：\n\
         \x20 1) 配置里加一行自己的口令：api-token <你的强口令>\n\
         \x20 2) 让后台只监听本机：bind-http 127.0.0.1:8000\n\
         \x20    只对外提供 DoH、不想暴露后台：给该监听加 -no-api\n\
         \x20    要远程管理，建议用 SSH 隧道：ssh -L 8000:127.0.0.1:8000 服务器",
        exposed.join(", ")
    ))
}

async fn api_auth_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    let expected_token = api_token();
    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    // 提取 HTTP Header 中的 Authorization 字段
    if let Some(auth_header) = req.headers().get(http::header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(provided_token) = auth_str.strip_prefix("Bearer ")
    {
        // 恒定时间比较：长度不同、或第几位不同都不提前返回，
        // 免得攻击者靠响应时间差一位一位把口令试出来。
        let (a, b) = (provided_token.as_bytes(), expected_token.as_bytes());
        let mut diff = (a.len() ^ b.len()) as u8;
        for i in 0..a.len().max(b.len()) {
            let x = *a.get(i).unwrap_or(&0);
            let y = *b.get(i).unwrap_or(&0);
            diff |= std::hint::black_box(x ^ y);
        }
        if diff == 0 {
            // 口令正确，放行。注意：正确口令永远不会被限速挡住——
            // 否则攻击者只要故意错几次，就能把你的管理员锁在后台之外。
            if let Some(ip) = client_ip {
                auth_record_success(ip);
            }
            return Ok(next.run(req).await);
        }
    }

    // 口令不对：记一次失败，错太多次就返回 429（只影响出错的那次请求）
    if let Some(ip) = client_ip {
        let count = auth_record_failure(ip);
        if count >= AUTH_FAIL_LIMIT {
            crate::log::warn!("来源 {ip} 在窗口期内连续 {count} 次口令错误");
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // 拦截非法访问，并打印警告日志记录来源 IP
    crate::log::warn!("Unauthorized API access attempt to: {}", req.uri().path());
    Err(StatusCode::UNAUTHORIZED)
}

