use axum::{
    Json,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
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

/// 🔐 P3：管理后台/接口的安全响应头 —— 以前一个都没有。
///
/// - `X-Content-Type-Options: nosniff`：禁止浏览器把我们的 JSON 猜成 HTML/脚本去执行；
/// - `X-Frame-Options: DENY` + CSP 里的 `frame-ancestors 'none'`：**禁止后台被任何页面嵌进 iframe**
///   （否则攻击者可以拿一个透明 iframe 盖在正常页面上，骗管理员点到后台按钮 —— 点击劫持）；
/// - `Referrer-Policy: no-referrer`：后台地址不要随外链泄漏出去；
/// - CSP：默认什么外部资源都不许加载，只放行内联脚本/样式与 Swagger 文档页用的 CDN
///   （文档页 `/api/docs` 是自带网页、需要这两项；其余接口都是 JSON，放行它们不会带来额外风险，
///    而 `object-src 'none'`、`base-uri 'none'` 仍然挡着插件与 `<base>` 劫持）。
const SECURITY_CSP: &str = "default-src 'none';      script-src 'self' 'unsafe-inline' https://unpkg.com;      style-src 'self' 'unsafe-inline' https://unpkg.com;      img-src 'self' data:; connect-src 'self';      frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'";

/// 给路由套上上面那组安全响应头（后台与 `-no-api` 的纯 DoH 监听都用它）。
fn with_security_headers<S>(router: axum::Router<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(
        ServiceBuilder::new()
            .layer(SetResponseHeaderLayer::overriding(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(SECURITY_CSP),
            )),
    )
}

/// 只提供 DoH（`/dns-query`）、不挂管理后台的路由。
/// 给 bind 加了 `-no-api` 的监听使用：对外提供加密 DNS，但不暴露 `/api` 接口。
pub fn dns_only_routes() -> axum::Router<Arc<ServeState>> {
    let (router, _openapi) = Router::new().merge(serve_dns::routes()).split_for_parts();

    with_security_headers(router).layer(ServiceBuilder::new().layer(
        SetResponseHeaderLayer::overriding(header::SERVER, HeaderValue::from_static(crate::NAME)),
    ))
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

    // 🔐 P3：安全响应头（CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy）
    with_security_headers(router).layer(ServiceBuilder::new().layer(
        SetResponseHeaderLayer::overriding(header::SERVER, HeaderValue::from_static(crate::NAME)),
    ))
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
        // 🔐 B9：所有变体统一成 JSON（`{"error": "..."}`）—— 以前只有 Internal 回纯文本、
        // 其余回裸字符串，前端/脚本没法用同一个结构解析错误。状态码语义保持不变。
        let (status, message) = match self {
            ApiError::Internal(error) => {
                // 🔐 问题 13-②：详情**只写服务端日志，不回给调用方**。
                //
                // 原来响应体里带 `Something went wrong: {error}`，而 `{error}` 是
                // `anyhow::Error` 的 Display —— 里面会带出**服务器路径、配置细节、
                // 甚至上游地址**（例如 "failed to open /etc/smartdns/managed/x.conf: ..."）。
                // 虽然调用方已经通过鉴权（所以报告把它定为"低"），但：
                //   ① 管理口令可能在多个设备上复用，拿到口令的人不该顺带拿到服务器内部结构；
                //   ② 这些细节对**服务端排障**有用（所以照写日志），对**调用方**没用 ——
                //      调用方真正需要的是"服务器出错了，去看服务端日志"。
                // 因此这里回一句稳定、可操作的话；完整错误仍在下面那行日志里。
                crate::log::error!("API internal error: {error:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong on the server; see the server log for details"
                        .to_string(),
                )
            }
            ApiError::BadRequest(err) => (StatusCode::BAD_REQUEST, err),
            ApiError::Conflict(err) => (StatusCode::CONFLICT, err),
            ApiError::NotFound(err) => (StatusCode::NOT_FOUND, err),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
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
        crate::log::warn!("DoH query failed: {self:?}");
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
            "the management console has no token configured, so one was generated: {token} (to make it permanent, add this line to the configuration: api-token {token})"
        );
        println!("[smartdns] management console token (randomly generated for this run): {token}");
        println!("[smartdns] to make it permanent, add this line to the configuration file: api-token {token}");
        token
    })
}

/// 口令是否来自用户自己的配置/环境变量（而不是自动生成的）
pub fn api_token_configured() -> bool {
    let _ = api_token();
    API_TOKEN_FROM_USER.load(std::sync::atomic::Ordering::Relaxed)
}

/// 🔐 13-⑥：可信反向代理清单，供鉴权中间件做**归组**用。
///
/// ## 为什么用全局存储而不是每次去捞配置
///
/// 鉴权中间件是 `middleware::from_fn` 形式的**无状态**函数，
/// 手上只有 `Request` —— 拿不到 `ServeState`（那是各路由的 `State` 提取器，
/// 中间件层取不到）。所以与 `api_token()` 同样走全局。
///
/// ## 默认值必须落在**安全的一侧**
///
/// 未经 `init_trusted_proxies` 初始化时返回**空清单** ——
/// 空清单 = 不信任任何代理头 = 与本项目原本的行为**完全一致**。
/// 这个默认方向很要紧：万一将来有人忘了初始化，退化的结果只是"功能不生效"，
/// 而不是"谁都可信"。
///
/// ## 为什么用 `RwLock` 而不是 `OnceLock`
///
/// 因为**热重载可能改这个清单**（用户改完 `trusted-proxy` 后 `POST /api/config/reload`，
/// 或 `-interval` 定时刷新）。`OnceLock` 只生效第一次，热重载后清单会一直是旧的 ——
/// 那会造成"改了配置不生效"，而这类"配了不生效"正是本项目反复在治理的问题。
/// 所以每次重载都覆盖一遍。
static TRUSTED_PROXIES: std::sync::LazyLock<
    std::sync::RwLock<crate::trusted_proxy::TrustedProxies>,
> = std::sync::LazyLock::new(|| {
    std::sync::RwLock::new(crate::trusted_proxy::TrustedProxies::default())
});

/// 由配置初始化/更新可信代理清单（启动时调用一次，之后每次热重载再调用）。
///
/// 锁中毒时用 `into_inner()` 继续 —— 与全仓库其它 50 余处保持一致：
/// 这里最坏只是清单短暂不准，远好过"因为一次偶发 panic 就让管理后台再也起不来"。
pub fn init_trusted_proxies(proxies: crate::trusted_proxy::TrustedProxies) {
    *TRUSTED_PROXIES.write().unwrap_or_else(|e| e.into_inner()) = proxies;
}

/// 取可信代理清单；未初始化时是空清单（安全默认，见上）。
fn api_trusted_proxies() -> crate::trusted_proxy::TrustedProxies {
    TRUSTED_PROXIES
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// 口令错误次数限制（防暴力破解）：同一来源在窗口期内错太多次，就暂时拒之门外。
///
/// 🔐 键必须按「来源网段」而不是「单个地址」来算，理由与连接数上限完全一致
/// （见 `server/limit.rs` 的 `SourceKey`）：
///
///   * **IPv6 按 /64 前缀聚合**。运营商与云厂商普遍按 /64 成段分配地址，一个 /64 里
///     有约 1800 亿亿个地址。若按单地址计数，攻击者每换一个地址计数就归零，
///     「60 秒内 10 次」形同虚设 —— 这正好是这道防线要防的事。
///   * **IPv4 按单个地址**（IPv4 地址稀缺，一个地址基本代表一个人）；
///     同时把 IPv4 映射到 IPv6 的地址（`::ffff:a.b.c.d`，双栈监听下的 IPv4 客户端）
///     还原成普通 IPv4，否则它们会全部落进 `::/64` 这一个桶里互相牵连。
static AUTH_FAILS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<AuthSourceKey, (u32, std::time::Instant)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

const AUTH_FAIL_LIMIT: u32 = 10;
const AUTH_FAIL_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// 口令失败计数的键：IPv4 按地址、IPv6 按 /64 前缀。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum AuthSourceKey {
    V4(std::net::Ipv4Addr),
    /// IPv6 的 /64 前缀（前 8 字节）
    V6([u8; 8]),
}

impl AuthSourceKey {
    fn from_ip(ip: std::net::IpAddr) -> Self {
        // 先还原「IPv4 映射到 IPv6」的形式，避免双栈监听下的 IPv4 客户端全挤进 ::/64
        let ip = match ip {
            std::net::IpAddr::V6(addr) => addr
                .to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(addr), std::net::IpAddr::V4),
            std::net::IpAddr::V4(addr) => std::net::IpAddr::V4(addr),
        };

        match ip {
            std::net::IpAddr::V4(v4) => Self::V4(v4),
            std::net::IpAddr::V6(v6) => {
                let o = v6.octets();
                Self::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
            }
        }
    }
}

/// 记录一次失败，返回该来源在窗口内的累计失败次数。
///
/// 🔐 清理过期记录**不是每次都做**：以前每来一次失败就 `retain` 全表扫一遍，
/// 而未认证请求就能触发这条路径 —— 地图越大、每次失败的固定开销越高，属可被放大的开销。
/// 现在按次数节流（每 64 次清一次），并且地图本身有容量上限兜底。
fn auth_record_failure(ip: std::net::IpAddr) -> u32 {
    /// 清理节流：每来这么多条失败才扫一次全表
    const PRUNE_EVERY: u64 = 64;
    /// 地图条目上限。正常部署远达不到；到了说明有人在用海量网段试探，
    /// 此时整表作废重来（而不是无限增长），保证内存可控。
    const MAX_ENTRIES: usize = 4096;

    let key = AuthSourceKey::from_ip(ip);
    let mut map = AUTH_FAILS.lock().unwrap_or_else(|e| e.into_inner());

    let seen = AUTH_FAILS_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if seen.is_multiple_of(PRUNE_EVERY) {
        map.retain(|_, (_, since)| since.elapsed() < AUTH_FAIL_WINDOW);
    }

    if map.len() >= MAX_ENTRIES {
        // 极端情况：地图被撑满。直接整表作废，避免内存无上限增长。
        // 代价是被攻击期间限流精度下降，但总好过内存被吃光。
        crate::log::warn!(
            "the token-failure table reached {MAX_ENTRIES} entries and was reset; \
             this suggests someone is probing from a very large number of network segments"
        );
        map.clear();
    }

    let entry = map.entry(key).or_insert((0, std::time::Instant::now()));
    entry.0 += 1;
    entry.0
}

/// 失败次数的累计调用计数，用于给「清理过期记录」节流（见 `auth_record_failure`）。
static AUTH_FAILS_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn auth_record_success(ip: std::net::IpAddr) {
    AUTH_FAILS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&AuthSourceKey::from_ip(ip));
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
            "the management console is served over plain HTTP on {addr}: the token travels the network unencrypted. Use it only on a trusted LAN; for remote access use bind-https (TLS) or a reverse proxy."
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
            // 🔐 A2：`-no-api` 的监听**根本不挂管理后台**（见 server/mod.rs 的 `http::serve(..., !no_api())`），
            // 所以它不算"暴露了后台"，不能被这道启动拦截拒绝 —— 否则"只对外做 DoH、不要后台"这种
            // 配置会起不来，而本函数下面的提示语恰好还在推荐这种做法（自相矛盾）。
            crate::config::BindAddrConfig::Http(c) => !c.opts.no_api(),
            #[cfg(feature = "dns-over-https")]
            crate::config::BindAddrConfig::Https(c) => !c.opts.no_api(),
            #[cfg(feature = "dns-over-h3")]
            crate::config::BindAddrConfig::H3(c) => !c.opts.no_api(),
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

    // 🔐 13-⑥：算出"按哪个地址归组"。
    //
    // ## 为什么这里能、而普通 DNS 查询不能
    //
    // 这是 **HTTP** 路径 —— 反向代理可以把真实客户端地址追加进 `X-Forwarded-For`。
    // （普通 DNS over UDP 没有 HTTP 头，做不到；见 `src/trusted_proxy.rs` 的边界说明。）
    //
    // ## 两条安全约束（缺一不可）
    //
    // ① **必须先确认对端在 `trusted-proxy` 清单内** —— 由 `resolve_client_ip` 内部完成。
    //    清单为空（默认）时它直接返回对端地址，**完全无视 XFF**，行为与改动前一致。
    // ② **只用于"归组"** —— 即下面 `auth_record_failure` / `auth_record_success`
    //    的计数键。它**不参与"口令对不对"的判定**，所以伪造 XFF 至多影响
    //    "自己的失败次数记在谁头上"，**无法借此通过鉴权**。
    //
    // ⚠️ 这条中间件**不读配置**（它是 per-request 的纯函数式中间件），
    // 所以可信清单从全局配置取 —— 与 `api_token()` 取自全局是同一种做法。
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    let client_ip = peer_ip.map(|peer| {
        let forwarded = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());
        let trusted = api_trusted_proxies();
        let (ip, source) = crate::trusted_proxy::resolve_client_ip(peer, forwarded, &trusted);
        if source.is_forwarded() {
            // 记一条 debug：说明"这次归组用的是代理自报的地址"，
            // 排障时能一眼看出限流为啥记在了某个地址上。
            crate::log::debug!(
                "API auth: client address taken from X-Forwarded-For (peer {peer} is a trusted proxy)"
            );
        }
        ip
    });

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
            crate::log::warn!("source {ip} sent {count} incorrect tokens within the window");
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // 拦截非法访问：每次都要记下来源 IP（B7：单次尝试也要能追溯到是谁，不能只在"错够 10 次"时才记）
    match client_ip {
        Some(ip) => crate::log::warn!(
            "Unauthorized API access attempt from {ip} to: {}",
            req.uri().path()
        ),
        None => crate::log::warn!(
            "unauthorized API access attempt (source address unknown; possibly a local proxy or Unix socket) to: {}",
            req.uri().path()
        ),
    }
    Err(StatusCode::UNAUTHORIZED)
}

#[cfg(test)]
mod auth_limit_tests {
    use super::*;
    use std::net::IpAddr;

    /// 🔐 问题 13-②：**内部错误详情不得出现在响应体里**。
    ///
    /// 原实现回 `Something went wrong: {error}`，而 `anyhow::Error` 的 Display 会带出
    /// 服务器路径、配置细节甚至上游地址。调用方（虽已鉴权）不需要这些；
    /// 需要它们的服务端已经写进日志了。
    ///
    /// 这条测试直接构造一个"带敏感路径"的错误，断言它**不出现在响应体**里。
    #[tokio::test]
    async fn internal_error_body_does_not_leak_details() {
        use axum::response::IntoResponse;

        const SECRET: &str = "/etc/smartdns/secret-config-path.conf";
        let err = ApiError::Internal(anyhow::anyhow!(
            "failed to open {SECRET}: permission denied"
        ));

        let resp = err.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "内部错误仍应是 500（不能糊成 4xx）"
        );

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("应当能读出响应体");
        let text = String::from_utf8_lossy(&body);

        assert!(!text.contains(SECRET), "响应体泄露了服务器路径：{text}");
        assert!(
            !text.contains("permission denied"),
            "响应体泄露了内部错误详情：{text}"
        );
        assert!(
            text.contains("server log"),
            "应当告诉调用方去服务端日志查（可操作）：{text}"
        );

        // 对照：客户端错误（400）**本来就该**把原因说明白 —— 不能把这条改动扩大到它们身上
        let bad = ApiError::BadRequest("invalid `name` parameter".to_string()).into_response();
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let bad_bytes = axum::body::to_bytes(bad.into_body(), 64 * 1024)
            .await
            .unwrap();
        let bad_text = String::from_utf8_lossy(&bad_bytes);
        assert!(
            bad_text.contains("invalid `name` parameter"),
            "400 必须保留可操作的原因，不能被一并抹掉：{bad_text}"
        );
    }

    /// 🔐 核心回归：同一个 /64 网段里的不同地址必须共用额度。
    ///
    /// 否则在 IPv6 环境下，攻击者每换一个地址计数就归零，
    /// 「60 秒内 10 次」这道防暴力破解的闸门等于不存在。
    #[test]
    fn ipv6_addresses_in_the_same_64_share_one_budget() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::9999".parse().unwrap();
        let c: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();

        assert_eq!(
            AuthSourceKey::from_ip(a),
            AuthSourceKey::from_ip(b),
            "同一 /64 内换地址不能重置计数"
        );
        assert_eq!(
            AuthSourceKey::from_ip(a),
            AuthSourceKey::from_ip(c),
            "同一 /64 内换地址不能重置计数"
        );

        // 换一个 /64 才是另一个来源（这正是运营商的分配粒度）
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_ne!(
            AuthSourceKey::from_ip(a),
            AuthSourceKey::from_ip(other),
            "不同 /64 应当分开计数"
        );
    }

    /// 🔐 IPv4 仍按单个地址计数（IPv4 地址稀缺，一个地址基本代表一个人）。
    #[test]
    fn ipv4_is_counted_per_address() {
        let a: IpAddr = "192.168.1.10".parse().unwrap();
        let b: IpAddr = "192.168.1.11".parse().unwrap();
        assert_ne!(
            AuthSourceKey::from_ip(a),
            AuthSourceKey::from_ip(b),
            "不同的 IPv4 设备必须各算各的"
        );
    }

    /// 🔐 双栈监听下 IPv4 客户端以 `::ffff:a.b.c.d` 出现，必须还原后按 IPv4 计数，
    /// 否则所有 IPv4 客户端会全部落进 `::/64` 这一个桶里互相牵连。
    #[test]
    fn mapped_ipv4_is_not_folded_into_the_ipv6_bucket() {
        let mapped: IpAddr = "::ffff:192.168.1.10".parse().unwrap();
        let plain: IpAddr = "192.168.1.10".parse().unwrap();
        assert_eq!(
            AuthSourceKey::from_ip(mapped),
            AuthSourceKey::from_ip(plain),
            "映射形式与普通形式必须是同一个来源"
        );

        // 两个不同的 IPv4 客户端不能因为映射形式而挤进同一个桶
        let mapped2: IpAddr = "::ffff:192.168.1.11".parse().unwrap();
        assert_ne!(
            AuthSourceKey::from_ip(mapped),
            AuthSourceKey::from_ip(mapped2),
            "不同的 IPv4 客户端不能被折叠到一起"
        );
    }

    /// 记账与清零的基本行为。
    #[test]
    fn failure_count_accumulates_and_success_clears_it() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        auth_record_success(ip); // 先清干净，避免受其它测试影响

        assert_eq!(auth_record_failure(ip), 1);
        assert_eq!(auth_record_failure(ip), 2);

        // 同网段的另一个地址应累计到同一笔账上
        let same_seg: IpAddr = "2001:db8:abcd:1::1".parse().unwrap();
        let same_seg2: IpAddr = "2001:db8:abcd:1::2".parse().unwrap();
        auth_record_success(same_seg);
        assert_eq!(auth_record_failure(same_seg), 1);
        assert_eq!(
            auth_record_failure(same_seg2),
            2,
            "同 /64 的另一个地址必须继续累加，而不是从 1 重新开始"
        );

        // 口令正确时清零
        auth_record_success(ip);
        assert_eq!(auth_record_failure(ip), 1, "成功后计数应当归零");
        auth_record_success(ip);
        auth_record_success(same_seg);
    }
}
