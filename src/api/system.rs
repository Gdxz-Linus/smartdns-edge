use super::openapi::{IntoRouter, routes};
use crate::libdns::proto::rr::Name;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{ServeState, StatefulRouter};

pub fn routes() -> StatefulRouter {
    routes![status,].into_router()
}

#[utoipa::path(get, path = "/system/status", tag="System", description = "Get system status", responses(
    (status = 200, content_type="application/json", body = SystemStatus )
))]
async fn status(State(s): State<Arc<ServeState>>) -> Json<SystemStatus> {
    let app = s.app.clone();
    let cfg = app.cfg().await;
    let limiter = crate::server::limit::global().stats();
    // 🔐 P1-10：让"端口被占导致某个监听绑不上"这件事第一次变得可见
    let (bind_retry_pending, bind_retry_last_error) = app.bind_retry_status().await;
    Json(SystemStatus {
        server_name: cfg.server_name(),
        version: crate::BUILD_VERSION,
        build_date: crate::BUILD_DATE.with_timezone(&chrono::Local),
        uptime: format!("{:?}", app.uptime()),
        config_loaded_at: format!("{:?}", app.loaded_at().await),
        active_queries: app.active_queries(),
        connections_current: limiter.0,
        connections_rejected: limiter.1,
        connections_limit: limiter.2,
        panics_total: crate::app::PANIC_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        udp_source_rejected: crate::socks5::rejected_by_source(),
        log_dropped: crate::infra::mapped_file::log_dropped_total(),
        log_flush_failed: crate::infra::mapped_file::log_flush_failed_total(),
        bind_retry_pending,
        bind_retry_last_error,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
struct SystemStatus {
    #[schema(value_type = String)]
    server_name: Name,
    version: &'static str,
    #[schema(value_type = String)]
    build_date: chrono::DateTime<chrono::Local>,
    uptime: String,
    config_loaded_at: String,
    active_queries: usize,
    /// 当前连接数 / 因超限被拒的累计次数 / 总上限
    connections_current: usize,
    connections_rejected: usize,
    connections_limit: usize,
    /// 进程启动至今捕获到的 panic 次数（正常应为 0）
    panics_total: usize,
    /// 代理路径上因数据报来源与我们查询的上游不符而被丢弃的数量（P1-9 投毒防护的可观测项）。
    /// 直连路径的同类丢弃由内核完成，应用侧看不到，因此不计入此数。
    udp_source_rejected: u64,
    /// 日志队列写满而被迫丢弃的日志条数（P1-14 的可观测项）。
    /// 正常应为 0；不为 0 说明日志有缺失，需要调大 log-size/log-num 或降低日志级别。
    log_dropped: u64,
    /// `flush()` 未能在超时内排空日志队列的次数（P1-14 的可观测项）。
    /// 正常应为 0；不为 0 说明磁盘/日志线程跟不上，可能有日志没能及时落盘。
    log_flush_failed: u64,
    /// 绑定失败、正在自动重试的监听数量（P1-10 的可观测项）。
    /// 正常应为 0；不为 0 说明某个监听地址当前绑不上（最常见的是端口被占用），
    /// 服务正在按指数退避自动重试，恢复后此值归零、无需人工重启。
    bind_retry_pending: usize,
    /// 最近一次绑定失败的原因（含地址）；当前没有失败时为 null。
    bind_retry_last_error: Option<String>,
}
