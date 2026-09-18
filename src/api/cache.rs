use std::sync::Arc;

use super::openapi::{IntoParams, IntoRouter, routes};
use super::{ServeState, StatefulRouter};
use crate::{config::CacheConfig, dns_mw_cache::CachedQueryRecord, log};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

pub fn routes() -> StatefulRouter {
    let r1 = routes![flush, caches].into_router();
    let r2 = routes![config].into_router();
    r1.merge(r2)
}

// 🌟 分页结构体
#[derive(Deserialize, IntoParams)]
pub struct CachePagination {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    100
} // 默认最多只返回 100 条，守住内存底线

/// 🔐 P2：单页硬上限。显式传入的 `?limit=` 也必须受它约束 ——
/// 原实现只在参数缺省时兜底，`?limit=1000000000` 能强制克隆并序列化整个缓存（内存与响应体双爆）。
const MAX_PAGE_LIMIT: usize = 1000;

// 内部自定义一个 Payload，以支持分页的总条数显示
#[derive(Deserialize, Serialize)]
struct CacheListPayload<T> {
    count: usize,
    total: usize, // 额外返回总数，方便前端做翻页器
    data: Vec<T>,
}

#[utoipa::path(
    get,
    path = "/caches",
    tag = "Caches",
    operation_id = "list_caches",
    params(CachePagination)
)]
async fn caches(
    State(state): State<Arc<ServeState>>,
    Query(page): Query<CachePagination>,
) -> Json<CacheListPayload<CachedQueryRecord>> {
    let limit = page.limit.min(MAX_PAGE_LIMIT);
    if limit != page.limit {
        log::debug!(
            "caches: 请求的 limit={} 超过单页上限，按 {} 返回",
            page.limit,
            MAX_PAGE_LIMIT
        );
    }

    let (total, data) = if let Some(c) = state.app.cache().await {
        c.cached_records_paginated(page.offset, limit).await
    } else {
        (0, vec![])
    };

    Json(CacheListPayload {
        count: data.len(),
        total,
        data,
    })
}

#[utoipa::path(
    post,
    path = "/caches/flush",
    tag = "Caches",
    operation_id = "flush_caches"
)]
async fn flush(State(state): State<Arc<ServeState>>) -> StatusCode {
    if let Some(c) = state.app.cache().await {
        c.clear().await;
    }
    log::info!("flushed cache");
    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    path = "/caches/config",
    tag = "Caches",
    operation_id = "get_cache_config"
)]
async fn config(State(state): State<Arc<ServeState>>) -> Json<CacheConfig> {
    let config = state.app.cfg().await.cache_config().clone();
    Json(config)
}
