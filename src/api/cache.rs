use std::sync::Arc;

use super::openapi::{
    IntoParams, IntoRouter,
    http::{get, post},
    routes,
};
use super::{ServeState, StatefulRouter};
use crate::{config::CacheConfig, dns_mw_cache::CachedQueryRecord, log};
use axum::{Json, extract::{State, Query}, http::StatusCode};
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
fn default_limit() -> usize { 100 } // 默认最多只返回 100 条，死死守住内存底线

// 内部自定义一个 Payload，以支持分页的总条数显示
#[derive(Deserialize, Serialize)]
struct CacheListPayload<T> {
    count: usize,
    total: usize, // 额外返回总数，方便前端做翻页器
    data: Vec<T>,
}

#[get("/caches", tag = "Caches", operation_id = "list_caches", params(CachePagination))]
async fn caches(
    State(state): State<Arc<ServeState>>,
    Query(page): Query<CachePagination>,
) -> Json<CacheListPayload<CachedQueryRecord>> {
    let (total, data) = if let Some(c) = state.app.cache().await {
        // 🌟 调用带有分页拦截的底层接口
        c.cached_records_paginated(page.offset, page.limit).await
    } else {
        (0, vec![])
    };

    Json(CacheListPayload {
        count: data.len(),
        total,
        data,
    })
}

#[post("/caches/flush", tag = "Caches", operation_id = "flush_caches")]
async fn flush(State(state): State<Arc<ServeState>>) -> StatusCode {
    if let Some(c) = state.app.cache().await {
        c.clear().await;
    }
    log::info!("flushed cache");
    StatusCode::NO_CONTENT
}

#[get("/caches/config", tag = "Caches", operation_id = "get_cache_config")]
async fn config(State(state): State<Arc<ServeState>>) -> Json<CacheConfig> {
    let config = state.app.cfg().await.cache_config().clone();
    Json(config)
}
