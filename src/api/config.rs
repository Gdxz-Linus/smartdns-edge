use std::sync::Arc;

use axum::extract::State;
use axum::Json;

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
        .map(|p| p.to_string_lossy().into_owned());

    Json(ServerConfig {
        server_name: cfg.server_name(),
        conf_dir,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
struct ServerConfig {
    #[schema(value_type = String)]
    server_name: Name,
    conf_dir: Option<String>,
}