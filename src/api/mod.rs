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
                router.merge(openapi::swagger_cdn("/api/docs", "/api/openapi.json", openapi, None))
            }
            else if #[cfg(feature = "swagger-ui-embed")]
            {
                use utoipa_swagger_ui::{Config, SwaggerUi};
                router.merge(
                    SwaggerUi::new("/api/docs")
                        .config(
                            Config::default()
                                .show_extensions(true)
                                .show_common_extensions(true)
                                .use_base_layout(),
                        )
                        .url("/api/openapi.json", openapi),
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
    NotFound(String),
}

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Internal(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Something went wrong: {error}"),
            )
                .into_response(),
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{ "error": "{self}" }}"#),
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
async fn api_auth_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    // 从环境变量读取 API 密钥，如果没有配置，则默认使用 "admin_secret"
    let expected_token = std::env::var("SMARTDNS_API_TOKEN").unwrap_or_else(|_| "admin_secret".to_string());

    // 提取 HTTP Header 中的 Authorization 字段
    if let Some(auth_header) = req.headers().get(http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            // 校验 Bearer Token
            if auth_str.starts_with("Bearer ") {
                let provided_token = &auth_str[7..];

                // 🌟 上帝视角安全防御：恒定时间比较 (Constant-Time Comparison)
                // 绝不使用原生的 `==` 短路比较，防止黑客通过极其微小的微秒级响应时间差，逐位爆破出你的管理密码。
                if provided_token.len() == expected_token.len() {
                    let mut diff = 0;
                    for (a, b) in provided_token.bytes().zip(expected_token.bytes()) {
                        // 使用 std::hint::black_box 蒙蔽 LLVM 的窥视优化，
                        // 强迫 CPU 无论匹配与否，都必须老老实实做完所有的异或和位或运算，保证耗时绝对恒定！
                        diff |= std::hint::black_box(a ^ b);
                    }
                    if diff == 0 {
                        // 密码正确，放行！进入真正的 API 处理逻辑
                        return Ok(next.run(req).await);
                    }
                }
            }
        }
    }
    
    // 拦截非法访问，并打印警告日志记录黑客 IP
    crate::log::warn!("Unauthorized API access attempt to: {}", req.uri().path());
    Err(StatusCode::UNAUTHORIZED)
}
