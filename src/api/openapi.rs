#![allow(unused_imports)]

use axum::routing::MethodRouter;
use utoipa::{
    OpenApi,
    openapi::{Paths, RefOr, Schema},
};

pub use utoipa::{IntoParams, ToSchema, path};
pub use utoipa_axum::{router::OpenApiRouter as Router, routes};

pub trait IntoRouter<S = ()> {
    fn into_router(self) -> Router<S>;
}

impl<S: Send + Sync + Clone + 'static> IntoRouter<S>
    for (Vec<(String, RefOr<Schema>)>, Paths, MethodRouter<S>)
{
    fn into_router(self) -> Router<S> {
        Router::new().routes(self)
    }
}

#[cfg(feature = "swagger-ui-cdn")]
pub fn swagger_cdn<S: Clone + Send + Sync + 'static>(
    doc_url: &str,
    openapi_url: &str,
    openapi: utoipa::openapi::OpenApi,
    cdn: Option<&str>,
) -> axum::Router<S> {
    use axum::{
        Router,
        extract::State,
        response::{Html, Json},
        routing::get,
    };
    use std::sync::Arc;
    use utoipa::openapi::OpenApi;

    let cdn = cdn.unwrap_or("https://unpkg.com/swagger-ui-dist");
    let html = r#"<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>{title}</title>
      <link rel="stylesheet" href="{cdn}/swagger-ui.css" />
    </head>
    <body>
      <div id="swagger-ui"></div>
      <script src="{cdn}/swagger-ui-bundle.js"></script>
      <script>
        window.onload = () => {
          window.ui = SwaggerUIBundle({
            url: '{openapi}',
            dom_id: '#swagger-ui',
          });
        };
      </script>
    </body>
    </html>"#
        .replace("{cdn}", cdn)
        .replace("{openapi}", openapi_url)
        .replace("{title}", crate::NAME);

    async fn doc(State(doc): State<Arc<OpenApi>>) -> Json<OpenApi> {
        Json(doc.as_ref().clone())
    }

    async fn index(State(html): State<Arc<String>>) -> Html<String> {
        Html(html.to_string())
    }

    Router::new()
        .route(doc_url, get(index).with_state(Arc::new(html)))
        .route(openapi_url, get(doc).with_state(Arc::new(openapi)))
}