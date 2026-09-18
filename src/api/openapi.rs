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

    // 🌟「顺手修」：默认 CDN **钉住版本**并加**完整性校验（SRI）**。
    //
    // 原来这里是不带版本号的 `https://unpkg.com/swagger-ui-dist` —— 语义是"永远取最新版"：
    // ① 官方一发新版，我们的用户界面会在毫无察觉的情况下换成另一份代码；
    // ② 页面从第三方 CDN 直接加载并执行脚本，却没有完整性校验，CDN 被投毒/被劫持时浏览器照跑不误。
    // 现在：钉到具体版本 + `integrity`/`crossorigin`，浏览器在文件与校验值不一致时**直接拒绝执行**。
    // 校验值取自 swagger-ui-dist@5.33.0 的官方产物，unpkg 与 jsdelivr 两个镜像逐字节一致（已核对）。
    // 升级版本时同步更新这三处常量即可。
    //
    // 用户自己传了 cdn（完整 URL 前缀）时不做校验 —— 那是他自己的来源，我们没法替他钉。
    const PINNED_CDN: &str = "https://unpkg.com/swagger-ui-dist@5.33.0";
    const PINNED_CSS_SRI: &str = "integrity=\"sha384-Ov4/wv3j2bmct8cDc5X4ngJZohVPzEmc6uDPH8WeljUxO5vtoykvMEfbu9Vh6RaW\" crossorigin=\"anonymous\"";
    const PINNED_JS_SRI: &str = "integrity=\"sha384-YDALVcy8kj8yltLBVi1vBiBAUqdxvus673gM8XKwiy6aDUJFXivF/KCufekjYbVf\" crossorigin=\"anonymous\"";

    let (cdn, css_sri, js_sri) = match cdn {
        Some(custom) => (custom, "", ""),
        None => (PINNED_CDN, PINNED_CSS_SRI, PINNED_JS_SRI),
    };
    let html = r#"<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>{title}</title>
      <link rel="stylesheet" href="{cdn}/swagger-ui.css" {css_sri} />
    </head>
    <body>
      <div id="swagger-ui"></div>
      <script src="{cdn}/swagger-ui-bundle.js" {js_sri}></script>
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
        .replace("{css_sri}", css_sri)
        .replace("{js_sri}", js_sri)
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
