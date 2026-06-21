pub trait HttpResponse {
    fn text(self) -> anyhow::Result<String>;
}

#[cfg(feature = "ureq")]
use ureq as http_client;

#[cfg(feature = "ureq")]
pub fn get<T>(uri: T, proxy_url: Option<&str>) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>
where
    http::Uri: TryFrom<T>,
    <http::Uri as TryFrom<T>>::Error: Into<http::Error>,
{
    if let Some(p) = proxy_url {
        // 🌟 核心修复 1：拦截并动态装配 ureq 代理引擎
        if let Ok(proxy) = ureq::Proxy::new(p) {
            let agent = ureq::Agent::config_builder().proxy(Some(proxy)).build().new_agent();
            return Ok(agent.get(uri).call()?);
        }
    }
    // 代理无效或未提供时，回退直连
    let res = http_client::get(uri).call()?;
    Ok(res)
}

#[cfg(feature = "ureq")]
impl HttpResponse for ureq::http::Response<ureq::Body> {
    fn text(mut self) -> anyhow::Result<String> {
        Ok(self.body_mut().read_to_string()?)
    }
}

#[cfg(feature = "reqwest")]
use reqwest::blocking as reqwest_client;

#[cfg(feature = "reqwest")]
pub fn get<T>(uri: T, proxy_url: Option<&str>) -> Result<impl HttpResponse, reqwest::Error>
where
    T: reqwest::IntoUrl,
{
    let mut builder = reqwest_client::Client::builder();
    if let Some(p) = proxy_url {
        // 🌟 核心修复 1：拦截并动态装配 reqwest 代理引擎
        if let Ok(proxy) = reqwest::Proxy::all(p) {
            builder = builder.proxy(proxy);
        }
    }
    let res = builder.build()?.get(uri).send()?;
    Ok(res)
}

#[cfg(feature = "reqwest")]
impl HttpResponse for reqwest::blocking::Response {
    fn text(self) -> anyhow::Result<String> {
        Ok(self.text()?)
    }
}
