use std::io::Read;

pub trait HttpResponse {
    fn text(self) -> anyhow::Result<String>;
}

/// 🔐 P2：名单 / 订阅类下载的硬限制。
///
/// 原实现既没有超时也没有大小上限：
///   * 对端只连不回 → 启动或配置重载会一直卡住；
///   * 响应超大 → 直接读进内存，把进程打爆。
const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 8 MiB —— 域名名单 / 订阅文件远小于此，超过基本可以断定对面不对劲。
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// 带上限地读完整正文：多读 1 字节用来判断"是否超限"。
fn read_capped<R: Read>(reader: R) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    reader.take(MAX_BODY_BYTES + 1).read_to_end(&mut buf)?;

    if buf.len() as u64 > MAX_BODY_BYTES {
        anyhow::bail!(
            "响应体超过上限 {} 字节，已拒绝（这个地址可能返回了异常内容）",
            MAX_BODY_BYTES
        );
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(feature = "ureq")]
pub fn get<T>(
    uri: T,
    proxy_url: Option<&str>,
) -> Result<ureq::http::Response<ureq::Body>, ureq::Error>
where
    http::Uri: TryFrom<T>,
    <http::Uri as TryFrom<T>>::Error: Into<http::Error>,
{
    // 🔐 P2：给所有下载都套上总超时（原实现没有超时，对端不回应就永久卡住）
    let mut config_builder = ureq::Agent::config_builder().timeout_global(Some(DOWNLOAD_TIMEOUT));

    if let Some(p) = proxy_url {
        // 🌟 核心修复 1：拦截并动态装配 ureq 代理引擎
        if let Ok(proxy) = ureq::Proxy::new(p) {
            config_builder = config_builder.proxy(Some(proxy));
        }
    }

    let agent = config_builder.build().new_agent();
    agent.get(uri).call()
}

#[cfg(feature = "ureq")]
impl HttpResponse for ureq::http::Response<ureq::Body> {
    fn text(self) -> anyhow::Result<String> {
        read_capped(self.into_body().into_reader())
    }
}

#[cfg(feature = "reqwest")]
use reqwest::blocking as reqwest_client;

#[cfg(feature = "reqwest")]
pub fn get<T>(uri: T, proxy_url: Option<&str>) -> Result<impl HttpResponse, reqwest::Error>
where
    T: reqwest::IntoUrl,
{
    // 🔐 P2：同上，套上总超时
    let mut builder = reqwest_client::Client::builder().timeout(DOWNLOAD_TIMEOUT);
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
        read_capped(self)
    }
}
