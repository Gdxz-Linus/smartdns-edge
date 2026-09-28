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

/// 🔐 问题 39：名单下载**只跟随这么多次跳转**。
///
/// 原实现不限制跳转次数（ureq 的默认值在实际使用中形同惯例，但项目的意图从未写明），
/// 一个被控的名单地址可以把请求重定向到任意目标，配合 `-proxy` 构成请求伪造面。
/// 3 次足够覆盖"http→https 规范跳转 + CDN 一跳"这类正常情形。
const MAX_REDIRECTS: u32 = 3;

/// 🔐 问题 39：强制「仅 https」。
///
/// 两个必须拦住的点，ureq 的 `https_only` 在**每一跳**都检查（见其 `run.rs`），
/// 所以一个开关同时覆盖：
///   1. 直接写 `http://…` 的明文名单 —— 下载内容会被直接编译成规则，而规则语法支持
///      `*`、`+.` 这类通配写法。明文 http 可被中间人篡改，注入一条 `+.com` 就能**整体劫持分流**；
///   2. `https → http` 降级跳转 —— 首跳是 https 不代表后续跳转还是。
const HTTPS_ONLY: bool = true;

/// 🔐 问题 39：下载地址的协议白名单校验（错误文案里要能指出是哪个地址、为什么被拒）。
///
/// 单独抽成函数是为了让"拒绝"这件事**可被测试直接断言**，而不是只能靠端到端失败来推断。
pub fn check_download_url(url: &str) -> anyhow::Result<()> {
    let scheme = url
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .unwrap_or_default()
        .to_ascii_lowercase();

    match scheme.as_str() {
        "https" => Ok(()),
        // 明文 http 明确拒绝：名单内容会被编译成规则，可被中间人篡改成通配规则劫持分流
        "http" => anyhow::bail!(
            "plaintext http is not allowed for remote list downloads ({url}); \
             use https instead -- a list fetched over http can be modified in transit, \
             and its content is compiled into matching rules (a single injected wildcard rule \
             can hijack name resolution)"
        ),
        "" => anyhow::bail!(
            "the download address has no scheme ({url}); write it as an absolute https:// URL"
        ),
        other => anyhow::bail!(
            "unsupported download scheme `{other}://` ({url}); only https is accepted"
        ),
    }
}

/// 🔐 问题 39：测试专用的「信任本地自签证书」开关。
///
/// 生产代码始终用 ureq 的默认根证书库（webpki-roots），**这段只在 `cfg(test)` 下存在**。
///
/// 为什么需要它：问题 39 收紧为「仅 https」之后，名单类测试不能再拿明文 http 回环服务器
/// 凑合（那样测的就不是`https_only` 生效的那条路径了）。改用真实 HTTPS 后，
/// 测试服务器用的是本地自签证书，而默认根证书库当然不认它。
///
/// 为什么用**线程局部**而不是全局：测试是并发跑的，改全局根证书会波及同进程里
/// 其它走公网 HTTPS 的用例。名单测试的下载是同步阻塞调用、就在当前线程上，
/// 所以线程局部既够用、又不会串扰。
#[cfg(test)]
pub(crate) mod test_tls {
    use std::cell::RefCell;

    /// 测试证书的 PEM 内容（随仓库提交，见 `tests/test_data/tls/`）。
    ///
    /// 用 `include_bytes!` 而不是运行时读文件：单元测试的工作目录不保证是 crate 根，
    /// 但 `include_bytes!` 是编译期相对当前源文件解析的，永远稳。
    pub(crate) const TEST_CA_PEM: &[u8] = include_bytes!("../../tests/test_data/tls/cert.pem");
    pub(crate) const TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/test_data/tls/key.pem");

    thread_local! {
        /// 本线程是否要额外信任测试 CA。默认关（不影响任何既有用例）。
        static TRUST_TEST_CA: RefCell<bool> = const { RefCell::new(false) };
    }

    /// 让**当前线程**后续的下载信任测试自签证书。由需要 HTTPS 名单服务器的用例调用。
    pub(crate) fn trust_test_ca_for_this_thread() {
        TRUST_TEST_CA.with(|v| *v.borrow_mut() = true);
    }

    /// 当前线程是否需要信任测试 CA。
    pub(crate) fn should_trust_test_ca() -> bool {
        TRUST_TEST_CA.with(|v| *v.borrow())
    }

    pub(crate) fn test_ca_certificates() -> Vec<ureq::tls::Certificate<'static>> {
        // 模块级 `parse_pem` 会逐段产出 PEM 项，这里只挑出证书
        ureq::tls::parse_pem(TEST_CA_PEM)
            .filter_map(|item| item.ok())
            .filter_map(|item| match item {
                ureq::tls::PemItem::Certificate(cert) => Some(cert),
                _ => None,
            })
            .collect()
    }
}

/// 带上限地读完整正文：多读 1 字节用来判断"是否超限"。
fn read_capped<R: Read>(reader: R) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    reader.take(MAX_BODY_BYTES + 1).read_to_end(&mut buf)?;

    if buf.len() as u64 > MAX_BODY_BYTES {
        anyhow::bail!(
            "response body exceeds the {} byte limit and was rejected (this address may have returned unexpected content)",
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
    let mut config_builder = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        // 🔐 问题 39：仅 https + 限制跳转（每一跳都会重新检查协议，故降级跳转同样被拦下）
        .https_only(HTTPS_ONLY)
        .max_redirects(MAX_REDIRECTS);

    // 🔐 问题 39：仅测试时，允许本线程额外信任本地自签证书（见 `test_tls` 的说明）。
    // 生产编译下这段不存在，行为与从前完全一致。
    #[cfg(test)]
    if test_tls::should_trust_test_ca() {
        let certs = test_tls::test_ca_certificates();
        config_builder = config_builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                .build(),
        );
    }

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
    // 🔐 问题 39：同样收紧 —— 拒绝明文 http 与降级跳转、限制跳转次数。
    // 两个后端必须口径一致，否则"换一个 feature 编译"就把防护丢了。
    let mut builder = reqwest_client::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .https_only(HTTPS_ONLY)
        .redirect(reqwest_client::redirect::Policy::limited(
            MAX_REDIRECTS as usize,
        ));
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

#[cfg(test)]
mod problem_39_tests {
    use super::*;

    /// 🔐 问题 39 的核心回归①：明文 http 名单**必须被拒绝**。
    ///
    /// 为什么这条重要：下载到的域名会被直接编译成规则，而规则语法支持 `*`、`+.` 这类通配写法。
    /// 明文 http 可被中间人篡改，注入一条 `+.com` 就能整体劫持分流 —— 所以这里必须是"拒绝"，
    /// 而不是"告警后继续"。
    #[test]
    fn plaintext_http_download_is_rejected() {
        let err = check_download_url("http://example.com/list.txt")
            .expect_err("明文 http 名单必须被拒绝（内容可被中间人篡改成通配规则）");
        let shown = err.to_string();
        assert!(
            shown.contains("http"),
            "错误文案应指出是 http 的问题: {shown}"
        );
        assert!(
            shown.contains("https"),
            "错误文案应告诉用户改用 https: {shown}"
        );
        assert!(
            shown.contains("http://example.com/list.txt"),
            "错误文案应带上具体地址，便于定位是哪条配置: {shown}"
        );
    }

    /// 🔐 问题 39：https 与大小写不敏感之外，其它协议（ftp/file/data…）一并拒绝。
    #[test]
    fn non_https_schemes_are_rejected() {
        for url in [
            "ftp://example.com/list.txt",
            "file:///etc/passwd",
            "data:text/plain,evil",
        ] {
            assert!(
                check_download_url(url).is_err(),
                "非 https 协议必须被拒绝: {url}"
            );
        }

        // 没写协议的地址也要明确报错，而不是让底层抛一句含糊的传输层错误
        assert!(check_download_url("example.com/list.txt").is_err());
        assert!(check_download_url("//example.com/list.txt").is_err());
    }

    /// 🔐 问题 39：https 必须放行，且大小写不敏感（`HTTPS://` 也应通过）。
    #[test]
    fn https_is_accepted() {
        for url in [
            "https://example.com/list.txt",
            "HTTPS://example.com/list.txt",
            "https://example.com:8443/a/b?c=d",
        ] {
            assert!(check_download_url(url).is_ok(), "https 必须被放行: {url}");
        }
    }

    /// 🔐 问题 39：跳转次数必须被限制（不能是"跟随无限次"）。
    /// 这条钉住的是常量本身，防止日后被改回无限制。
    #[test]
    fn redirects_are_limited() {
        assert!(MAX_REDIRECTS > 0, "要允许正常的规范跳转");
        assert!(
            MAX_REDIRECTS <= 5,
            "跳转次数必须有明确上限，当前 {MAX_REDIRECTS} 过大"
        );
    }

    /// 🔐 问题 39：`https_only` 必须开着。
    /// 这是"禁止 https→http 降级"的实现依据 —— ureq 在**每一跳**都检查该开关，
    /// 因此首跳 https、后续跳到 http 同样会被拒绝（若这个开关被关掉，降级就放行了）。
    #[test]
    fn https_only_is_enabled() {
        assert!(
            HTTPS_ONLY,
            "名单下载必须强制仅 https（含禁止 https→http 降级跳转）"
        );
    }
}
