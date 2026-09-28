use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Query;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Request, State},
};
use serde::{Deserialize, Serialize};

use super::openapi::{IntoParams, IntoRouter, ToSchema, routes};
use super::{ApiError, ServeState, StatefulRouter};
use crate::{dns::SerialMessage, libdns::Protocol, log};

pub fn routes() -> StatefulRouter {
    routes![serve_dns_get, serve_dns].into_router()
}

#[utoipa::path(get, path = "/dns-query", tag="DNS", params(QueryParam), responses(
    (status = 200, description = "DNS response", body = DnsResponse)
))]
async fn serve_dns_get(
    State(state): State<Arc<ServeState>>,
    Query(parameters): Query<QueryParam>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
    match process(&state, req, addr, Some(parameters)).await {
        Ok((content_type, bytes)) => {
            let mut res = Body::from(bytes).into_response();
            res.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            res
        }
        Err(err) => err.into_response(),
    }
}

#[utoipa::path(post, path = "/dns-query", tag = "DNS")]
async fn serve_dns(
    State(state): State<Arc<ServeState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    match process(&state, req, addr, None).await {
        Ok((content_type, bytes)) => {
            let mut res = Body::from(bytes).into_response();
            res.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            res
        }
        Err(err) => err.into_response(),
    }
}

async fn process(
    state: &ServeState,
    req: Request,
    addr: SocketAddr,
    query_param: Option<QueryParam>,
) -> Result<(&'static str, Bytes), ApiError> {
    // 🔐 13-⑥：如果请求来自**可信反向代理**，算出真实客户端地址。
    //
    // 这个值接下来会被放进 `SerialMessage`，最终成为 `DnsRequest` 上的
    // 「**归组地址**」——**只用于按来源选规则组**，**不用于 ACL 放行判定**。
    //
    // ⚠️ 这一点是硬约束（`src/trusted_proxy.rs` 模块文档的"铁律 ③"）：
    // `X-Forwarded-For` 是调用方可以伪造的普通 HTTP 头。若拿它做放行判定，
    // 攻击者伪造一个能匹配白名单的头就**绕过了 ACL** —— 那就把"限流问题"
    // 升级成了"安全问题"。所以：
    //   · `DnsRequest::src()`          → 恒为**真实对端**（内核给出，不可伪造），ACL 用它；
    //   · `DnsRequest::grouping_addr()` → 可能是 XFF 里的值，**只用于归组**。
    let peer = addr.ip();
    let forwarded = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());

    // 清单为空（默认）时 `resolve_client_ip` 直接返回对端地址、完全无视 XFF，
    // 于是 `forwarded_addr` 与 `peer` 相同 —— 行为与改动前**逐字节一致**。
    let trusted = state.app.cfg().await.trusted_proxies();
    let (grouping_ip, source) = crate::trusted_proxy::resolve_client_ip(peer, forwarded, &trusted);

    if source.is_forwarded() {
        log::debug!(
            "DoH: grouping by X-Forwarded-For address {grouping_ip} (peer {peer} is a trusted proxy)"
        );
    }

    // 只有"确实从 XFF 解析出了不同地址"时才带上，否则保持 `None`
    // （让下游走与改动前完全相同的路径，不引入任何额外分支）。
    let forwarded_addr = (grouping_ip != peer).then(|| SocketAddr::new(grouping_ip, addr.port()));

    let accept = match req.headers().get(header::ACCEPT).map(|s| s.to_str()) {
        Some(Ok(s)) => s,
        _ => "",
    };

    log::debug!(
        "DoH {} {} {}",
        req.method().as_str(),
        req.uri().to_string(),
        accept
    );

    // 🔐 问题 33：`Accept` 以前是**全等比较**，于是真实客户端常带的
    // `application/dns-message, */*`（或带 `;q=` 参数的写法）会被判成"不是 DNS 模式"，
    // 结果是**客户端明确要 DNS 报文、服务器却回 JSON**。按 RFC 7231 解析列表。
    let accepts_dns_message = accepts_dns_message(accept);

    // 🔐 问题 33：RFC 8484 的 `GET /dns-query?dns=<base64url>`。
    // `?dns=` 请求本身**没有 `name` 参数**（见 QueryParam 里 name 已改为 Option），
    // 所以这条分支必须排在"JSON 风格参数"之前判断。
    if let Some(encoded) = query_param.as_ref().and_then(|p| p.dns.as_deref()) {
        let raw = decode_dns_param(encoded).map_err(ApiError::BadRequest)?;
        // RFC 8484 规定该形式承载的就是 DNS 报文，因此**一律回二进制**，
        // 不能因为 `Accept` 没写全就退回 JSON（否则标准客户端拿不到报文）。
        // 🔐 13-⑥：带上归组地址（若来自可信代理则有值，否则与 `addr` 等价、不影响行为）
        let req_msg = SerialMessage::binary(raw, addr, Protocol::Https);
        let req_msg = match forwarded_addr {
            Some(fwd) => req_msg.with_grouping_addr(fwd),
            None => req_msg,
        };
        // 第四个参数（`client_cd`）只服务于 JSON 视图；这条分支一律回二进制报文，
        // 报文里自带 CD 位，不需要（也不应该）由这里另外拼一个。
        return finish(state, req_msg, true, false).await;
    }

    let req_msg = match query_param {
        Some(query_param) if !accepts_dns_message => {
            // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
            use crate::libdns::proto::{
                op::{Edns, Message, Query},
                rr::{Name, RecordType},
            };

            // 🔐 P2：参数写错要回 400（Bad Request），不能再 `?` 冒泡成 500 ——
            // 否则客户端的输入错误会伪装成服务器故障，把监控和告警带偏。
            //
            // 🔐 问题 33：`name` 现在是 Option（为了 `?dns=` 形式）。走到这里说明
            // 既没有 `?dns=`、又没给 `name` —— 要给出**可操作**的 400，
            // 而不是让用户对着一句 "missing field" 猜。
            let name: Name = query_param
                .name
                .as_deref()
                .ok_or_else(|| {
                    ApiError::BadRequest(
                        "missing `name` parameter (this endpoint needs either `name`, or the RFC 8484 form `?dns=<base64url>`)"
                            .to_string(),
                    )
                })?
                .parse()
                .map_err(|_| {
                    ApiError::BadRequest(format!(
                        "invalid `name` parameter: {}",
                        query_param.name.as_deref().unwrap_or_default()
                    ))
                })?;
            // 🔐 B8：`?type=` 写错以前被**静默**当成 A 查询（与 `name` 写错回 400 的口径不一致），
            // 用户会拿到一份"看起来正常但答的是另一回事"的结果。
            //
            // `?type=` 的文本写法不区分大小写（`aaaa` / `AAAA` 等价，RFC 1035）。
            // 早先内嵌 hickory 的 `RecordType::from_str` 里有 `debug_assert!(不含小写)`，
            // 小写输入在 debug 构建下 panic、release 下退化成 400；该断言已在**内嵌副本里改掉**，
            // 所以这里不再需要转大写（改动登记在 `hickory-dns/VENDORED.md`）。
            let query_type: RecordType = query_param.query_type.parse().map_err(|_| {
                ApiError::BadRequest(format!(
                    "invalid `type` parameter: {}",
                    query_param.query_type
                ))
            })?;

            let dnssec = query_param.dnssec;
            let checking_disabled = query_param.checking_disabled;

            let mut message = Message::query();
            message.add_query(Query::query(name, query_type));
            message.set_checking_disabled(checking_disabled);
            if dnssec {
                let mut edns = Edns::new();
                edns.set_dnssec_ok(dnssec);
                message.set_edns(edns);
            }

            SerialMessage::raw(message, addr, Protocol::Https)
        }
        _ => {
            // 🌟 核心防线：抛弃存在隐患的 FromRequest 默认提取器，直接读取底层 Body！
            // 强行施加 64KB 物理截断（DNS 协议理论最大极限），超过该字节数底层的读取器会直接抛错掐断流。
            // 这巧妙规避了 Axum `Router::merge` 会静默丢失 Layer 的深坑，精准且彻底地封死了 DoH 的 OOM 攻击面！
            let bytes = axum::body::to_bytes(req.into_body(), 65536).await?;
            SerialMessage::binary(bytes, addr, Protocol::Https)
        }
    };

    // 🔐 13-⑥：统一在这里带上归组地址 —— 上面两条分支（JSON 风格参数、二进制 POST）
    // 都从这里出去，集中处理可以避免"只接了一条分支、另一条漏了"。
    // （`?dns=` 那条分支在上面已经单独带上并提前返回。）
    let req_msg = match forwarded_addr {
        Some(fwd) => req_msg.with_grouping_addr(fwd),
        None => req_msg,
    };

    // 🔐 问题 32（真机验证抓出的修正）：`CD` 是**请求的属性** ——
    // "客户端是否要求禁用校验"，因此必须从**请求**里取。
    // 第一版是在 `From<&Message>` 里读 `message.checking_disabled()`，
    // 但那个 `message` 是**响应**消息，它由上游/响应构造路径决定，
    // 真机实测**恒为 true**，于是"回显客户端"变成了"写死 true"的另一种写法。
    //
    // 必须在 `send()` 之前取（`send` 会把 `req_msg` 移走）。两种载体分别取：
    //   * `Raw`（GET 的 JSON 风格参数）→ 请求消息上已被 `?cd=` 设好；
    //   * `Bytes`（POST 的 DNS 报文）→ 直接从报文头第 4 字节取 CD 位
    //     （flags 低字节：RA=0x80、Z=0x40、AD=0x20、**CD=0x10**、RCODE=0x0F）。
    let client_cd = match &req_msg {
        SerialMessage::Raw(message, ..) => message.checking_disabled(),
        SerialMessage::Bytes(bytes, ..) => bytes.get(3).is_some_and(|b| b & 0x10 != 0),
    };

    let res_msg = state.dns_handle.send(req_msg).await;
    finish(state, res_msg, accepts_dns_message, client_cd).await
}

/// 把一次已发出的查询收敛成 `(Content-Type, body)`。
///
/// 抽出来是为了让 RFC 8484 的 `?dns=` 分支与普通分支**共用同一条出口** ——
/// 两处各写一份的话，「回二进制还是回 JSON」的判定迟早会漂移。
async fn finish(
    _state: &ServeState,
    res_msg: crate::dns::SerialMessage,
    accepts_dns_message: bool,
    client_cd: bool,
) -> Result<(&'static str, Bytes), ApiError> {
    const APPLICATION_DNS_MESSAGE: &str = "application/dns-message";
    const APPLICATION_JSON: &str = "application/json";

    let (content_type, bytes) = if accepts_dns_message {
        (APPLICATION_DNS_MESSAGE, res_msg.try_into()?)
    } else {
        let message = match res_msg {
            SerialMessage::Raw(message, ..) => message,
            SerialMessage::Bytes(..) => Err(anyhow::anyhow!("Invliad message type"))?,
        };
        (
            APPLICATION_JSON,
            serde_json::to_vec(&DnsResponse::from_message(message.as_ref(), client_cd))?,
        )
    };

    Ok((content_type, bytes.into()))
}

#[derive(Deserialize, IntoParams)]
struct QueryParam {
    /// Query name
    ///
    /// 🔐 问题 33：改为**可选** —— RFC 8484 的 `GET /dns-query?dns=<base64url>`
    /// 不带 `name`。以前这里是必填，那种请求会在**参数提取阶段就 400**，
    /// 根本走不到下面的分支（这就是"只加解码分支不够"的原因）。
    name: Option<String>,

    /// Query type (either a numeric value or text ↗).
    #[serde(default = "QueryParam::default_query_type", rename = "type")]
    query_type: String,

    /// DO bit - whether the client wants DNSSEC data (either empty or one of 0, false, 1, or true).
    #[serde(default, deserialize_with = "de_bool_flexible", rename = "do")]
    dnssec: bool,

    /// CD bit - disable validation (either empty or one of 0, false, 1, or true).
    #[serde(default, deserialize_with = "de_bool_flexible", rename = "cd")]
    checking_disabled: bool,

    /// 🔐 问题 33：RFC 8484 的 base64url 编码 DNS 报文（`?dns=`）。
    #[serde(default, rename = "dns")]
    dns: Option<String>,
}

impl QueryParam {
    fn default_query_type() -> String {
        "A".to_string()
    }
}

/// 🔐 问题 33（真机验证抓出的配套缺陷）：`?cd=1` / `?do=1` 必须能解析。
///
/// 这个接口兼容 Cloudflare 的 JSON 风格 DoH，而 Cloudflare 对该参数的文档写法
/// 就是 **`cd=1` / `do=1`**（"either empty or one of 0, false, 1, or true"）。
/// 而 serde 对 `bool` 只认 `true`/`false`，于是 `?cd=1` 会在**参数提取阶段**
/// 直接 400：`Failed to deserialize query string: cd: provided string was not 'true' or 'false'`。
///
/// 真机脚本 `_p32_33_doh.ps1` 一跑就撞上（单元测试看不见，因为单测直接调函数、
/// 不经过 serde 提取器）——这正是"三层验证缺一不可"的又一例。
fn de_bool_flexible<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    // 参数是从 URL 里来的，先按字符串收，再按几套通行写法解释。
    let raw = Option::<String>::deserialize(deserializer)?;
    match raw.as_deref().map(str::trim) {
        None | Some("") => Ok(false),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(D::Error::custom(format!(
                "invalid boolean value {other:?}: use one of 0/1/true/false"
            ))),
        },
    }
}

/// 🔐 问题 33：判断 `Accept` 里是否**包含** `application/dns-message`。
///
/// 原实现是 `accept == "application/dns-message"` 的**全等比较**，因此
/// 真实客户端常见的这些写法全都被判成"不是 DNS 模式"：
///   * `application/dns-message, */*`（最典型的浏览器/curl 组合）
///   * `application/dns-message;q=1.0`
///   * `Application/DNS-Message`（媒体类型按 RFC 2045 **大小写无关**）
///   * `*/*`（"什么格式都行" ⇒ 可以给 DNS 报文）
///
/// 按 RFC 7231 的媒体范围解析：按逗号切分，逐个去参数（`;q=`）与空白后比对。
fn accepts_dns_message(accept: &str) -> bool {
    const DNS_MESSAGE: &str = "application/dns-message";

    accept.split(',').any(|part| {
        let media = part
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        media == DNS_MESSAGE || media == "*/*"
    })
}

/// 🔐 问题 33：解 RFC 8484 的 `?dns=<base64url>`。
///
/// RFC 8484 规定用的是 **base64url、且不带 `=` 填充**（见该 RFC 第 4.1 节）。
/// 但现实里不少客户端（以及手写的 curl 命令）会带上填充，所以这里
/// **带/不带填充都接受** —— 拒绝它们只会换来"标准写法能用、顺手写的不能用"。
fn decode_dns_param(encoded: &str) -> Result<Vec<u8>, String> {
    // base64 0.13 的旧式 API（本仓库锁的就是这个版本，见 Cargo.toml）。
    // `URL_SAFE_NO_PAD` 表在 0.13 里以 `Config` 常量形式提供。
    //
    // 容错：URL 里 `+` 有时被写成空格（表单编码的残留），顺手换回来。
    let normalized = encoded.trim().replace(' ', "+");

    base64::decode_config(normalized.trim_end_matches('='), base64::URL_SAFE_NO_PAD).map_err(
        |err| {
            format!("invalid `dns` parameter: it must be base64url-encoded DNS wire data ({err})")
        },
    )
}

#[derive(Serialize, ToSchema)]
#[allow(non_snake_case)]
struct DnsResponse {
    /// The Response Code of the DNS Query
    status: u16,

    /// If true, it means the truncated bit was set.
    /// This happens when the DNS answer is larger
    /// than a single UDP or TCP packet. TC will
    /// almost always be false with Cloudflare
    /// DNS over HTTPS because Cloudflare supports
    /// the maximum response size.
    TC: bool,

    /// If true, it means the Recursive Desired
    /// bit was set. This is always set to true
    /// for Cloudflare DNS over HTTPS.
    RD: bool,

    /// If true, it means the Recursion Available
    /// bit was set. This is always set to true
    /// for Cloudflare DNS over HTTPS.
    RA: bool,

    /// If true, it means that every record
    /// in the answer was verified with DNSSEC.
    AD: bool,

    /// If true, the client asked to disable
    /// DNSSEC validation. In this case,
    /// Cloudflare will still fetch the DNSSEC-related records,
    /// but it will not attempt to validate the records.
    CD: bool,

    Question: Vec<Question>,
    Answer: Vec<Answer>,
}

#[derive(Serialize, ToSchema)]
struct Question {
    name: String,
    r#type: u16,
}

#[derive(Serialize, ToSchema)]
#[allow(non_snake_case)]
struct Answer {
    name: String,
    r#type: u16,
    TTL: u32,
    data: String,
}

impl DnsResponse {
    /// 由响应消息构造 JSON 视图。
    ///
    /// `client_cd` 必须由**调用方从请求侧取出**传入（见 `process()`）——
    /// 不能从这个响应消息里读：那是"响应是否要求禁用校验"，不是"客户端是否要求"。
    fn from_message(message: &crate::libdns::proto::op::Message, client_cd: bool) -> Self {
        DnsResponse {
            status: message.response_code().into(),
            TC: message.truncated(),
            RD: message.recursion_desired(),
            RA: message.recursion_available(),
            // 🔐 问题 32：`AD`（RFC 4035）的语义是「**应答里的数据已通过 DNSSEC 校验**」。
            // 原实现填的是 `message.authoritative()`，那是响应头里的 **AA 位**
            // （"本服务器是权威应答"），两者含义完全不同 ——
            // 依赖该字段判断数据可信度的客户端与监控会得到与事实无关的结论。
            //
            // 这里**刻意回 false**，而不是透传 `message.authentic_data()`：
            // 本机是**递归/转发**服务器，自己不做 DNSSEC 校验，
            // 上游给的 AD 位我们无从核实；把未经验证的位透传出去，
            // 等于替上游背书"数据可信"，比回 false 更危险。
            // 等将来真正实现了校验，再把这里改成如实反映本地校验结果。
            AD: false,
            // 🔐 问题 32：`CD`（RFC 4035）表示「客户端要求**禁用**校验」，
            // 原实现写死 `true`，与客户端实际请求无关。现在回显请求侧的真实取值。
            CD: client_cd,
            Question: message
                .queries()
                .iter()
                .map(|q| Question {
                    name: q.name().to_string(),
                    r#type: q.query_type().into(),
                })
                .collect(),
            Answer: message
                .answers()
                .iter()
                .map(|r| Answer {
                    name: r.name().to_string(),
                    r#type: r.record_type().into(),
                    TTL: r.ttl(),
                    data: r.data().to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    //! 内嵌 hickory 的本地改动：记录类型 / 类别的**文本写法不区分大小写**。
    //!
    //! 背景：`?type=aaaa` 这种小写写法在管理接口里最自然，而内嵌副本原先的
    //! `debug_assert!` 只在 debug 构建下拦它 —— 同一个请求 debug 下 panic、release 下 400。
    //! 现在按 RFC 1035 处理（文本写法不区分大小写）。改动登记在 `hickory-dns/VENDORED.md` 4.7 节。
    use crate::libdns::proto::rr::{DNSClass, RecordType};
    // ⚠️ 必须显式导入：本模块里的 `DnsResponse` 是 DoH **JSON 结构体**，
    // 而 `crate::dns::DnsResponse`（同名）是内部的响应类型，两者不是一个东西。
    use super::{DnsResponse, QueryParam, accepts_dns_message, decode_dns_param};

    #[test]
    fn record_type_text_is_case_insensitive() {
        for text in ["aaaa", "Aaaa", "AAAA"] {
            let parsed: RecordType = text.parse().expect("小写也应当认得");
            assert_eq!(parsed, RecordType::AAAA, "{text} 应解析为 AAAA");
        }
        // 不认识的名字必须报错 —— 不能被静默当成 A（那是复核报告 B8 修掉的毛病）
        assert!("aaaaa".parse::<RecordType>().is_err());
    }

    #[test]
    fn dns_class_text_is_case_insensitive() {
        for text in ["in", "In", "IN"] {
            let parsed: DNSClass = text.parse().expect("小写也应当认得");
            assert_eq!(parsed, DNSClass::IN, "{text} 应解析为 IN");
        }
        assert!("qq".parse::<DNSClass>().is_err());
    }

    // ================= 🔐 问题 33：Accept 解析 =================

    /// 真实的客户端写法必须都被认成"要 DNS 报文"。
    /// 以前是全等比较，下面**除了第一条以外全都会失败**（退化成回 JSON）。
    #[test]
    fn accept_list_recognises_dns_message() {
        for accept in [
            "application/dns-message",
            "application/dns-message, */*", // 浏览器 / curl 最常见
            "application/dns-message;q=1.0",
            "application/dns-message ; q=0.9",
            "Application/DNS-Message", // 媒体类型大小写无关（RFC 2045）
            "text/html, application/dns-message",
            "*/*", // "什么格式都行" ⇒ 可以给 DNS 报文
            "  application/dns-message  ",
        ] {
            assert!(
                accepts_dns_message(accept),
                "{accept:?} 应被认成支持 application/dns-message"
            );
        }
    }

    /// 反向：明确只接受别的格式时，**不能**硬塞 DNS 报文
    /// （否则会把 JSON 客户端也喂成二进制）。
    #[test]
    fn accept_without_dns_message_is_not_treated_as_binary() {
        for accept in [
            "",
            "application/json",
            "text/html",
            // ⚠️ 只写了 json、同时带 */* 之外的其它类型 → 不含 dns-message
            "application/json, text/plain",
            // 含 `dns-message` 字样但不是完整媒体类型（子串误判的防线）
            "application/x-dns-message",
        ] {
            assert!(
                !accepts_dns_message(accept),
                "{accept:?} 不该被认成支持 application/dns-message"
            );
        }
    }

    // ================= 🔐 问题 33：RFC 8484 `?dns=` 解码 =================

    /// RFC 8484 要求 base64url **无填充**；带填充的写法也一并接受（现实客户端常见）。
    #[test]
    fn dns_param_decodes_base64url_with_and_without_padding() {
        let wire = [0xAB, 0xCD, 0xEF, 0x01, 0x02];

        let no_pad = base64::encode_config(wire, base64::URL_SAFE_NO_PAD);
        assert_eq!(decode_dns_param(&no_pad).unwrap(), wire, "无填充写法应能解");

        let padded = base64::encode_config(wire, base64::URL_SAFE);
        assert_eq!(
            decode_dns_param(&padded).unwrap(),
            wire,
            "带填充写法也应能解"
        );

        // URL-safe 表特有的 `-` / `_` 必须认得（标准表会在这里失败）
        let has_url_safe_chars = [0xFB, 0xFF, 0xBF];
        let encoded = base64::encode_config(has_url_safe_chars, base64::URL_SAFE_NO_PAD);
        assert!(
            encoded.contains('-') || encoded.contains('_'),
            "这组字节应编码出 URL-safe 专有字符，实际为 {encoded}"
        );
        assert_eq!(decode_dns_param(&encoded).unwrap(), has_url_safe_chars);
    }

    /// 非法输入要**明确报错**，且错误信息里要留下"该怎么写"的线索。
    #[test]
    fn dns_param_rejects_garbage_with_actionable_error() {
        let err = decode_dns_param("!!!not base64!!!").unwrap_err();
        assert!(
            err.contains("base64url"),
            "错误信息应说明要求的是 base64url，实际为：{err}"
        );
    }

    // ================= 🔐 问题 32：AD / CD =================

    /// `AD` 必须是 **false** —— 本机是递归/转发服务器，不做 DNSSEC 校验，
    /// 不能声称"数据已通过校验"（更不能像原来那样错填成 AA 位）。
    /// `CD` 必须**回显客户端请求值**（由调用方从请求侧取出后传入），不能写死。
    #[test]
    fn json_response_reports_ad_false_and_echoes_cd() {
        use crate::libdns::proto::op::{Message, Query};
        use crate::libdns::proto::rr::{Name, RecordType};

        // 造一个**带 AA 位**的响应：如果 AD 还读 AA 位，这条就会暴露成 true
        let mut message = Message::query();
        message
            .add_query(Query::query(
                Name::from_ascii("ad-cd.test.").unwrap(),
                RecordType::A,
            ))
            .set_authoritative(true)
            .set_authentic_data(false);

        // 客户端**要求禁用校验** → CD 应为 true
        let json = DnsResponse::from_message(&message, true);
        assert!(
            !json.AD,
            "AD 必须为 false（不做 DNSSEC 校验，且不能拿 AA 位顶替）"
        );
        assert!(json.CD, "客户端请求了 CD=1，响应应回显 true");

        // 客户端**没**要求禁用校验 → CD 应为 false（原实现写死 true，这里会失败）
        let json = DnsResponse::from_message(&message, false);
        assert!(!json.CD, "客户端没请求 CD，响应就不该写死成 true");
        assert!(!json.AD);
    }

    /// 🔐 问题 33（真机抓出的配套缺陷）：`?cd=1` / `?do=1` 必须能解析。
    /// serde 对 `bool` 只认 true/false，`?cd=1` 会在提取器处直接 400。
    ///
    /// ⚠️ 这里用 JSON 承载**字符串值**来模拟参数表（URL 参数到达 serde 时都是字符串），
    /// 走的是与 HTTP 提取器同一套 serde 逻辑。
    /// **真实 urlencoded 路径**（`?cd=1` 的原始形态）由真机脚本
    /// `tests/e2e/_p32_33_doh.ps1` 覆盖 —— 单元测试碰不到 axum 的提取器。
    #[test]
    fn query_param_accepts_numeric_and_textual_booleans() {
        fn parse(v: serde_json::Value) -> Result<QueryParam, serde_json::Error> {
            serde_json::from_value(v)
        }

        // 1/0 —— Cloudflare 文档里的写法，也是最容易被手写出来的一种
        assert!(
            parse(serde_json::json!({"name": "a.test", "cd": "1"}))
                .unwrap()
                .checking_disabled
        );
        assert!(
            !parse(serde_json::json!({"name": "a.test", "cd": "0"}))
                .unwrap()
                .checking_disabled
        );
        assert!(
            parse(serde_json::json!({"name": "a.test", "do": "1"}))
                .unwrap()
                .dnssec
        );

        // true/false（原写法，必须保持可用）
        assert!(
            parse(serde_json::json!({"name": "a.test", "cd": "true"}))
                .unwrap()
                .checking_disabled
        );
        assert!(
            !parse(serde_json::json!({"name": "a.test", "cd": "false"}))
                .unwrap()
                .checking_disabled
        );

        // 缺省 → false
        assert!(
            !parse(serde_json::json!({"name": "a.test"}))
                .unwrap()
                .checking_disabled
        );
        assert!(
            !parse(serde_json::json!({"name": "a.test", "cd": ""}))
                .unwrap()
                .checking_disabled
        );

        // 真写错了要明确报错，而不是静默当 false
        assert!(
            parse(serde_json::json!({"name": "a.test", "cd": "maybe"})).is_err(),
            "无法解释的布尔值必须报错，不能静默当 false"
        );
    }

    /// 🔐 问题 33：`name` 必须是**可选**的，否则 RFC 8484 的 `?dns=` 形式
    /// 会在参数提取阶段就 400，根本走不到解码分支。
    #[test]
    fn query_param_allows_missing_name_for_dns_form() {
        let p: QueryParam = serde_json::from_value(
            serde_json::json!({"dns": "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"}),
        )
        .expect("?dns= 形式没有 name，也必须能解析");
        assert!(p.name.is_none(), "?dns= 形式本就不带 name");
        assert!(p.dns.is_some(), "dns 参数应被收下");
    }
}
