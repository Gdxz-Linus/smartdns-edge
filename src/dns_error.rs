use crate::dns::{DefaultSOA as _, DnsResponse};
use crate::libdns::proto::{
    AuthorityData, NoRecords, ProtoError, ProtoErrorKind,
    op::{Query, ResponseCode},
    rr::{Record, rdata::SOA},
};
use std::{io, sync::Arc};
use thiserror::Error;

#[allow(clippy::large_enum_variant)]
/// A query could not be fulfilled
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum LookupError {
    /// A record at the same Name as the query exists, but not of the queried RecordType
    #[error("The name exists, but not for the record requested")]
    NameExists,
    /// There was an error performing the lookup
    #[error("Error performing lookup: {0}")]
    ResponseCode(ResponseCode),
    /// An error got returned by the hickory-proto crate
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(Arc<io::Error>),
}

impl PartialEq for LookupError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ResponseCode(l0), Self::ResponseCode(r0)) => l0 == r0,
            (Self::Proto(l0), Self::Proto(r0)) => l0.to_string() == r0.to_string(),
            (Self::Io(l0), Self::Io(r0)) => l0.to_string() == r0.to_string(),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl LookupError {
    pub fn is_nx_domain(&self) -> bool {
        // "上游明确说这个域名不存在"有两种形态，都要认：
        //   1) 错误本身就是一个 ResponseCode（历史上预留的形态）；
        //   2) hickory 把非 NOERROR 的应答包成 NoRecordsFound —— 真实路径走的就是这个：
        //      NXDOMAIN 的 SOA 可有可无，带 SOA 时会被 as_soa() 赦免成 Ok，不带的就只剩这个错误。
        match self {
            Self::ResponseCode(resc) => resc.eq(&ResponseCode::NXDomain),
            Self::Proto(err) => matches!(
                err.kind(),
                ProtoErrorKind::NoRecordsFound(NoRecords { response_code, .. })
                    if response_code.eq(&ResponseCode::NXDomain)
            ),
            _ => false,
        }
    }

    #[inline]
    pub fn is_soa(&self) -> bool {
        if let Self::Proto(err) = self
            && let ProtoErrorKind::NoRecordsFound(NoRecords { soa: Some(_), .. }) = err.kind() {
                return true;
            }
        false
    }
	
    /// 🔐 第三部分第 1 条（`acl-enable`）：取出"我们主动给出的明确响应码"。
    ///
    /// 例：ACL 拒绝时中间件直接产出 `REFUSED`（"服务器拒绝为你服务"）—— 这与"解析出错"
    /// （超时/上游故障 → SERVFAIL）是两件事，上层必须**原样回给客户端**，
    /// 绝不能被一律抹成 SERVFAIL（否则客户端以为是服务器故障、跑去重试别的服务器，
    /// 而不是认识到"你不被允许查询"）。与 A3 那次修复同一个原则：别把明确的返回码洗掉。
    #[inline]
    pub fn explicit_response_code(&self) -> Option<ResponseCode> {
        match self {
            Self::ResponseCode(code) => Some(*code),
            _ => None,
        }
    }

	// 🌟 核心修复 3：精准探查彻底空包（无数据也无SOA），替代脆弱的字符串匹配
    pub fn is_no_records_found(&self) -> bool {
        if let Self::Proto(err) = self {
            matches!(err.kind(), ProtoErrorKind::NoRecordsFound(_))
        } else {
            false
        }
    }

    /// 🔐 A3（2026-09-17）：把这个"被底层强行包装成错误"的 SOA 还原成响应 ——
    /// **只认两种返回码：NoError（合法的空包/没有该类型记录）与 NXDomain（名字不存在）**。
    ///
    /// 为什么必须卡这一条：底层（`hickory-dns/crates/proto/src/error.rs` 的 `ProtoError::from_response`）
    /// 对 SERVFAIL / REFUSED / FormErr 这类**真正的故障码**也会把响应里的 SOA 一并塞进错误里
    /// （返回码本身也一起带着）。若这里只看"错误里有没有 SOA"就赦免，故障就会被伪装成
    /// "这个名字没有该记录"交给客户端 —— 客户端（尤其苹果设备）会把它当有效否定答案
    /// **按 SOA 的 TTL 缓存住**，上游恢复后仍解析不出来；我们自己也会把它当否定答案存起来。
    /// 实测（`probe_a3_soa.py`）：上游 SERVFAIL+SOA → 改前客户端收到 NOERROR+SOA 且被缓存，
    /// 改后回到 SERVFAIL；上游回 NXDOMAIN+SOA 或 NOERROR+SOA（合法空包）→ 一律不变，仍是 NOERROR+SOA。
    ///
    /// 与用户定调的关系（README 第 33 条）：定调覆盖的是"上游**明确说**不存在 → NOERROR+SOA"
    /// 与"我们**没问到**（超时/网络故障）→ SERVFAIL"两句；"上游**明确回了故障码**"这一格
    /// 定调里没写，这里按"真故障必须保持是故障"把空格补上，不动那两句。
    pub fn as_soa(&self, query: &Query) -> Option<DnsResponse> {
        if let Self::Proto(err) = self {
            // 🌟 核心修复：取出被底层强行当作 Error 包装起来的 SOA 和真实 ResponseCode
            if let ProtoErrorKind::NoRecordsFound(no_records) = err.kind()
                && let Some(record) = &no_records.soa
                && matches!(
                    no_records.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                )
            {
                let mut dns_response = DnsResponse::new_with_max_ttl(query.to_owned(), Vec::new());
                dns_response.add_authority(record.as_ref().to_owned().into_record_of_rdata());
                // 将 NXDomain 等原始状态码原封不动地还给它
                dns_response.set_response_code(no_records.response_code);
                return Some(dns_response);
            }
        }
        None
    }

    pub fn no_records_found(query: Query, ttl: u32) -> LookupError {
        let soa = Record::from_rdata(query.name().to_owned(), ttl, SOA::default_soa());

        let no_records = AuthorityData::new(query.into(), Some(Box::new(soa)), true, true, None);
        let mut no_records: NoRecords = no_records.into();
        no_records.response_code = ResponseCode::ServFail;

        ProtoErrorKind::NoRecordsFound(no_records).into()
    }
}

impl From<ResponseCode> for LookupError {
    fn from(value: ResponseCode) -> Self {
        Self::ResponseCode(value)
    }
}

impl From<ProtoErrorKind> for LookupError {
    fn from(value: ProtoErrorKind) -> Self {
        Self::Proto(value.into())
    }
}
