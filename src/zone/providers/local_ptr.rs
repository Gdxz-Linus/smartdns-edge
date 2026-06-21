use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dns::{DefaultSOA, DnsContext, DnsError, DnsRequest, DnsResponse, Name, RData, RecordType};
use crate::zone::ZoneProvider;
use crate::libdns::proto::rr::rdata::PTR;

pub struct LocalPtrZoneProvider {
    server_names: BTreeSet<Name>,
}

impl LocalPtrZoneProvider {
    pub fn new() -> Self {
        let mut server_names = BTreeSet::new();
        server_names.insert(Name::from_str("smartdns.").unwrap());
        server_names.insert(Name::from_str("whoami.").unwrap());

        Self { server_names }
    }
}

#[async_trait::async_trait]
impl ZoneProvider for LocalPtrZoneProvider {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError> {
        if req.query().query_type() != RecordType::PTR {
            return Ok(None);
        }

        let query = req.query();
        let name: &Name = query.name().borrow();

        // 1. 匹配本机特有域名
        if self.server_names.contains(name) {
            return Ok(Some(DnsResponse::from_rdata(
                query.original().to_owned(),
                RData::PTR(PTR(ctx.cfg().server_name())),
            )));
        }

        // 2. 解析 ARPA 格式，利用纯数学规则拦截私网反向查询
        if let Ok(net) = name.parse_arpa_name() {
            let ip = net.addr();
            
            // 🌟 核心修复：抛弃僵化的网卡 IP 抓取，改用数学法则覆盖全量私网网段！
            // 无论宿主机增加多少虚拟网卡或 VPN，只要落在私有网段内，100% 绝对拦截！
            let is_private_ip = match ip {
                IpAddr::V4(v4) => {
                    v4.is_private() || v4.is_loopback() || v4.is_link_local()
                }
                IpAddr::V6(v6) => {
                    let segments = v6.segments();
                    v6.is_loopback() 
                        || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 链路本地
                        || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 唯一本地地址 (ULA)
                }
            };

            if is_private_ip {
                // 🌟 上帝视角防御：一旦命中私有 IP，强制返回 NXDOMAIN + SOA
                // 这将阻断任何泄露到外网的可能，并迫使客户端缓存这个“否定结果”，避免泛洪
                use crate::libdns::proto::op::ResponseCode;
                let mut res = DnsResponse::empty();
                res.add_query(query.original().to_owned());
                res.set_response_code(ResponseCode::NXDomain);
                
                let soa = crate::dns::Record::from_rdata(
                    crate::dns::Name::root(), 
                    3600, 
                    crate::dns::RData::default_soa()
                );
                res.add_authority(soa);
                
                return Ok(Some(res));
            }
        }

        Ok(None)
    }
}
