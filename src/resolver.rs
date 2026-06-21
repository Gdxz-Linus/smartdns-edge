use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::str::FromStr;

use clap::Parser;
use console::Style;
use console::style;

use crate::libdns::proto::{
    op::Message,
    rr::{DNSClass, DNSClass as QueryClass, Name as Domain, Record, RecordType},
    xfer::Protocol as DnsOverProtocol,
};

use crate::dns_client::{DnsClient, GenericResolver, LookupOptions};
use crate::dns_url::DnsUrl;

impl ResolveCommand {
    pub fn execute(self) {
        let is_json = self.json;
        let is_short = self.short;
        
        let proto = self.proto();
        // 如果没写 -s，就必须老老实实去读网卡的系统 DNS！
        let mut server = match self.global_server() {
            Some(s) => DnsUrl::from_str(s).ok(),
            None => {
                if proto.is_some() {
                    // 如果用户没指定 -s，但强制指定了特殊协议 (如 -T 走 TCP)
                    // 我们直接去网卡里抠出第一个默认 DNS 的 IP，然后给它套上协议！
                    crate::libdns::resolver::system_conf::read_system_conf()
                        .ok()
                        // 🌟 修复报错：适配最新版本 hickory-resolver 的 API 变更，直接读取 ns.ip
                        .and_then(|(conf, _)| conf.name_servers.first().map(|ns| DnsUrl::from(ns.ip)))
                } else {
                    // 什么都没指定，返回 None。
                    // 底层会自动调用我们前几天写好的 BootstrapResolver，完美联动红字高亮报警！
                    None
                }
            }
        };
        if let Some(proto) = proto {
            if let Some(s) = server.as_mut() {
                s.set_proto(proto)
            }
        }
        let domains = self.domains();
        // 🌟 核心修复 1：如果解析出来的类型是空的，强制兜底注入 A 记录！
        let mut query_types = self.q_type().to_vec();
        if query_types.is_empty() {
            query_types.push(RecordType::A);
        }

        let palette = Colours::pretty();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let dns_client = if let Some(server) = server {
                    // 如果是 JSON 或 Short 模式，静默表头，保持纯净输出
                    if !is_json && !is_short {
                        println!(
                            "{} {}",
                            palette.authority.apply_to("SERVER:"),
                            palette.authority.apply_to(&server)
                        );
                    }
                    DnsClient::builder().add_server(server).build().await
                } else {
                    DnsClient::builder().build().await
                };

                for domain in domains {
                    for query_type in &query_types {
                        let options = LookupOptions {
                            record_type: *query_type,
                            ..Default::default()
                        };

                        match dns_client.lookup(domain.clone(), options).await {
                            Ok(res) => {
                                // 🌟 核心补充：根据参数分发输出格式
                                if is_json {
                                    print_json(&res, None);
                                } else if is_short {
                                    print_short(&res);
                                } else {
                                    // 🌟 修复 2：收到截断包，不再装死，而是像顶级工具一样提示用户切换 TCP
                                    if res.truncated() {
                                        println!("{}\tTRUNCATED (Packet too large, please use '-T' to query via TCP)", palette.qname.apply_to(&domain));
                                    } else if res.answers().is_empty() && res.authorities().is_empty() && res.additionals().is_empty() {
                                        println!("{}\tNO DATA", palette.qname.apply_to(&domain));
                                    } else {
                                        print(&res, &palette);
                                    }
                                }
                            }
                            Err(err) => {
                                let query = crate::libdns::proto::op::Query::query(domain.clone(), *query_type);
                                
                                if is_json {
                                    if let Some(soa_res) = err.as_soa(&query) {
                                        print_json(&soa_res, Some(&err.to_string()));
                                    } else {
                                        let msg = Message::query();
                                        print_json(&msg, Some(&err.to_string()));
                                    }
                                } else if is_short {
                                    // Short 模式下，报错时行为对标 dig +short，静默不输出任何内容
                                } else {
                                    // 🌟 修复 3：如果查外网遇到了头铁的上游发巨型包导致 10040 崩溃，优雅提示！
                                    if err.to_string().contains("10040") || err.to_string().contains("WSAEMSGSIZE") {
                                        println!("{}\tUDP PACKET TOO LARGE (OS error 10040, please use '-T' to query via TCP)", palette.qname.apply_to(&domain));
                                    } else if let Some(soa_res) = err.as_soa(&query) {
                                        print(&soa_res, &palette);
                                    } else if err.is_nx_domain() {
                                        println!("{}\tNXDOMAIN", palette.qname.apply_to(&domain));
                                    } else if err.to_string().contains("no records found") {
                                        println!("{}\tNO DATA", palette.qname.apply_to(&domain));
                                    } else {
                                        println!("Error: {err}");
                                    }
                                }
                            }
                        }
                    }
                }
            });
    }
}

#[derive(Parser, Debug, Default, PartialEq, Eq)]
#[command(after_help=include_str!("../RESOLVE_EXAMPLES.txt"))]
pub struct ResolveCommand {
    #[command(flatten)]
    proto: ProtocolType,

    /// Output the DNS response in JSON format
    #[arg(short = 'J', long)]
    json: bool,

    /// Short output format, print only the record data (e.g. IP address)
    #[arg(short = '1', long)]
    short: bool,

    /// is in the Domain Name System
    #[arg(value_name = "domain", num_args = 1, value_parser = Variant::parse::<Domain>)]
    domains: Vec<Domain>,

    /// is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...)
    #[arg(value_name = "q-type", num_args = 1, value_parser = Variant::parse::<RecordType>)]
    record_types: Vec<RecordType>,

    /// is one of (in,hs,ch,...)
    #[arg(value_name = "q-class", value_parser = Variant::parse::<DNSClass>)]
    q_class: Option<DNSClass>,

    /// Specify the DNS server to query (e.g. -s 119.29.29.29)
    #[arg(short = 's', long = "server", value_name = "SERVER")]
    global_server: Option<String>,
}

#[derive(Parser, Debug, Default, PartialEq, Eq)]
struct ProtocolType {
    /// Use the DNS protocol over UDP
    #[arg(short = 'U', long, group = "proto")]
    udp: bool,

    /// Use the DNS protocol over TCP
    #[arg(short = 'T', long, group = "proto")]
    tcp: bool,

    /// Use the DNS-over-TLS protocol
    #[arg(short = 'S', long, group = "proto")]
    tls: bool,

    /// Use the DNS-over-QUIC protocol
    #[arg(short = 'Q', long, group = "proto")]
    quic: bool,

    /// Use the DNS-over-HTTPS protocol
    #[arg(short = 'H', long, group = "proto")]
    https: bool,

    /// Use the DNS-over-HTTPS/3 protocol
    #[arg(long, group = "proto")]
    h3: bool,
}

impl ResolveCommand {
    pub fn parse() -> Self {
        match Parser::try_parse() {
            Ok(cli) => cli,
            Err(e) => {
                if let Ok(resolve_command) = ResolveCommand::try_parse() {
                    return resolve_command;
                }
                e.exit()
            }
        }
    }

    pub fn try_parse_from<I, T>(itr: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        use DnsOverProtocol::*;
        let mut proto = None;
        let mut q_types = Vec::new();
        let mut q_class = None;
        
        // 🌟 修复暗坑 1：将单变量改为数组，容量无限，绝不覆盖！
        let mut domains = Vec::new(); 
        let mut global_server = None;
        
        // 🌟 修复暗坑 2：让自定义解析器也认识这俩参数
        let mut is_json = false;
        let mut is_short = false;

        let mut iter = itr.into_iter().skip(1).map(|a| a.into().into_string().expect("Failed to convert OsString to String"));

        while let Some(arg) = iter.next() {
            if arg == "resolve" {
                continue;
            }

            if arg == "-s" || arg == "--server" {
                if let Some(server_ip) = iter.next() {
                    global_server = Some(server_ip);
                    continue;
                } else {
                    return Err(format!("Missing server address after {}", arg));
                }
            }

            if arg.starts_with('-') && proto.is_none() {
                match arg.as_str() {
                    "-U" | "--udp" => { proto = Some(Udp); continue; }
                    "-T" | "--tcp" => { proto = Some(Tcp); continue; }
                    "-S" | "--tls" => { proto = Some(Tls); continue; }
                    "-Q" | "--quic" => { proto = Some(Quic); continue; }
                    "-H" | "--https" => { proto = Some(Https); continue; }
                    "-H3" | "--h3" => { proto = Some(H3); continue; }
                    
                    // 🌟 拦截短格式与 JSON 参数
                    "-J" | "--json" => { is_json = true; continue; }
                    "-1" | "--short" => { is_short = true; continue; }
                    _ => (),
                }
            }

            if let Some(s) = arg.strip_prefix('@') {
                global_server = Some(s.to_string());
                continue;
            }

            if arg.contains('+') {
                let record_types = arg
                    .split('+')
                    .map(|p| p.to_uppercase())
                    .flat_map(|s| RecordType::from_str(&s))
                    .collect::<Vec<RecordType>>();
                if !record_types.is_empty() {
                    q_types.extend(record_types);
                    continue;
                }
            }

            if let Ok(v) = Variant::from_str(&arg) {
                match v {
                    Variant::Domain(d) => {
                        // 🌟 核心修复：来多少个域名就存多少个，绝不覆盖！
                        domains.push(d); 
                    }
                    Variant::RecordType(t) => {
                        q_types.push(t);
                    }
                    Variant::DNSClass(c) => {
                        q_class = Some(c);
                    }
                    Variant::Server(s) => {
                        global_server = Some(s);
                    }
                }
                continue;
            }
            return Err(format!("Invalid argument {arg}"));
        }

        // 如果连一个域名都没输入，报错
        if domains.is_empty() {
            return Err("domain is required".to_string());
        }

        if q_types.is_empty() {
            q_types.push(RecordType::A);
        }

        Ok(Self {
            proto: ProtocolType {
                udp: matches!(proto, Some(Udp)),
                tcp: matches!(proto, Some(Tcp)),
                tls: matches!(proto, Some(Tls)),
                quic: matches!(proto, Some(Quic)),
                https: matches!(proto, Some(Https)),
                h3: matches!(proto, Some(H3)),
            },
            global_server,
            domains,
            record_types: q_types,
            q_class,
            json: is_json,
            short: is_short,
        })
    }

    pub fn is_resolve_cli() -> bool {
        std::env::args()
            .next()
            .as_deref()
            .map(Path::new)
            .and_then(|s| s.file_stem())
            .and_then(|s| s.to_str())
            .map(|s| matches!(s, "dig" | "nslookup" | "resolve"))
            .unwrap_or_default()
    }

    pub fn proto(&self) -> Option<DnsOverProtocol> {
        use DnsOverProtocol::*;
        let proto = &self.proto;
        if proto.udp {
            Some(Udp)
        } else if proto.tcp {
            Some(Tcp)
        } else if proto.tls {
            Some(Tls)
        } else if proto.quic {
            Some(Quic)
        } else if proto.https {
            Some(Https)
        } else if proto.h3 {
            Some(H3)
        } else {
            None
        }
    }

    pub fn global_server(&self) -> Option<&str> {
        self.global_server.as_deref()
    }

    pub fn domains(&self) -> &[Domain] {
        &self.domains
    }

    pub fn q_type(&self) -> &[RecordType] {
        &self.record_types
    }

    pub fn q_class(&self) -> QueryClass {
        self.q_class.unwrap_or(QueryClass::IN)
    }
}

enum Variant {
    Domain(Domain),
    RecordType(RecordType),
    DNSClass(DNSClass),
    Server(String),
}

impl Variant {
    fn parse<T: TryFrom<Self, Error = String>>(s: &str) -> Result<T, String> {
        Self::from_str(s).and_then(|s| s.try_into())
    }
}

impl TryFrom<Variant> for Domain {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::Domain(domain) => Ok(domain),
            _ => Err("Expected a domain".to_string()),
        }
    }
}

impl TryFrom<Variant> for RecordType {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::RecordType(record_type) => Ok(record_type),
            _ => Err("Expected a record type".to_string()),
        }
    }
}

impl TryFrom<Variant> for DNSClass {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::DNSClass(dns_class) => Ok(dns_class),
            _ => Err("Expected a DNS class".to_string()),
        }
    }
}

impl TryFrom<Variant> for String {
    type Error = String;
    fn try_from(s: Variant) -> Result<Self, Self::Error> {
        match s {
            Variant::Server(server) => Ok(server),
            _ => Err("Expected a server".to_string()),
        }
    }
}

impl FromStr for Variant {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix('@') {
            return Ok(Self::Server(s.to_string()));
        }

        let upper = s.to_uppercase();

        if let Ok(record_type) = RecordType::from_str(&upper) {
            return Ok(Self::RecordType(record_type));
        }
        if let Ok(dns_class) = DNSClass::from_str(&upper) {
            return Ok(Self::DNSClass(dns_class));
        }

        if let Ok(name) = Domain::from_str(s) {
            return Ok(Self::Domain(name));
        }

        Err(format!("Invalid query variant: {s}"))
    }
}

// =========================================================================
// 🌟 核心重构：微软 Resolve-DnsName 同款专业级动态排版引擎 (防物理截断版)
// 动态限制 Name 切片长度保留视觉空格，并动态探测终端宽度控制 Data 换行！
// =========================================================================
fn print(message: &Message, palette: &Colours) {
    let mut rows = Vec::new();

    let mut process_records = |records: &[Record], sec: &str| {
        for r in records {
            let name_str = r.name().to_string();
            let type_str = r.record_type().to_string();
            let ttl_str = r.ttl().to_string();
            let sec_str = sec.to_string();
            let data_str = r.data().to_string();
            rows.push((r.record_type(), name_str, type_str, ttl_str, sec_str, data_str));
        }
    };

    process_records(message.answers(), "Answer");
    process_records(message.authorities(), "Authority");
    process_records(message.additionals(), "Additional");

    if rows.is_empty() { return; }

    // 🌟 列宽与视觉边界控制
    const W_NAME: usize = 40;        // Name 列总物理宽度
    const MAX_NAME_LEN: usize = 37;  // Name 切片最大长度（强制预留至少 3 个视觉空格！）
    const W_TYPE: usize = 10;        // Type 列宽度
    const W_TTL: usize = 8;          // TTL 列宽度
    const W_SEC: usize = 12;         // Section 列宽度
    
    // 🌟 核心修复：动态获取终端物理宽度，精准计算 Data 列的最大安全宽度
    // 彻底杜绝由于终端硬回车导致的“孤儿字符”错位现象！
    let term_cols = console::Term::stdout().size().1 as usize;
    let prefix_len = W_NAME + W_TYPE + W_TTL + W_SEC;
    let max_data_len = if term_cols > prefix_len + 5 {
        term_cols - prefix_len - 2 // 留 2 个字符的安全边距
    } else {
        45 // 如果终端被缩得极窄，使用 45 作为兜底宽度
    };

    let header_style = Style::new().green().bold();
    
    // 1. 打印表头
    println!(
        "{}{}{}{}{}",
        header_style.apply_to(format!("{:<w$}", "Name", w = W_NAME)),
        header_style.apply_to(format!("{:<w$}", "Type", w = W_TYPE)),
        header_style.apply_to(format!("{:<w$}", "TTL", w = W_TTL)),
        header_style.apply_to(format!("{:<w$}", "Section", w = W_SEC)),
        header_style.apply_to("Data")
    );

    // 2. 打印分隔线
    println!(
        "{}{}{}{}{}",
        header_style.apply_to(format!("{:<w$}", "----", w = W_NAME)),
        header_style.apply_to(format!("{:<w$}", "----", w = W_TYPE)),
        header_style.apply_to(format!("{:<w$}", "---", w = W_TTL)),
        header_style.apply_to(format!("{:<w$}", "-------", w = W_SEC)),
        header_style.apply_to("----")
    );

    // 辅助闭包：按字符精准切片（防中文或 Emoji 截断导致乱码）
    let chunk_string = |s: &str, max_len: usize| -> Vec<String> {
        let mut chunks = Vec::new();
        let mut chars = s.chars().peekable();
        while chars.peek().is_some() {
            chunks.push(chars.by_ref().take(max_len).collect());
        }
        if chunks.is_empty() {
            chunks.push(String::new());
        }
        chunks
    };

    // 3. 打印数据行
    for (r_type, name, typ, ttl, sec, data) in rows {
        // 严格按照对应的限制长度进行切片
        let name_chunks = chunk_string(&name, MAX_NAME_LEN);
        let data_chunks = chunk_string(&data, max_data_len);
        
        let max_lines = std::cmp::max(name_chunks.len(), data_chunks.len());

        for i in 0..max_lines {
            let n_chunk = name_chunks.get(i).map(|s| s.as_str()).unwrap_or("");
            let d_chunk = data_chunks.get(i).map(|s| s.as_str()).unwrap_or("");

            // 无论 n_chunk 是多长(最大37)，都在右侧用空格填充到严格的 40 字符宽
            let padded_name = format!("{:<w$}", n_chunk, w = W_NAME);

            if i == 0 {
                // 第一行：打印所有完整列信息
                let padded_type = format!("{:<w$}", typ, w = W_TYPE);
                let padded_ttl = format!("{:<w$}", ttl, w = W_TTL);
                let padded_sec = format!("{:<w$}", sec, w = W_SEC);

                let type_styled = palette
                    .record_types
                    .get(&r_type)
                    .unwrap_or(&palette.unknown)
                    .clone()
                    .apply_to(padded_type);

                println!(
                    "{}{}{}{}{}",
                    palette.qname.apply_to(padded_name),
                    type_styled,
                    style(padded_ttl).blue(),
                    style(padded_sec).cyan(),
                    d_chunk
                );
            } else {
                // 后续换行部分：Type、TTL、Section 列全部用隐形空格垫片填满！
                let empty_middle = " ".repeat(W_TYPE + W_TTL + W_SEC);
                println!(
                    "{}{}{}",
                    palette.qname.apply_to(padded_name),
                    empty_middle,
                    d_chunk
                );
            }
        }
    }
}

#[derive(Default)]
struct Colours {
    pub qname: Style,

    pub answer: Style,
    pub authority: Style,
    pub additional: Style,

    pub record_types: HashMap<RecordType, Style>,
    pub unknown: Style,
}

impl Colours {
    pub fn pretty() -> Self {
        use RecordType::*;
        let mut record_types = HashMap::new();
        record_types.insert(A, Style::new().green());
        record_types.insert(AAAA, Style::new().green());
        record_types.insert(CAA, Style::new().red());
        record_types.insert(CNAME, Style::new().yellow());
        record_types.insert(MX, Style::new().cyan());
        record_types.insert(NAPTR, Style::new().green());
        record_types.insert(NS, Style::new().red());
        record_types.insert(OPENPGPKEY, Style::new().cyan());
        record_types.insert(OPT, Style::new().magenta());
        record_types.insert(PTR, Style::new().red());
        record_types.insert(SSHFP, Style::new().cyan());
        record_types.insert(SOA, Style::new().magenta());
        record_types.insert(SRV, Style::new().cyan());
        record_types.insert(TLSA, Style::new().yellow());
        record_types.insert(TXT, Style::new().yellow());

        Self {
            qname: Style::new().blue().bold(),

            answer: Style::default(),
            authority: Style::new().cyan(),
            additional: Style::new().green(),

            record_types,
            unknown: Style::new().white().on_red(),
        }
    }

    pub fn plain() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse() {
        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a+aaaa"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a", "aaaa", "TXT"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA", "TXT"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a", "aaaa", "in"]).unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                q_class: Some(DNSClass::IN),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "example.com", "a", "aaaa", "in", "@1.1.1.1"])
                .unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                global_server: Some("1.1.1.1".to_string()),
                q_class: Some(DNSClass::IN),
                ..Default::default()
            }
        );

        assert_eq!(
            ResolveCommand::try_parse_from(["dig", "@1.1.1.1", "example.com", "a", "aaaa", "in"])
                .unwrap(),
            ResolveCommand {
                domains: vec!["example.com".parse().unwrap()],
                record_types: ["A", "AAAA"]
                    .iter()
                    .map(|s| s.parse())
                    .collect::<Result<Vec<RecordType>, _>>()
                    .unwrap(),
                global_server: Some("1.1.1.1".to_string()),
                q_class: Some(DNSClass::IN),
                ..Default::default()
            }
        );
    }
}

// =========================================================================
// 🌟 核心补充：短格式与 JSON 格式的输出引擎
// =========================================================================

fn print_short(message: &Message) {
    // 行为完美对标 dig +short，只输出核心数据（如 IP）
    for r in message.answers() {
        println!("{}", r.data());
    }
}

fn print_json(message: &Message, error: Option<&str>) {
    // 🌟 核心修复 4：严谨的系统级 JSON 字符安全逃逸机制！
    // 彻底防御上游通过恶意 TXT 记录下发带换行符(\n)、制表符(\t)或控制符的载荷，
    // 杜绝 JSON 结构断裂导致的下游解析器崩溃注入漏洞。
    let escape_json = |s: &str| -> String {
        let mut escaped = String::with_capacity(s.len() + 4);
        for c in s.chars() {
            match c {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                // 将看不见的系统控制字符安全转化为 Unicode 码点
                c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
                c => escaped.push(c),
            }
        }
        escaped
    };

    let mut json = String::new();
    json.push('{');
    
    if let Some(e) = error {
        json.push_str(&format!(r#""error":"{}","#, escape_json(e)));
    }
    
    json.push_str(&format!(r#""status":"{}","#, message.response_code()));
    json.push_str(&format!(r#""tc":{},"#, message.truncated()));
    
    // 零依赖宏，手动高效组装 JSON 数组
    macro_rules! format_section {
        ($records:expr) => {{
            let mut vec = Vec::new();
            for r in $records {
                vec.push(format!(
                    r#"{{"name":"{}","type":"{}","ttl":{},"class":"{}","data":"{}"}}"#,
                    escape_json(&r.name().to_string()),
                    r.record_type(),
                    r.ttl(),
                    r.dns_class(),
                    escape_json(&r.data().to_string())
                ));
            }
            vec.join(",")
        }}
    }
    
    json.push_str(&format!(r#""answers":[{}],"#, format_section!(message.answers())));
    json.push_str(&format!(r#""authorities":[{}],"#, format_section!(message.authorities())));
    json.push_str(&format!(r#""additionals":[{}]"#, format_section!(message.additionals())));
    
    json.push('}');
    println!("{}", json);
}