//! 🔐 P2-1 配套：自签名证书自动生成（对齐 C 版 utils/ssl.c 的 generate_cert_key）。
//!
//! 触发语义（对齐 C 版 smartdns.c 的三态开关 bind-cert-generate）：
//! * `no`   —— 不生成，缺证书按原有报错走；
//! * `yes`  —— 生成（根 CA 已存在则复用）；
//! * `auto`（缺省）—— 证书路径与私钥路径都未配置时才生成；
//! * 用户显式配置了证书路径 —— 绝不覆盖，直接使用。
//!
//! 生成内容（对齐 C 版）：根 CA（10 年，私钥 root-ca.key 落盘复用，避免每次重启换 CA
//! 导致客户端信任库失效）+ 服务器证书（SAN 含 smartdns/主机名/server-name/全部网卡地址，
//! 默认 390 天）。证书文件同时含服务器证书与 CA 证书两条；私钥权限收紧到仅所有者可读。

use std::path::Path;

use crate::log::info;

const DEFAULT_VALIDITY_DAYS: i64 = 390;
const ROOT_CA_VALIDITY_DAYS: i64 = 3650;

/// 组装 SAN 列表：smartdns + 主机名 + server-name + 全部网卡地址（对齐 C 版 generate_cert_san）。
fn collect_san(
    server_name: Option<&str>,
    local_domain: Option<&str>,
    append_san: Option<&str>,
) -> Vec<rcgen::SanType> {
    use std::net::IpAddr;
    let mut sans: Vec<rcgen::SanType> = vec![rcgen::SanType::DnsName(
        rcgen::Ia5String::try_from("smartdns").expect("ascii dns name"),
    )];

    let mut push_dns = |name: &str, sans: &mut Vec<rcgen::SanType>| {
        if let Ok(san) = rcgen::Ia5String::try_from(name)
            .map(rcgen::SanType::DnsName)
        {
            if !sans.contains(&san) {
                sans.push(san);
            }
        }
    };

    if let Some(name) = server_name {
        push_dns(name, &mut sans);
    }
    if let Ok(host) = hostname::get() {
        if let Some(s) = host.to_str() {
            if !s.is_empty() && s != "(none)" {
                push_dns(s, &mut sans);
            }
        }
    }
    // 本地域名（NIS 域名，getdomainname；仅 Unix——C 版同款来源，Windows 无此概念）
    if let Some(dom) = local_domain {
        if !dom.is_empty() && dom != "(none)" {
            push_dns(dom, &mut sans);
        }
    }
    // 用户追加的自定义条目（对齐 C 版 append_san；支持逗号分隔多个）。
    // 值是合法 IP 时写入 IP Address 类型（客户端按 IP 访问时才匹配），否则按 DNS 名。
    if let Some(appended) = append_san {
        for entry in appended.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let san = match entry.parse::<std::net::IpAddr>() {
                Ok(ip) => rcgen::SanType::IpAddress(ip),
                Err(_) => match rcgen::Ia5String::try_from(entry) {
                    Ok(name) => rcgen::SanType::DnsName(name),
                    Err(_) => continue,
                },
            };
            if !sans.contains(&san) {
                sans.push(san);
            }
        }
    }

    // 全部网卡地址（v4/v6）：客户端用 IP 访问时证书也匹配；回环与链路本地无意义
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (_, ip) in interfaces {
            let ip = match ip {
                std::net::IpAddr::V4(v4) => IpAddr::V4(v4),
                std::net::IpAddr::V6(v6) => {
                    let is_link_local = v6.segments()[0] & 0xffc0 == 0xfe80;
                    if v6.is_loopback() || is_link_local {
                        continue;
                    }
                    IpAddr::V6(v6)
                }
            };
            if ip.is_loopback() {
                continue;
            }
            let san = rcgen::SanType::IpAddress(ip);
            if !sans.contains(&san) {
                sans.push(san);
            }
        }
    }

    sans
}


/// 本地域名（NIS 域名，对齐 C 版 getdomainname）。仅 Unix；Windows 返回 None。
#[cfg(unix)]
fn local_nis_domain() -> Option<String> {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::getdomainname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    if s.is_empty() || s == "(none)" {
        None
    } else {
        Some(s)
    }
}

#[cfg(not(unix))]
fn local_nis_domain() -> Option<String> {
    None
}

fn ca_params() -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(vec![]).expect("empty SAN is always valid");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "SmartDNS Edge Root CA");
    params.not_after =
        time::OffsetDateTime::now_utc() + time::Duration::days(ROOT_CA_VALIDITY_DAYS);
    params
}

fn server_params(sans: &[rcgen::SanType], days: i64) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(vec![]).expect("empty SAN is always valid");
    params.subject_alt_names = sans.to_vec();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "SmartDNS Edge");
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    params
}

/// 生成自签证书链。文件已存在时直接返回（幂等，不覆盖用户文件）。
/// `root_key_path` 缺省取私钥同目录的 root-ca.key（对齐 C 版）。
pub fn generate_self_signed_chain(
    cert_path: &Path,
    key_path: &Path,
    root_key_path: Option<&Path>,
    server_name: Option<&str>,
    append_san: Option<&str>,
    validity_days: Option<i64>,
) -> Result<(), String> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    let root_key_path = match root_key_path {
        Some(p) => p.to_path_buf(),
        None => key_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("root-ca.key"),
    };

    // 根 CA：私钥已存在则复用（客户端信任库里的旧 CA 保持有效），否则新生成
    let (ca_kp, ca_cert) = if root_key_path.exists() {
        let pem = std::fs::read_to_string(&root_key_path)
            .map_err(|e| format!("read root CA key {}: {e}", root_key_path.display()))?;
        let kp =
            rcgen::KeyPair::from_pem(&pem).map_err(|e| format!("parse root CA key: {e}"))?;
        let cert = ca_params()
            .self_signed(&kp)
            .map_err(|e| format!("self-sign root CA: {e}"))?;
        (kp, cert)
    } else {
        let kp = rcgen::KeyPair::generate().map_err(|e| format!("generate root CA key: {e}"))?;
        let cert = ca_params()
            .self_signed(&kp)
            .map_err(|e| format!("self-sign root CA: {e}"))?;
        if let Some(parent) = root_key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&root_key_path, kp.serialize_pem())
            .map_err(|e| format!("write root CA key: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&root_key_path, std::fs::Permissions::from_mode(0o400));
        }
        info!("generated root CA key: {}", root_key_path.display());
        (kp, cert)
    };

    let days = validity_days.unwrap_or(DEFAULT_VALIDITY_DAYS);
    let server_kp = rcgen::KeyPair::generate().map_err(|e| format!("generate server key: {e}"))?;
    let local_domain = local_nis_domain();
    let server_cert = server_params(
        &collect_san(server_name, local_domain.as_deref(), append_san),
        days,
    )
        .signed_by(&server_kp, &ca_cert, &ca_kp)
        .map_err(|e| format!("sign server certificate: {e}"))?;

    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // 证书文件：服务器证书 + CA 证书两条（对齐 C 版，客户端可直接导入 CA 段）
    let cert_pem = format!("{}{}", server_cert.pem(), ca_cert.pem());
    std::fs::write(cert_path, cert_pem).map_err(|e| format!("write certificate: {e}"))?;
    std::fs::write(key_path, server_kp.serialize_pem())
        .map_err(|e| format!("write private key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o400));
        let _ = std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o444));
    }

    info!(
        "generated self-signed certificate (valid {} days): cert={}, key={} ; \
         to enable full TLS verification, import the CA section into the client trust store",
        days,
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}


/// 🔐 P2-1：启动早期（降权之前）检查并生成自签证书。
///
/// 为什么必须在降权前：程序启动后会把运行身份切到 nobody（`user nobody` 配置或默认），
/// 生成目录（配置文件所在目录）往往只有 root 可写——降权后生成会 Permission denied
/// （WSL 真机实测暴露）。C 版同样在降权前生成（smartdns.c 的启动序列）。
///
/// 判定：存在 TLS/HTTPS 监听 && generate != Some(false) && (证书路径或私钥路径缺失)
/// → 生成到 conf_dir/smartdns-cert.pem 与 conf_dir/smartdns-key.pem。
/// create_cert_resolver 在路径仍缺失时会使用同一路径（两边对齐）。
pub fn ensure_cert_for_binds(
    cfg: &crate::dns_conf::RuntimeConfig,
    target_uid: Option<u32>,
    target_gid: Option<u32>,
) {
    let generate = cfg.bind_cert_generate;
    if generate == Some(false) {
        return;
    }
    let has_tls_bind = cfg.binds().iter().any(|b| {
        matches!(
            b,
            crate::config::BindAddrConfig::Tls(_)
                | crate::config::BindAddrConfig::Https(_)
                | crate::config::BindAddrConfig::H3(_)
        )
    });
    if !has_tls_bind {
        return;
    }
    let need_generate = cfg.binds().iter().any(|b| {
        let ssl = match b {
            crate::config::BindAddrConfig::Tls(x) => Some(&x.ssl_config),
            crate::config::BindAddrConfig::Https(x) => Some(&x.ssl_config),
            crate::config::BindAddrConfig::H3(x) => Some(&x.ssl_config),
            _ => None,
        };
        match ssl {
            Some(ssl) => ssl.certificate.is_none() || ssl.certificate_key.is_none(),
            None => false,
        }
    });
    if !need_generate {
        return;
    }

    let cert_dir = cfg
        .conf_dir()
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let cert_path = cert_dir.join("smartdns-cert.pem");
    let key_path = cert_dir.join("smartdns-key.pem");
    // 已存在（上次启动生成过）就不重复
    if cert_path.exists() && key_path.exists() {
        return;
    }

    let server_name = {
        let n = cfg.server_name();
        let s = n.to_string();
        let s = s.trim_end_matches('.').to_string();
        if s.is_empty() { None } else { Some(s) }
    };

    let validity_days = cfg.bind_cert_validity_days.map(|d| d as i64);
    let append_san = if cfg.bind_cert_san.is_empty() {
        None
    } else {
        Some(cfg.bind_cert_san.join(","))
    };
    let root_key = cfg.bind_cert_root_key_file.as_deref();
    if let Err(err) = generate_self_signed_chain(
        &cert_path,
        &key_path,
        root_key,
        server_name.as_deref(),
        append_san.as_deref(),
        validity_days,
    )
    {
        crate::log::error!("failed to generate a self-signed certificate: {err}");
        return;
    }

    // 🔐 对齐 C 版（smartdns.c:459-467 的 chown）：私钥收紧到 0400 后，运行身份（降权目标）
    // 必须能读——否则降权后监听加载私钥 Permission denied（WSL 真机实测暴露）。
    // 生成文件所有权移交给降权目标用户。
    if let (Some(uid), Some(gid)) = (target_uid, target_gid) {
        #[cfg(unix)]
        {
            for path in [&cert_path, &key_path] {
                let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
            }
        }
        let _ = (target_uid, target_gid);
    }
}