use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
pub type Certificate = CertificateDer<'static>;
pub type PrivateKey = PrivateKeyDer<'static>;

pub use rustls::server::ResolvesServerCert;
use rustls::{ClientConfig, RootCertStore, ServerConfig, sign::CertifiedKey};

use ring::digest::{SHA256, digest};

use crate::log::{info, warn};

#[derive(Clone)]
pub struct TlsClientConfigBundle {
    pub normal: Arc<ClientConfig>,
    pub sni_off: Arc<ClientConfig>,
    pub verify_off: Arc<ClientConfig>,
    /// 建 normal 时用的那份根证书库（造 `-spki-pin` 的配置时要拿它重建证书链校验器）
    roots: Arc<RootCertStore>,
}

impl TlsClientConfigBundle {
    pub fn new(ca_path: Option<PathBuf>, ca_file: Option<PathBuf>) -> Self {
        let roots = Arc::new(Self::create_root_store(
            [ca_path, ca_file]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .as_slice(),
        ));
        let config = Self::create_tls_client_config(roots.clone());

        let sni_off = {
            let mut sni_off = config.clone();
            sni_off.enable_sni = false;
            sni_off
        };

        let verify_off = {
            let mut verify_off = config.clone();
            verify_off
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification));

            verify_off
        };

        Self {
            normal: Arc::new(config),
            sni_off: Arc::new(sni_off),
            verify_off: Arc::new(verify_off),
            roots,
        }
    }

    /// 🔐 给"配了 `-spki-pin` 的上游"造一份客户端 TLS 配置。
    ///
    /// 语义严格对齐 C 版 `src/dns_client/client_tls.c`（`_dns_client_tls_verify`）：
    /// · `-spki-pin` 是**额外的**确认条件，**不替代**证书链校验 —— 想跳过链校验仍然要显式写 `-k`；
    /// · 两者叠加就是"纯 pin"模式（自签证书 + pin，链校验关掉、只认公钥）；
    /// · pin 对不上 → 这次连接直接拒绝（握手报错），日志里写清"实际公钥是多少"，方便用户核对。
    pub fn with_spki_pin(
        &self,
        pin: [u8; 32],
        ssl_verify: bool,
        sni_off: bool,
    ) -> Result<Arc<ClientConfig>, rustls::Error> {
        let base = if !ssl_verify {
            &self.verify_off
        } else if sni_off {
            &self.sni_off
        } else {
            &self.normal
        };

        // 链校验照原有规矩来：用户没关（ssl_verify）就用根证书库真验；关了就用"什么都不验"
        let inner: Arc<dyn rustls::client::danger::ServerCertVerifier> = if ssl_verify {
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                self.roots.clone(),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .map_err(|err| rustls::Error::General(format!("failed to build the certificate chain verifier: {err}")))?
        } else {
            Arc::new(NoCertificateVerification)
        };

        let mut config = base.as_ref().clone();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SpkiPinVerifier { inner, pin }));

        Ok(Arc::new(config))
    }

    fn create_root_store(paths: &[PathBuf]) -> RootCertStore {
        let mut root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let certs = {
            let certs1 = rustls_native_certs::load_native_certs().certs;

            let certs2 = paths
                .iter()
                .filter_map(|path| match load_certs_from_path(path.as_path()) {
                    Ok(certs) => Some(certs),
                    Err(err) => {
                        warn!("load certs from path failed.{}", err);
                        None
                    }
                })
                .flatten();

            certs1.into_iter().chain(certs2)
        };

        for cert in certs {
            root_store.add(cert).unwrap_or_else(|err| {
                warn!("load certs from path failed.{}", err);
            })
        }

        root_store
    }

    fn create_tls_client_config(roots: Arc<RootCertStore>) -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
}

#[derive(Debug)]
pub(super) struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
            ED448,
        ]
    }
}

/// 🔐 第三部分第 2 条（上游 `-spki-pin`）：在原有校验之上，再核对"对端证书公钥"是否符合配置的 pin。
///
/// 判据与 C 版 `src/dns_client/client_tls.c` 完全一致：把证书里的 **SPKI（SubjectPublicKeyInfo）**
/// 整段 DER 拿出来做 SHA-256，与用户配的 32 字节比。这就是业界说的 "SPKI pin"（HPKP 那一套），
/// 用户用 `openssl` 也能自己算出来核对：
/// ```text
/// openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
///   | openssl dgst -sha256 -binary | openssl enc -base64
/// ```
#[derive(Debug)]
pub(super) struct SpkiPinVerifier {
    /// 原有的校验器（证书链 + 主机名；用户写了 `-k` 时就是"什么都不验"）
    inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    /// 用户配的 pin：SPKI 的 SHA-256，32 字节
    pin: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // ① 先按原有规矩验（这一步保证"配了 pin"不等于"放开了证书链校验"）
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // ② 再核对公钥
        let spki = extract_spki(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("cannot read the peer certificate public key (SPKI); spki-pin cannot be checked".to_string())
        })?;

        let hash = digest(&SHA256, &spki);
        if hash.as_ref() != self.pin {
            return Err(rustls::Error::General(format!(
                "peer certificate public key does not match spki-pin (actual pin: {}); the connection was rejected",
                write_sha256_hex(hash.as_ref())
            )));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// 把 SPKI 的 SHA-256 写成 C 版日志里那种冒号分隔的十六进制（只为日志好核对）
fn write_sha256_hex(digest: &[u8]) -> String {
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 🔐 从证书 DER 里取出 **SPKI（SubjectPublicKeyInfo）那一段的完整 TLV**。
///
/// 证书结构（RFC 5280 §4.1）：
/// ```text
/// Certificate       ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// tbsCertificate    ::= SEQUENCE { [0] version（可选）, serialNumber, signature, issuer,
///                                  validity, subject, subjectPublicKeyInfo, ... }
/// ```
/// 所以进 tbs 之后**按顺序数第 7 个元素**就是 SPKI（版本字段在时也占一个位置，编号不受影响）。
///
/// 取的是"连 TLV 头一起"的整段字节 —— 这正是 OpenSSL `i2d_X509_PUBKEY()` 的产物，
/// 也是 C 版拿去算 SHA-256 的东西，两边的 pin 才能对上。
fn extract_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    /// 读一个 TLV：返回 (标签, 内容, 整个 TLV 的长度)
    fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
        let tag = *buf.first()?;
        let first_len = *buf.get(1)?;

        let (len, header) = if first_len < 0x80 {
            (first_len as usize, 2)
        } else {
            let n = (first_len & 0x7F) as usize;
            if n == 0 || n > 4 || buf.len() < 2 + n {
                return None;
            }

            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | buf[2 + i] as usize;
            }
            (len, 2 + n)
        };

        let end = header.checked_add(len)?;
        Some((tag, buf.get(header..end)?, end))
    }

    const SEQUENCE: u8 = 0x30;

    let (tag, body, _) = read_tlv(cert_der)?;
    if tag != SEQUENCE {
        return None;
    }

    let (tag, tbs, _) = read_tlv(body)?;
    if tag != SEQUENCE {
        return None;
    }

    let mut rest = tbs;

    // 第一个字段可能是 [0] version（v2/v3 证书都有）：先把它跳掉，
    // 这样后面的位置就固定了 —— serialNumber, signature, issuer, validity, subject,
    // subjectPublicKeyInfo（= 第 6 个）。
    if let Some((tag, _, total)) = read_tlv(rest) {
        if tag == 0xA0 {
            rest = &rest[total..];
        }
    }

    for index in 1..=6 {
        let (tag, _, total) = read_tlv(rest)?;

        if index == 6 {
            return (tag == SEQUENCE).then(|| rest[..total].to_vec());
        }

        rest = &rest[total..];
    }

    None
}

/// Load certificates from specific directory or file.
pub fn load_certs_from_path(path: &Path) -> Result<Vec<Certificate>, io::Error> {
    if path.is_dir() {
        let mut certs = vec![];
        for entry in path.read_dir()? {
            let path = entry?.path();
            if path.is_file() {
                certs.extend(load_pem_certs(path.as_path())?);
            }
        }
        Ok(certs)
    } else {
        load_pem_certs(path)
    }
}

fn load_pem_certs(path: &Path) -> Result<Vec<Certificate>, io::Error> {
    let mut file = BufReader::new(File::open(path)?);

    match rustls_pemfile::certs(&mut file).collect() {
        Ok(certs) => Ok(certs),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Could not load PEM file {err} {path:?}"),
        )),
    }
}

#[cfg(feature = "dns-over-tls")]
pub fn tls_server_config(
    protocol: &[u8],
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Result<ServerConfig, io::Error> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(server_cert_resolver);

    config.alpn_protocols = vec![protocol.to_vec()];
    Ok(config)
}

#[derive(Debug)]
pub struct TlsServerCertResolver {
    path: PathBuf,
    private_key: PathBuf,
    certified_key: RwLock<Arc<CertifiedKey>>,
}

impl TlsServerCertResolver {
    pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self, crate::Error> {
        let certified_key = Self::load(cert_path, key_path)?;
        Ok(TlsServerCertResolver {
            path: cert_path.to_path_buf(),
            private_key: key_path.to_path_buf(),
            certified_key: RwLock::new(Arc::new(certified_key)),
        })
    }

    pub fn load(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey, crate::Error> {
        use crate::Error;
        use rustls::crypto::ring::default_provider;

        let cert_chain = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| {
                Error::LoadCertificateFailed(
                    cert_path.to_path_buf(),
                    format!(
                        "failed to read cert chain from {}: {e}",
                        cert_path.display()
                    ),
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                Error::LoadCertificateFailed(
                    cert_path.to_path_buf(),
                    format!(
                        "failed to parse cert chain from {}: {e}",
                        cert_path.display()
                    ),
                )
            })?;

        let key_extension = key_path.extension();

        fn from_pem_file(key_path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
            let key_path = &key_path;
            info!("loading TLS PKCS8 key from PEM: {}", key_path.display());
            PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("failed to read key from {}: {e}", key_path.display()),
                )
            })
        }

        fn try_from(key_path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
            let key_path = &key_path;
            info!("loading TLS PKCS8 key from DER: {}", key_path.display());

            let buf = fs::read(key_path).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("error reading key from file: {e}"),
                )
            })?;

            PrivateKeyDer::try_from(buf).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("error parsing key DER: {e}"),
                )
            })
        }

        let key = if key_extension.is_some_and(|ext| ext == "pem") {
            from_pem_file(key_path)?
        } else if key_extension.is_some_and(|ext| ext == "der") {
            try_from(key_path)?
        } else {
            from_pem_file(key_path).or_else(|_| try_from(key_path)).map_err(|_| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!(
                        "unsupported private key file format (expected `.pem` or `.der` `.key` extension): {}",
                        key_path.display()
                    ),
                )
            })?
        };

        let certified_key =
            CertifiedKey::from_der(cert_chain, key, &default_provider()).map_err(|err| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("failed to read certificate and keys: {err:?}"),
                )
            })?;

        Ok(certified_key)
    }
}

impl ResolvesServerCert for TlsServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.certified_key.read().ok().as_deref().cloned()
    }
}

#[cfg(test)]
mod spki_pin_tests {
    use super::extract_spki;

    /// 按 DER 规矩拼一个 TLV（这里只用短长度形式，够测了）
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            out.push(0x81);
            out.push(content.len() as u8);
        }
        out.extend_from_slice(content);
        out
    }

    /// 造一个"结构上完全合规"的最小证书：tbs 里七个字段，第 7 个就是 SPKI
    fn fake_cert(spki: &[u8]) -> Vec<u8> {
        let tbs = tlv(
            0x30,
            &[
                tlv(0xA0, &tlv(0x02, &[0x02])), // [0] version（可选字段，占了第一个位置）
                tlv(0x02, &[0x01]),             // serialNumber
                tlv(0x30, &tlv(0x06, &[0x2A])), // signature
                tlv(0x30, &[]),                 // issuer
                tlv(0x30, &[]),                 // validity
                tlv(0x30, &[]),                 // subject
                spki.to_vec(),                  // ← 第 7 个：subjectPublicKeyInfo
                tlv(0x03, &[0x00]),             // 后面还有别的字段，验证"只看第 7 个"
            ]
            .concat(),
        );

        tlv(
            0x30,
            &[
                tbs,
                tlv(0x30, &tlv(0x06, &[0x2A, 0x86])), // signatureAlgorithm
                tlv(0x03, &[0x00]),                   // signatureValue
            ]
            .concat(),
        )
    }

    /// 取出来的必须是"连 TLV 头一起"的整段 SPKI（= OpenSSL `i2d_X509_PUBKEY` 的产物）
    #[test]
    fn extract_spki_in_a_v3_certificate() {
        let spki = tlv(
            0x30,
            &[
                tlv(0x30, &tlv(0x06, &[0x2A, 0x86, 0x48])), // algorithm
                tlv(0x03, &[0x00, 0xAA, 0xBB, 0xCC]),       // BIT STRING（公钥本体）
            ]
            .concat(),
        );

        let cert = fake_cert(&spki);
        assert_eq!(extract_spki(&cert), Some(spki));
    }

    /// 老式 v1 证书（没有 version 字段）也不能数错：跳 version 之后第 6 个才是 SPKI
    #[test]
    fn extract_spki_without_version_field() {
        let spki = tlv(0x30, &tlv(0x03, &[0x00, 0x11]));
        let tbs = tlv(
            0x30,
            &[
                tlv(0x02, &[0x01]), // serialNumber（没有 version 时它是第 1 个）
                tlv(0x30, &[]),     // signature
                tlv(0x30, &[]),     // issuer
                tlv(0x30, &[]),     // validity
                tlv(0x30, &[]),     // subject
                spki.clone(),       // 第 6 个 = SPKI
                tlv(0x30, &[]),     // 后面还有别的字段
            ]
            .concat(),
        );
        let cert = tlv(0x30, &[tbs].concat());

        assert_eq!(extract_spki(&cert), Some(spki));
    }

    /// 乱七八糟的输入不能 panic，只能返回 None
    #[test]
    fn extract_spki_returns_none_on_garbage() {
        assert_eq!(extract_spki(&[]), None);
        assert_eq!(extract_spki(&[0x30]), None);
        assert_eq!(
            extract_spki(&[0x30, 0x05, 0x01]),
            None,
            "长度声明的比实际长"
        );
        assert_eq!(extract_spki(&[0x31, 0x00]), None, "顶层不是 SEQUENCE");
        assert_eq!(
            extract_spki(&[0x30, 0x02, 0x31, 0x00]),
            None,
            "里面第一个不是 SEQUENCE"
        );
    }
}
