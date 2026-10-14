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
            .map_err(|err| {
                rustls::Error::General(format!(
                    "failed to build the certificate chain verifier: {err}"
                ))
            })?
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
            rustls::Error::General(
                "cannot read the peer certificate public key (SPKI); spki-pin cannot be checked"
                    .to_string(),
            )
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
    pub fn new(
        cert_path: &Path,
        key_path: &Path,
        key_passphrase: Option<&str>,
    ) -> Result<Self, crate::Error> {
        let certified_key = Self::load(cert_path, key_path, key_passphrase)?;
        Ok(TlsServerCertResolver {
            path: cert_path.to_path_buf(),
            private_key: key_path.to_path_buf(),
            certified_key: RwLock::new(Arc::new(certified_key)),
        })
    }

    pub fn load(
        cert_path: &Path,
        key_path: &Path,
        key_passphrase: Option<&str>,
    ) -> Result<CertifiedKey, crate::Error> {
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

        fn from_pem_file(
            key_path: &Path,
            key_passphrase: Option<&str>,
        ) -> Result<PrivateKeyDer<'static>, Error> {
            let key_path = &key_path;
            info!("loading TLS key from PEM: {}", key_path.display());
            // 🔐 P2-1：先读原文识别加密私钥（rustls-pemfile/from_pem_file 不解密，
            // 加密文件会直接报错且用户分不清是口令错还是文件坏）。
            let text = fs::read_to_string(key_path).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("failed to read key from {}: {e}", key_path.display()),
                )
            })?;
            let is_encrypted_pkcs8 = text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
            let is_legacy_encrypted = text.contains("Proc-Type: 4,ENCRYPTED");
            if is_encrypted_pkcs8 {
                // 加密私钥：必须配了口令才能解
                let Some(passphrase) = key_passphrase.filter(|p| !p.is_empty()) else {
                    return Err(Error::LoadCertificateKeyFailed(
                        key_path.to_path_buf(),
                        "the private key is encrypted (PKCS#8) but no passphrase was configured; \
                         add `bind-cert-key-pass <passphrase>` to the configuration"
                            .to_string(),
                    ));
                };
                // 提取 PEM base64 段并解码为 DER
                let der = {
                    let body: String = text
                        .lines()
                        .skip_while(|l| !l.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
                        .skip(1)
                        .take_while(|l| !l.starts_with("-----END ENCRYPTED PRIVATE KEY-----"))
                        .collect::<Vec<_>>()
                        .join("");
                    base64::decode(body.trim()).map_err(|e| {
                            Error::LoadCertificateKeyFailed(
                                key_path.to_path_buf(),
                                format!("invalid base64 in encrypted private key: {e}"),
                            )
                        })?
                };
                match decrypt_pkcs8_encrypted_private_key(&der, passphrase) {
                    Ok(plain) => {
                        info!(
                            "decrypted PKCS#8 encrypted private key from {}",
                            key_path.display()
                        );
                        return PrivateKeyDer::try_from(plain).map_err(|e| {
                            Error::LoadCertificateKeyFailed(
                                key_path.to_path_buf(),
                                format!("decrypted key is not a valid PKCS#8 key: {e}"),
                            )
                        });
                    }
                    Err(DecryptError::WrongPassphrase) => {
                        // 口令错误是最常见原因，单独给出明确文案（不含口令本身）
                        return Err(Error::LoadCertificateKeyFailed(
                            key_path.to_path_buf(),
                            "the private key passphrase is incorrect (PKCS#7 padding check failed); \
                             check `bind-cert-key-pass` in the configuration"
                                .to_string(),
                        ));
                    }
                    Err(DecryptError::UnsupportedAlgorithm) => {
                        return Err(Error::LoadCertificateKeyFailed(
                            key_path.to_path_buf(),
                            "the encrypted private key uses an unsupported algorithm; \
                             supported: PBES2 with PBKDF2-HMAC-SHA256 and AES-128/256-CBC \
                             (the default of modern `openssl genpkey -aes256`)"
                                .to_string(),
                        ));
                    }
                    Err(DecryptError::MalformedParameters(why)) => {
                        return Err(Error::LoadCertificateKeyFailed(
                            key_path.to_path_buf(),
                            format!("malformed encrypted private key: {why}"),
                        ));
                    }
                }
            }
            if is_legacy_encrypted {
                // OpenSSL 已弃用的传统格式（BEGIN RSA PRIVATE KEY + Proc-Type）不支持，
                // 给出可操作的导出指引
                return Err(Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    "this private key uses the legacy encrypted format (Proc-Type header) which is \
                     not supported; re-export it as PKCS#8 with: \
                     `openssl pkcs8 -topk8 -in <key> -out <new-key> -passin pass:<old-pass> -passout pass:<new-pass>`"
                        .to_string(),
                ));
            }
            // 明文私钥：走原有逻辑
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
            from_pem_file(key_path, key_passphrase)?
        } else if key_extension.is_some_and(|ext| ext == "der") {
            try_from(key_path)?
        } else {
            from_pem_file(key_path, key_passphrase)
                .or_else(|_| try_from(key_path))
                .map_err(|_| {
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

// ============================================================
// 🔐 P2-1：PKCS#8 加密私钥解密（RFC 8018 PBES2）
// ============================================================
//
// C 版（pymumu/smartdns）通过 OpenSSL 的口令回调（SSL_CTX_set_default_passwd_cb）
// 支持加密私钥：读 `SSL_CTX_use_PrivateKey_file` 时 OpenSSL 自动调回调取口令解密。
// Rust 的 rustls 生态不做解密——rustls-pemfile 能定位加密段，解密需要自行实现。
//
// 支持范围（对齐现代 openssl 默认输出）：PKCS#8 加密格式（`BEGIN ENCRYPTED PRIVATE KEY`，
// PBES2 + PBKDF2-HMAC-SHA256 + AES-CBC）。OpenSSL 已弃用的传统格式（`BEGIN RSA PRIVATE KEY`
// 带 Proc-Type 头）不支持——遇到时给出可操作的导出指引。
//
// 安全纪律：解密失败的错误信息只含文件路径与失败原因，**绝不含口令本身**（与
// `redact_config_line` 的日志脱敏纪律一致，测试有断言拦截）。

/// PBES2 相关 OID（RFC 8018）
const OID_PBES2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];
const OID_PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];
const OID_HMAC_WITH_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07]; // 1.2.840.113549.2.7
const OID_HMAC_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09]; // 1.2.840.113549.2.9
const OID_HMAC_WITH_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B]; // 1.2.840.113549.2.11
const OID_AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]; // 2.16.840.1.101.3.4.1.2
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]; // 2.16.840.1.101.3.4.1.42

/// 解密失败的原因（用于区分"口令错误"与"文件/格式问题"，给出可操作的报错）
#[derive(Debug)]
pub enum DecryptError {
    /// PKCS#8 加密参数解析失败（文件不是合法的加密私钥结构）
    MalformedParameters(&'static str),
    /// 加密算法不受支持（目前支持 AES-128/256-CBC 的 PBES2）
    UnsupportedAlgorithm,
    /// 口令不正确（解密后 PKCS#7 填充校验失败——加密私钥场景下最常见的原因）
    WrongPassphrase,
}

/// 最小 DER 读取器：只实现本模块需要的三件事——读 TLV 头、断言 tag、取出内容。
struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// 读一个 TLV 的 tag 与内容，返回 (tag, 内容切片)。
    fn next_tlv(&mut self) -> Result<(u8, &'a [u8]), DecryptError> {
        if self.pos >= self.data.len() {
            return Err(DecryptError::MalformedParameters("unexpected end of DER"));
        }
        let tag = self.data[self.pos];
        self.pos += 1;
        let first = *self
            .data
            .get(self.pos)
            .ok_or(DecryptError::MalformedParameters("missing length"))?;
        self.pos += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7F) as usize;
            if n == 0 || n > 4 {
                return Err(DecryptError::MalformedParameters("unsupported length form"));
            }
            let mut len = 0usize;
            for _ in 0..n {
                let b = *self
                    .data
                    .get(self.pos)
                    .ok_or(DecryptError::MalformedParameters("truncated length"))?;
                len = (len << 8) | b as usize;
                self.pos += 1;
            }
            len
        };
        let content = self
            .data
            .get(self.pos..self.pos + len)
            .ok_or(DecryptError::MalformedParameters("truncated content"))?;
        self.pos += len;
        Ok((tag, content))
    }

    /// 读 TLV 并断言其 tag，返回内容
    fn expect(&mut self, tag: u8) -> Result<&'a [u8], DecryptError> {
        let (t, content) = self.next_tlv()?;
        if t != tag {
            return Err(DecryptError::MalformedParameters("unexpected DER tag"));
        }
        Ok(content)
    }
}

/// PBES2 参数（解密所需的最小集）
struct Pbes2Params {
    salt: Vec<u8>,
    iterations: u32,
    key_len: usize,
    iv: Vec<u8>,
    prf: ring::pbkdf2::Algorithm,
}

/// 解析 PBES2-params（从 EncryptionAlgorithmIdentifier 的内容）
fn parse_pbes2_params(seq: &[u8]) -> Result<Pbes2Params, DecryptError> {
    let mut params = DerReader::new(seq);

    // keyDerivationFunc: SEQUENCE { OID(PBKDF2), SEQUENCE { salt, iterations, [keyLen], [prf] } }
    let kdf_outer = params.expect(0x30)?;
    let mut kdf_alg = DerReader::new(kdf_outer);
    let (t, oid_pbkdf2) = kdf_alg.next_tlv()?;
    if t != 0x06 || oid_pbkdf2 != OID_PBKDF2 {
        return Err(DecryptError::UnsupportedAlgorithm);
    }
    let kdf_params_seq = kdf_alg.expect(0x30)?;

    // PBKDF2-params: SEQUENCE { salt OCTET STRING, iterations INTEGER,
    //                            [keyLength INTEGER], [prf AlgorithmIdentifier] }
    let mut kdf_params = DerReader::new(kdf_params_seq);
    let salt = kdf_params.expect(0x04)?.to_vec();
    let iterations = {
        let it = kdf_params.expect(0x02)?;
        if it.is_empty() || it.len() > 8 {
            return Err(DecryptError::MalformedParameters("bad iteration count"));
        }
        let mut v: u64 = 0;
        for b in it {
            v = (v << 8) | *b as u64;
        }
        // 防御：0 无意义；上限防恶意构造的超长派生卡死启动
        if v == 0 || v > 100_000_000 {
            return Err(DecryptError::MalformedParameters(
                "iteration count out of range",
            ));
        }
        v as u32
    };
    // 可选的 keyLength 与 prf：prf 缺省为 HMAC-SHA1（RFC 8018），openssl 生成的现代文件
    // 显式写 HMAC-SHA256。这里接受"显式 SHA256"或"缺省"，显式写了其它 prf 则拒绝——
    // 避免静默用错派生函数产出错误密钥。
    // prf（可选，RFC 8018 缺省 HMAC-SHA1）：按 OID 映射到 ring 的 PBKDF2 算法；
    // 显式写了不支持的 prf 则拒绝——避免静默用错派生函数产出错误密钥。
    let prf = match kdf_params.next_tlv() {
        Ok((0x02, _key_len_ignored)) => {
            // keyLength 由加密算法 OID 决定，这里忽略；继续看有没有 prf
            match kdf_params.next_tlv() {
                Ok((0x30, prf_seq)) => {
                    let mut prf_reader = DerReader::new(prf_seq);
                    let (_, oid_prf) = prf_reader.next_tlv()?;
                    prf_algorithm(oid_prf)?
                }
                Ok(_) => return Err(DecryptError::MalformedParameters("unexpected PBKDF2 field")),
                Err(_) => ring::pbkdf2::PBKDF2_HMAC_SHA1,
            }
        }
        Ok((0x30, prf_seq)) => {
            let mut prf_reader = DerReader::new(prf_seq);
            let (_, oid_prf) = prf_reader.next_tlv()?;
            prf_algorithm(oid_prf)?
        }
        Ok(_) => return Err(DecryptError::MalformedParameters("unexpected PBKDF2 field")),
        Err(_) => ring::pbkdf2::PBKDF2_HMAC_SHA1,
    };

    // encryptionScheme: SEQUENCE { OID(aes-cbc), IV OCTET STRING }
    let enc_seq = params.expect(0x30)?;
    let mut enc = DerReader::new(enc_seq);
    let (t, oid_enc) = enc.next_tlv()?;
    if t != 0x06 {
        return Err(DecryptError::MalformedParameters("bad encryption oid tag"));
    }
    let key_len = if oid_enc == OID_AES256_CBC {
        32usize
    } else if oid_enc == OID_AES128_CBC {
        16
    } else {
        return Err(DecryptError::UnsupportedAlgorithm);
    };
    let iv = enc.expect(0x04)?.to_vec();
    if iv.len() != 16 {
        return Err(DecryptError::MalformedParameters("bad IV length"));
    }

    Ok(Pbes2Params {
        salt,
        iterations,
        key_len,
        iv,
        prf,
    })
}

/// 按 OID 映射 PBKDF2 的伪随机函数（ring 提供的三种都支持；其它拒绝）
fn prf_algorithm(oid: &[u8]) -> Result<ring::pbkdf2::Algorithm, DecryptError> {
    if oid == OID_HMAC_WITH_SHA1 {
        Ok(ring::pbkdf2::PBKDF2_HMAC_SHA1)
    } else if oid == OID_HMAC_WITH_SHA256 {
        Ok(ring::pbkdf2::PBKDF2_HMAC_SHA256)
    } else if oid == OID_HMAC_WITH_SHA512 {
        Ok(ring::pbkdf2::PBKDF2_HMAC_SHA512)
    } else {
        Err(DecryptError::UnsupportedAlgorithm)
    }
}

/// 解密 PKCS#8 加密私钥（PBES2：PBKDF2-HMAC-SHA256 + AES-128/256-CBC）。
///
/// `der` 是 `ENCRYPTED PRIVATE KEY` 段的 DER 内容，`passphrase` 是配置的口令。
/// 成功返回明文私钥的 PKCS#8 DER（可直接交给 rustls）。
pub fn decrypt_pkcs8_encrypted_private_key(
    der: &[u8],
    passphrase: &str,
) -> Result<Vec<u8>, DecryptError> {
    // 顶层：SEQUENCE { SEQUENCE(算法), OCTET STRING(密文) }
    let mut top = DerReader::new(der);
    let top_seq = top.expect(0x30)?;
    let mut fields = DerReader::new(top_seq);
    let alg_seq = fields.expect(0x30)?;
    let encrypted = fields.expect(0x04)?;

    // 算法：SEQUENCE { OID(PBES2), SEQUENCE(params) }
    let mut alg = DerReader::new(alg_seq);
    let (t, oid_pbes2) = alg.next_tlv()?;
    if t != 0x06 || oid_pbes2 != OID_PBES2 {
        return Err(DecryptError::UnsupportedAlgorithm);
    }
    let params_seq = alg.expect(0x30)?;
    let params = parse_pbes2_params(params_seq)?;

    // PBKDF2-HMAC-SHA256 派生密钥（ring）
    let mut derived = vec![0u8; params.key_len];
    ring::pbkdf2::derive(
        params.prf,
        std::num::NonZeroU32::new(params.iterations)
            .ok_or(DecryptError::MalformedParameters("zero iterations"))?,
        &params.salt,
        passphrase.as_bytes(),
        &mut derived,
    );

    // AES-CBC 解密 + PKCS#7 去填充（填充错误 = 口令不正确）
    use aes::cipher::{BlockDecryptMut, KeyIvInit as _};
    if encrypted.is_empty() || encrypted.len() % 16 != 0 {
        return Err(DecryptError::MalformedParameters(
            "ciphertext not block-aligned",
        ));
    }
    
    let mut buf = encrypted.to_vec();
    let dec = cbc::Decryptor::<aes::Aes256>::new_from_slices(
        &derived[..params.key_len],
        &params.iv,
    )
    .map_err(|_| DecryptError::MalformedParameters("bad key/iv length"))?;
    let plain = dec
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|_| DecryptError::WrongPassphrase)?;

    Ok(plain.to_vec())
}


/// P2-1 解密模块的单元测试（夹具：tests/test_data/tls/ 下 openssl 预生成的加密私钥）
///
/// 夹具说明（生成命令，口令均为 test-pass-123）：
///   * `enc-key.pem`    —— PKCS#8 加密：`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes256 -pass pass:test-pass-123`
///   * `plain-key.pem`  —— 同一把钥的明文 PKCS#8（解密结果应与之等价）
///   * `legacy-key.pem` —— 传统加密格式（Proc-Type 头，OpenSSL 3 需 -traditional），应被拒绝并给指引
#[cfg(test)]
mod decrypt_tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/tls");
        std::fs::read_to_string(dir.join(name)).expect("fixture should exist")
    }

    /// 从 PEM 文本提取 base64 段并解码为 DER
    fn pem_body_to_der(text: &str, begin: &str, end: &str) -> Vec<u8> {
        let body: String = text
            .lines()
            .skip_while(|l| !l.starts_with(begin))
            .skip(1)
            .take_while(|l| !l.starts_with(end))
            .collect::<Vec<_>>()
            .join("");
        base64::decode(body.trim()).expect("valid base64")
    }

    /// 解密成功：结果与同一把钥的明文 PKCS#8 DER 完全一致
    #[test]
    fn decrypt_encrypted_key_matches_plain() {
        let enc = fixture("enc-key.pem");
        let der = pem_body_to_der(
            &enc,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
        );
        let plain = decrypt_pkcs8_encrypted_private_key(&der, "test-pass-123")
            .expect("correct passphrase must decrypt");

        let plain_ref = fixture("plain-key.pem");
        let expected = pem_body_to_der(
            &plain_ref,
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
        );
        assert_eq!(plain, expected, "解密结果应与明文导出的 DER 一致");
    }

    /// 口令错误：报 WrongPassphrase
    #[test]
    fn decrypt_wrong_passphrase_fails() {
        let enc = fixture("enc-key.pem");
        let der = pem_body_to_der(
            &enc,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
        );
        let err = decrypt_pkcs8_encrypted_private_key(&der, "wrong-pass")
            .expect_err("wrong passphrase must fail");
        assert!(matches!(err, DecryptError::WrongPassphrase));
    }

    /// 传统格式：文件含 Proc-Type 头，根本不该进解密函数——这里验证识别逻辑
    /// （from_pem_file 层拒绝并给指引，见其实现；此处确认夹具确实是传统格式）
    #[test]
    fn legacy_fixture_is_traditional_format() {
        let legacy = fixture("legacy-key.pem");
        assert!(legacy.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(legacy.contains("Proc-Type: 4,ENCRYPTED"));
        assert!(!legacy.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    }

    /// 结构破坏：截断的 DER 报 MalformedParameters
    #[test]
    fn decrypt_truncated_der_fails() {
        let enc = fixture("enc-key.pem");
        let der = pem_body_to_der(
            &enc,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----END ENCRYPTED PRIVATE KEY-----",
        );
        let err = decrypt_pkcs8_encrypted_private_key(&der[..der.len() / 2], "test-pass-123")
            .expect_err("truncated DER must fail");
        assert!(matches!(err, DecryptError::MalformedParameters(_)));
    }
}

