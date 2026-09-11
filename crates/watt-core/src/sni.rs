//! TLS/SNI：MITM 动态证书接入层 + 出站 TLS 连接器。

use rustls::pki_types::ServerName;
use std::sync::Arc;
use watt_cert::ca::CaCertificate;
use watt_cert::leaf::SyncLeafCertResolver;

/// MITM TLS 接入配置：ALPN h2 + http/1.1，按 SNI 动态签发证书
pub fn mitm_tls_acceptor(ca: Arc<CaCertificate>) -> tokio_rustls::TlsAcceptor {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SyncLeafCertResolver::new(ca)));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// 出站 TLS 验证模式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutboundVerify {
    /// 标准验证
    Standard,
    /// 忽略证书名称不匹配（对齐 TlsIgnoreNameMismatch）
    IgnoreNameMismatch,
    /// 完全跳过验证
    SkipAll,
}

/// 出站 TLS 连接器
///
/// `alt_name`：SNI 覆盖时的证书名称校验替代值。原版 C# 直连路径在证书名称
/// 与假 SNI 不匹配时，用**原始请求域名**的 DNS 名校验证书（证书链仍正常验证），
/// 见 ReverseProxyHttpClientHandler.ValidateServerCertificate。
pub fn outbound_tls_connector(
    verify: OutboundVerify,
    alt_name: Option<String>,
) -> Arc<tokio_rustls::TlsConnector> {
    let builder = rustls::ClientConfig::builder();
    let config = match verify {
        OutboundVerify::Standard => builder
            .with_root_certificates(root_store())
            .with_no_client_auth(),
        OutboundVerify::IgnoreNameMismatch => {
            let roots = root_store();
            match alt_name.map(|n| server_name(&n)).and_then(|s| s) {
                Some(alt) => {
                    // 证书链正常校验，名称用原始域名（对齐原版 ValidateServerCertificate）
                    let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
                        .build()
                        .unwrap_or_else(|_| unreachable!("合法 roots 构建 verifier 不会失败"));
                    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                        Arc::new(RelaxedNameVerifier { inner, alt });
                    builder
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                        .with_no_client_auth()
                }
                None => {
                    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                        Arc::new(PermissiveVerifier);
                    builder
                        .dangerous()
                        .with_custom_certificate_verifier(verifier)
                        .with_no_client_auth()
                }
            }
        }
        OutboundVerify::SkipAll => {
            let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                Arc::new(PermissiveVerifier);
            builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };
    Arc::new(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// 系统根证书存储
pub fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                let _ = roots.add(cert);
            }
        }
        Err(e) => {
            tracing::warn!("系统根证书加载失败: {e}");
        }
    }
    if roots.is_empty() {
        tracing::warn!("系统根证书存储为空");
    }
    roots
}

/// 目标 ServerName（支持 DNS 名称；IP 直连用 IP 类型）
pub fn server_name(host: &str) -> Option<ServerName<'static>> {
    ServerName::try_from(host.to_string()).ok()
}

/// 宽松名称验证器：证书链正常校验（webpki），但名称改用原始请求域名。
/// 对齐原版 ValidateServerCertificate——SNI 覆盖（FakeServerName）引发名称
/// 不匹配时，按原始域名 DNS 名判定证书有效性。
#[derive(Debug)]
struct RelaxedNameVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    alt: ServerName<'static>,
}

impl rustls::client::danger::ServerCertVerifier for RelaxedNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.alt, ocsp_response, now)
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
}

/// 宽松验证器（跳过全部校验）
#[derive(Debug)]
struct PermissiveVerifier;
impl rustls::client::danger::ServerCertVerifier for PermissiveVerifier {
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
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
