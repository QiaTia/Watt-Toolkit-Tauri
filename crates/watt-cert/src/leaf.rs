//! 叶子证书：按 SNI 动态签发（一年期）并缓存。对齐 CertService.GetOrCreateServerCert。

use crate::ca::CaCertificate;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum LeafCertError {
    #[error("cert generation: {0}")]
    Generation(String),
}

/// 单个叶子证书（cert + key）
pub struct LeafCertificate {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

impl Clone for LeafCertificate {
    fn clone(&self) -> Self {
        Self {
            cert_der: self.cert_der.clone(),
            key_der: self.key_der.clone_key(),
            not_after: self.not_after,
        }
    }
}

/// 异步缓存版（供逻辑层显式预取）
pub struct LeafCertCache {
    ca: Arc<CaCertificate>,
    certs: Mutex<HashMap<String, LeafCertificate>>,
    not_after: chrono::DateTime<chrono::Utc>,
}

impl LeafCertCache {
    pub fn new(ca: Arc<CaCertificate>) -> Self {
        Self {
            ca,
            certs: Mutex::new(HashMap::new()),
            not_after: chrono::Utc::now() + Duration::from_secs(365 * 86400),
        }
    }

    /// 获取或签发域名证书（缓存一年，过期重签）
    pub async fn get_or_create(&self, domain: &str) -> Result<LeafCertificate, LeafCertError> {
        let mut certs = self.certs.lock().await;
        if let Some(cert) = certs.get(domain) {
            if chrono::Utc::now() < cert.not_after {
                return Ok(cert.clone());
            }
        }
        let cert = create_leaf(&self.ca, domain, self.not_after)?;
        certs.insert(domain.to_string(), cert.clone());
        // 防缓存无界增长
        if certs.len() > 4096 {
            let now = chrono::Utc::now();
            certs.retain(|_, c| c.not_after > now);
        }
        Ok(cert)
    }
}

/// rustls ResolvesServerCert：握手回调内按 SNI 同步签发（DashMap 缓存保证热路径 O(1)）
#[derive(Debug)]
pub struct SyncLeafCertResolver {
    ca: Arc<CaCertificate>,
    cache: dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>,
    not_after: chrono::DateTime<chrono::Utc>,
}

impl SyncLeafCertResolver {
    pub fn new(ca: Arc<CaCertificate>) -> Self {
        Self {
            ca,
            cache: dashmap::DashMap::new(),
            not_after: chrono::Utc::now() + Duration::from_secs(365 * 86400),
        }
    }

    fn resolve_key(&self, domain: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(entry) = self.cache.get(domain) {
            return Some(entry.clone());
        }
        let leaf = create_leaf(&self.ca, domain, self.not_after).ok()?;
        let key = build_certified_key(leaf)?;
        self.cache.insert(domain.to_string(), key.clone());
        Some(key)
    }
}

impl rustls::server::ResolvesServerCert for SyncLeafCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello
            .server_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        if sni.is_empty() {
            return None;
        }
        self.resolve_key(&sni)
    }
}

fn build_certified_key(leaf: LeafCertificate) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&leaf.key_der).ok()?;
    Some(Arc::new(rustls::sign::CertifiedKey::new(
        vec![leaf.cert_der],
        signing_key,
    )))
}

fn create_leaf(
    ca: &CaCertificate,
    domain: &str,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<LeafCertificate, LeafCertError> {
    let key_pair = KeyPair::generate().map_err(|e| LeafCertError::Generation(e.to_string()))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain.to_string());

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    // 对齐原实现：SAN 包含 域名、127.0.0.1、::1
    params.subject_alt_names = vec![
        SanType::DnsName(
            domain
                .try_into()
                .map_err(|e| LeafCertError::Generation(format!("bad domain: {e:?}")))?,
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    // 对齐原实现：notBefore=-1d，notAfter=+1y
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = chrono_to_offset(not_after);

    let signed = params
        .signed_by(&key_pair, &ca.issuer, &ca.key_pair)
        .map_err(|e| LeafCertError::Generation(e.to_string()))?;

    Ok(LeafCertificate {
        cert_der: CertificateDer::from(signed.der().to_vec()),
        key_der: PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        not_after,
    })
}

fn chrono_to_offset(dt: chrono::DateTime<chrono::Utc>) -> time::OffsetDateTime {
    match time::OffsetDateTime::from_unix_timestamp(dt.timestamp()) {
        Ok(base) => base + time::Duration::nanoseconds(dt.timestamp_subsec_nanos() as i64),
        Err(_) => time::OffsetDateTime::now_utc(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_leaf_cert_cache() {
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let cache = LeafCertCache::new(ca);
        let c1 = cache.get_or_create("steamcommunity.com").await.unwrap();
        let c2 = cache.get_or_create("steamcommunity.com").await.unwrap();
        assert_eq!(c1.cert_der, c2.cert_der); // 命中缓存
        let c3 = cache.get_or_create("store.steampowered.com").await.unwrap();
        assert_ne!(c1.cert_der, c3.cert_der); // 不同域不同证书
    }

    #[test]
    fn test_sync_resolver() {
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let resolver = SyncLeafCertResolver::new(ca);
        let key = resolver.resolve_key("steamcommunity.com");
        assert!(key.is_some());
    }
}
