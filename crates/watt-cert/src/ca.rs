//! CA 根证书：生成/加载/导出/到期检查。对齐 CertificateManagerImpl。

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::{Path, PathBuf};

/// CA 有效期（对齐原 CertificateConstants）
pub const CA_VALID_DAYS: u64 = 3650;

/// CA 证书主题（对齐原实现 CN）
pub const CA_SUBJECT_CN: &str = "Watt Toolkit";

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("cert generation: {0}")]
    Generation(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cert load: {0}")]
    Load(String),
    #[error("cert expired")]
    Expired,
    #[error("key parse: {0}")]
    KeyParse(String),
}

/// CA 证书：持有密钥对与签发能力，可为叶子证书签名。
pub struct CaCertificate {
    pub key_pair: KeyPair,
    /// 签发用 issuer 对象（含主题 DN/SKI/KeyUsage，作为 signed_by 的签发者）
    pub issuer: rcgen::Certificate,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub serial: String,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for CaCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaCertificate")
            .field("serial", &self.serial)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl CaCertificate {
    /// 生成新 CA
    pub fn generate() -> Result<Self, CaError> {
        let key_pair = KeyPair::generate().map_err(|e| CaError::Generation(e.to_string()))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CA_SUBJECT_CN);
        dn.push(DnType::OrganizationName, "Watt Toolkit");
        dn.push(DnType::CountryName, "CN");

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(CA_VALID_DAYS as i64);
        let serial_bytes = random_serial();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| CaError::Generation(e.to_string()))?;
        let not_after = offset_to_chrono(cert.params().not_after)?;

        Ok(Self {
            serial: hex_string(&serial_bytes),
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
            not_after,
            key_pair,
            issuer: cert,
        })
    }

    /// 从 PEM 文件（cert.pem + key.pem）加载
    pub fn load(cert_pem: &Path, key_pem: &Path) -> Result<Self, CaError> {
        let cert_pem_str = std::fs::read_to_string(cert_pem)?;
        let key_pem_str = std::fs::read_to_string(key_pem)?;

        // 原始 DER（保留真实证书字节，用于导出/展示）
        let cert_der = rustls_pemfile::certs(&mut cert_pem_str.as_bytes())
            .next()
            .ok_or_else(|| CaError::Load("no cert in PEM".into()))?
            .map_err(|e| CaError::Load(e.to_string()))?;

        // 重建 params（主题 DN/SKI/KeyUsage/有效期/序列号均取自原证书）
        let params = CertificateParams::from_ca_cert_pem(&cert_pem_str)
            .map_err(|e| CaError::Load(format!("parse CA PEM: {e}")))?;
        let key_pair =
            KeyPair::from_pem(&key_pem_str).map_err(|e| CaError::KeyParse(e.to_string()))?;
        // 重建 issuer Certificate：signed_by 需要 &Certificate 作为签发者
        let issuer = params
            .self_signed(&key_pair)
            .map_err(|e| CaError::Load(format!("rebuild issuer: {e}")))?;

        let not_after = offset_to_chrono(issuer.params().not_after)?;
        if chrono::Utc::now() > not_after {
            return Err(CaError::Expired);
        }

        // 序列号从原始 DER 解析（按字节十六进制，保留首字节前导零，与 generate 一致）
        let parsed = x509_parser::parse_x509_certificate(&cert_der)
            .map_err(|e| CaError::Load(e.to_string()))?;
        let serial = hex_string(&parsed.1.tbs_certificate.serial.to_bytes_be());

        Ok(Self {
            key_pair,
            issuer,
            cert_der: cert_der.to_vec(),
            cert_pem: cert_pem_str,
            serial,
            not_after,
        })
    }

    /// 生成或加载（幂等）
    pub fn load_or_generate(dir: &Path) -> Result<Self, CaError> {
        let cert_path = Self::cert_path(dir);
        let key_path = Self::key_path(dir);
        if cert_path.exists() && key_path.exists() {
            match Self::load(&cert_path, &key_path) {
                Ok(ca) => return Ok(ca),
                Err(CaError::Expired) => {
                    tracing::warn!("CA 已过期，重新生成");
                }
                Err(e) => {
                    tracing::warn!("CA 加载失败（{e}），重新生成");
                }
            }
        }
        let ca = Self::generate()?;
        ca.save(dir)?;
        Ok(ca)
    }

    pub fn cert_path(dir: &Path) -> PathBuf {
        dir.join("ca.cert.pem")
    }

    pub fn key_path(dir: &Path) -> PathBuf {
        dir.join("ca.key.pem")
    }

    /// 导出证书 PEM
    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// 导出私钥 PEM
    pub fn key_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    fn save(&self, dir: &Path) -> Result<(), CaError> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(Self::cert_path(dir), &self.cert_pem)?;
        std::fs::write(Self::key_path(dir), self.key_pem())?;
        Ok(())
    }

    /// 证书展示信息（对齐 CertificateManagerImpl.GetCertificateInfo）
    pub fn certificate_info(&self) -> Result<CertificateInfo, CaError> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.cert_der)
            .map_err(|e| CaError::Load(format!("parse cert: {e}")))?;
        let to_chrono = |t: &x509_parser::time::ASN1Time| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(t.timestamp(), 0)
                .unwrap_or_else(chrono::Utc::now)
        };
        Ok(CertificateInfo {
            subject: cert.tbs_certificate.subject.to_string(),
            serial: self.serial.to_uppercase(),
            not_before: to_chrono(&cert.tbs_certificate.validity.not_before),
            not_after: to_chrono(&cert.tbs_certificate.validity.not_after),
            sha1: crate::trust::sha1_hex(&self.cert_der).to_uppercase(),
            sha256: crate::trust::sha256_hex_upper(&self.cert_der),
        })
    }
}

/// 证书信息（展示用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateInfo {
    /// 主题（DN）
    pub subject: String,
    /// 序列号（十六进制大写）
    pub serial: String,
    /// 生效时间
    pub not_before: chrono::DateTime<chrono::Utc>,
    /// 过期时间
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// SHA-1 指纹（十六进制大写）
    pub sha1: String,
    /// SHA-256 指纹（十六进制大写）
    pub sha256: String,
}

fn offset_to_chrono(dt: time::OffsetDateTime) -> Result<chrono::DateTime<chrono::Utc>, CaError> {
    chrono::DateTime::from_timestamp(dt.unix_timestamp(), dt.nanosecond())
        .ok_or_else(|| CaError::Load("bad not_after".into()))
}

fn random_serial() -> [u8; 16] {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    buf[0] &= 0x7f; // 确保正数
    buf
}

fn hex_string(bytes: &[u8]) -> String {
    // DER 整数去除前导零字节，与 x509 解析出的 BigUint 十六进制一致
    let pos = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[pos..];
    if trimmed.is_empty() {
        return "0".into();
    }
    trimmed.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("watt-cert-test-{}", std::process::id()));
        let ca = CaCertificate::generate().unwrap();
        ca.save(&dir).unwrap();

        let loaded = CaCertificate::load(
            &CaCertificate::cert_path(&dir),
            &CaCertificate::key_path(&dir),
        )
        .unwrap();
        assert_eq!(loaded.cert_der, ca.cert_der);
        assert_eq!(loaded.serial, ca.serial);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_or_generate_idempotent() {
        let dir = std::env::temp_dir().join(format!("watt-cert-test2-{}", std::process::id()));
        let ca1 = CaCertificate::load_or_generate(&dir).unwrap();
        let ca2 = CaCertificate::load_or_generate(&dir).unwrap();
        assert_eq!(ca1.cert_der, ca2.cert_der);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 序列号前导零半字节（首字节 < 0x10）时，load 与 generate 的十六进制一致
    #[test]
    fn test_hex_string_leading_zero_nibble() {
        assert_eq!(hex_string(&[0x00, 0x12, 0x34]), "1234");
        assert_eq!(hex_string(&[0x0a, 0xe4, 0xfb]), "0ae4fb");
        // BigUint::to_bytes_be 的输出（无前导零字节）
        let bytes = [0x0a, 0xe4, 0xfb];
        let big = num_bigint::BigUint::from_bytes_be(&bytes);
        assert_eq!(hex_string(&big.to_bytes_be()), "0ae4fb");
    }
}
