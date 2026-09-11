//! 旧版 CA PFX 导入：解析 PKCS#12（空密码）→ 转 PEM → 走 CaCertificate::load 校验。
//!
//! 对齐迁移计划「旧 CA PFX（空密码）导入保持已信任状态」：
//! 旧版 `SteamTools.Certificate.pfx` 由 .NET 导出（AES-256-CBC / PBKDF2-SHA256，
//! 或旧系统 RC2-40），p12-keystore 两者均可解。导入成功后系统信任存储中的
//! 旧根证书指纹与新 PEM 一致，无需重新安装信任。

use crate::ca::CaCertificate;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum PfxError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("p12 解析失败: {0}")]
    Parse(String),
    #[error("PFX 中无私钥或证书链")]
    Empty,
    #[error("CA 校验失败: {0}")]
    Invalid(String),
}

/// 从 PFX 文件导入 CA 并写入 cert_dir（ca.cert.pem + ca.key.pem）。
///
/// 返回导入后的 CA。失败不阻断主流程（调用方降级为重新生成，引导重装信任）。
pub fn import_pfx(
    pfx_path: &Path,
    password: &str,
    cert_dir: &Path,
) -> Result<CaCertificate, PfxError> {
    let data = std::fs::read(pfx_path)?;

    let ks = p12_keystore::KeyStore::from_pkcs12(
        &data,
        password,
        p12_keystore::Pkcs12ImportPolicy::Relaxed,
    )
    .map_err(|e| PfxError::Parse(e.to_string()))?;

    let (_, chain) = ks.private_key_chain().ok_or(PfxError::Empty)?;
    let key_der = chain.key().as_der().to_vec();
    let cert_der = chain
        .certs()
        .first()
        .ok_or(PfxError::Empty)?
        .as_der()
        .to_vec();

    let cert_pem = encode_pem("CERTIFICATE", &cert_der);
    let key_pem = encode_pem("PRIVATE KEY", &key_der);

    // 写入临时校验：CaCertificate::load 会做 X.509 解析 + rcgen 重建 + 到期检查
    std::fs::create_dir_all(cert_dir)?;
    let cert_path = CaCertificate::cert_path(cert_dir);
    let key_path = CaCertificate::key_path(cert_dir);
    std::fs::write(&cert_path, &cert_pem)?;
    std::fs::write(&key_path, &key_pem)?;

    let ca = CaCertificate::load(&cert_path, &key_path).map_err(|e| {
        // 校验失败：清理半成品，避免下次启动加载到坏文件
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        PfxError::Invalid(e.to_string())
    })?;
    Ok(ca)
}

/// DER → PEM（RFC 7468，64 字节换行）
fn encode_pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_pem_format() {
        let pem = encode_pem("CERTIFICATE", &[0x30, 0x03, 0x02, 0x01]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        // 4 字节 DER → base64 单行
        assert_eq!(pem.lines().count(), 3);
    }

    #[test]
    fn test_import_pfx_missing_file() {
        let err = import_pfx(Path::new("Z:/nonexistent.pfx"), "", Path::new("Z:/nowhere"));
        assert!(matches!(err, Err(PfxError::Io(_))));
    }

    /// 端到端：CA → 组装 PKCS#12（AES-256，模拟旧版 .NET 导出）→ import_pfx → DER 一致
    #[test]
    fn test_import_pfx_roundtrip() {
        let dir = std::env::temp_dir().join(format!("watt-pfx-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 1. 生成 CA 并取 DER
        let ca = CaCertificate::generate().unwrap();
        let key_der = ca.key_pair.serialize_der();
        let cert_der = ca.cert_der.clone();

        // 2. 组装 PKCS#12（空密码，AES-256-CBC，对齐 .NET 导出参数）
        let mut ks = p12_keystore::KeyStore::new();
        let chain = p12_keystore::PrivateKeyChain::new(
            "watt-ca",
            p12_keystore::PrivateKey::from_der(&key_der).unwrap(),
            vec![p12_keystore::Certificate::from_der(&cert_der).unwrap()],
        );
        ks.add_entry(
            "SteamTools.Certificate",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain),
        );
        let pfx_bytes = ks.writer("").write().unwrap();
        let pfx_path = dir.join("SteamTools.Certificate.pfx");
        std::fs::write(&pfx_path, pfx_bytes).unwrap();

        // 3. 导入到新证书目录
        let cert_dir = dir.join("Certificates");
        let imported = import_pfx(&pfx_path, "", &cert_dir).unwrap();

        // 4. DER 字节一致（信任存储指纹不变）
        assert_eq!(imported.cert_der, cert_der);
        assert_eq!(imported.serial, ca.serial);

        // 5. 文件已落地，且可再次加载
        assert!(CaCertificate::cert_path(&cert_dir).exists());
        assert!(CaCertificate::key_path(&cert_dir).exists());
        let reloaded = CaCertificate::load(
            &CaCertificate::cert_path(&cert_dir),
            &CaCertificate::key_path(&cert_dir),
        )
        .unwrap();
        assert_eq!(reloaded.cert_der, cert_der);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
