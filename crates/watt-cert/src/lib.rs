//! 证书域：CA 生成/加载/导出、叶子证书按域动态签发（带缓存）、三平台信任安装。
//! 对齐原 CertificateManagerImpl / CertService。

pub mod ca;
pub mod leaf;
pub mod pfx;
pub mod trust;

pub use ca::{CaCertificate, CaError, CA_VALID_DAYS};
pub use leaf::{LeafCertCache, LeafCertError};
pub use pfx::{import_pfx, PfxError};

/// 证书目录：{AppData}/WattToolkit/Certificates
pub fn cert_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("WattToolkit")
        .join("Certificates")
}
