//! 信任存储诊断：「证书装不上 / 装了不生效」的一次性自查。
//!
//! 对齐上游 3.2.0 KeyIso 诊断的**目的**（让用户看懂失败原因），但落点不同：
//!
//! - 上游用 `X509Store` 导入 PFX，私钥落在 CNG/KeyIso 里，被组策略或安全软件
//!   锁定后报错极其含混，所以才需要单独探测 KeyIso；
//! - 本应用只把**公开证书**写进 Root 存储，私钥留在应用数据目录参与 rustls
//!   握手，完全不经过 CNG —— KeyIso 不在我们的故障面上。
//!
//! 我们真正的故障面有三个：同名旧根残留、证书在库但信任设置未写入、提权被拒。

use std::path::Path;

use serde::Serialize;

use crate::trust::{self, CA_SUBJECT_CN};

/// 诊断结果（Rust → 前端）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustDiagnostics {
    /// CA 的 PEM 文件是否存在
    pub cert_file_exists: bool,
    /// 是否已在信任存储中生效
    pub installed: bool,
    /// 信任存储中同 CN 的证书数量；None = 该平台无法统计
    pub same_cn_certs: Option<usize>,
    /// 当前进程是否已提权；None = 该平台无此概念
    pub elevated: Option<bool>,
    /// 结论与建议（已按优先级排序，可直接展示）
    pub advice: Vec<String>,
}

/// 依据各项观测值生成建议。纯函数，便于跨平台单测。
fn build_advice(
    cert_file_exists: bool,
    installed: bool,
    same_cn_certs: Option<usize>,
    elevated: Option<bool>,
) -> Vec<String> {
    let mut advice = Vec::new();

    if !cert_file_exists {
        advice.push("证书文件缺失，请在设置页重新生成根证书".to_string());
    }

    match same_cn_certs {
        // 有同 CN 证书但整体判定未安装：macOS 上是「已导入但信任设置没写成功」，
        // Windows 上是「库里是旧 CA、当前 CA 没写进去」——两种都要重装，不能只看数量。
        Some(n) if n > 1 => advice.push(format!(
            "信任存储中有 {n} 张同名的根证书，旧证书残留会让部分客户端继续信任旧 CA；请先移除旧证书再重新安装"
        )),
        Some(1) if !installed && cert_file_exists => advice.push(
            "信任存储中存在同名证书，但当前 CA 未被信任（可能是旧证书或信任设置未写入）；请重新安装证书"
                .to_string(),
        ),
        Some(0) if cert_file_exists => {
            advice.push("信任存储中没有本应用的根证书，请点击「安装证书」".to_string())
        }
        _ => {}
    }

    if installed {
        advice.push("根证书已安装并生效".to_string());
    }

    if elevated == Some(false) {
        advice.push(
            "当前进程未以管理员身份运行，写系统信任存储会失败；请以管理员身份重新启动应用"
                .to_string(),
        );
    }

    if advice.is_empty() {
        advice.push("未发现异常".to_string());
    }
    advice
}

/// 采集并诊断当前信任状态
pub fn diagnose(cert_pem_path: &Path) -> TrustDiagnostics {
    let cert_file_exists = cert_pem_path.exists();
    let installed = cert_file_exists && trust::is_root_cert_installed(cert_pem_path);
    let same_cn_certs = trust::platform::count_root_certs_with_cn(CA_SUBJECT_CN);
    let elevated = trust::platform::is_elevated();

    TrustDiagnostics {
        cert_file_exists,
        installed,
        same_cn_certs,
        elevated,
        advice: build_advice(cert_file_exists, installed, same_cn_certs, elevated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_and_clean() {
        let a = build_advice(true, true, Some(1), Some(true));
        assert_eq!(a, vec!["根证书已安装并生效".to_string()]);
    }

    #[test]
    fn missing_cert_file() {
        let a = build_advice(false, false, Some(0), Some(false));
        assert!(a[0].contains("证书文件缺失"));
        // 未提权时也要提示提权问题
        assert!(a.iter().any(|s| s.contains("管理员")));
    }

    #[test]
    fn legacy_roots_detected() {
        let a = build_advice(true, true, Some(3), Some(true));
        let legacy = a
            .iter()
            .find(|s| s.contains("同名"))
            .expect("必须提示同名旧根残留");
        assert!(legacy.contains('3'), "应报出实际数量: {legacy}");
        // 即使当前 CA 已生效，残留也要提示（否则用户不明白为何偶发证书错误）
        assert!(a.iter().any(|s| s.contains("已安装并生效")));
    }

    #[test]
    fn imported_but_not_trusted() {
        // macOS 典型故障：证书进了钥匙串，trust settings 没写成功
        let a = build_advice(true, false, Some(1), Some(true));
        let hit = a
            .iter()
            .find(|s| s.contains("未被信任"))
            .expect("必须区分「已导入但未信任」");
        assert!(hit.contains("重新安装"));
    }

    #[test]
    fn never_installed() {
        let a = build_advice(true, false, Some(0), Some(true));
        assert!(a.iter().any(|s| s.contains("没有本应用的根证书")));
    }

    #[test]
    fn unknown_platform_values_do_not_panic() {
        // 平台无法统计（None）时不能编造结论，也不能崩
        let a = build_advice(true, false, None, None);
        assert!(!a.is_empty());
        assert!(!a.iter().any(|s| s.contains("同名")));
    }
}
