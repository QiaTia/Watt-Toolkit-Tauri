//! 证书命令：状态查询 / 安装信任 / 移除信任 / CA 导出 / 重新生成 / 证书信息。
//! 对齐 CertificateManagerImpl（SetupRootCertificate / DeleteRootCertificate / GetCertificateInfo）。

use serde::Serialize;
use std::sync::Arc;
use watt_cert::ca::{CaCertificate, CertificateInfo};

use crate::AppState;

/// CA 证书状态（Rust → 前端）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertStatusDto {
    /// 主题 CN
    pub subject: String,
    /// 序列号（十六进制）
    pub serial: String,
    /// 过期时间
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// 剩余有效天数
    pub days_remaining: i64,
    /// 是否已过期
    pub expired: bool,
    /// 是否已安装并信任
    pub installed: bool,
}

fn to_status(ca: &CaCertificate, installed: bool) -> CertStatusDto {
    let now = chrono::Utc::now();
    let days_remaining = (ca.not_after - now).num_days().max(0);
    CertStatusDto {
        subject: watt_cert::ca::CA_SUBJECT_CN.to_string(),
        serial: ca.serial.clone(),
        not_after: ca.not_after,
        days_remaining,
        expired: now > ca.not_after,
        installed,
    }
}

/// CA 证书 PEM 文件路径（信任安装入参）
fn ca_cert_file(state: &AppState) -> std::path::PathBuf {
    CaCertificate::cert_path(&state.cert_dir())
}

/// 确保证书 PEM 文件存在（load_or_generate 已保证，此处兜底重写）
fn ensure_cert_file(state: &AppState, ca: &CaCertificate) -> Result<(), String> {
    let path = ca_cert_file(state);
    if !path.exists() {
        std::fs::create_dir_all(state.cert_dir()).map_err(|e| e.to_string())?;
        std::fs::write(&path, ca.cert_pem()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub async fn cert_get_status(state: tauri::State<'_, AppState>) -> Result<CertStatusDto, String> {
    let ca = state.ca.read().await;
    ensure_cert_file(&state, &ca)?;
    let path = ca_cert_file(&state);
    let installed =
        tokio::task::spawn_blocking(move || watt_cert::trust::is_root_cert_installed(&path))
            .await
            .map_err(|e| e.to_string())?;
    Ok(to_status(&ca, installed))
}

/// 导出 CA 证书 PEM（供用户手动安装到系统信任存储）
#[tauri::command]
pub async fn cert_export_ca(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let ca = state.ca.read().await;
    Ok(ca.cert_pem())
}

/// 安装根证书到系统信任存储（对齐 SetupRootCertificate：安装后校验）
#[tauri::command]
pub async fn cert_install(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    let ca = state.ca.read().await;
    ensure_cert_file(&state, &ca)?;

    let path = ca_cert_file(&state);
    // 安装（可能触发 UAC 提权）
    tokio::task::spawn_blocking(move || watt_cert::trust::install_root_cert(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    // 安装后校验（对齐原实现 IsRootCertificateInstalled 二次确认）
    let path = ca_cert_file(&state);
    let installed =
        tokio::task::spawn_blocking(move || watt_cert::trust::is_root_cert_installed(&path))
            .await
            .map_err(|e| e.to_string())?;
    Ok(installed)
}

/// 移除根证书信任（对齐 DeleteRootCertificate：移除信任后删除证书文件）
#[tauri::command]
pub async fn cert_uninstall(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    {
        let engine = state.engine.lock().await;
        if matches!(
            engine.state(),
            watt_core::engine::EngineState::Running { .. }
        ) {
            return Err("请先停止加速再移除证书".into());
        }
    }

    // 移除信任（可能触发 UAC 提权）
    tokio::task::spawn_blocking(watt_cert::trust::remove_root_cert)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    // 校验已移除后删除证书文件（对齐原实现）
    let path = ca_cert_file(&state);
    let installed =
        tokio::task::spawn_blocking(move || watt_cert::trust::is_root_cert_installed(&path))
            .await
            .map_err(|e| e.to_string())?;
    if !installed {
        let cert_dir = state.cert_dir();
        let _ = std::fs::remove_file(CaCertificate::cert_path(&cert_dir));
        let _ = std::fs::remove_file(CaCertificate::key_path(&cert_dir));
    }
    Ok(!installed)
}

/// 证书详细信息（对齐 GetCertificateInfo：主题/序列号/有效期/SHA1/SHA256）
#[tauri::command]
pub async fn cert_get_info(state: tauri::State<'_, AppState>) -> Result<CertificateInfo, String> {
    let ca = state.ca.read().await;
    ca.certificate_info().map_err(|e| e.to_string())
}

/// 重新生成 CA（需引擎停止状态；旧叶子证书全部失效）
#[tauri::command]
pub async fn cert_regenerate(state: tauri::State<'_, AppState>) -> Result<CertStatusDto, String> {
    {
        let engine = state.engine.lock().await;
        if matches!(
            engine.state(),
            watt_core::engine::EngineState::Running { .. }
        ) {
            return Err("请先停止加速再重新生成证书".into());
        }
    }

    let new_ca = Arc::new(CaCertificate::generate().map_err(|e| e.to_string())?);
    let cert_dir = state.cert_dir();
    std::fs::create_dir_all(&cert_dir).map_err(|e| e.to_string())?;
    std::fs::write(CaCertificate::cert_path(&cert_dir), new_ca.cert_pem())
        .map_err(|e| e.to_string())?;
    std::fs::write(CaCertificate::key_path(&cert_dir), new_ca.key_pem())
        .map_err(|e| e.to_string())?;

    let mut ca = state.ca.write().await;
    *ca = new_ca.clone();
    Ok(to_status(&new_ca, false))
}
