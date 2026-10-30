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
    // 先克隆 Arc 释放读锁：信任查询在 macOS/Windows 都可能很慢（UAC/钥匙串）
    let ca = state.ca.read().await.clone();
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
    let ca = state.ca.read().await.clone();
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
    // 持 engine 锁贯穿「检查停止 → 移除信任 → 删除证书文件」：
    // 否则并发 engine_start 可在移除信任后、删文件前启动，出现「引擎在跑但 CA 已不受信任」。
    let engine = state.engine.lock().await;
    if matches!(
        engine.state(),
        watt_core::engine::EngineState::Running { .. }
    ) {
        return Err("请先停止加速再移除证书".into());
    }

    // 移除信任（可能触发 UAC 提权）。按当前证书 DER 精确删除，避免误删同名第三方根证书。
    let cert_path = ca_cert_file(&state);
    let remove_path = cert_path.clone();
    tokio::task::spawn_blocking(move || watt_cert::trust::remove_root_cert(&remove_path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;

    // 校验已移除后删除证书文件（对齐原实现）
    let path = cert_path;
    let installed =
        tokio::task::spawn_blocking(move || watt_cert::trust::is_root_cert_installed(&path))
            .await
            .map_err(|e| e.to_string())?;
    if !installed {
        let cert_dir = state.cert_dir();
        let _ = std::fs::remove_file(CaCertificate::cert_path(&cert_dir));
        let _ = std::fs::remove_file(CaCertificate::key_path(&cert_dir));
    }
    drop(engine);
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
    // 持 engine 锁完成「检查停止 → 生成 → 换内存 CA」全过程：与 engine_start
    // （同样先拿 engine 锁再读 CA）互斥，避免引擎用旧 CA 服务新证书文件。
    let engine = state.engine.lock().await;
    if matches!(
        engine.state(),
        watt_core::engine::EngineState::Running { .. }
    ) {
        return Err("请先停止加速再重新生成证书".into());
    }

    let cert_dir = state.cert_dir();
    // 旧 CA 的 DER 必须在保存新证书前取走：新证书会覆盖 cert.pem，之后无法再按
    // 指纹定位旧信任，只能退回按 CN 模糊删除（会误删同名第三方根证书）。
    let old_der = {
        let ca = state.ca.read().await;
        ca.cert_der.clone()
    };
    // 生成 + 私钥落盘（可能涉及权限调整）放阻塞线程
    let new_ca = tokio::task::spawn_blocking(move || {
        let ca = CaCertificate::generate().map_err(|e| e.to_string())?;
        ca.save(&cert_dir).map_err(|e| e.to_string())?;
        Ok::<Arc<CaCertificate>, String>(Arc::new(ca))
    })
    .await
    .map_err(|e| e.to_string())??;

    // 旧受信任根不会被新 CA 自动替换：按旧 DER 精确移除，避免旧根长期留信任库
    if let Err(e) = tokio::task::spawn_blocking(move || {
        watt_cert::trust::remove_root_cert_der(&old_der)
    })
    .await
    .map_err(|e| e.to_string())?
    {
        tracing::warn!("重新生成 CA 后清理旧信任失败（可手动卸载）: {e}");
    }

    let mut ca = state.ca.write().await;
    *ca = new_ca.clone();
    drop(ca);
    drop(engine);
    Ok(to_status(&new_ca, false))
}
