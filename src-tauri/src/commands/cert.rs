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
    /// 非致命告警（如重新生成后旧信任未能清除），供 UI 明确提示
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
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
        warning: None,
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

/// 信任存储诊断：「装不上 / 装了不生效」时的一次性自查
///
/// 平台侧要 spawn `security`/`whoami`，必须离开 tokio worker。
/// 诊断只读取状态，不写入任何内容，可随时点击。
#[tauri::command]
pub async fn cert_diagnose(
    state: tauri::State<'_, AppState>,
) -> Result<watt_cert::TrustDiagnostics, String> {
    let path = ca_cert_file(&state);
    tokio::task::spawn_blocking(move || watt_cert::diagnose(&path))
        .await
        .map_err(|e| format!("诊断任务异常: {e}"))
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
    // 提权对话框可能停留数十秒：期间 engine_start/tray 的 try_lock 会快速失败
    let _cert_guard = state.cert_lock.lock().await;
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
    // 串行化证书操作；engine_start/tray 持同一把锁的 try_lock，故可以安全地在
    // 提权（UAC/钥匙串对话框，最长 120s）期间释放 engine 锁，避免阻塞其他引擎查询。
    let _cert_guard = state.cert_lock.lock().await;
    {
        let engine = state.engine.lock().await;
        if matches!(
            engine.state(),
            watt_core::engine::EngineState::Running { .. }
        ) {
            return Err("请先停止加速再移除证书".into());
        }
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
    // 持 cert_lock 贯穿「检查停止 → 生成 → 清理旧信任 → 换内存 CA」：
    // engine_start/tray 用同一把锁的 try_lock 快速失败，故无需长期占用 engine 锁
    // （旧的实现会在 UAC 弹窗的 120s 内一直阻塞引擎命令）。
    let _cert_guard = state.cert_lock.lock().await;
    {
        let engine = state.engine.lock().await;
        if matches!(
            engine.state(),
            watt_core::engine::EngineState::Running { .. }
        ) {
            return Err("请先停止加速再重新生成证书".into());
        }
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

    // 旧受信任根不会被新 CA 自动替换：按旧 DER 精确移除，避免旧根长期留信任库。
    // 删除失败不阻断轮换（新 CA 已落盘），但必须把失败传给 UI —— 否则用户会以为
    // 旧根已清理，继续在新旧两张受信任根并存的状态下运行。
    let warning =
        match tokio::task::spawn_blocking(move || watt_cert::trust::remove_root_cert_der(&old_der))
            .await
        {
            Ok(Ok(())) => None,
            Ok(Err(e)) => {
                tracing::warn!("重新生成 CA 后清理旧信任失败（可手动卸载）: {e}");
                Some(format!("旧证书信任未能自动移除，请手动删除旧根证书：{e}"))
            }
            Err(e) => {
                tracing::warn!("重新生成 CA 后清理旧信任任务异常: {e}");
                Some(format!("旧证书信任清理任务异常：{e}"))
            }
        };

    let mut ca = state.ca.write().await;
    *ca = new_ca.clone();
    drop(ca);
    let mut status = to_status(&new_ca, false);
    status.warning = warning;
    Ok(status)
}
