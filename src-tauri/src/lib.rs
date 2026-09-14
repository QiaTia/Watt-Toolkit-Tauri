//! Watt Toolkit Tauri 应用壳：状态装配 + 命令注册。
//!
//! 启动流程：初始化日志 → 首启迁移（旧版设置/CA PFX）→ 加载/生成 CA（数据目录）→ 装配 AppState → 注册命令。

pub mod commands;
pub mod migrate;

use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;
use watt_cert::ca::CaCertificate;
use watt_core::engine::ProxyEngine;

/// 全局应用状态（由 Tauri 管理）
pub struct AppState {
    /// 代理引擎（start/stop 需要 &mut，命令层用 Mutex 串行化）
    pub engine: tokio::sync::Mutex<ProxyEngine>,
    /// CA 证书（重新生成时替换）
    pub ca: tokio::sync::RwLock<Arc<CaCertificate>>,
    /// 应用数据目录（{AppData}/WattToolkit）
    pub data_dir: PathBuf,
    /// 首启迁移报告（旧版数据导入结果）
    pub migration: migrate::MigrationReport,
}

impl AppState {
    /// CA 存储目录：{data_dir}/Certificates
    pub fn cert_dir(&self) -> PathBuf {
        self.data_dir.join("Certificates")
    }
}

/// 解析应用数据目录（优先 Tauri app_data_dir，回退 watt-config 通用目录）
fn resolve_data_dir(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| watt_config::settings::app_data_dir())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 安装 rustls crypto provider（reqwest 使用 rustls-no-provider，不会自动安装；
    // 进程级全局、幂等，覆盖 watt-cloud / watt-core 所有 TLS 客户端）
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,watt_core=debug".into()),
        )
        .init();

    let app = tauri::Builder::default()
        .setup(|app| {
            let data_dir = resolve_data_dir(app.handle());
            std::fs::create_dir_all(&data_dir)?;

            // 首启迁移：旧版设置 + CA PFX 导入（PFX 成功后由 load_or_generate 加载）
            let migration = migrate::run_startup_migration(&data_dir);

            // CA 加载或生成
            let cert_dir = data_dir.join("Certificates");
            let ca = Arc::new(
                CaCertificate::load_or_generate(&cert_dir)
                    .map_err(|e| format!("CA 证书初始化失败: {e}"))?,
            );

            app.manage({
                // 兜底清理：上次进程被强杀 / 崩溃 / 开发期热重启时，hosts 标记块与系统代理
                // 是持久化的、而运行态记忆随进程消失，会残留「域名 → 127.0.0.1 但无人监听
                // 443」的黑洞（浏览器报连接被拒绝 / 找不到此网页）。此处仅清理确定属于本
                // 引擎的残留（hosts 标记块 + 指向本引擎端口的系统代理 / PAC）。
                let proxy_port =
                    watt_config::settings::load_proxy_settings_in(&data_dir.join("Settings"))
                        .unwrap_or_default()
                        .system_proxy_port;
                let engine = ProxyEngine::new();
                let cleaned = engine.cleanup_orphans(None, &[proxy_port]);
                if !cleaned.is_empty() {
                    tracing::warn!("启动清理残留代理状态: {}", cleaned.join(", "));
                }

                AppState {
                    engine: tokio::sync::Mutex::new(engine),
                    ca: tokio::sync::RwLock::new(ca),
                    data_dir,
                    migration,
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info::get_app_info,
            commands::engine::engine_start,
            commands::engine::engine_stop,
            commands::engine::engine_get_state,
            commands::engine::engine_get_stats,
            commands::cert::cert_get_status,
            commands::cert::cert_get_info,
            commands::cert::cert_install,
            commands::cert::cert_uninstall,
            commands::cert::cert_export_ca,
            commands::cert::cert_regenerate,
            commands::settings::settings_get_proxy,
            commands::settings::settings_save_proxy,
            commands::accelerate::accelerate_get_projects,
            commands::accelerate::accelerate_refresh,
            commands::accelerate::accelerate_set_enabled,
            commands::accelerate::accelerate_get_rules,
            commands::accelerate::accelerate_connectivity_test,
            commands::migrate::migration_get_report,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    // 退出清理：正常退出前停止引擎（摘 hosts + 取消系统代理 + 关监听），保证本机不留黑洞；
    // 若引擎已非运行态（例如运行中已被停过），则兜底摘除残留。
    app.run(|handle, event| {
        if let tauri::RunEvent::Exit = event {
            let state = handle.state::<AppState>();
            let port =
                watt_config::settings::load_proxy_settings_in(&state.data_dir.join("Settings"))
                    .map(|s| s.system_proxy_port)
                    .unwrap_or(watt_config::constants::DEFAULT_HTTP_PROXY_PORT);
            tauri::async_runtime::block_on(async {
                let mut engine = state.engine.lock().await;
                engine.shutdown(None, &[port]).await;
            });
        }
    });
}
