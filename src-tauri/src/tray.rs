//! 系统托盘（Windows / macOS）：图标 + 右键菜单 + 左键唤起主窗口。
//!
//! # 交互约定
//! - **左键单击**托盘图标 → 显示并聚焦主窗口；
//! - **右键单击**（macOS 亦支持左键长按/双指）→ 弹出菜单：
//!   `网络加速 - 启动/停止`、`打开主面板`、`退出`；
//! - 主窗口关闭按钮仅隐藏窗口（见 `lib.rs` 的 `CloseRequested` 处理），
//!   引擎服务继续在后台运行；仅菜单「退出」才真正结束进程并清理。
//!
//! # 启动参数来源
//! 托盘「启动」不依赖前端，直接从持久化的 `ProxySettings` + 已勾选加速项目 Id
//! 复刻前端 `toggleEngine` 的装配逻辑（见 `ui/src/views/AcceleratorPage.vue`），
//! 保证托盘与面板启动的引擎配置一致。

use std::net::IpAddr;
use std::sync::Arc;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use watt_cert::ca::CaCertificate;
use watt_config::ProxyMode;
use watt_core::engine::{EngineConfig, EngineState};
use watt_dns::DnsConfig;

use crate::AppState;

/// 菜单项 Id：启停切换
const MENU_TOGGLE: &str = "tray-toggle-accelerate";
/// 菜单项 Id：打开主面板
const MENU_OPEN: &str = "tray-open-main";
/// 菜单项 Id：退出
const MENU_QUIT: &str = "tray-quit";

/// 引擎状态变更事件（后端 → 前端），前端据此刷新面板状态
pub const ENGINE_STATE_EVENT: &str = "watt://engine-state-changed";

/// 托盘句柄（由 Tauri 托管）：持有「启停」菜单项以便按引擎状态更新文案
pub struct TrayState {
    toggle: MenuItem<tauri::Wry>,
}

/// 创建托盘图标与菜单（在 `setup` 中调用）。
pub fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    let toggle = MenuItem::with_id(app, MENU_TOGGLE, "网络加速 - 启动", true, None::<&str>)?;
    let open = MenuItem::with_id(app, MENU_OPEN, "打开主面板", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, MENU_QUIT, "退出", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(app, &[&toggle, &sep1, &open, &sep2, &quit])?;

    let mut builder = TrayIconBuilder::with_id("watt-main-tray")
        .tooltip("Watt Toolkit")
        .menu(&menu)
        // 左键不弹菜单（改为唤起窗口），右键始终弹菜单
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_TOGGLE => {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    toggle_accelerate(handle).await;
                });
            }
            MENU_OPEN => show_main_window(app),
            MENU_QUIT => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // 左键抬起 → 唤起主窗口
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;

    app.manage(TrayState { toggle });
    Ok(())
}

/// 显示并聚焦主窗口（不存在则忽略）。
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// 按引擎运行态刷新托盘「启停」菜单项文案。
pub fn sync_tray_label(app: &AppHandle, running: bool) {
    if let Some(tray) = app.try_state::<TrayState>() {
        let text = if running {
            "网络加速 - 停止"
        } else {
            "网络加速 - 启动"
        };
        let _ = tray.toggle.set_text(text);
    }
}

/// 切换加速：运行中 → 停止；否则按保存的设置启动。完成后同步托盘文案并广播事件。
pub async fn toggle_accelerate(app: AppHandle) {
    let is_running = {
        let state = app.state::<AppState>();
        let engine = state.engine.lock().await;
        matches!(engine.state(), EngineState::Running { .. })
    };

    let outcome = if is_running {
        let state = app.state::<AppState>();
        let mut engine = state.engine.lock().await;
        match engine.stop().await {
            Ok(_) => Ok::<EngineState, String>(engine.state()),
            Err(e) => Err(e.to_string()),
        }
    } else {
        start_engine_from_settings(&app).await
    };

    match outcome {
        Ok(state) => {
            let running = matches!(state, EngineState::Running { .. });
            sync_tray_label(&app, running);
            let _ = app.emit(ENGINE_STATE_EVENT, ());
        }
        Err(e) => {
            tracing::error!("托盘切换加速失败: {e}");
            sync_tray_label(&app, false);
            let _ = app.emit(ENGINE_STATE_EVENT, ());
        }
    }
}

/// 从持久化设置 + 已勾选加速项目构建 `EngineConfig` 并启动引擎。
///
/// 复刻前端 `toggleEngine` 的参数装配（模式、端口、二级代理、DNS、规则），
/// 使托盘启动与面板启动完全一致。
pub async fn start_engine_from_settings(app: &AppHandle) -> Result<EngineState, String> {
    let state = app.state::<AppState>();

    let settings = watt_config::settings::load_proxy_settings_in(&state.data_dir.join("Settings"))
        .map_err(|e| e.to_string())?;

    // 勾选项目 → 引擎规则（取本地缓存目录；缺失时以空规则启动）
    let cache_dir = state.data_dir.join("Accelerate");
    let rules = watt_cloud::load_cached(Some(&cache_dir))
        .map(|catalog| {
            catalog
                .with_builtins()
                .to_domain_rules(Some(&settings.enabled_accelerate_ids))
        })
        .unwrap_or_default();

    let listen_ip: IpAddr = settings
        .system_proxy_ip
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let forward_proxy_port = if settings.system_proxy_port == 0 {
        watt_config::constants::DEFAULT_HTTP_PROXY_PORT
    } else {
        settings.system_proxy_port
    };

    // 终端（CLI）接入面：托盘恢复加速时同样按设置注入（与 engine_start 一致）
    let terminal_proxy = settings.terminal_proxy_enable.then(|| {
        let ca_pem = CaCertificate::cert_path(&state.cert_dir());
        watt_core::terminal_proxy::TerminalProxyPlan {
            backup_path: state
                .data_dir
                .join("Settings")
                .join("TerminalProxyEnv.backup.json"),
            proxy_url: (!matches!(settings.proxy_mode, ProxyMode::Hosts))
                .then(|| format!("http://127.0.0.1:{forward_proxy_port}")),
            no_proxy: watt_core::terminal_proxy::default_no_proxy(),
            ca_pem: ca_pem.exists().then_some(ca_pem),
        }
    });

    // 与 cert_regenerate 共用 engine 锁顺序：先锁引擎再读 CA，避免读到已被替换的旧 CA
    let mut engine = state.engine.lock().await;
    let ca: Arc<CaCertificate> = state.ca.read().await.clone();

    let config = EngineConfig {
        mode: settings.proxy_mode,
        listen_ip,
        https_port: watt_config::constants::HTTPS_PORT,
        http_port: if settings.enable_http_proxy_to_https {
            Some(80)
        } else {
            None
        },
        forward_proxy_port,
        socks5_port: if settings.socks5_proxy_enable {
            Some(if settings.socks5_proxy_port == 0 {
                watt_config::constants::DEFAULT_SOCKS5_PROXY_PORT
            } else {
                settings.socks5_proxy_port
            })
        } else {
            None
        },
        enable_http_to_https: settings.enable_http_proxy_to_https,
        only_enable_proxy_script: false,
        is_only_work_steam_browser: false,
        two_level_agent: settings.two_level_agent,
        dns: DnsConfig {
            master_dns: settings.dns.master_dns,
            use_doh: settings.dns.use_doh,
            custom_doh_address: settings.dns.custom_doh_address,
        },
        server_side_proxy_token: None,
        rules,
        scripts: Vec::new(),
        ca,
        hosts_path: None,
        // 托盘启动沿用 P2 默认关（不落盘、不裁剪）；如需开启经 engine_start 参数
        probe_cache_path: None,
        probe_cache_persist: false,
        probe_top_k: None,
        terminal_proxy,
    };

    engine.start(config).await.map_err(|e| e.to_string())?;
    Ok(engine.state())
}
