//! 自动更新命令：检查 / 下载安装 / 更新设置。
//!
//! 关键设计（与规划书 §6 一致）：
//! - **不用前端 JS 插件**：多源顺序回退、引擎运行时的代理直连、安装前强制停引擎
//!   都只能在 Rust 侧做，因此检查与安装统一走这里的命令，前端只消费事件。
//! - **不能依赖 `endpoints` 数组做回退**：官方语义是「仅非 2XX 才试下一个」，
//!   而 GitHub 不可达通常表现为超时/连接重置，不会自动落到下一个源。这里逐个
//!   用单 endpoint 构造 updater 并设短超时，捕获错误后再试下一个。
//! - **安装前必须停引擎**：hosts 仍在劫持态就退出会留下「域名指向 127.0.0.1
//!   但无人监听 443」的全网黑洞，比更新失败严重得多。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{Emitter, Url};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::AppState;

/// 下载/安装进度事件（前端订阅）
pub const UPDATE_PROGRESS_EVENT: &str = "watt://update-progress";

/// 单次探测超时：GitHub 直连较慢，镜像通常更快
const DEFAULT_TIMEOUT_SECS: u64 = 8;
const CUSTOM_TIMEOUT_SECS: u64 = 6;

/// 更新源候选（None = tauri.conf.json 里配置的官方 GitHub 源）
#[derive(Clone, Debug)]
struct Candidate {
    endpoint: Option<Url>,
    use_proxy: bool,
    timeout: Duration,
}

/// 检查结果：只回传元信息，不持有 Update（安装时会重新取一次，状态无残留）
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfoDto {
    pub version: String,
    pub current_version: String,
    pub date: Option<String>,
    pub body: Option<String>,
    /// 实际命中的更新源（安装时优先复用，避免重新猜一遍）
    pub endpoint: Option<String>,
}

/// 下载/安装进度
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgressDto {
    /// downloading | installing
    pub stage: &'static str,
    pub downloaded: u64,
    pub total: Option<u64>,
}

fn engine_proxy_url(state: &AppState) -> Option<Url> {
    let settings =
        watt_config::settings::load_proxy_settings_in(&state.data_dir.join("Settings")).ok()?;
    let port = if settings.system_proxy_port == 0 {
        watt_config::constants::DEFAULT_HTTP_PROXY_PORT
    } else {
        settings.system_proxy_port
    };
    format!("http://127.0.0.1:{port}").parse().ok()
}

fn parse_endpoint(raw: &str) -> Result<Url, String> {
    let url: Url = raw
        .trim()
        .parse()
        .map_err(|e| format!("更新源地址非法: {e}"))?;
    // 远程源强制 HTTPS：latest.json 若走 http 可被中间人篡改（降级 / 喂旧版本）。
    // 安装包本身有 minisign 校验，但清单完整性仍需 TLS 保障。仅本机回环允许 http 便于测试。
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err("更新源必须是 HTTPS 链接（仅本机回环地址允许 http 用于测试）".to_string()),
    }
}

/// 组装候选源：自定义源 → 自定义源+代理 → 官方源 → 官方源+代理。
///
/// 只有引擎确实在运行、且不是 Hosts 模式（Hosts 模式不监听正向代理端口）时才加代理候选。
fn candidates(custom: Option<&str>, use_proxy: bool) -> Vec<Candidate> {
    let mut list = Vec::new();
    let custom_url = custom.and_then(|s| {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        match parse_endpoint(s) {
            Ok(url) => Some(url),
            Err(e) => {
                tracing::warn!("自定义更新源无效，忽略并回退官方源: {e}");
                None
            }
        }
    });
    if let Some(url) = custom_url.clone() {
        list.push(Candidate {
            endpoint: Some(url),
            use_proxy: false,
            timeout: Duration::from_secs(CUSTOM_TIMEOUT_SECS),
        });
    }
    if use_proxy {
        if let Some(url) = custom_url {
            list.push(Candidate {
                endpoint: Some(url),
                use_proxy: true,
                timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            });
        }
    }
    list.push(Candidate {
        endpoint: None,
        use_proxy: false,
        timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
    });
    if use_proxy {
        list.push(Candidate {
            endpoint: None,
            use_proxy: true,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        });
    }
    list
}

/// 引擎是否可作为更新请求的出口代理：运行中且模式不是 Hosts
async fn can_use_engine_proxy(state: &AppState) -> bool {
    let engine = state.engine.lock().await;
    match engine.state() {
        watt_core::engine::EngineState::Running { mode, .. } => {
            !matches!(mode, watt_config::ProxyMode::Hosts)
        }
        _ => false,
    }
}

fn build_updater(
    app: &tauri::AppHandle,
    candidate: &Candidate,
    proxy: Option<&Url>,
) -> Result<tauri_plugin_updater::Updater, String> {
    let mut builder = app.updater_builder().timeout(candidate.timeout);
    if let Some(endpoint) = candidate.endpoint.clone() {
        builder = builder
            .endpoints(vec![endpoint])
            .map_err(|e| format!("更新源配置无效: {e}"))?;
    }
    if candidate.use_proxy {
        if let Some(proxy) = proxy {
            builder = builder.proxy(proxy.clone());
        }
    } else {
        // 显式 no_proxy：避免继承系统代理（用户系统代理可能正指向本引擎的转发端口，
        // 引擎没跑时请求会直接失败）
        builder = builder.no_proxy();
    }
    builder.build().map_err(|e| format!("更新器初始化失败: {e}"))
}

/// 按候选顺序逐个尝试，返回首个成功拿到结果的 Update。
async fn find_update(
    app: &tauri::AppHandle,
    state: &AppState,
    custom: Option<&str>,
) -> Result<Option<(Update, Option<String>)>, String> {
    let use_proxy = can_use_engine_proxy(state).await;
    let proxy = use_proxy.then(|| engine_proxy_url(state)).flatten();
    let mut last_err: Option<String> = None;

    for candidate in candidates(custom, proxy.is_some()) {
        let updater = match build_updater(app, &candidate, proxy.as_ref()) {
            Ok(u) => u,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let url_repr = candidate.endpoint.as_ref().map(|u| u.to_string());
        match updater.check().await {
            Ok(Some(update)) => {
                tracing::info!(
                    version = %update.version,
                    endpoint = url_repr.as_deref().unwrap_or("config-default"),
                    via_proxy = candidate.use_proxy,
                    "发现新版本"
                );
                return Ok(Some((update, url_repr)));
            }
            Ok(None) => return Ok(None),
            Err(e) => {
                tracing::warn!(
                    endpoint = url_repr.as_deref().unwrap_or("config-default"),
                    via_proxy = candidate.use_proxy,
                    error = %e,
                    "更新源不可用"
                );
                last_err = Some(e.to_string());
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "没有可用的更新源".to_string()))
}

/// 检查更新。`endpoint` 为空 = 使用设置里的自定义源 / 官方源。
#[tauri::command]
pub async fn update_check(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    endpoint: Option<String>,
) -> Result<Option<UpdateInfoDto>, String> {
    let custom = match endpoint {
        Some(v) => Some(v),
        None => {
            watt_config::settings::load_update_settings_in(&state.data_dir.join("Settings"))
                .ok()
                .and_then(|s| s.endpoint)
        }
    };

    match find_update(&app, &state, custom.as_deref()).await? {
        None => Ok(None),
        Some((update, used)) => Ok(Some(UpdateInfoDto {
            version: update.version.clone(),
            current_version: update.current_version.clone(),
            date: update.date.map(|d| d.to_string()),
            body: update.body.clone(),
            endpoint: used,
        })),
    }
}

/// 停引擎 + 还原终端代理：更新前必须完成（缺一会让用户重启后全网黑洞）
async fn stop_engine_before_install(app: &tauri::AppHandle, state: &AppState) {
    let settings =
        watt_config::settings::load_proxy_settings_in(&state.data_dir.join("Settings"))
            .unwrap_or_default();
    let port = settings.system_proxy_port;
    let listen_ip = settings
        .system_proxy_ip
        .as_deref()
        .and_then(|s| s.parse().ok());

    {
        let mut engine = state.engine.lock().await;
        engine.shutdown(None, &[port], listen_ip).await;
    }
    // shutdown 在引擎非运行态时不会走 stop()，终端代理环境变量需单独还原
    let tp_backup = state
        .data_dir
        .join("Settings")
        .join("TerminalProxyEnv.backup.json");
    if watt_core::terminal_proxy::is_enabled(&tp_backup) {
        if let Err(e) = watt_core::terminal_proxy::disable(&tp_backup) {
            tracing::warn!("更新前还原终端代理环境变量失败: {e}");
        }
    }
    crate::tray::sync_tray_label(app, false);
    let _ = app.emit(crate::tray::ENGINE_STATE_EVENT, ());
}

/// 下载并安装。成功返回时进程通常已被安装器接管（Windows 静默安装后自动重启；
/// macOS / Linux 由本命令显式 `app.restart()` 拉起新版本）。
#[tauri::command]
pub async fn update_install(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    endpoint: Option<String>,
    expected_version: Option<String>,
) -> Result<(), String> {
    let custom = match endpoint {
        Some(v) => Some(v),
        None => {
            watt_config::settings::load_update_settings_in(&state.data_dir.join("Settings"))
                .ok()
                .and_then(|s| s.endpoint)
        }
    };

    // 重检拿 Update：引擎若仍在运行，find_update 可经引擎代理访问更新源；随后停引擎再下载。
    // 注意下载阶段引擎已停，安装包地址必须「直连 / 镜像」可达——代理回退只对检查有效，
    // 仅能经代理访问 GitHub 的网络请配置镜像源（见 doc/auto-update-plan.md 方案 B）。
    let Some((update, _)) = find_update(&app, &state, custom.as_deref()).await? else {
        return Err("没有可用的新版本".to_string());
    };

    // 版本一致性：检查与安装之间若发布了更高版本，避免静默装到与弹窗展示不同的版本
    if let Some(expected) = expected_version.as_deref() {
        if update.version != expected {
            return Err(format!(
                "更新版本已变化（{expected} → {}），请重新检查更新",
                update.version
            ));
        }
    }

    stop_engine_before_install(&app, &state).await;

    let emitter = app.clone();
    let downloaded = Arc::new(AtomicU64::new(0));
    let last_emit = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&downloaded);
    // 单调时钟节流：Instant 不会倒退，不受系统时钟回拨影响
    let start = Instant::now();
    let result = update
        .download_and_install(
            move |chunk, total| {
                let done = counter.fetch_add(chunk as u64, Ordering::Relaxed) + chunk as u64;
                let now = start.elapsed().as_millis() as u64;
                // 分片回调非常密集，按 100ms 节流，避免 IPC 洪水拖慢下载
                if now.saturating_sub(last_emit.load(Ordering::Relaxed)) >= 100
                    || total == Some(done)
                {
                    last_emit.store(now, Ordering::Relaxed);
                    let _ = emitter.emit(
                        UPDATE_PROGRESS_EVENT,
                        UpdateProgressDto {
                            stage: "downloading",
                            downloaded: done,
                            total,
                        },
                    );
                }
            },
            || {},
        )
        .await;

    match result {
        Ok(()) => {
            let _ = app.emit(
                UPDATE_PROGRESS_EVENT,
                UpdateProgressDto {
                    stage: "installing",
                    downloaded: downloaded.load(Ordering::Relaxed),
                    total: None,
                },
            );
            // Windows NSIS 安装器自行接管并重启；macOS / Linux 插件只替换文件，
            // 需显式 relaunch 才能运行新版本（tauri-plugin-updater 文档明确）。
            if !cfg!(target_os = "windows") {
                app.restart();
            }
            Ok(())
        }
        Err(e) => Err(format!("下载或安装失败: {e}")),
    }
}

/// 读取更新设置
#[tauri::command]
pub fn update_get_settings(
    state: tauri::State<'_, AppState>,
) -> Result<watt_config::settings::UpdateSettings, String> {
    watt_config::settings::load_update_settings_in(&state.data_dir.join("Settings"))
        .map_err(|e| e.to_string())
}

/// 保存更新设置（校验自定义源格式，避免写入一个永远失败的地址）
#[tauri::command]
pub fn update_save_settings(
    state: tauri::State<'_, AppState>,
    settings: watt_config::settings::UpdateSettings,
) -> Result<(), String> {
    if let Some(endpoint) = settings.endpoint.as_deref() {
        let endpoint = endpoint.trim();
        if !endpoint.is_empty() {
            parse_endpoint(endpoint)?;
        }
    }
    let dir = state.data_dir.join("Settings");
    watt_config::settings::save_update_settings_in(&dir, &settings).map_err(|e| e.to_string())
}

/// 用系统浏览器打开外部链接（WebView 内直接跳转会把整个界面导航走）
#[tauri::command]
pub fn open_external(url: String) -> Result<(), String> {
    let parsed = tauri::Url::parse(&url).map_err(|e| format!("链接非法: {e}"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err("只允许打开 http(s) 链接".to_string());
    }
    tauri_plugin_opener::open_url(url, None::<&str>).map_err(|e| e.to_string())
}

/// macOS Gatekeeper 绕过脚本：清除 .app 的隔离扩展属性（quarantine）。
///
/// 未签名 / 未公证的应用经自动更新替换后，首次打开可能被 Gatekeeper 拦截
/// （「已损坏」/「无法验证开发者」）。把此脚本复制到「终端」运行即可放行。
/// 路径取自当前可执行文件向上回溯到的 .app bundle，安装到非默认位置也准确。
/// 非 macOS 返回空串（前端按平台决定是否展示）。
#[tauri::command]
pub fn update_gatekeeper_script() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let exe = std::env::current_exe().map_err(|e| format!("无法定位应用路径: {e}"))?;
        // current_exe 形如 /Applications/Watt Toolkit.app/Contents/MacOS/Watt Toolkit，
        // 向上回溯到 .app bundle 根目录
        let mut cur = exe.as_path();
        let bundle = loop {
            if cur.extension().and_then(|e| e.to_str()) == Some("app") {
                break cur;
            }
            match cur.parent() {
                Some(parent) => cur = parent,
                None => break cur,
            }
        };
        let path = bundle.to_string_lossy();
        Ok(format!("sudo xattr -cr \"{path}\""))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(String::new())
    }
}
