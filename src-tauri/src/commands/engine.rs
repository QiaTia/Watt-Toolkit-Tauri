//! 引擎命令：启停 / 状态 / 流量统计。
//! 对齐原应用 IPC：AccelerateService.Operate / ProxyService 状态查询。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tauri::Emitter;
use watt_cert::ca::CaCertificate;
use watt_config::{DnsSettings, DomainRule, ProxyMode, TwoLevelAgentSettings};
use watt_core::engine::{EngineConfig, EngineState};
use watt_dns::DnsConfig;

use crate::AppState;

/// 引擎启动参数（前端 → Rust）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStartParams {
    /// 代理模式
    pub mode: ProxyMode,
    /// 监听 IP（默认 127.0.0.1）
    pub listen_ip: Option<String>,
    /// HTTPS MITM 端口（默认 443）
    pub https_port: Option<u16>,
    /// HTTP→HTTPS 重定向端口
    pub http_port: Option<u16>,
    /// 正向代理端口（System/PAC/ProxyOnly 模式，默认 26501）
    pub forward_proxy_port: Option<u16>,
    /// SOCKS5 端口
    pub socks5_port: Option<u16>,
    #[serde(default)]
    pub enable_http_to_https: bool,
    #[serde(default)]
    pub two_level_agent: TwoLevelAgentSettings,
    #[serde(default)]
    pub dns: DnsSettings,
    #[serde(default)]
    pub server_side_proxy_token: Option<String>,
    #[serde(default)]
    pub rules: Vec<DomainRule>,
    /// 探测缓存落盘（P2，默认关）
    #[serde(default)]
    pub probe_cache_persist: bool,
    /// top-K 裁剪（P2，默认关= None）
    #[serde(default)]
    pub probe_top_k: Option<usize>,
    /// 终端（CLI）代理环境变量 + 证书注入（默认开：让 git/curl/npm/pip 也能走加速）
    #[serde(default = "default_true")]
    pub terminal_proxy_enable: bool,
}

fn default_true() -> bool {
    true
}

/// 引擎状态（Rust → 前端）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum EngineStateDto {
    Stopped,
    Starting,
    Running {
        started_at: chrono::DateTime<chrono::Utc>,
        mode: String,
    },
    Stopping,
    Error {
        message: String,
        /// 结构化错误分类（bindPort / accessSurface / hostsWrite / dnsInit / …）
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
}

/// 构建 DTO：错误分类来自 engine（`EngineState` 本身只带消息文本）
fn state_dto(engine: &watt_core::ProxyEngine) -> EngineStateDto {
    let mut dto: EngineStateDto = engine.state().into();
    if let EngineStateDto::Error { code, .. } = &mut dto {
        *code = engine.error_code().map(|c| c.as_str().to_string());
    }
    dto
}

impl From<EngineState> for EngineStateDto {
    fn from(value: EngineState) -> Self {
        match value {
            EngineState::Stopped => EngineStateDto::Stopped,
            EngineState::Starting => EngineStateDto::Starting,
            EngineState::Running { started_at, mode } => EngineStateDto::Running {
                started_at,
                mode: mode.as_str().to_string(),
            },
            EngineState::Stopping => EngineStateDto::Stopping,
            EngineState::Error(message) => EngineStateDto::Error {
                message,
                code: None,
            },
        }
    }
}

/// 流量统计（Rust → 前端）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowStatsDto {
    pub up_bytes: u64,
    pub down_bytes: u64,
}

#[tauri::command]
pub async fn engine_start(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
    params: EngineStartParams,
) -> Result<EngineStateDto, String> {
    // 解析监听 IP
    let listen_ip: IpAddr = match params.listen_ip.as_deref() {
        Some("") | None => "127.0.0.1".parse().unwrap(),
        Some(ip) => ip.parse().map_err(|_| format!("无效监听 IP: {ip}"))?,
    };

    // DNS 设置转换：有序列表优先，空列表时由旧三字段合成（兼容 v0.5.x 配置）。
    // `prefer_public_dns` 由 watt-core 按代理模式决定（Hosts 模式替换系统 DNS）。
    let dns = DnsConfig {
        resolver_servers: watt_dns::parse_server_list(&params.dns.resolver_servers),
        master_dns: params.dns.master_dns,
        use_doh: params.dns.use_doh,
        custom_doh_address: params.dns.custom_doh_address,
        before_dns_check: params.dns.before_dns_check,
        prefer_public_dns: false,
        strict: false,
    };

    // 端口 0 在 bind 语义里是「由系统分配随机端口」，而设置页清空端口输入框会写入 0。
    // 若不归一化：正向代理会监听随机端口，系统代理却写成 `127.0.0.1:0`（必断网）；
    // HTTPS/HTTP 端口同理。统一回退到各端口默认值。
    let https_port = params
        .https_port
        .filter(|p| *p > 0)
        .unwrap_or(watt_config::constants::HTTPS_PORT);
    let forward_proxy_port = params
        .forward_proxy_port
        .filter(|p| *p > 0)
        .unwrap_or(watt_config::constants::DEFAULT_HTTP_PROXY_PORT);
    let http_port = params.http_port.filter(|p| *p > 0);
    // 端口 0 在 bind 语义里是「由系统分配随机端口」，前端填写 0 时用户看到的是
    // 「已启用 SOCKS5」却永远连不上。统一回退默认端口。
    let socks5_port = params.socks5_port.map(|p| {
        if p == 0 {
            watt_config::constants::DEFAULT_SOCKS5_PROXY_PORT
        } else {
            p
        }
    });

    // 终端（CLI）接入面：仅当存在正向代理监听时注入代理变量；
    // 证书变量在所有模式下都注入（Hosts 模式终端仍需信任 MITM 根证书）。
    let terminal_proxy = params.terminal_proxy_enable.then(|| {
        let ca_pem = CaCertificate::cert_path(&state.cert_dir());
        watt_core::terminal_proxy::TerminalProxyPlan {
            backup_path: state
                .data_dir
                .join("Settings")
                .join("TerminalProxyEnv.backup.json"),
            proxy_url: (!matches!(params.mode, ProxyMode::Hosts))
                .then(|| watt_core::terminal_proxy::proxy_url(listen_ip, forward_proxy_port)),
            no_proxy: watt_core::terminal_proxy::default_no_proxy(),
            ca_pem: ca_pem.exists().then_some(ca_pem),
        }
    });

    // 证书操作（安装/卸载/重新生成）期间禁止启动引擎：提权对话框可能停留数十秒，
    // 不能让引擎带着「即将被替换的 CA」启动。try_lock 快速失败，避免 UI 长时间转圈。
    // 锁顺序固定为 cert_lock → engine：证书命令同样先拿 cert_lock 再检查引擎状态。
    let _cert_guard = state
        .cert_lock
        .try_lock()
        .map_err(|_| "证书操作进行中，请稍后重试".to_string())?;

    // 先拿 engine 锁再读 CA：与证书操作互斥，
    // 避免「读到旧 CA → 等锁 → 新 CA 已落盘」导致引擎用旧 CA 服务新证书文件。
    let mut engine = state.engine.lock().await;
    let ca: Arc<CaCertificate> = state.ca.read().await.clone();

    let config = EngineConfig {
        mode: params.mode,
        listen_ip,
        https_port,
        http_port,
        forward_proxy_port,
        socks5_port,
        enable_http_to_https: params.enable_http_to_https,
        // 脚本子系统已移除：以下字段保持引擎默认（仅代理域名，无脚本注入）
        only_enable_proxy_script: false,
        is_only_work_steam_browser: false,
        two_level_agent: params.two_level_agent,
        dns,
        server_side_proxy_token: params.server_side_proxy_token,
        rules: params.rules,
        scripts: Vec::new(),
        ca,
        hosts_path: None,
        // P2：探测缓存落盘（默认关；开启时路径为 {settings_dir}/probe-cache.json）
        probe_cache_path: params
            .probe_cache_persist
            .then(|| watt_config::settings::settings_dir().join("probe-cache.json")),
        probe_cache_persist: params.probe_cache_persist,
        probe_top_k: params.probe_top_k.filter(|k| *k > 0),
        terminal_proxy,
    };

    engine.start(config).await.map_err(|e| e.to_string())?;
    let dto = state_dto(&engine);
    drop(engine);
    // 同步托盘菜单文案并广播状态变更（使面板与托盘一致）
    crate::tray::sync_tray_label(&app, matches!(dto, EngineStateDto::Running { .. }));
    let _ = app.emit(crate::tray::ENGINE_STATE_EVENT, ());
    Ok(dto)
}

#[tauri::command]
pub async fn engine_stop(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<EngineStateDto, String> {
    let mut engine = state.engine.lock().await;
    engine.stop().await.map_err(|e| e.to_string())?;
    let dto = state_dto(&engine);
    drop(engine);
    crate::tray::sync_tray_label(&app, false);
    let _ = app.emit(crate::tray::ENGINE_STATE_EVENT, ());
    Ok(dto)
}

/// 最近一次候选探测摘要（UI「已择优」展示；None = 尚未探测或无规则）
#[tauri::command]
pub async fn engine_probe_summary(
    state: tauri::State<'_, AppState>,
) -> Result<Option<watt_core::probe_cache::ProbeSummary>, String> {
    let engine = state.engine.lock().await;
    Ok(engine.probe_summary())
}

#[tauri::command]
pub async fn engine_get_state(state: tauri::State<'_, AppState>) -> Result<EngineStateDto, String> {
    let engine = state.engine.lock().await;
    Ok(state_dto(&engine))
}

#[tauri::command]
pub async fn engine_get_stats(state: tauri::State<'_, AppState>) -> Result<FlowStatsDto, String> {
    let engine = state.engine.lock().await;
    let stats = engine.stats();
    Ok(FlowStatsDto {
        up_bytes: stats.up_bytes(),
        down_bytes: stats.down_bytes(),
    })
}
