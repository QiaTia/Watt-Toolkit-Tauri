//! 引擎命令：启停 / 状态 / 流量统计。
//! 对齐原应用 IPC：AccelerateService.Operate / ProxyService 状态查询。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
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
    },
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
            EngineState::Error(message) => EngineStateDto::Error { message },
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
    params: EngineStartParams,
) -> Result<EngineStateDto, String> {
    // 解析监听 IP
    let listen_ip: IpAddr = match params.listen_ip.as_deref() {
        Some("") | None => "127.0.0.1".parse().unwrap(),
        Some(ip) => ip.parse().map_err(|_| format!("无效监听 IP: {ip}"))?,
    };

    // CA（若引擎在运行则不允许重新生成，此处仅读取）
    let ca: Arc<CaCertificate> = state.ca.read().await.clone();

    // DNS 设置转换
    let dns = DnsConfig {
        master_dns: params.dns.master_dns,
        use_doh: params.dns.use_doh,
        custom_doh_address: params.dns.custom_doh_address,
    };

    let https_port = params
        .https_port
        .unwrap_or(watt_config::constants::HTTPS_PORT);
    let forward_proxy_port = params
        .forward_proxy_port
        .unwrap_or(watt_config::constants::DEFAULT_HTTP_PROXY_PORT);

    let config = EngineConfig {
        mode: params.mode,
        listen_ip,
        https_port,
        http_port: params.http_port,
        forward_proxy_port,
        socks5_port: params.socks5_port,
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
    };

    let mut engine = state.engine.lock().await;
    engine.start(config).await.map_err(|e| e.to_string())?;
    Ok(engine.state().into())
}

#[tauri::command]
pub async fn engine_stop(state: tauri::State<'_, AppState>) -> Result<EngineStateDto, String> {
    let mut engine = state.engine.lock().await;
    engine.stop().await.map_err(|e| e.to_string())?;
    Ok(engine.state().into())
}

#[tauri::command]
pub async fn engine_get_state(state: tauri::State<'_, AppState>) -> Result<EngineStateDto, String> {
    let engine = state.engine.lock().await;
    Ok(engine.state().into())
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
