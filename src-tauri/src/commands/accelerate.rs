//! 加速项目与脚本命令：云端目录获取 / 勾选持久化 / 已安装脚本列表。
//!
//! 对齐原 IPC：AccelerateService.GetAllProjects / ProxyService 勾选保存 / Scripts 服务。

use serde::Serialize;
use watt_cloud::model::AccelerateCatalog;

use crate::AppState;

/// 加速项目目录响应（含来源标记，前端据此决定是否提示刷新）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccelerateCatalogDto {
    pub catalog: AccelerateCatalog,
    /// 数据来源：`cloud`（本次在线拉取）或 `cache`（离线降级）
    pub source: String,
}

/// 获取加速项目目录：优先云端，失败降级缓存，双失败返回错误。
/// 返回前注入内置分组（Google 翻译等，按 Id 去重），并随缓存落盘。
#[tauri::command]
pub async fn accelerate_get_projects(
    state: tauri::State<'_, AppState>,
) -> Result<AccelerateCatalogDto, String> {
    let client = watt_cloud::AccelerateClient::new();
    match client.fetch_catalog().await {
        Ok(catalog) => {
            let catalog = catalog.with_builtins();
            // 在线成功 → 更新本地缓存（异步落盘不阻塞响应）
            watt_cloud::save_cached(&catalog, Some(&state.data_dir.join("Accelerate")));
            Ok(AccelerateCatalogDto {
                catalog,
                source: "cloud".into(),
            })
        }
        Err(e) => {
            tracing::warn!(error = %e, "云端加速项目拉取失败，尝试本地缓存");
            let cache_dir = state.data_dir.join("Accelerate");
            watt_cloud::load_cached(Some(&cache_dir))
                .map(|catalog| {
                    let catalog = catalog.with_builtins();
                    AccelerateCatalogDto {
                        catalog,
                        source: "cache".into(),
                    }
                })
                .ok_or_else(|| format!("云端拉取失败且无本地缓存: {e}"))
        }
    }
}

/// 强制刷新：仅云端，成功后更新缓存。
#[tauri::command]
pub async fn accelerate_refresh(
    state: tauri::State<'_, AppState>,
) -> Result<AccelerateCatalogDto, String> {
    let catalog = watt_cloud::AccelerateClient::new()
        .fetch_catalog()
        .await
        .map_err(|e| e.to_string())?
        .with_builtins();
    watt_cloud::save_cached(&catalog, Some(&state.data_dir.join("Accelerate")));
    Ok(AccelerateCatalogDto {
        catalog,
        source: "cloud".into(),
    })
}

/// 保存用户勾选的加速项目 Id 集合（持久化到 ProxySettings）
#[tauri::command]
pub async fn accelerate_set_enabled(
    state: tauri::State<'_, AppState>,
    enabled_ids: Vec<String>,
) -> Result<(), String> {
    let dir = state.data_dir.join("Settings");
    let mut settings =
        watt_config::settings::load_proxy_settings_in(&dir).map_err(|e| e.to_string())?;
    settings.enabled_accelerate_ids = enabled_ids;
    watt_config::settings::save_proxy_settings_in(&dir, &settings).map_err(|e| e.to_string())
}

/// 由勾选 Id 集合构建引擎规则（目录取自本地缓存，需先调用 accelerate_get_projects）。
/// 缓存读取后同样注入内置分组（避免「仅走 get_rules 时内置分组规则缺失」）。
#[tauri::command]
pub async fn accelerate_get_rules(
    state: tauri::State<'_, AppState>,
    enabled_ids: Vec<String>,
) -> Result<Vec<watt_config::DomainRule>, String> {
    let cache_dir = state.data_dir.join("Accelerate");
    let catalog = watt_cloud::load_cached(Some(&cache_dir))
        .ok_or_else(|| "本地无加速项目缓存，请先获取加速项目列表".to_string())?
        .with_builtins();
    Ok(catalog.to_domain_rules(Some(&enabled_ids)))
}

/// 连通性测试单项结果
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityTestItem {
    pub host: String,
    pub ok: bool,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// 分组连通性测试：并发对每个域名发起完整 HTTPS GET 并计时。
/// 语义对齐原版 `NetworkTestService.TestOpenUrlAsync`：
/// 系统解析（含 hosts 加速劫持）+ 系统证书，收到任意状态码响应即算连通。
#[tauri::command]
pub async fn accelerate_connectivity_test(hosts: Vec<String>) -> Vec<ConnectivityTestItem> {
    let results =
        watt_core::connect_test::probe_https_all(&hosts, std::time::Duration::from_secs(25)).await;
    results
        .into_iter()
        .map(|r| ConnectivityTestItem {
            host: r.host,
            ok: r.ok,
            status: r.status,
            latency_ms: r.latency_ms,
            error: r.error,
        })
        .collect()
}
