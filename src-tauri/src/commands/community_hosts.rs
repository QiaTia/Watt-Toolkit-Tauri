//! 社区维护的 GitHub Hosts 源：设置读写、立即拉取、后台定期拉取。
//!
//! 数据源默认 `https://hosts.gitcdn.top/hosts.json`，解析与合并逻辑在
//! [`watt_core::community_hosts`]。本层只负责「配置 + 调度 + 落盘」。
//!
//! 调度策略与更新检查一致，不常驻 sleep 到点：**每 30 分钟醒一次，判断是否到期**
//! （`last_fetch_ms + interval_hours`）。这样用户把间隔改成 1 小时也能及时生效，
//! 又不必在启动时阻塞等待网络。失败后退避 1 小时，避免不可达网络下每半小时刷日志。

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use watt_config::CommunityHostsSettings;

use crate::AppState;

/// 探测用端口（社区源给的是 HTTPS 入口）
const PROBE_PORT: u16 = 443;
/// 单候选探测超时
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// 后台检查周期
const TICK: Duration = Duration::from_secs(30 * 60);
/// 失败后的重试间隔（内存态，不落盘）
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60 * 60);
/// 启动后首次拉取的延迟：避开 CA 生成 / 迁移 / 池加载的启动高峰
const STARTUP_DELAY: Duration = Duration::from_secs(20);

/// 前端可编辑字段。
///
/// `last_fetch_ms` / `last_error` 由后端维护，不接受前端回传：前端手里的值可能是
/// 几分钟前的快照，直接覆盖会把后台刚写入的结果冲掉。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommunityHostsForm {
    pub enabled: bool,
    pub url: String,
    pub interval_hours: u64,
}

fn settings_dir(state: &AppState) -> PathBuf {
    state.data_dir.join("Settings")
}

/// 校验源地址：必须 HTTPS（回环允许 http，便于自建/本地测试）
fn validate_url(raw: &str) -> Result<String, String> {
    let url = raw.trim();
    if url.is_empty() {
        return Err("源地址不能为空".into());
    }
    let parsed = tauri::Url::parse(url).map_err(|e| format!("源地址非法: {e}"))?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    match parsed.scheme() {
        "https" => Ok(parsed.to_string()),
        "http" if loopback => Ok(parsed.to_string()),
        _ => Err("源地址必须是 HTTPS（仅本机回环允许 http 用于测试）".into()),
    }
}

#[tauri::command]
pub fn community_hosts_get_settings(
    state: tauri::State<'_, AppState>,
) -> Result<CommunityHostsSettings, String> {
    watt_config::settings::load_community_hosts_settings_in(&settings_dir(&state))
        .map_err(|e| e.to_string())
}

/// 保存设置，返回保存后的完整设置（含后端维护字段）
#[tauri::command]
pub fn community_hosts_save_settings(
    state: tauri::State<'_, AppState>,
    form: CommunityHostsForm,
) -> Result<CommunityHostsSettings, String> {
    let dir = settings_dir(&state);
    let mut cfg =
        watt_config::settings::load_community_hosts_settings_in(&dir).map_err(|e| e.to_string())?;
    cfg.enabled = form.enabled;
    cfg.url = validate_url(&form.url)?;
    cfg.interval_hours = form.interval_hours;
    watt_config::settings::save_community_hosts_settings_in(&dir, &cfg)
        .map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// 立即拉取（手动触发；失败时把原因写进设置供 UI 展示）
#[tauri::command]
pub async fn community_hosts_refresh(
    state: tauri::State<'_, AppState>,
) -> Result<watt_core::community_hosts::FetchOutcome, String> {
    run_refresh(&state.data_dir).await
}

/// 拉取一次并落盘（手动命令与后台任务共用）。
///
/// 失败不抛给调用方之外的任何地方：池保持原样，只把原因记进 `last_error`。
pub(crate) async fn run_refresh(data_dir: &Path) -> Result<watt_core::community_hosts::FetchOutcome, String> {
    let dir = data_dir.join("Settings");
    let mut cfg =
        watt_config::settings::load_community_hosts_settings_in(&dir).map_err(|e| e.to_string())?;

    let result =
        watt_core::community_hosts::fetch_and_merge(&cfg.url, PROBE_PORT, PROBE_TIMEOUT).await;

    match result {
        Ok(outcome) => {
            cfg.last_fetch_ms = outcome.fetched_at_ms;
            cfg.last_error = None;
            if let Err(e) = watt_config::settings::save_community_hosts_settings_in(&dir, &cfg) {
                tracing::warn!(error = %e, "保存社区源设置失败");
            }
            // 池落盘：下次启动无需等拉取就有候选
            let pool_path = dir.join("IpPool.json");
            let _ = tokio::task::spawn_blocking(move || watt_core::ip_pool::save_to(&pool_path)).await;
            Ok(outcome)
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(source = %cfg.url, error = %msg, "社区 hosts 源拉取失败");
            cfg.last_error = Some(msg.clone());
            if let Err(save_err) =
                watt_config::settings::save_community_hosts_settings_in(&dir, &cfg)
            {
                tracing::warn!(error = %save_err, "保存社区源设置失败");
            }
            Err(msg)
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 是否到期（`interval_hours == 0` 表示只在手动触发时拉取）
fn is_due(cfg: &CommunityHostsSettings) -> bool {
    if cfg.interval_hours == 0 || !cfg.enabled {
        return false;
    }
    if cfg.last_fetch_ms == 0 {
        return true;
    }
    let interval_ms = cfg.interval_hours.saturating_mul(3_600_000);
    now_ms().saturating_sub(cfg.last_fetch_ms) >= interval_ms
}

/// 后台定期拉取循环（由 `lib.rs` 的 setup 启动，进程生命周期内常驻）
pub async fn spawn_refresh_loop(data_dir: PathBuf) {
    tokio::time::sleep(STARTUP_DELAY).await;
    let mut retry_after: Option<std::time::Instant> = None;

    loop {
        let due = retry_after.map(|t| std::time::Instant::now() >= t).unwrap_or(true);
        if due {
            let dir = data_dir.join("Settings");
            let cfg = watt_config::settings::load_community_hosts_settings_in(&dir).ok();
            if let Some(cfg) = cfg {
                if is_due(&cfg) {
                    match run_refresh(&data_dir).await {
                        Ok(o) => {
                            tracing::info!(
                                hosts = o.hosts_touched,
                                ips = o.ips_merged,
                                "社区 hosts 源定期更新完成"
                            );
                            retry_after = None;
                        }
                        Err(_) => {
                            // 失败退避：不可达网络下不该每 30 分钟重试一次
                            retry_after = Some(std::time::Instant::now() + RETRY_AFTER_FAILURE);
                        }
                    }
                }
            }
        }
        tokio::time::sleep(TICK).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_must_be_https_except_loopback() {
        assert!(validate_url("https://hosts.gitcdn.top/hosts.json").is_ok());
        assert!(validate_url("http://127.0.0.1:8080/hosts.json").is_ok());
        // 明文远程源可被中间人篡改，至少能在池里塞入错误候选
        assert!(validate_url("http://hosts.gitcdn.top/hosts.json").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("").is_err());
    }

    fn cfg(enabled: bool, interval_hours: u64, last_fetch_ms: u64) -> CommunityHostsSettings {
        CommunityHostsSettings {
            enabled,
            url: "https://hosts.gitcdn.top/hosts.json".into(),
            interval_hours,
            last_fetch_ms,
            last_error: None,
        }
    }

    /// 真实链路：拉取 → 探测 → 写设置 → 落盘池（需网络）
    #[tokio::test]
    #[ignore = "需要网络：真实拉取并落盘"]
    async fn diag_run_refresh_persists() {
        let data_dir =
            std::env::temp_dir().join(format!("watt-community-{}", std::process::id()));
        let dir = data_dir.join("Settings");
        std::fs::create_dir_all(&dir).unwrap();

        let outcome = run_refresh(&data_dir).await.expect("拉取失败");
        println!("{outcome:#?}");

        assert!(outcome.ips_merged > 0, "应至少写入一个 IP");
        let cfg = watt_config::settings::load_community_hosts_settings_in(&dir).unwrap();
        assert!(cfg.last_fetch_ms > 0, "成功后必须记录拉取时刻");
        assert!(cfg.last_error.is_none(), "成功时不应残留错误");
        assert!(dir.join("IpPool.json").exists(), "池必须落盘");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn due_logic() {
        // 从未拉取 → 到期
        assert!(is_due(&cfg(true, 24, 0)));
        // 刚拉过 → 未到期
        assert!(!is_due(&cfg(true, 24, now_ms())));
        // 间隔 0 = 仅手动
        assert!(!is_due(&cfg(true, 0, 0)));
        // 关闭后即使从未拉取也不拉
        assert!(!is_due(&cfg(false, 24, 0)));
        // 超过间隔 → 到期
        let old = now_ms().saturating_sub(25 * 3_600_000);
        assert!(is_due(&cfg(true, 24, old)));
    }
}
