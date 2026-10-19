//! 动态 IP 池命令：从健康 DNS 解析 → 本地探测 → 写池。
//!
//! 对齐用户需求「设置页点击后自动从健康 DNS 服务拿到 IP 列表，本地判断是否能用，
//! 更新到 IP 池」。刷新范围 = 当前**已勾选**的加速项目域名。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use watt_dns::{DnsConfig, DnsResolver};

use crate::AppState;

/// 刷新用解析器优先级：用户配置的 DNS（仅 IP 字面量）→ 内置公共 DNS（UDP）
/// → 系统 DNS。首个返回非空可用地址者胜出。
///
/// 注：**不使用 DoH**。`watt-dns` 的 DoH 只接受 IP 字面量端点，而 hickory 解析该
/// URL 时实测报 `bad dns_name`（`https://223.5.5.5/dns-query` 直接失败）；域名型
/// 端点又被 `parse_doh_url` 拒绝——两条路都不可用，故一律走 UDP/系统解析。
/// `1.1.1.1` 在本网络实测 UDP 需 ~6s（Cloudflare 多被阻断），一并剔除以免拖慢刷新。
const PUBLIC_DNS_IPS: &[&str] = &["223.5.5.5", "119.29.29.29", "8.8.8.8"];

/// 单次刷新最多处理的域名数（防异常大的规则集把一次点击拖得过久）
const MAX_HOSTS: usize = 64;
/// 单候选探测超时（握手用途，3s 足够判死活）
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// 构建解析器链
fn build_resolvers(dns: &watt_config::DnsSettings) -> Vec<Arc<DnsResolver>> {
    let mut out: Vec<Arc<DnsResolver>> = Vec::new();

    // 1. 用户配置的 DNS（仅当为 IP 字面量时生效；域名型 / DoH 不适用于本链路）
    if let Some(master) = dns.master_dns.as_deref().filter(|s| !s.is_empty()) {
        if master.parse::<IpAddr>().is_ok() {
            out.push(Arc::new(DnsResolver::with_config(DnsConfig {
                master_dns: Some(master.to_string()),
                use_doh: false,
                custom_doh_address: None,
            })));
        }
    }

    // 2. 内置公共 DNS（UDP）
    for ip in PUBLIC_DNS_IPS {
        out.push(Arc::new(DnsResolver::with_config(DnsConfig {
            master_dns: Some((*ip).to_string()),
            use_doh: false,
            custom_doh_address: None,
        })));
    }

    // 3. 系统 DNS（最终兜底）
    out.push(Arc::new(DnsResolver::system()));
    out
}

/// 从健康 DNS 解析当前已勾选加速项目的域名，本地探测可用 IP 并更新动态 IP 池。
///
/// 返回逐域名结果（供 UI 展示「可用 N/M、最快 Xms、来源」）。
#[tauri::command]
pub async fn ip_pool_refresh(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<watt_core::ip_pool::RefreshHostResult>, String> {
    let dir = state.data_dir.join("Settings");
    let settings =
        watt_config::settings::load_proxy_settings_in(&dir).map_err(|e| e.to_string())?;

    // 已勾选项目 → 规则 → 待刷新域名
    let cache_dir = state.data_dir.join("Accelerate");
    let catalog = watt_cloud::load_cached(Some(&cache_dir))
        .ok_or_else(|| "本地无加速项目缓存，请先在加速页获取项目列表".to_string())?
        .with_builtins();
    let rules = catalog.to_domain_rules(Some(&settings.enabled_accelerate_ids));
    let hosts: Vec<String> = watt_core::ip_pool::hosts_from_rules(&rules)
        .into_iter()
        .take(MAX_HOSTS)
        .collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    let resolvers = build_resolvers(&settings.dns);
    let results =
        watt_core::ip_pool::refresh_hosts(&hosts, &resolvers, 443, PROBE_TIMEOUT).await;

    // 落盘（下次启动自动加载）
    watt_core::ip_pool::save_to(&dir.join("IpPool.json"));

    let total_ok: usize = results.iter().map(|r| r.ok).sum();
    tracing::info!(
        "IP 池刷新完成：{} 域名，{} 个可用候选（共 {} 候选）",
        results.len(),
        total_ok,
        results.iter().map(|r| r.candidates).sum::<usize>()
    );

    Ok(results)
}
