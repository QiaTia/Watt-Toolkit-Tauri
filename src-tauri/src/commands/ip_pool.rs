//! 动态 IP 池命令：从健康 DNS 解析 → 本地探测 → 写池；以及管理页的增删改查。
//!
//! 对齐用户需求「从健康 DNS 服务拿到 IP 列表，本地判断是否能用，更新到 IP 池」。
//! 全量刷新范围 = 当前**已勾选**的加速项目域名；单域名刷新/探测由 IP 池管理页驱动。
//!
//! 池是 `watt-core::ip_pool` 的进程级全局态，落盘 `{data_dir}/Settings/IpPool.json`。
//! 所有变更命令（保存/删除/清空/刷新）都会在写内存后立即落盘，保证重启后一致。

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
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

/* —————————————————————— 管理页 DTO —————————————————————— */

/// 池内单个域名（管理页列表行）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolDomainDto {
    pub host: String,
    /// 池内 IP（写入时的顺序，即上次刷新的 RTT 升序）
    pub ips: Vec<String>,
    /// 该条目最近一次写入的时刻（unix 毫秒）
    pub refreshed_at_ms: u64,
}

impl PoolDomainDto {
    fn from_entry(host: String, entry: watt_core::ip_pool::PoolEntry) -> Self {
        Self {
            host,
            ips: entry.all_ips().iter().map(|ip| ip.to_string()).collect(),
            refreshed_at_ms: entry.refreshed_at_ms,
        }
    }
}

/* —————————————————————— 内部工具 —————————————————————— */

fn pool_dir(state: &AppState) -> std::path::PathBuf {
    state.data_dir.join("Settings")
}

/// 落盘（best-effort：失败仅记日志，不影响本次内存态）
async fn persist(state: &AppState) {
    let path = pool_dir(state).join("IpPool.json");
    let _ = tokio::task::spawn_blocking(move || watt_core::ip_pool::save_to(&path)).await;
}

/// 域名规范化 + 校验：去协议/路径/端口/尾点，转小写，只允许 `[a-z0-9.-_]`。
///
/// 手输域名是最容易出错的一环（粘贴整条 URL、带通配符、带空格），
/// 这里统一在边界收口，避免脏 key 写进池（后缀匹配会把脏 key 变成永不命中的死数据）。
fn normalize_host(input: &str) -> Result<String, String> {
    let raw = input.trim();
    let lower = raw.to_ascii_lowercase();
    let stripped = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    // 去路径 / 查询，再去端口，再去尾点
    let host = stripped
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.');
    if host.is_empty() {
        return Err(format!("无效域名：{raw}"));
    }
    if host.contains('*') {
        return Err(format!("不支持通配符域名：{raw}"));
    }
    if !host.contains('.') {
        return Err(format!("域名需包含点号：{raw}"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("域名含非法字符：{raw}"));
    }
    Ok(host.to_string())
}

/// IP 列表解析：逐行（也容忍逗号/空格分隔）转 `IpAddr`，去重保序。
fn parse_ips(input: &[String]) -> Result<Vec<IpAddr>, String> {
    let mut out: Vec<IpAddr> = Vec::new();
    for chunk in input {
        for token in chunk.split(['\n', ',', ' ', '\t', '\r']) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let ip = IpAddr::from_str(token).map_err(|_| format!("无效 IP：{token}"))?;
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    Ok(out)
}

/* —————————————————————— 命令：全量刷新（原设置页入口） —————————————————————— */

/// 从健康 DNS 解析当前已勾选加速项目的域名，本地探测可用 IP 并更新动态 IP 池。
///
/// 返回逐域名结果（供 UI 展示「可用 N/M、最快 Xms、来源」）。
#[tauri::command]
pub async fn ip_pool_refresh(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<watt_core::ip_pool::RefreshHostResult>, String> {
    let dir = pool_dir(&state);
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
    let results = watt_core::ip_pool::refresh_hosts(&hosts, &resolvers, 443, PROBE_TIMEOUT).await;

    // 落盘（下次启动自动加载）
    persist(&state).await;

    let total_ok: usize = results.iter().map(|r| r.ok).sum();
    tracing::info!(
        "IP 池刷新完成：{} 域名，{} 个可用候选（共 {} 候选）",
        results.len(),
        total_ok,
        results.iter().map(|r| r.candidates).sum::<usize>()
    );

    Ok(results)
}

/* —————————————————————— 命令：管理页增删改查 —————————————————————— */

/// 内置备用池分组（编译期常量，只读）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuiltinPoolDto {
    pub pattern: String,
    pub note: String,
    pub ips: Vec<String>,
}

/// 加速域名 → IP 来源总览（管理页「加速域名总览」用）
///
/// 回答的是「这个域名实际会连哪些 IP」：内置加速服务为部分域写死了覆盖 IP
/// （如 Figma 的 CloudFront 段），其余靠动态池 / 内置备用池 / DNS 解析。
/// 与出站候选链（`outbound::resolve_candidates`）的顺序一致：
/// 覆盖 IP → 转发目标 → DNS → 动态池 → 内置备用池。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainPoolDto {
    /// 规则里的原始匹配模式（可能含 `*.`）
    pub pattern: String,
    /// 规范化后的域名（查询池用）
    pub host: String,
    /// 规则写死的覆盖 IP（`ip_address`）
    pub override_ips: Vec<String>,
    /// 动态池命中的 IP
    pub dynamic_ips: Vec<String>,
    /// 内置备用池命中的 IP
    pub builtin_ips: Vec<String>,
    /// 生效来源（有序）：override / dynamic / builtin / dns（dns 恒在末位）
    pub sources: Vec<String>,
}

/// 由规则构建「域名 → IP 来源」总览（纯函数，便于单测）
fn build_domain_overview(rules: &[watt_config::DomainRule]) -> Vec<DomainPoolDto> {
    /// 域名总数上限（异常大的规则集不该把页面撑爆）
    const MAX_DOMAINS: usize = 500;

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<DomainPoolDto> = Vec::new();

    for rule in rules {
        // 一条规则的覆盖 IP 对其全部域名共用（下面按域名克隆一份）
        let override_ip: Option<String> = rule.fields.ip_address.map(|ip| ip.to_string());

        for raw in rule
            .match_domain_names
            .iter()
            .chain(rule.listening_domain_names.iter())
        {
            let pattern = raw.trim().to_string();
            // URL 模式（含 `/`，如 maxcdn.bootstrapcdn.com/bootstrap）不是域名，跳过
            if pattern.is_empty() || pattern.contains('/') {
                continue;
            }
            let host = pattern
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if host.is_empty() || !host.contains('.') || !seen.insert(host.clone()) {
                continue;
            }

            let dynamic_ips: Vec<String> = watt_core::ip_pool::dynamic_ips(&host)
                .iter()
                .map(|ip| ip.to_string())
                .collect();
            let builtin_ips: Vec<String> = watt_core::fallback::fallback_ips(&host)
                .iter()
                .map(|ip| ip.to_string())
                .collect();

            let mut sources: Vec<String> = Vec::new();
            let override_ips: Vec<String> = override_ip.iter().cloned().collect();
            if !override_ips.is_empty() {
                sources.push("override".into());
            }
            if !dynamic_ips.is_empty() {
                sources.push("dynamic".into());
            }
            if !builtin_ips.is_empty() {
                sources.push("builtin".into());
            }
            // 任何域名最终都还有一条 DNS 解析候选（抗污染解析 + 竞速）
            sources.push("dns".into());

            out.push(DomainPoolDto {
                pattern,
                host,
                override_ips,
                dynamic_ips,
                builtin_ips,
                sources,
            });
            if out.len() >= MAX_DOMAINS {
                break;
            }
        }
        if out.len() >= MAX_DOMAINS {
            break;
        }
    }

    out.sort_by(|a, b| a.host.cmp(&b.host));
    out
}

/// 列出当前已勾选加速项目的全部域名及其 IP 来源
#[tauri::command]
pub async fn ip_pool_domain_overview(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<DomainPoolDto>, String> {
    let data_dir = state.data_dir.clone();
    tokio::task::spawn_blocking(move || {
        let settings_dir = data_dir.join("Settings");
        let settings = watt_config::settings::load_proxy_settings_in(&settings_dir)
            .map_err(|e| e.to_string())?;

        let cache_dir = data_dir.join("Accelerate");
        let catalog = watt_cloud::load_cached(Some(&cache_dir))
            .ok_or_else(|| "本地无加速项目缓存，请先在加速页获取项目列表".to_string())?
            .with_builtins();
        let rules = catalog.to_domain_rules(Some(&settings.enabled_accelerate_ids));

        Ok(build_domain_overview(&rules))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 列出版本内置的备用 IP 池（`watt-core::fallback` 的 7 组常量）
///
/// 这组 IP 随版本发布、不落盘、不可编辑；动态池无命中或候选全失效时，
/// 出站竞速会把它们作为兜底候选。管理页只做展示，避免用户误以为「内置池没生效」。
#[tauri::command]
pub fn ip_pool_builtin_list() -> Vec<BuiltinPoolDto> {
    watt_core::fallback::BUILTIN_POOL_GROUPS
        .iter()
        .map(|g| BuiltinPoolDto {
            pattern: g.pattern.to_string(),
            note: g.note.to_string(),
            ips: g.ips.iter().map(|ip| (*ip).to_string()).collect(),
        })
        .collect()
}

/// 列出池内全部域名（按域名升序）
#[tauri::command]
pub fn ip_pool_list() -> Result<Vec<PoolDomainDto>, String> {
    let mut list: Vec<PoolDomainDto> = watt_core::ip_pool::snapshot()
        .into_iter()
        .map(|(host, entry)| PoolDomainDto::from_entry(host, entry))
        .collect();
    list.sort_by(|a, b| a.host.cmp(&b.host));
    Ok(list)
}

/// 保存某域名的手工 IP 池（新增或覆盖；手工 IP 不随动态刷新丢失）
#[tauri::command]
pub async fn ip_pool_save_domain(
    state: tauri::State<'_, AppState>,
    host: String,
    ips: Vec<String>,
) -> Result<PoolDomainDto, String> {
    let host = normalize_host(&host)?;
    let parsed = parse_ips(&ips)?;
    if parsed.is_empty() {
        return Err("至少填写一个 IP".to_string());
    }
    watt_core::ip_pool::set_manual_entry(&host, parsed);
    persist(&state).await;
    let entry = watt_core::ip_pool::entry(&host).ok_or_else(|| "写入 IP 池失败".to_string())?;
    Ok(PoolDomainDto::from_entry(host, entry))
}

/// 删除某域名的 IP 池（该域名回退到内置备用池 / 系统 DNS）
#[tauri::command]
pub async fn ip_pool_remove_domain(
    state: tauri::State<'_, AppState>,
    host: String,
) -> Result<(), String> {
    let host = normalize_host(&host)?;
    watt_core::ip_pool::remove_entry(&host);
    persist(&state).await;
    Ok(())
}

/// 清空全部 IP 池
#[tauri::command]
pub async fn ip_pool_clear(state: tauri::State<'_, AppState>) -> Result<(), String> {
    watt_core::ip_pool::clear();
    persist(&state).await;
    Ok(())
}

/// 重新解析并探测单个域名（从 DNS 刷新该域名的池）
#[tauri::command]
pub async fn ip_pool_refresh_host(
    state: tauri::State<'_, AppState>,
    host: String,
) -> Result<watt_core::ip_pool::RefreshHostResult, String> {
    let host = normalize_host(&host)?;
    let dir = pool_dir(&state);
    let settings =
        watt_config::settings::load_proxy_settings_in(&dir).map_err(|e| e.to_string())?;
    let resolvers = build_resolvers(&settings.dns);

    let mut results =
        watt_core::ip_pool::refresh_hosts(std::slice::from_ref(&host), &resolvers, 443, PROBE_TIMEOUT).await;
    persist(&state).await;
    results
        .pop()
        .ok_or_else(|| format!("刷新 {host} 失败：无结果"))
}

/// 探测池内某域名的全部 IP（TCP + TLS 握手，与竞速同层判据）
///
/// 只读：不改池内容，返回逐 IP 的 RTT（None = 不可用），由 UI 决定是否移除。
#[tauri::command]
pub async fn ip_pool_probe_domain(
    host: String,
) -> Result<Vec<watt_core::ip_pool::IpProbeResult>, String> {
    let host = normalize_host(&host)?;
    let ips = watt_core::ip_pool::entry_ips(&host);
    if ips.is_empty() {
        return Ok(Vec::new());
    }

    let mut set = tokio::task::JoinSet::new();
    for ip in ips {
        let h = host.clone();
        set.spawn(async move {
            let rtt = watt_core::ip_pool::probe_ip(&h, ip, 443, PROBE_TIMEOUT).await;
            watt_core::ip_pool::IpProbeResult { ip, rtt_ms: rtt }
        });
    }
    let mut out: Vec<watt_core::ip_pool::IpProbeResult> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(v) = joined {
            out.push(v);
        }
    }
    // RTT 升序，未通过者沉底
    out.sort_by_key(|r| (r.rtt_ms.is_none(), r.rtt_ms.unwrap_or(u64::MAX)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_accepts_common_shapes() {
        assert_eq!(normalize_host("figma.com").unwrap(), "figma.com");
        assert_eq!(normalize_host("  FIGMA.com.  ").unwrap(), "figma.com");
        assert_eq!(normalize_host("https://api.figma.com/v1/x").unwrap(), "api.figma.com");
        assert_eq!(normalize_host("figma.com:443").unwrap(), "figma.com");
    }

    #[test]
    fn normalize_host_rejects_invalid() {
        assert!(normalize_host("").is_err());
        assert!(normalize_host("localhost").is_err());
        assert!(normalize_host("*.figma.com").is_err());
        assert!(normalize_host("http://a b.com").is_err());
    }

    #[test]
    fn parse_ips_dedups_and_splits() {
        let ips = parse_ips(&[
            "1.1.1.1\n2.2.2.2".into(),
            "1.1.1.1, 2606:4700::1111".into(),
            "   ".into(),
        ])
        .unwrap();
        assert_eq!(
            ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            vec!["1.1.1.1", "2.2.2.2", "2606:4700::1111"]
        );
    }

    #[test]
    fn parse_ips_rejects_garbage() {
        assert!(parse_ips(&["not-an-ip".into()]).is_err());
        assert!(parse_ips(&["1.2.3.256".into()]).is_err());
    }

    fn rule(domains: &[&str], ip: Option<&str>) -> watt_config::DomainRule {
        watt_config::DomainRule {
            match_domain_names: domains.iter().map(|d| (*d).to_string()).collect(),
            listening_domain_names: Vec::new(),
            order: 0,
            fields: watt_config::DomainRuleFields {
                ip_address: ip.map(|s| s.parse().unwrap()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn overview_marks_override_and_builtin_sources() {
        // figma 同时有覆盖 IP 与内置备用池
        let rules = vec![rule(&["*.figma.com"], Some("18.65.14.5"))];
        let list = build_domain_overview(&rules);
        assert_eq!(list.len(), 1);
        let d = &list[0];
        assert_eq!(d.pattern, "*.figma.com");
        assert_eq!(d.host, "figma.com");
        assert_eq!(d.override_ips, vec!["18.65.14.5"]);
        assert!(!d.builtin_ips.is_empty(), "figma 应命中内置备用池");
        assert_eq!(d.sources, vec!["override", "builtin", "dns"]);
    }

    #[test]
    fn overview_marks_dns_only_and_dedups() {
        // 无覆盖 IP、无备用池 → 仅 DNS；同域名重复出现只保留一条
        let rules = vec![
            rule(&["office.com", "outlook.com"], None),
            rule(&["Office.com"], None),
        ];
        let list = build_domain_overview(&rules);
        assert_eq!(
            list.iter().map(|d| d.host.as_str()).collect::<Vec<_>>(),
            vec!["office.com", "outlook.com"]
        );
        for d in &list {
            assert_eq!(d.sources, vec!["dns"], "{} 应仅走 DNS", d.host);
            assert_eq!(d.override_ips.len() + d.dynamic_ips.len() + d.builtin_ips.len(), 0);
        }
    }

    #[test]
    fn overview_skips_url_patterns_and_bare_names() {
        let rules = vec![rule(&["maxcdn.bootstrapcdn.com/bootstrap", "localhost"], None)];
        assert!(build_domain_overview(&rules).is_empty());
    }

    /// 诊断（真实数据，`#[ignore]`）：
    /// `WATT_DATA_DIR=<app_data_dir> cargo test -p watt-toolkit-app --lib -- --ignored overview_diag --nocapture`
    #[test]
    #[ignore]
    fn overview_diag_with_real_catalog() {
        let Ok(dir) = std::env::var("WATT_DATA_DIR") else {
            eprintln!("[diag] 未设置 WATT_DATA_DIR，跳过");
            return;
        };
        let data_dir = std::path::PathBuf::from(dir);
        let settings = watt_config::settings::load_proxy_settings_in(&data_dir.join("Settings"))
            .expect("读取 ProxySettings 失败");
        let catalog = watt_cloud::load_cached(Some(&data_dir.join("Accelerate")))
            .expect("无加速项目缓存")
            .with_builtins();
        let rules = catalog.to_domain_rules(Some(&settings.enabled_accelerate_ids));
        let list = build_domain_overview(&rules);

        let mut by_src: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for d in &list {
            for s in &d.sources {
                *by_src.entry(s.clone()).or_insert(0) += 1;
            }
        }
        let with_ip = list.iter().filter(|d| d.sources.len() > 1).count();
        println!(
            "[diag] domains={} withStaticOrPoolIp={} dnsOnly={}",
            list.len(),
            with_ip,
            list.len() - with_ip
        );
        println!("[diag] 来源计数: {by_src:?}");
        for d in list.iter().take(15) {
            println!(
                "[diag] {:<45} {:?} ov={} dyn={} bi={}",
                d.pattern,
                d.sources,
                d.override_ips.len(),
                d.dynamic_ips.len(),
                d.builtin_ips.len()
            );
        }
    }
}
