//! 启动预探测编排（对齐 doc/ip-probe-prefetch-plan.md §4.4/4.6）。
//!
//! 引擎 `start()` 成功后 spawn 本任务：对勾选项目域名的候选全集做 TCP+TLS
//! 握手探测，RTT 写入 [`ProbeCache`] 供竞速排序（`outbound::connect`）。
//! best-effort：任何失败都不影响引擎；整体预算超时即截断，
//! 探测不全时竞速按「已探测优先 + 未探测沉底」降级，行为仍正确。

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::outbound::{OutboundConnector, OutboundTarget};
use crate::probe_cache::{ProbeCache, ProbeSummary};
use watt_config::DomainRule;

/// 单候选探测超时（排序用途 2s 足够判死活；真实竞速超时由 target.timeout_ms 决定）
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(2);
/// 整体探测预算（跨全部域名）：到点即返回已有结果
const OVERALL_BUDGET: Duration = Duration::from_secs(12);
/// 域名间探测并发上限（16 域名 / 8 并发 ≈ 2 轮；避免串行时死候选把预算打满）
const HOST_CONCURRENCY: usize = 8;
/// 周期重探间隔（P2-a；与 CandidateHealth 的 DEMOTE_SECS 对齐，网络切换后约 1 分钟自愈）
const PROBE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// 每域名最多探测的候选数（防异常大候选列表）
const MAX_CANDIDATES_PER_HOST: usize = 16;

/// 从规则提取探测目标：每个规则取首个代表性域名（通配 `*.x.com` 取主域 `x.com`），
/// 用该规则的覆盖 IP / 转发域名 / 超时构造 target，保证探测与真实请求同层。
pub fn probe_targets_from_rules(rules: &[DomainRule]) -> Vec<OutboundTarget> {
    let mut seen = std::collections::HashSet::new();
    let mut targets = Vec::new();
    for rule in rules {
        let Some(host) = rule
            .match_domain_names
            .iter()
            .filter_map(|d| representative_domain(d))
            .find(|d| seen.insert(d.clone()))
        else {
            continue;
        };
        targets.push(OutboundTarget {
            host,
            port: 443,
            tls: true,
            // SNI 用 host 本身；SNI 覆盖（FakeServerName）场景 P1 可 refine
            tls_sni: None,
            tls_ignore_name_mismatch: rule.fields.tls_ignore_name_mismatch,
            override_ip: rule.fields.ip_address,
            forward_destination: rule
                .fields
                .forward_destination
                .clone()
                .or_else(|| rule.fields.destination.clone()),
            timeout_ms: rule.fields.timeout_ms,
        });
    }
    targets
}

/// 规则的单个匹配域名 → 探测用具体域名：
/// `*.example.com` → `example.com`（主域边缘代表）；具体域名原样；其余（空/纯通配）跳过
fn representative_domain(pattern: &str) -> Option<String> {
    let d = pattern.trim().trim_start_matches("*.").to_ascii_lowercase();
    (!d.is_empty() && d.contains('.') && !d.contains('*')).then_some(d)
}

/// 批量探测并写缓存：域名间有界并发（[`HOST_CONCURRENCY`]），逐域名
/// `probe_target`（内部候选再并发）。汇总摘要。
pub async fn run_probe_pass(
    connector: &Arc<OutboundConnector>,
    targets: &[OutboundTarget],
    cache: &Arc<ProbeCache>,
) -> ProbeSummary {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(HOST_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();

    for target in targets {
        let sem = semaphore.clone();
        let connector = Arc::clone(connector);
        let target = target.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let results = connector.probe_target(&target, CANDIDATE_TIMEOUT).await;
            (target.host, results)
        });
    }

    let mut total_candidates = 0usize;
    let mut total_ok = 0usize;
    let mut fastest: Option<u64> = None;
    while let Some(joined) = set.join_next().await {
        let Ok((host, results)) = joined else { continue };
        for (ip, rtt) in results.iter().take(MAX_CANDIDATES_PER_HOST) {
            total_candidates += 1;
            if let Some(ms) = rtt {
                total_ok += 1;
                fastest = Some(fastest.map_or(*ms, |f: u64| f.min(*ms)));
                cache.put(&host, *ip, *ms);
            }
        }
    }
    ProbeSummary {
        hosts: targets.len(),
        candidates: total_candidates,
        ok: total_ok,
        fastest_ms: fastest,
        finished: true,
    }
}

/// spawn 启动预探测任务（P2-a：首探 + 每 60s 周期重探；整体预算 + best-effort）。
/// 返回 JoinHandle，引擎 stop 时 abort；结果写 cache（含摘要），请求竞速与
/// UI 查询命令自动消费，无需等待本任务完成。
pub fn spawn_probe_task(
    connector: Arc<OutboundConnector>,
    targets: Vec<OutboundTarget>,
    cache: Arc<ProbeCache>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let count = targets.len();
        loop {
            let mut summary = tokio::time::timeout(
                OVERALL_BUDGET,
                run_probe_pass(&connector, &targets, &cache),
            )
            .await
            .unwrap_or_else(|_| {
                tracing::warn!("候选探测超预算（{OVERALL_BUDGET:?}），采用已探测部分");
                ProbeSummary {
                    hosts: count,
                    candidates: 0,
                    ok: 0,
                    fastest_ms: None,
                    finished: false,
                }
            });
            summary.hosts = summary.hosts.min(count);
            cache.record_summary(summary.clone());
            match summary.fastest_ms {
                Some(ms) if summary.finished => tracing::info!(
                    "候选探测完成：{}/{count} 域名，{}/{} 候选可达，最快 {ms}ms",
                    summary.hosts,
                    summary.ok,
                    summary.candidates
                ),
                Some(ms) => tracing::warn!(
                    "候选探测被预算截断：{}/{} 候选可达，最快 {ms}ms（其余按默认顺序竞速）",
                    summary.ok,
                    summary.candidates
                ),
                None => tracing::warn!(
                    "候选探测完成：{}/{count} 域名，无可达候选（竞速保持原行为）",
                    summary.hosts
                ),
            }
            tokio::time::sleep(PROBE_REFRESH_INTERVAL).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(match_names: &[&str], ip: Option<&str>, fwd: Option<&str>) -> DomainRule {
        let mut r = DomainRule::default();
        r.match_domain_names = match_names.iter().map(|s| s.to_string()).collect();
        r.fields.ip_address = ip.map(|s| s.parse().unwrap());
        r.fields.forward_destination = fwd.map(|s| s.to_string());
        r
    }

    #[test]
    fn representative_domain_variants() {
        assert_eq!(representative_domain("*.steamcommunity.com").as_deref(), Some("steamcommunity.com"));
        assert_eq!(representative_domain("github.com").as_deref(), Some("github.com"));
        assert_eq!(representative_domain("  GitHub.COM  ").as_deref(), Some("github.com"));
        assert_eq!(representative_domain(""), None);
        assert_eq!(representative_domain("*"), None);
        assert_eq!(representative_domain("*.com"), None); // 主域无点，跳过
    }

    #[test]
    fn probe_targets_from_rules_basic() {
        let rules = vec![
            rule(&["github.com", "api.github.com"], Some("20.205.243.166"), None),
            rule(&["*.steamcommunity.com"], None, Some("steamcommunity.rmbgame.net")),
            rule(&["translate.google.com"], None, None),
        ];
        let targets = probe_targets_from_rules(&rules);
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].host, "github.com");
        assert_eq!(targets[0].port, 443);
        assert!(targets[0].tls);
        assert_eq!(targets[0].override_ip.unwrap().to_string(), "20.205.243.166");
        // 通配取主域；转发域名透传
        assert_eq!(targets[1].host, "steamcommunity.com");
        assert_eq!(targets[1].forward_destination.as_deref(), Some("steamcommunity.rmbgame.net"));
        assert_eq!(targets[2].host, "translate.google.com");
    }

    #[test]
    fn probe_targets_dedup_across_rules() {
        // 两个规则都含 github.com → 只探测一次（前者优先，携带其覆盖 IP）
        let rules = vec![
            rule(&["github.com"], Some("140.82.112.4"), None),
            rule(&["github.com", "gist.github.com"], None, None),
        ];
        let targets = probe_targets_from_rules(&rules);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "github.com");
        assert_eq!(targets[0].override_ip.unwrap().to_string(), "140.82.112.4");
        assert_eq!(targets[1].host, "gist.github.com");
    }

    #[test]
    fn probe_targets_empty_rules() {
        assert!(probe_targets_from_rules(&[]).is_empty());
    }
}
