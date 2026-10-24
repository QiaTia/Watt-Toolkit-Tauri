//! 启动预探测诊断（需真实网络，默认 ignore）：
//! `cargo test -p watt-core --test diag_probe -- --ignored --nocapture`
//!
//! 验证探测 → 缓存 → 竞速排序的端到端链路（对齐 doc/ip-probe-prefetch-plan.md §6）。

use std::sync::Arc;
use std::time::Duration;

use watt_core::outbound::{OutboundConnector, OutboundTarget};
use watt_core::probe_cache::ProbeCache;

fn tls_target(host: &str, override_ip: Option<&str>) -> OutboundTarget {
    OutboundTarget {
        host: host.to_string(),
        port: 443,
        tls: true,
        tls_sni: None,
        tls_ignore_name_mismatch: false,
        tls_skip_verify: false,
        override_ip: override_ip.map(|s| s.parse().unwrap()),
        forward_destination: None,
        timeout_ms: None,
    }
}

#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_github_probe_sort() {
    let dns = Arc::new(watt_core::http_relay::RelayDnsAdapter(Arc::new(
        watt_dns::DnsResolver::system(),
    )));
    let ob = OutboundConnector::new(dns, None);
    let target = tls_target("github.com", None);
    let cache = Arc::new(ProbeCache::new());

    // —— 1) 探测：输出 IP → RTT 排序表 ——
    let results = ob.probe_target(&target, Duration::from_secs(3)).await;
    assert!(!results.is_empty(), "github.com 无任何候选（DNS+fallback 均空）");
    let mut sorted = results.clone();
    sorted.sort_by_key(|(_, rtt)| rtt.unwrap_or(u64::MAX));
    println!("[diag] github.com 候选探测（按 RTT 升序）：");
    for (ip, rtt) in &sorted {
        println!("  {ip:20} rtt={}", rtt.map(|m| format!("{m}ms")).unwrap_or("失败".into()));
    }

    // —— 2) 写缓存并验证 sort_addrs 端到端 ——
    let mut ok = 0usize;
    for (ip, rtt) in &results {
        if let Some(ms) = rtt {
            cache.put("github.com", *ip, *ms);
            ok += 1;
        }
    }
    println!("[diag] 探测成功 {ok}/{}", results.len());
    assert!(ok > 0, "github.com 全候选探测失败（网络环境不支持），竞速应保持原行为");

    let mut addrs: Vec<_> = results.iter().map(|(ip, _)| std::net::SocketAddr::new(*ip, 443)).collect();
    cache.sort_addrs("github.com", &mut addrs);
    let first = addrs[0].ip();
    let first_rtt = cache.get("github.com", first).expect("首位候选应有探测结果");
    for a in &addrs[1..] {
        // None = 未探测，按规则沉底（在已探测之后）
        if let Some(rtt) = cache.get("github.com", a.ip()) {
            assert!(rtt >= first_rtt, "已探测候选未按 RTT 升序: {first_rtt}ms > {rtt}ms");
        }
    }
    println!("[diag] sort_addrs 首位 = {first} ({first_rtt}ms)，未探测沉底 ✓");

    // —— 3) 竞速消费：排序后 connect 应更快/同等（不做严格耗时断言，环境噪音大）——
    let ob2 = OutboundConnector::new(
        Arc::new(watt_core::http_relay::RelayDnsAdapter(Arc::new(
            watt_dns::DnsResolver::system(),
        ))),
        None,
    )
    .with_probe(cache.clone());
    let t0 = std::time::Instant::now();
    let r = ob2.connect(&target).await;
    println!("[diag] 择优后 connect: ok={} elapsed={:?}", r.is_ok(), t0.elapsed());
    assert!(r.is_ok(), "有探测成功的候选，connect 不应失败");
}

#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_probe_pass_concurrent_16_hosts() {
    // 复现真实启动场景：勾选项目 ≈ 16 域名，域名间有界并发后应在整体预算内跑完
    // （修复前串行遇死候选每域名等满超时，8s 预算必然截断）
    use std::sync::Arc;
    use watt_core::probe::{probe_targets_from_rules, run_probe_pass};

    let hosts = [
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "translate.google.com",
        "translate.googleapis.com",
        "translate.gstatic.com",
        "www.figma.com",
        "static.figma.com",
        "cdn.figma.com",
        "s3-alpha-sig.figma.com",
        "api.figma.com",
        "assets.twitch.tv",
        "settings-win.data.microsoft.com",
        "steamcommunity.com",
        "api.steampowered.com",
        "store.steampowered.com",
    ];
    let rules: Vec<watt_config::DomainRule> = hosts
        .iter()
        .map(|h| watt_config::DomainRule {
            match_domain_names: vec![h.to_string()],
            ..Default::default()
        })
        .collect();
    let targets = probe_targets_from_rules(&rules);
    assert_eq!(targets.len(), hosts.len());

    let connector = Arc::new(OutboundConnector::new(
        Arc::new(watt_core::http_relay::RelayDnsAdapter(Arc::new(
            watt_dns::DnsResolver::system(),
        ))),
        None,
    ));
    let cache = Arc::new(ProbeCache::new());

    let t0 = std::time::Instant::now();
    let summary = run_probe_pass(&connector, &targets, &cache).await;
    println!(
        "[diag] run_probe_pass(16 域名): hosts={} candidates={} ok={} fastest={:?} elapsed={:?}",
        summary.hosts,
        summary.candidates,
        summary.ok,
        summary.fastest_ms,
        t0.elapsed()
    );
    assert!(summary.finished, "并发探测应在预算内跑完");
    assert!(summary.ok > 0, "16 域名中应有可达候选");
}

#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_translate_probe() {
    // Google 翻译分组（有固定覆盖 IP 与 fallback 池），验证覆盖 IP 参与探测
    let dns = Arc::new(watt_core::http_relay::RelayDnsAdapter(Arc::new(
        watt_dns::DnsResolver::system(),
    )));
    let ob = OutboundConnector::new(dns, None);
    let target = tls_target("translate.google.com", Some("120.253.253.34"));
    let results = ob.probe_target(&target, Duration::from_secs(3)).await;
    println!("[diag] translate.google.com 候选数: {}", results.len());
    for (ip, rtt) in &results {
        println!("  {ip:20} rtt={}", rtt.map(|m| format!("{m}ms")).unwrap_or("失败".into()));
    }
    assert!(!results.is_empty());
}
