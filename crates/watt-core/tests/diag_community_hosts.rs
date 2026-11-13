//! 社区 hosts 源真实链路诊断（拉取 → 解析 → 本地探测 → 并入池）。
//!
//! 默认忽略（需要网络，且结果取决于当前网络对 GitHub 的可达性）：
//! `cargo test -p watt-core --test diag_community_hosts -- --ignored --nocapture`

use std::time::Duration;

#[tokio::test]
#[ignore = "需要网络：真实拉取并探测社区 hosts 源"]
async fn diag_community_hosts_live() {
    let url = watt_config::constants::DEFAULT_COMMUNITY_HOSTS_URL;
    let outcome = watt_core::community_hosts::fetch_and_merge(url, 443, Duration::from_secs(3))
        .await
        .expect("拉取或探测失败");

    println!("{outcome:#?}");

    assert!(outcome.entries > 0, "源里应有条目");
    assert!(
        outcome.probed_ok > 0,
        "至少应有一个 IP 通过 TLS 探测（全灭通常说明本机网络不通 GitHub）"
    );
    assert!(outcome.ips_merged > 0, "探测通过后必须写进池");

    // 池里应能看到社区源写入的域名
    let github = watt_core::ip_pool::entry("github.com");
    println!("池中 github.com: {github:?}");
    assert!(
        github.map(|e| !e.ips.is_empty()).unwrap_or(false),
        "github.com 应已进入动态池"
    );
}

/// 回归验证：刷新 IP 池时必须保留池内已有的非 DNS 来源候选。
///
/// 修复前 `refresh_one` 用 `set_entry` 整体替换动态部分，社区源写入的 IP 会在
/// 每次手动刷新后消失。修复后池内动态 IP 一并参与探测，可达者保留。
///
/// 用一个已知可达的 GitHub 入口 IP 作为「社区源候选」的替身：先写进池，
/// 再跑一次真实刷新，断言它仍在新结果里。
#[tokio::test]
#[ignore = "需要网络：真实 DNS 解析 + TLS 探测"]
async fn diag_refresh_keeps_existing_pool_ips() {
    use std::sync::Arc;
    use std::time::Duration;

    let seed: std::net::IpAddr = "140.82.112.3".parse().unwrap();
    watt_core::ip_pool::clear();
    watt_core::ip_pool::add_dynamic_ips("github.com", &[seed], 8);

    let resolvers = vec![Arc::new(watt_dns::DnsResolver::system())];
    let results = watt_core::ip_pool::refresh_hosts(
        &["github.com".to_string()],
        &resolvers,
        443,
        Duration::from_secs(3),
    )
    .await;

    let r = results.first().expect("应有一个域名的结果");
    println!("{r:#?}");
    if r.ok == 0 {
        // 本机完全连不上 GitHub 时该断言无意义，直接跳过而不是误报失败
        eprintln!("本次网络不可达 GitHub，跳过断言");
        return;
    }
    assert!(
        r.ips.iter().any(|p| p.ip == seed),
        "池内已有候选应参与探测并被保留，实际: {:?}",
        r.ips.iter().map(|p| p.ip).collect::<Vec<_>>()
    );
    // 池里也应仍能查到
    assert!(
        watt_core::ip_pool::entry_ips("github.com").contains(&seed),
        "刷新后池内应保留该候选"
    );
}
