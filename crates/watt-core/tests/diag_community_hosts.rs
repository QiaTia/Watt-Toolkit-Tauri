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
