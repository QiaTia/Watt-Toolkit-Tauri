//! 动态 IP 池真实链路诊断（`#[ignore]`，需联网）。
//!
//! 验证「健康 DNS 解析 → 逐 IP 本地 TCP+TLS 探测 → 写池」这条链路：
//! ```text
//! cargo test -p watt-core --test diag_ip_pool -- --ignored --nocapture
//! ```
//!
//! 解析器链与 `src-tauri/src/commands/ip_pool.rs::build_resolvers` 保持一致，
//! 用于判断内置公共 DoH（IP 直连端点）是否真的可用、以及整条刷新的实际耗时。

use std::sync::Arc;
use std::time::{Duration, Instant};

use watt_dns::{DnsConfig, DnsResolver};

/// 与命令层一致的解析器链（内置公共 DNS → 系统 DNS；不使用 DoH，见命令层注释）
fn resolvers() -> Vec<(String, Arc<DnsResolver>)> {
    let mut out: Vec<(String, Arc<DnsResolver>)> = Vec::new();
    for ip in ["223.5.5.5", "119.29.29.29", "8.8.8.8"] {
        out.push((
            format!("DNS {ip}"),
            Arc::new(DnsResolver::with_config(DnsConfig {
                master_dns: Some((*ip).to_string()),
                use_doh: false,
                custom_doh_address: None,
            })),
        ));
    }
    out.push(("系统 DNS".to_string(), Arc::new(DnsResolver::system())));
    out
}

/// 逐解析器测 www.figma.com 的解析耗时与结果——定位「刷新很慢」是否卡在解析层
#[tokio::test]
#[ignore]
async fn diag_resolver_latency_figma() {
    for (label, r) in resolvers() {
        let t0 = Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(8), r.resolve_clean("www.figma.com")).await;
        let dt = t0.elapsed();
        match res {
            Ok(Ok(ips)) => println!("[resolver] {label:<28} {:>7.0?}  -> {ips:?}", dt),
            Ok(Err(e)) => println!("[resolver] {label:<28} {:>7.0?}  -> ERR {e}", dt),
            Err(_) => println!("[resolver] {label:<28} {:>7.0?}  -> TIMEOUT", dt),
        }
    }
}

/// 端到端刷新：解析 figma 加速域 → 本地探测 → 写池
#[tokio::test]
#[ignore]
async fn diag_ip_pool_refresh_figma() {
    let hosts = vec![
        "www.figma.com".to_string(),
        "api.figma.com".to_string(),
        "static.figma.com".to_string(),
    ];
    let rs: Vec<Arc<DnsResolver>> = resolvers().into_iter().map(|(_, r)| r).collect();

    let t0 = Instant::now();
    let results =
        watt_core::ip_pool::refresh_hosts(&hosts, &rs, 443, Duration::from_secs(3)).await;
    println!("[diag-ip-pool] refresh_hosts 总耗时 {:?}", t0.elapsed());

    for r in &results {
        println!(
            "[diag-ip-pool] {} ok={}/{} source={:?} err={:?}",
            r.host, r.ok, r.candidates, r.source, r.error
        );
        for p in &r.ips {
            println!("               {} rtt={:?}", p.ip, p.rtt_ms);
        }
    }

    println!(
        "[diag-ip-pool] dynamic_ips(www.figma.com) = {:?}",
        watt_core::ip_pool::dynamic_ips("www.figma.com")
    );
    assert!(
        results.iter().any(|r| r.ok > 0),
        "三个 figma 域至少应有一个候选可用（否则池无法提供救援候选）"
    );
}
