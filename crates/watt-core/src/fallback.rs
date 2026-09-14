//! 备用 IP 池（出站候选的应急兜底）
//!
//! # 背景
//!
//! 部分服务的权威 DNS 只返回**单个** A 记录，当该 IP 被网络阻断时会出现
//! 「规则 IP 失效 + DNS 解析结果同样不可达」的双重失败，表现为 500 连接失败。
//! 典型场景：`github.com` 的权威 DNS 在所有公共 DNS 上均只返回 `20.205.243.166`，
//! 而该 IP 在部分网络下被阻断；同期 GitHub 的其他入口 IP 却是可达的。
//!
//! 本模块为这类已知服务维护**备用 IP 列表**，作为并发竞速的额外候选来源。
//! 由于出站连接采用 happy-eyeballs 竞速，追加候选不会增加成功路径的延迟——
//! 谁先握手成功就用谁，失败的候选会被丢弃。
//!
//! # 数据来源
//!
//! GitHub 官方 `https://api.github.com/meta` 公布的 `web` / `raw` 段，
//! 取其中长期有效的单播地址（Azure `20.x` 段与 `140.82.112.0/20`）。
//! 列表按实测可达性排序，可达地址前置以减少无效连接开销。
//!
//! # 与「迁移一致性」的关系
//!
//! 这是**超出原版 C# 实现的容错增强**（原版同样依赖 DNS 结果，遇到同样网络
//! 状况会一并失败）。它只影响「所有常规候选都不可达」时的兜底路径，不改变
//! 常规解析成功场景下的出站行为。

use std::net::IpAddr;

/// GitHub 主站 / API / 页面（`*.github.com`、`github.com`）备用 IP。
/// 140.82.112.0/20 与 Azure 20.x 段，实测前置项稳定可达。
const GITHUB_WEB_IPS: &[&str] = &[
    "140.82.112.3",
    "140.82.113.3",
    "20.27.177.113",
    "140.82.114.3",
    "140.82.116.3",
    "20.200.245.247",
    "20.201.28.151",
    "20.233.83.145",
    "20.248.137.48",
    "20.29.134.23",
];

/// `*.githubusercontent.com`（raw / camo / objects 等）备用 IP（Fastly 段）。
const GITHUB_USERCONTENT_IPS: &[&str] = &[
    "185.199.108.133",
    "185.199.109.133",
    "185.199.110.133",
    "185.199.111.133",
];

/// `*.githubassets.com`（静态资源 CDN）备用 IP（Fastly 段）。
const GITHUB_ASSETS_IPS: &[&str] = &[
    "185.199.108.154",
    "185.199.109.154",
    "185.199.110.154",
    "185.199.111.154",
];

/// Google 翻译系（translate.google.com / translate.googleapis.com /
/// translate.gstatic.com）备用 IP（Google China 边缘段）。
/// 注意：该段不同 IP 覆盖的 SNI 集合不同（部分 IP 对个别域名 TLS 握手即被重置），
/// 出站竞速以「TLS 握手完成」为胜出条件，可自动跳过 SNI 不匹配的候选。
/// 2026-09 实测前置项：120.253.253.34 对三个域名均全证书验证通过。
const GOOGLE_TRANSLATE_IPS: &[&str] = &[
    "120.253.253.34",
    "120.253.253.98",
    "120.253.253.226",
    "203.208.49.99",
    "203.208.49.98",
    "203.208.49.66",
    "120.253.253.240",
    "120.253.253.250",
];

/// 返回该 host 的备用 IP 列表（无匹配时为空）。
///
/// 匹配按后缀进行，更具体的服务段优先：
/// `*.githubusercontent.com` / `*.githubassets.com` 各有独立 IP 段，
/// 不能与 `*.github.com` 混用。
pub fn fallback_ips(host: &str) -> Vec<IpAddr> {
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    let pool: &[&str] =
        if host == "translate.googleapis.com"
            || host.ends_with(".translate.googleapis.com")
            || host == "translate.gstatic.com"
            || host.ends_with(".translate.gstatic.com")
            || host == "translate.google.com"
            || host.ends_with(".translate.google.com")
        {
            GOOGLE_TRANSLATE_IPS
        } else if host == "githubusercontent.com" || host.ends_with(".githubusercontent.com") {
            GITHUB_USERCONTENT_IPS
        } else if host == "githubassets.com" || host.ends_with(".githubassets.com") {
            GITHUB_ASSETS_IPS
        } else if host == "github.com" || host.ends_with(".github.com") {
            GITHUB_WEB_IPS
        } else {
            return Vec::new();
        };

    pool.iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_web_hosts_hit_web_pool() {
        for host in [
            "github.com",
            "www.github.com",
            "api.github.com",
            "gist.github.com",
        ] {
            let ips = fallback_ips(host);
            assert!(!ips.is_empty(), "{host} 应有备用 IP");
            assert!(
                ips.iter().any(|ip| ip.to_string() == "140.82.112.3"),
                "{host} 应命中 GitHub 主站段"
            );
        }
    }

    #[test]
    fn test_usercontent_and_assets_use_own_pools() {
        let raw = fallback_ips("raw.githubusercontent.com");
        assert!(raw.iter().any(|ip| ip.to_string() == "185.199.108.133"));
        // 不得混入主站段
        assert!(!raw.iter().any(|ip| ip.to_string() == "140.82.112.3"));

        let assets = fallback_ips("github.githubassets.com");
        assert!(assets.iter().any(|ip| ip.to_string() == "185.199.108.154"));
        assert!(!assets.iter().any(|ip| ip.to_string() == "185.199.108.133"));
    }

    #[test]
    fn test_case_and_port_insensitive() {
        assert_eq!(fallback_ips("GitHub.com").len(), GITHUB_WEB_IPS.len());
        assert_eq!(fallback_ips("github.com:443").len(), GITHUB_WEB_IPS.len());
    }

    #[test]
    fn test_unrelated_host_has_no_fallback() {
        assert!(fallback_ips("example.com").is_empty());
        // 形似但非目标（防止后缀误命中）
        assert!(fallback_ips("notgithub.com").is_empty());
        // google.com 主站不命中翻译段（仅 translate.* 前缀）
        assert!(fallback_ips("www.google.com").is_empty());
    }

    #[test]
    fn test_google_translate_hosts_hit_translate_pool() {
        for host in [
            "translate.google.com",
            "translate.googleapis.com",
            "translate.gstatic.com",
        ] {
            let ips = fallback_ips(host);
            assert!(!ips.is_empty(), "{host} 应有备用 IP");
            assert!(
                ips.iter().any(|ip| ip.to_string() == "120.253.253.34"),
                "{host} 应命中 Google 翻译段"
            );
        }
    }
}
