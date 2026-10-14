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

/// Figma 全系（www / static / cdn / s3-alpha-sig / api）备用 IP：CloudFront
/// 任播边缘段。2026-10 实测：任意 99.86.x 边缘 IP 凭 SNI + Host 对全部
/// figma.com 加速域均出具有效证书（静态资源经覆盖 IP 取回内容与直连一致）。
/// 99.86.24.5 实测不可达，不入池；个别 IP 失效由竞速自动跳过。
const FIGMA_CF_IPS: &[&str] = &[
    "99.86.18.30",
    "99.86.18.5",
    "99.86.18.28",
    "99.86.18.67",
    "99.86.19.5",
    "99.86.20.5",
    "99.86.21.5",
    "99.86.22.5",
    "99.86.23.5",
];

/// `api.figma.com` 的 AWS Global Accelerator 任播段（原生路径，实测最快）。
/// 该段仅对 api.figma.com 有效（GA 任播 IP 按加速器绑定），只对 api 域返回。
const FIGMA_API_GA_IPS: &[&str] = &[
    "13.35.190.56",
    "13.35.190.115",
    "13.35.190.109",
    "13.35.190.39",
];

/// `errors.figma.com`（Sentry 错误上报）与 `s3-alpha-sig.figma.com`（预览图）
/// 的 AWS S3 段。2026-10 实测：S3 段 IP 凭 SNI + Host 可服务两个域。
const FIGMA_S3_IPS: &[&str] = &["65.8.76.37", "65.8.76.35", "65.8.76.16", "65.8.76.41"];

/// 返回该 host 的备用 IP 列表（无匹配时为空）。
///
/// 匹配按后缀进行，更具体的服务段优先：
/// `*.githubusercontent.com` / `*.githubassets.com` 各有独立 IP 段，
/// 不能与 `*.github.com` 混用；`api.figma.com` 走 Global Accelerator 段
/// （前置）+ CloudFront 段兜底；`errors.figma.com` / `s3-alpha-sig.figma.com`
/// 走 S3 段（前置）+ CloudFront 段兜底；其余 `*.figma.com` 走 CloudFront 段。
pub fn fallback_ips(host: &str) -> Vec<IpAddr> {
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    let pool: Vec<&str> =
        if host == "translate.googleapis.com"
            || host.ends_with(".translate.googleapis.com")
            || host == "translate.gstatic.com"
            || host.ends_with(".translate.gstatic.com")
            || host == "translate.google.com"
            || host.ends_with(".translate.google.com")
        {
            GOOGLE_TRANSLATE_IPS.to_vec()
        } else if host == "api.figma.com" || host.ends_with(".api.figma.com") {
            // GA 任播段为原生路径（前置），CloudFront 边缘段兜底
            FIGMA_API_GA_IPS
                .iter()
                .copied()
                .chain(FIGMA_CF_IPS.iter().copied())
                .collect()
        } else if host == "errors.figma.com" || host == "s3-alpha-sig.figma.com" {
            // S3 段为原生路径（前置），CloudFront 边缘段兜底
            FIGMA_S3_IPS
                .iter()
                .copied()
                .chain(FIGMA_CF_IPS.iter().copied())
                .collect()
        } else if host == "figma.com" || host.ends_with(".figma.com") {
            FIGMA_CF_IPS.to_vec()
        } else if host == "githubusercontent.com" || host.ends_with(".githubusercontent.com") {
            GITHUB_USERCONTENT_IPS.to_vec()
        } else if host == "githubassets.com" || host.ends_with(".githubassets.com") {
            GITHUB_ASSETS_IPS.to_vec()
        } else if host == "github.com" || host.ends_with(".github.com") {
            GITHUB_WEB_IPS.to_vec()
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

    #[test]
    fn test_figma_hosts_hit_cf_pool() {
        for host in [
            "www.figma.com",
            "static.figma.com",
            "cdn.figma.com",
            "s3-alpha-sig.figma.com",
            "figma.com",
        ] {
            let ips = fallback_ips(host);
            assert!(!ips.is_empty(), "{host} 应有备用 IP");
            assert!(
                ips.iter().any(|ip| ip.to_string() == "99.86.18.30"),
                "{host} 应命中 CloudFront 边缘段"
            );
        }
    }

    #[test]
    fn test_figma_api_uses_ga_pool_first() {
        let ips = fallback_ips("api.figma.com");
        assert!(!ips.is_empty());
        // GA 任播段前置（原生路径）
        assert_eq!(ips[0].to_string(), "13.35.190.56", "GA 段应前置");
        assert!(ips.iter().any(|ip| ip.to_string() == "13.35.190.39"));
        // CloudFront 段兜底追加
        assert!(ips.iter().any(|ip| ip.to_string() == "99.86.18.30"));
        assert_eq!(ips.len(), FIGMA_API_GA_IPS.len() + FIGMA_CF_IPS.len());
    }

    #[test]
    fn test_figma_s3_hosts_use_s3_pool_first() {
        for host in ["errors.figma.com", "s3-alpha-sig.figma.com"] {
            let ips = fallback_ips(host);
            assert!(!ips.is_empty(), "{host} 应有备用 IP");
            // S3 段前置（原生路径）
            assert_eq!(ips[0].to_string(), "65.8.76.37", "{host} S3 段应前置");
            assert!(ips.iter().any(|ip| ip.to_string() == "65.8.76.41"));
            // CloudFront 段兜底追加（实测 S3 域亦可经 CF 边缘 IP 访问）
            assert!(ips.iter().any(|ip| ip.to_string() == "99.86.18.30"));
            assert_eq!(ips.len(), FIGMA_S3_IPS.len() + FIGMA_CF_IPS.len());
        }
    }

    #[test]
    fn test_figma_verify_uses_cf_pool() {
        // verify.figma.com（Arkose 人验）在 CloudFront 上，走 CF 段
        let ips = fallback_ips("verify.figma.com");
        assert!(!ips.is_empty());
        assert!(ips.iter().any(|ip| ip.to_string() == "99.86.18.30"));
    }

    #[test]
    fn test_figma_pools_do_not_leak_to_other_domains() {
        // 非 figma 域不得命中 Figma 池
        for host in ["example.com", "google.com", "www.google.com", "github.com"] {
            let ips = fallback_ips(host);
            assert!(
                !ips.iter().any(|ip| ip.to_string().starts_with("99.86.")),
                "{host} 不应命中 CloudFront 段"
            );
            assert!(
                !ips.iter().any(|ip| ip.to_string().starts_with("13.35.")),
                "{host} 不应命中 GA 段"
            );
        }
    }

    #[test]
    fn test_figma_case_and_port_insensitive() {
        assert_eq!(fallback_ips("WWW.Figma.com").len(), FIGMA_CF_IPS.len());
        assert_eq!(fallback_ips("www.figma.com:443").len(), FIGMA_CF_IPS.len());
    }
}
