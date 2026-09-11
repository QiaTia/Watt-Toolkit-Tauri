//! DNS 解析器：支持自定义主 DNS / DoH，带正/负缓存。

use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// DNS 解析配置
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// 主 DNS 服务器（如 "223.5.5.5"），None 用系统默认
    pub master_dns: Option<String>,
    /// 使用 DoH
    pub use_doh: bool,
    /// 自定义 DoH 地址
    pub custom_doh_address: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            master_dns: None,
            use_doh: false,
            custom_doh_address: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("resolve failed: {0}")]
    Resolve(String),
}

/// DNS 解析器：包装 hickory-resolver，支持按配置重建。
///
/// 持有两个解析器：`resolver`（系统语义，读 hosts 文件，用于污染判定等
/// 需对齐 getaddrinfo 行为的场景）与 `clean`（绕过 hosts，专供加速引擎
/// 出站连接——引擎自身会写入 hosts 劫持条目，出站解析若读 hosts 会把
/// 加速域名解析成 127.0.0.1 导致回环连接）。
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    clean: TokioAsyncResolver,
    config: DnsConfig,
}

impl DnsResolver {
    /// 用系统默认配置创建
    pub fn system() -> Self {
        Self::with_config(DnsConfig::default())
    }

    /// 按配置创建（主 DNS / DoH）
    pub fn with_config(config: DnsConfig) -> Self {
        let resolver = build_resolver(&config, true);
        let clean = build_resolver(&config, false);
        Self {
            resolver,
            clean,
            config,
        }
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// 解析域名（A/AAAA，返回全部结果）
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        // IP 字面量直通
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let response = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(|e| DnsError::Resolve(format!("{host}: {e}")))?;
        Ok(response.iter().collect())
    }

    /// 绕过 hosts 文件解析（出站连接专用，加速域名不会被劫持成回环）
    pub async fn resolve_clean(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let response = self
            .clean
            .lookup_ip(host)
            .await
            .map_err(|e| DnsError::Resolve(format!("{host}: {e}")))?;
        Ok(response.iter().collect())
    }

    /// 解析首个地址（对齐 AnalysisDomainIpAsync(...).FirstOrDefaultAsync）
    pub async fn resolve_first(&self, host: &str) -> Option<IpAddr> {
        self.resolve(host)
            .await
            .ok()
            .and_then(|v| v.into_iter().next())
    }

    /// 解析首个地址（绕过 hosts）。用于 DNS 污染判定——原版固定用 DNSPod 公共
    /// DNS 反查（DnsAnalysis.AnalysisDomainIpAsync），以排除本机 hosts 条目干扰。
    pub async fn resolve_first_clean(&self, host: &str) -> Option<IpAddr> {
        self.resolve_clean(host)
            .await
            .ok()
            .and_then(|v| v.into_iter().next())
    }
}

fn build_resolver(config: &DnsConfig, use_hosts_file: bool) -> TokioAsyncResolver {
    use hickory_resolver::config::*;

    // DoH 模式
    if config.use_doh {
        let doh_url = config
            .custom_doh_address
            .clone()
            .unwrap_or_else(|| crate::DEFAULT_DOH_ADDRESS.to_string());
        if let Ok(name_server) = parse_doh_url(&doh_url) {
            let mut ns_config = NameServerConfig::new(name_server, Protocol::Https);
            ns_config.trust_negative_responses = false;
            let mut resolver_config = ResolverConfig::new();
            resolver_config.add_name_server(ns_config);
            let mut opts = ResolverOpts::default();
            opts.cache_size = 1024;
            opts.use_hosts_file = use_hosts_file;
            return TokioAsyncResolver::tokio(resolver_config, opts);
        }
    }

    // 自定义主 DNS
    if let Some(master) = config.master_dns.as_deref().filter(|s| !s.is_empty()) {
        if let Ok(ip) = master.parse::<IpAddr>() {
            let ns = match ip {
                IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), 53),
                IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), 53),
            };
            let mut ns_config = NameServerConfig::new(ns, Protocol::Udp);
            ns_config.trust_negative_responses = false;
            let mut resolver_config = ResolverConfig::new();
            resolver_config.add_name_server(ns_config);
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(3);
            opts.attempts = 2;
            opts.cache_size = 1024;
            opts.use_hosts_file = use_hosts_file;
            return TokioAsyncResolver::tokio(resolver_config, opts);
        }
    }

    // 系统默认
    if use_hosts_file {
        return TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        });
    }
    // 绕过 hosts：手动读系统配置并关闭 hosts 优先
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, mut opts)) => {
            opts.use_hosts_file = false;
            TokioAsyncResolver::tokio(config, opts)
        }
        Err(_) => {
            let mut opts = ResolverOpts::default();
            opts.use_hosts_file = false;
            TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
        }
    }
}

fn parse_doh_url(url: &str) -> Result<SocketAddr, ()> {
    // 仅支持模板 https://ip[:port]/dns-query
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or(())?;
    let host_port = rest.split('/').next().ok_or(())?;
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| ())?),
        None => (host_port, 443u16),
    };
    let ip: IpAddr = host.parse().map_err(|_| ())?;
    Ok(SocketAddr::new(ip, port))
}

/// 最快 DNS 竞速：并发查询，任一成功即返回（对齐 GetFastestDNSAsync）
pub async fn fastest_dns(
    candidates: Vec<String>,
    use_doh: bool,
    custom_doh: Option<String>,
) -> Option<String> {
    use futures::stream::StreamExt;

    let candidates: Vec<String> = candidates.into_iter().filter(|c| !c.is_empty()).collect();
    if candidates.is_empty() {
        return None;
    }

    let futures: Vec<_> = candidates
        .into_iter()
        .map(|c| {
            let is_doh = use_doh;
            let doh = custom_doh.clone();
            async move {
                let config = if is_doh {
                    DnsConfig {
                        master_dns: None,
                        use_doh: true,
                        custom_doh_address: doh,
                    }
                } else {
                    DnsConfig {
                        master_dns: Some(c.clone()),
                        use_doh: false,
                        custom_doh_address: None,
                    }
                };
                let resolver = DnsResolver::with_config(config);
                match resolver.resolve(crate::DNS_CHECK_HOST).await {
                    Ok(ips) if !ips.is_empty() => Some(c),
                    _ => None,
                }
            }
        })
        .collect();

    let mut stream = futures::stream::iter(futures).buffer_unordered(8);
    while let Some(result) = stream.next().await {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// 供 watt-core 注入的共享解析器类型
pub type SharedDnsResolver = Arc<DnsResolver>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_doh_url() {
        assert_eq!(
            parse_doh_url("https://1.12.12.12/dns-query").unwrap(),
            "1.12.12.12:443".parse().unwrap()
        );
        assert_eq!(
            parse_doh_url("https://120.53.53.53:8443/dns-query").unwrap(),
            "120.53.53.53:8443".parse().unwrap()
        );
        assert!(parse_doh_url("https://doh.pub/dns-query").is_err()); // 非IP主机暂不支持
    }

    #[tokio::test]
    async fn test_resolve_ip_literal() {
        let resolver = DnsResolver::system();
        let ips = resolver.resolve("127.0.0.1").await.unwrap();
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    /// clean 解析不得返回回环地址（hosts 劫持的域名应走真实 DNS）
    #[tokio::test]
    async fn test_resolve_clean_bypasses_hosts() {
        let resolver = DnsResolver::system();
        // 无网络环境下解析失败则跳过断言
        if let Ok(ips) = resolver.resolve_clean("gist.github.com").await {
            assert!(
                !ips.is_empty(),
                "clean 解析返回空（若 hosts 已劫持该域名则说明绕过失败）"
            );
            for ip in ips {
                assert!(!ip.is_loopback(), "clean 解析不应返回回环地址: {ip}");
            }
        }
    }
}
