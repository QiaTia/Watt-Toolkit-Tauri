//! DNS 解析器：支持自定义主 DNS / DoH，带正/负缓存。

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// DoH 默认路径（RFC 8484 约定）
const DEFAULT_DOH_PATH: &str = "/dns-query";
/// 域名型 DoH 端点的引导解析超时（getaddrinfo 可能长时间阻塞）
const DOH_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(3);
/// 单个 DoH 端点最多保留的引导地址数（避免某个失败地址拖慢每次查询）
const DOH_MAX_ADDRS: usize = 4;

/// DNS 解析配置
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// 主 DNS 服务器（如 "223.5.5.5"），None 用系统默认
    pub master_dns: Option<String>,
    /// 使用 DoH
    pub use_doh: bool,
    /// 自定义 DoH 地址
    pub custom_doh_address: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("resolve failed: {0}")]
    Resolve(String),
}

/// 实际生效的 DNS 后端。
///
/// DoH 配置失效（地址非法、引导解析失败等）时会回退到主 DNS / 系统 DNS，
/// UI 不能再按「用户勾了 DoH」就宣称正在使用加密 DNS。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsBackend {
    /// 系统默认 DNS
    System,
    /// 指定 IP 的明文 UDP DNS
    Udp(String),
    /// 生效中的 DoH 端点
    Doh(String),
}

/// DNS 解析器：包装 hickory-resolver，支持按配置重建。
///
/// 持有两个解析器：`resolver`（系统语义，读 hosts 文件，用于污染判定等
/// 需对齐 getaddrinfo 行为的场景）与 `clean`（绕过 hosts，专供加速引擎
/// 出站连接——引擎自身会写入 hosts 劫持条目，出站解析若读 hosts 会把
/// 加速域名解析成 127.0.0.1 导致回环连接）。
pub struct DnsResolver {
    resolver: TokioResolver,
    clean: TokioResolver,
    config: DnsConfig,
    /// 实际生效的后端（DoH 失效时为回退后的后端）
    backend: DnsBackend,
    /// DoH 配置失败原因（仅用于诊断/UI 提示）
    doh_error: Option<String>,
}

impl DnsResolver {
    /// 用系统默认配置创建
    pub fn system() -> Self {
        Self::with_config(DnsConfig::default())
    }

    /// 按配置创建（主 DNS / DoH）
    pub fn with_config(config: DnsConfig) -> Self {
        let (doh, doh_error) = match build_doh_plan(&config) {
            Ok(plan) => (plan, None),
            Err(err) => (None, Some(err)),
        };

        match (
            build_resolver(&config, true, doh.as_ref()),
            build_resolver(&config, false, doh.as_ref()),
        ) {
            (Ok(resolver), Ok(clean)) => Self {
                resolver,
                clean,
                backend: select_backend(&config, doh.as_ref()),
                config,
                doh_error,
            },
            (resolver, clean) => {
                // 正常输入不会走到这里（DoH 构建失败已在上面兜底）；仅当系统配置
                // 本身不可用时最后兜底，保证应用仍能解析 DNS。
                let err = resolver
                    .as_ref()
                    .err()
                    .or(clean.as_ref().err())
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                tracing::error!(error = %err, "DNS 解析器构造失败，回退系统 DNS");
                Self {
                    resolver: system_resolver(true),
                    clean: system_resolver(false),
                    backend: DnsBackend::System,
                    config,
                    doh_error: Some(err),
                }
            }
        }
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// 实际生效的 DNS 后端
    pub fn backend(&self) -> &DnsBackend {
        &self.backend
    }

    /// DoH 是否真正生效（而不是配置后静默回退）
    pub fn is_doh_active(&self) -> bool {
        matches!(self.backend, DnsBackend::Doh(_))
    }

    /// DoH 配置失败原因（None = 未配置 DoH 或 DoH 正常）
    pub fn doh_error(&self) -> Option<&str> {
        self.doh_error.as_deref()
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

/// 已解析好的 DoH 端点：主机名（用于 TLS 校验 + SNI）、路径与引导得到的 IP 列表
struct DohPlan {
    /// 用户配置的原始 URL，用于日志/UI 展示
    url: String,
    /// TLS ServerName；IP 端点时即 IP 字面量（按 IP SAN 校验）
    server_name: String,
    /// DoH 请求路径（hickory 0.26 支持自定义）
    path: String,
    /// 引导解析得到的连接地址
    addrs: Vec<SocketAddr>,
}

/// DoH 端点解析结果（URL → 主机/端口/路径）
struct DohEndpoint {
    host: String,
    port: u16,
    path: String,
}

fn build_doh_plan(config: &DnsConfig) -> Result<Option<DohPlan>, String> {
    if !config.use_doh {
        return Ok(None);
    }
    let url = config
        .custom_doh_address
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| crate::DEFAULT_DOH_ADDRESS.to_string());
    let endpoint = parse_doh_endpoint(&url)?;
    let addrs = resolve_doh_addrs(&endpoint.host, endpoint.port)?;
    Ok(Some(DohPlan {
        url,
        server_name: endpoint.host,
        path: endpoint.path,
        addrs,
    }))
}

/// 根据配置与 DoH 计划推导实际后端（必须与 `build_resolver` 的回退顺序一致）
fn select_backend(config: &DnsConfig, doh: Option<&DohPlan>) -> DnsBackend {
    if let Some(plan) = doh {
        return DnsBackend::Doh(plan.url.clone());
    }
    if let Some(ip) = config
        .master_dns
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return DnsBackend::Udp(ip.to_string());
    }
    DnsBackend::System
}

fn build_resolver(
    config: &DnsConfig,
    use_hosts_file: bool,
    doh: Option<&DohPlan>,
) -> Result<TokioResolver, String> {
    // DoH 模式：每个引导地址一条 nameserver（hickory 会自行轮询/重试）
    if let Some(plan) = doh {
        let mut resolver_config = empty_resolver_config();
        for addr in &plan.addrs {
            let mut ns_config = NameServerConfig::https(
                addr.ip(),
                Arc::from(plan.server_name.as_str()),
                Some(Arc::from(plan.path.as_str())),
            );
            if let Some(conn) = ns_config.connections.first_mut() {
                conn.port = addr.port();
            }
            ns_config.trust_negative_responses = false;
            resolver_config.add_name_server(ns_config);
        }
        return TokioResolver::builder_with_config(
            resolver_config,
            TokioRuntimeProvider::default(),
        )
        .with_options(base_opts(use_hosts_file, 4, 2))
        .with_tls_config(doh_tls_client_config().clone())
        .build()
        .map_err(|e| format!("构建 DoH 解析器失败: {e}"));
    }

    // 自定义主 DNS
    if let Some(master) = config.master_dns.as_deref().filter(|s| !s.is_empty()) {
        if let Ok(ip) = master.parse::<IpAddr>() {
            let mut resolver_config = empty_resolver_config();
            resolver_config.add_name_server(NameServerConfig::udp(ip));
            return TokioResolver::builder_with_config(
                resolver_config,
                TokioRuntimeProvider::default(),
            )
            .with_options(base_opts(use_hosts_file, 3, 2))
            .build()
            .map_err(|e| format!("构建 UDP DNS 解析器失败: {e}"));
        }
        tracing::warn!(master, "主 DNS 不是合法 IP，已回退到系统 DNS（设置页请填写 IP 字面量）");
    }

    Ok(system_resolver(use_hosts_file))
}

fn base_opts(use_hosts_file: bool, timeout_secs: u64, attempts: usize) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(timeout_secs);
    opts.attempts = attempts;
    opts.cache_size = 1024;
    opts.use_hosts_file = if use_hosts_file {
        ResolveHosts::Always
    } else {
        ResolveHosts::Never
    };
    opts
}

fn system_resolver(use_hosts_file: bool) -> TokioResolver {
    let hosts = if use_hosts_file {
        ResolveHosts::Always
    } else {
        ResolveHosts::Never
    };
    if let Ok(mut builder) = TokioResolver::builder_tokio() {
        builder.options_mut().use_hosts_file = hosts;
        match builder.build() {
            Ok(resolver) => return resolver,
            Err(e) => tracing::warn!(error = %e, "系统 DNS 配置不可用，使用默认公共 DNS"),
        }
    }
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = hosts;
    TokioResolver::builder_with_config(ResolverConfig::default(), TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .expect("默认公共 DNS 解析器构造失败")
}

fn empty_resolver_config() -> ResolverConfig {
    let mut config = ResolverConfig::default();
    // Default 会预置 Google DNS，这里要的是「空配置 + 自定义 nameserver」
    config.name_servers.clear();
    config
}

/// DoH 专用 TLS 配置：Mozilla 根证书 + 开启 SNI + ALPN=h2。
///
/// hickory 0.26 允许通过 `ResolverBuilder::with_tls_config` 注入 rustls 配置；
/// 与工作区共用 rustls 0.23，避免此前 0.24 时代 rustls 0.21 的漏洞链。
static DOH_TLS: Lazy<rustls::ClientConfig> = Lazy::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls 默认协议版本不可用")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.enable_sni = true;
    config
});

fn doh_tls_client_config() -> &'static rustls::ClientConfig {
    &DOH_TLS
}

/// 解析 DoH URL。
///
/// 支持 `https://<域名或 IP>[:端口][/路径]`，路径缺省为 `/dns-query`。
/// hickory 0.26 支持自定义 DoH 路径。
fn parse_doh_endpoint(url: &str) -> Result<DohEndpoint, String> {
    let url = url.trim();
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        if url.starts_with("http://") {
            "DoH 必须使用 https://（http 不是加密 DNS）".to_string()
        } else {
            "DoH 地址必须以 https:// 开头".to_string()
        }
    })?;
    if rest.contains('@') {
        return Err("DoH 地址不能包含认证信息".to_string());
    }

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, DEFAULT_DOH_PATH.to_string()),
    };
    if !path.starts_with('/') {
        return Err(format!("DoH 路径非法: {path}"));
    }
    if path.contains('?') || path.contains('#') || path.chars().any(char::is_whitespace) {
        return Err("DoH 路径不能包含查询串、片段或空白".to_string());
    }

    let (host, port) = split_host_port(authority)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("DoH 地址缺少主机名".to_string());
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\' || c == '?' || c == '#')
    {
        return Err(format!("DoH 主机名非法: {host}"));
    }
    Ok(DohEndpoint { host, port, path })
}

fn split_host_port(authority: &str) -> Result<(String, u16), String> {
    // IPv6: [2606:4700::1111]:443
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "IPv6 地址缺少 `]`".to_string())?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| format!("无效 IPv6 地址: {host}"))?;
        let port = if tail.is_empty() {
            443
        } else if let Some(port) = tail.strip_prefix(':') {
            parse_port(port)?
        } else {
            return Err(format!("IPv6 地址后存在非法字符: {tail}"));
        };
        return Ok((host.to_string(), port));
    }

    if !authority.contains(':') {
        return Ok((authority.to_string(), 443));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| format!("无法解析主机端口: {authority}"))?;
    if host.contains(':') {
        return Err("IPv6 地址请使用 [] 包裹".to_string());
    }
    if host.is_empty() {
        return Err("DoH 地址缺少主机名".to_string());
    }
    Ok((host.to_string(), parse_port(port)?))
}

fn parse_port(port: &str) -> Result<u16, String> {
    let port: u16 = port.parse().map_err(|_| format!("无效端口: {port}"))?;
    if port == 0 {
        return Err("端口不能为 0".to_string());
    }
    Ok(port)
}

/// 引导解析 DoH 主机名。
///
/// 这里故意用系统解析器（getaddrinfo）：DoH 端点本身必须先有 IP 才能握手。
/// 即使引导结果被污染也无法冒充目标——TLS 会按 `server_name` 校验证书。
/// getaddrinfo 是阻塞调用，放到独立线程并限时，避免卡住 Tauri 命令线程。
fn resolve_doh_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let host_owned = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("doh-bootstrap".to_string())
        .spawn(move || {
            let result = (host_owned.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        })
        .map_err(|e| format!("无法启动 DoH 引导解析线程: {e}"))?;

    let addrs = match rx.recv_timeout(DOH_BOOTSTRAP_TIMEOUT) {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => return Err(format!("解析 DoH 主机 {host} 失败: {e}")),
        Err(_) => {
            return Err(format!(
                "解析 DoH 主机 {host} 超时（{}s）",
                DOH_BOOTSTRAP_TIMEOUT.as_secs()
            ))
        }
    };

    let mut seen = HashSet::new();
    let mut addrs: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|addr| seen.insert(*addr))
        .collect();
    if addrs.is_empty() {
        return Err(format!("DoH 主机 {host} 没有可用地址"));
    }
    // IPv4 优先：多数网络 IPv6 只有默认路由，先试 IPv6 会让首个查询多等一个超时。
    // 先排序再截断，避免 getaddrinfo 先返回一堆 IPv6 时把 IPv4 挤掉。
    addrs.sort_by_key(|addr| addr.is_ipv6());
    addrs.truncate(DOH_MAX_ADDRS);
    Ok(addrs)
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
                let resolver = match tokio::task::spawn_blocking(move || {
                    DnsResolver::with_config(config)
                })
                .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, "DNS 竞速解析器构造任务异常");
                        return None;
                    }
                };
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
        let ip = parse_doh_endpoint("https://1.12.12.12/dns-query").unwrap();
        assert_eq!(ip.host, "1.12.12.12");
        assert_eq!(ip.port, 443);
        assert_eq!(ip.path, "/dns-query");

        let domain = parse_doh_endpoint("https://doh.pub/dns-query").unwrap();
        assert_eq!(domain.host, "doh.pub");
        assert_eq!(domain.port, 443);

        // 0.26 支持自定义路径；缺省路径为 /dns-query
        let custom_path = parse_doh_endpoint("https://dns.google/resolve").unwrap();
        assert_eq!(custom_path.path, "/resolve");
        let no_path = parse_doh_endpoint("https://doh.pub").unwrap();
        assert_eq!(no_path.path, "/dns-query");

        let custom_port = parse_doh_endpoint("https://120.53.53.53:8443/dns-query").unwrap();
        assert_eq!(custom_port.port, 8443);

        let v6 = parse_doh_endpoint("https://[2606:4700::1111]:8443/dns-query").unwrap();
        assert_eq!(v6.host, "2606:4700::1111");
        assert_eq!(v6.port, 8443);

        // 大小写/尾部点归一化
        let normalized = parse_doh_endpoint("https://DoH.Pub./dns-query").unwrap();
        assert_eq!(normalized.host, "doh.pub");
    }

    #[test]
    fn test_parse_doh_url_rejects_unsupported() {
        // 明文 HTTP 不是加密 DNS
        assert!(parse_doh_endpoint("http://doh.pub/dns-query").is_err());
        // 查询串/片段会让请求路径与 hickory 构造不一致
        assert!(parse_doh_endpoint("https://doh.pub/dns-query?x=1").is_err());
        assert!(parse_doh_endpoint("https://doh.pub/dns-query#frag").is_err());
        // 无主机 / 无 scheme / 非法端口
        assert!(parse_doh_endpoint("https:///dns-query").is_err());
        assert!(parse_doh_endpoint("doh.pub/dns-query").is_err());
        assert!(parse_doh_endpoint("https://doh.pub:0/dns-query").is_err());
        assert!(parse_doh_endpoint("https://doh.pub:99999/dns-query").is_err());
        // 未加 [] 的 IPv6
        assert!(parse_doh_endpoint("https://2606:4700::1111/dns-query").is_err());
    }

    #[test]
    fn test_doh_failure_reports_and_falls_back() {
        let resolver = DnsResolver::with_config(DnsConfig {
            master_dns: Some("223.5.5.5".into()),
            use_doh: true,
            custom_doh_address: Some("http://doh.pub/dns-query".into()),
        });
        assert!(!resolver.is_doh_active());
        assert_eq!(resolver.backend(), &DnsBackend::Udp("223.5.5.5".into()));
        assert!(resolver.doh_error().unwrap().contains("https://"));
    }

    #[test]
    fn test_resolve_ip_literal() {
        let resolver = DnsResolver::system();
        let ips = futures::executor::block_on(resolver.resolve("127.0.0.1")).unwrap();
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

    /// 真实网络验证：域名型 DoH 端点（需要 SNI + 根证书）
    #[tokio::test]
    #[ignore = "需要网络：验证真实 DoH 握手"]
    async fn test_doh_live_domain_endpoint() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("hickory_resolver=debug,hickory_net=debug")
            .with_test_writer()
            .try_init();

        let resolver = DnsResolver::with_config(DnsConfig {
            master_dns: None,
            use_doh: true,
            custom_doh_address: Some("https://doh.pub/dns-query".into()),
        });
        assert!(
            resolver.is_doh_active(),
            "DoH 未生效: {:?}",
            resolver.doh_error()
        );
        let ips = resolver.resolve_clean("example.com").await.unwrap();
        assert!(!ips.is_empty(), "DoH 返回空结果");
        assert!(ips.iter().all(|ip| ip.is_ipv4() || ip.is_ipv6()));
    }

    /// 真实网络验证：IP 型 DoH 端点（按 IP SAN 校验证书）
    #[tokio::test]
    #[ignore = "需要网络：验证真实 DoH 握手"]
    async fn test_doh_live_ip_endpoint() {
        let resolver = DnsResolver::with_config(DnsConfig {
            master_dns: None,
            use_doh: true,
            custom_doh_address: Some("https://1.12.12.12/dns-query".into()),
        });
        assert!(
            resolver.is_doh_active(),
            "DoH 未生效: {:?}",
            resolver.doh_error()
        );
        let ips = resolver.resolve_clean("example.com").await.unwrap();
        assert!(!ips.is_empty(), "DoH 返回空结果");
    }
}
