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
/// DoH 引导解析结果缓存时长（同一端点重复构造解析器时不再阻塞 getaddrinfo）
const DOH_BOOTSTRAP_CACHE_TTL: Duration = Duration::from_secs(600);

type BootstrapCache = std::sync::Mutex<
    std::collections::HashMap<(String, u16), (std::time::Instant, Vec<SocketAddr>)>,
>;

/// 引导地址缓存：`DnsResolver` 可能在引擎重启、竞速测速时被反复构造，
/// 每次都调用 getaddrinfo 会反复占用阻塞线程（超时后线程仍存活到系统返回）。
static DOH_BOOTSTRAP_CACHE: Lazy<BootstrapCache> =
    Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 单个解析服务器。
///
/// 对齐上游 `DnsAnalysisServiceSwitchImpl.Server`：配置是一个**有序列表**，
/// 顺序即优先级，逐个尝试、首个返回结果者生效。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverServer {
    /// 系统默认 DNS（读系统配置；Hosts 模式下会被替换为公共 DNS，防回环）
    SystemDefault,
    /// 明文 UDP/TCP DNS（IP 字面量）
    Udp(IpAddr),
    /// RFC 8484 DoH 端点（必须 https，已规范化为 `/dns-query` 等路径）
    Doh(String),
}

/// 配置里最多生效的服务器数量（超出截断，避免用户粘一整页地址拖慢每次解析）
const MAX_RESOLVER_SERVERS: usize = 8;

impl ResolverServer {
    /// 解析单条配置项。无法识别的项返回 `None`（调用方跳过，不让整表失效）。
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim();
        if s.is_empty() {
            return None;
        }
        if s.eq_ignore_ascii_case("system default") || s.eq_ignore_ascii_case("system") {
            return Some(Self::SystemDefault);
        }
        if s.len() >= 8 && s[..8].eq_ignore_ascii_case("https://") {
            let normalized = normalize_legacy_doh_endpoint(s);
            let endpoint = parse_doh_endpoint(&normalized).ok()?;
            return Some(Self::Doh(canonical_doh_url(&endpoint)));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(Self::Udp(ip));
        }
        None
    }

    /// 用于日志/UI 的短描述
    pub fn describe(&self) -> String {
        match self {
            Self::SystemDefault => "System Default".to_string(),
            Self::Udp(ip) => ip.to_string(),
            Self::Doh(url) => url.clone(),
        }
    }

    fn query_timeout(&self) -> Duration {
        match self {
            Self::Doh(_) => crate::DOH_QUERY_TIMEOUT,
            _ => crate::UDP_QUERY_TIMEOUT,
        }
    }
}

/// 历史预设的 DoH 端点多为 JSON 接口（`/resolve`），而客户端始终按 RFC 8484
/// 发送 wireformat 请求到该路径 → 必然失败。已知预设统一改写为 `/dns-query`。
///
/// 对齐上游 `NormalizeLegacyDohEndpoint`（保留既有配置的可用性）。
fn normalize_legacy_doh_endpoint(url: &str) -> String {
    let trimmed = url.trim();
    let Ok(endpoint) = parse_doh_endpoint(trimmed) else {
        return trimmed.to_string();
    };
    const JSON_ONLY_HOSTS: &[&str] = &[
        "doh.pub",
        "dns.alidns.com",
        "223.6.6.6",
        "1.12.12.12",
        "dns.google",
        "doh.360.cn",
        "101.6.6.6",
    ];
    if endpoint.path == "/resolve" && JSON_ONLY_HOSTS.contains(&endpoint.host.as_str()) {
        let mut fixed = endpoint;
        fixed.path = DEFAULT_DOH_PATH.to_string();
        return canonical_doh_url(&fixed);
    }
    trimmed.to_string()
}

/// 由解析结果还原规范 URL（IPv6 补方括号、默认端口省略）
fn canonical_doh_url(endpoint: &DohEndpoint) -> String {
    let host = if endpoint.host.contains(':') {
        format!("[{}]", endpoint.host)
    } else {
        endpoint.host.clone()
    };
    if endpoint.port == 443 {
        format!("https://{host}{}", endpoint.path)
    } else {
        format!("https://{host}:{}{}", endpoint.port, endpoint.path)
    }
}

/// DNS 解析配置
///
/// `resolver_servers` 为空时由旧字段（`use_doh` / `master_dns` / `custom_doh_address`）
/// 合成列表，保证 v0.5.x 的配置文件可直接读取。
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// 有序服务器列表（首个可用者生效）
    pub resolver_servers: Vec<ResolverServer>,
    /// 旧字段：主 DNS 服务器（如 "223.5.5.5"），None 用系统默认
    pub master_dns: Option<String>,
    /// 旧字段：使用 DoH
    pub use_doh: bool,
    /// 旧字段：自定义 DoH 地址
    pub custom_doh_address: Option<String>,
    /// Hosts 模式下把 `SystemDefault` 替换为公共 DNS。
    ///
    /// hosts 已把加速域名指向 127.0.0.1，此时用系统解析（哪怕绕过 hosts 文件）
    /// 仍可能被运营商 DNS 污染为回环地址 → 出站连回自己。上游同样处理。
    pub prefer_public_dns: bool,
    /// 严格模式：只使用显式列出的服务器，不注入隐式系统兜底。
    /// 用于「单端点探测」等必须如实报告失败的场景。
    pub strict: bool,
    /// 启动前做一次 DNS 可用性体检（仅诊断，不阻断启动）
    pub before_dns_check: bool,
}

/// 解析字符串列表；无法识别的项**跳过**而不是让整表失效
/// （用户在列表里多打一个空格，不应导致全部 DNS 降级）。
pub fn parse_server_list(list: &[String]) -> Vec<ResolverServer> {
    list.iter().filter_map(|s| ResolverServer::parse(s)).collect()
}

/// 合成生效服务器列表（去重、替换、截断）
pub fn effective_servers(config: &DnsConfig) -> Vec<ResolverServer> {
    plan_servers(config).0
}

/// 合成列表 + 旧配置遗留问题（用于诊断展示）
fn plan_servers(config: &DnsConfig) -> (Vec<ResolverServer>, Option<String>) {
    let (mut list, mut config_error) = if config.resolver_servers.is_empty() {
        legacy_servers(config)
    } else {
        (config.resolver_servers.clone(), None)
    };

    if config.prefer_public_dns {
        let mut replaced = Vec::with_capacity(list.len() + crate::DEFAULT_DNS_SERVERS.len());
        for server in list {
            match server {
                ResolverServer::SystemDefault => {
                    for raw in crate::DEFAULT_DNS_SERVERS {
                        if let Ok(ip) = raw.parse::<IpAddr>() {
                            replaced.push(ResolverServer::Udp(ip));
                        }
                    }
                }
                other => replaced.push(other),
            }
        }
        list = replaced;
    }

    // 去重保序（用户可能同时填了预设与手写）
    let mut seen = HashSet::new();
    list.retain(|server| {
        let key = server.describe();
        seen.insert(key)
    });
    list.truncate(MAX_RESOLVER_SERVERS);
    if list.is_empty() {
        config_error.get_or_insert_with(|| "没有可用的 DNS 服务器配置".to_string());
    }
    (list, config_error)
}

/// 旧配置字段 → 服务器列表（use_doh 为真时 DoH 优先）
fn legacy_servers(config: &DnsConfig) -> (Vec<ResolverServer>, Option<String>) {
    let mut list = Vec::new();
    let mut error = None;
    if config.use_doh {
        let url = config
            .custom_doh_address
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| crate::DEFAULT_DOH_ADDRESS.to_string());
        match ResolverServer::parse(&url) {
            Some(server) => list.push(server),
            None => {
                tracing::warn!(url, "旧版 DoH 地址非法，已忽略");
                error = Some(format!("旧版 DoH 地址非法: {url}"));
            }
        }
    }
    if let Some(ip) = config
        .master_dns
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        list.push(ResolverServer::Udp(ip));
    }
    if list.is_empty() {
        list.push(ResolverServer::SystemDefault);
    }
    (list, error)
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("resolve failed: {0}")]
    Resolve(String),
}

/// 实际生效的主后端（列表首项）。
///
/// DoH 配置失效（地址非法、引导解析失败等）时列表首项不再是 DoH，
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

/// 单个服务器的两套解析器
struct Entry {
    spec: ResolverServer,
    /// 读 hosts 文件（系统语义，用于污染判定等对齐 getaddrinfo 的场景）
    resolver: TokioResolver,
    /// 绕过 hosts（出站连接专用：引擎自身会写 hosts 劫持条目，
    /// 若读 hosts 会把加速域名解析成 127.0.0.1 导致回环）
    clean: TokioResolver,
}

/// DNS 解析器：按**有序服务器列表**逐个尝试，首个返回结果者生效。
///
/// 每个服务器各自持有一个 hickory 解析器实例，缓存天然按服务器隔离——
/// 若共享实例，hickory 以 question 为键的缓存会让「回退服务器的答案」
/// 冒充「首选服务器的答案」。
pub struct DnsResolver {
    entries: Vec<Entry>,
    config: DnsConfig,
    backend: DnsBackend,
    /// 构建/配置失败原因（仅用于诊断/UI 提示）
    doh_error: Option<String>,
}

impl DnsResolver {
    /// 用系统默认配置创建
    pub fn system() -> Self {
        Self::with_config(DnsConfig::default())
    }

    /// 单端点严格解析器：只使用给定服务器，失败即失败（供端点探测使用）。
    pub fn single(server: ResolverServer) -> Self {
        Self::with_config(DnsConfig {
            resolver_servers: vec![server],
            strict: true,
            ..Default::default()
        })
    }

    /// 按配置创建（有序列表 + 逐项回退）
    pub fn with_config(config: DnsConfig) -> Self {
        let (specs, config_error) = plan_servers(&config);
        let mut entries = Vec::with_capacity(specs.len());
        let mut errors: Vec<String> = Vec::new();
        if let Some(err) = config_error {
            errors.push(err);
        }

        for spec in specs {
            match build_entry(&spec) {
                Ok(entry) => entries.push(entry),
                Err(err) => {
                    tracing::warn!(server = %spec.describe(), error = %err, "DNS 服务器不可用，已跳过");
                    errors.push(format!("{}: {err}", spec.describe()));
                }
            }
        }

        // 非严格模式：全部显式服务器都不可用时兜底系统 DNS，保证应用仍能解析
        if entries.is_empty() && !config.strict {
            entries.push(Entry {
                spec: ResolverServer::SystemDefault,
                resolver: system_resolver(true),
                clean: system_resolver(false),
            });
            errors.push("已回退系统 DNS".to_string());
        }

        let backend = match entries.first().map(|e| &e.spec) {
            Some(ResolverServer::Doh(url)) => DnsBackend::Doh(url.clone()),
            Some(ResolverServer::Udp(ip)) => DnsBackend::Udp(ip.to_string()),
            _ => DnsBackend::System,
        };

        Self {
            entries,
            config,
            backend,
            doh_error: (!errors.is_empty()).then(|| errors.join("; ")),
        }
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// 实际生效的服务器列表（顺序即优先级，供 UI/日志展示真实状态）
    pub fn servers(&self) -> Vec<&ResolverServer> {
        self.entries.iter().map(|e| &e.spec).collect()
    }

    /// 实际生效的主后端（列表首项）
    pub fn backend(&self) -> &DnsBackend {
        &self.backend
    }

    /// DoH 是否真正生效（列表首项是 DoH 且构建成功）
    pub fn is_doh_active(&self) -> bool {
        matches!(self.backend, DnsBackend::Doh(_))
    }

    /// 配置/构建失败原因（None = 全部就绪）
    pub fn doh_error(&self) -> Option<&str> {
        self.doh_error.as_deref()
    }

    /// 解析域名（A/AAAA，返回全部结果）
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.lookup(host, false).await
    }

    /// 绕过 hosts 文件解析（出站连接专用，加速域名不会被劫持成回环）
    pub async fn resolve_clean(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        self.lookup(host, true).await
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

    /// 按顺序逐个服务器查询，首个非空结果即返回。
    ///
    /// 顺序而非并发：并发会让「能通但被污染」的服务器抢先返回，
    /// 反而盖掉首位服务器的正确结果。
    ///
    /// 全程受 [`crate::TOTAL_LOOKUP_BUDGET`] 约束：串行回退在「列表里全失败」时
    /// 会把各服务器的超时累加（3 DoH + 3 UDP 最坏 15s），而调用方（出站连接）
    /// 外侧没有超时兜底，不设总预算就会让单个请求挂十几秒。
    async fn lookup(&self, host: &str, clean: bool) -> Result<Vec<IpAddr>, DnsError> {
        // IP 字面量直通
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if self.entries.is_empty() {
            return Err(DnsError::Resolve(format!("{host}: 无可用 DNS 服务器")));
        }

        let deadline = tokio::time::Instant::now() + crate::TOTAL_LOOKUP_BUDGET;
        let mut last_err = String::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                last_err = format!(
                    "总预算 {}s 耗尽，已尝试 {index}/{} 个服务器（{last_err}）",
                    crate::TOTAL_LOOKUP_BUDGET.as_secs(),
                    self.entries.len()
                );
                break;
            }
            let resolver = if clean { &entry.clean } else { &entry.resolver };
            // 单项超时不得超过剩余预算，否则最后一个服务器会把总时长又拖出去
            let timeout = entry.spec.query_timeout().min(remaining);
            match tokio::time::timeout(timeout, resolver.lookup_ip(host)).await {
                Ok(Ok(response)) => {
                    let ips: Vec<IpAddr> = response.iter().collect();
                    if ips.is_empty() {
                        last_err = format!("{} 无记录", entry.spec.describe());
                        continue;
                    }
                    tracing::debug!(
                        host,
                        server = %entry.spec.describe(),
                        count = ips.len(),
                        "DNS 解析成功"
                    );
                    return Ok(ips);
                }
                Ok(Err(err)) => {
                    last_err = format!("{}: {err}", entry.spec.describe());
                }
                Err(_) => {
                    last_err = format!("{}: 超时({}s)", entry.spec.describe(), timeout.as_secs());
                }
            }
        }

        Err(DnsError::Resolve(format!(
            "{host}: 全部 DNS 均失败（{last_err}）"
        )))
    }
}

/// 为单个服务器构建两套解析器
fn build_entry(spec: &ResolverServer) -> Result<Entry, String> {
    match spec {
        ResolverServer::SystemDefault => Ok(Entry {
            spec: spec.clone(),
            resolver: system_resolver(true),
            clean: system_resolver(false),
        }),
        ResolverServer::Udp(ip) => Ok(Entry {
            spec: spec.clone(),
            resolver: build_udp_resolver(*ip, true)?,
            clean: build_udp_resolver(*ip, false)?,
        }),
        ResolverServer::Doh(url) => {
            let plan = build_doh_plan(url)?;
            Ok(Entry {
                spec: spec.clone(),
                resolver: build_doh_resolver(&plan, true)?,
                clean: build_doh_resolver(&plan, false)?,
            })
        }
    }
}

fn build_udp_resolver(ip: IpAddr, use_hosts_file: bool) -> Result<TokioResolver, String> {
    let mut resolver_config = empty_resolver_config();
    resolver_config.add_name_server(NameServerConfig::udp(ip));
    TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
        .with_options(base_opts(use_hosts_file, 3, 2))
        .build()
        .map_err(|e| format!("构建 UDP DNS 解析器失败: {e}"))
}

fn build_doh_resolver(plan: &DohPlan, use_hosts_file: bool) -> Result<TokioResolver, String> {
    // 每个引导地址一条 nameserver（hickory 会自行轮询/重试）
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
    TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
        .with_options(base_opts(use_hosts_file, 4, 2))
        .with_tls_config(doh_tls_client_config().clone())
        .build()
        .map_err(|e| format!("构建 DoH 解析器失败: {e}"))
}

/// 已解析好的 DoH 端点：主机名（用于 TLS 校验 + SNI）、路径与引导得到的 IP 列表
struct DohPlan {
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

fn build_doh_plan(url: &str) -> Result<DohPlan, String> {
    let endpoint = parse_doh_endpoint(url)?;
    let addrs = resolve_doh_addrs(&endpoint.host, endpoint.port)?;
    Ok(DohPlan {
        server_name: endpoint.host,
        path: endpoint.path,
        addrs,
    })
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

    let cache_key = (host.to_ascii_lowercase(), port);
    if let Ok(cache) = DOH_BOOTSTRAP_CACHE.lock() {
        if let Some((at, addrs)) = cache.get(&cache_key) {
            if at.elapsed() < DOH_BOOTSTRAP_CACHE_TTL && !addrs.is_empty() {
                return Ok(addrs.clone());
            }
        }
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
    if let Ok(mut cache) = DOH_BOOTSTRAP_CACHE.lock() {
        // 简单容量上限：DoH 端点通常只有一两个，避免被大量自定义地址撑大
        if cache.len() >= 32 {
            cache.clear();
        }
        cache.insert(cache_key, (std::time::Instant::now(), addrs.clone()));
    }
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
                        use_doh: true,
                        custom_doh_address: doh,
                        strict: true,
                        ..Default::default()
                    }
                } else {
                    DnsConfig {
                        resolver_servers: vec![ResolverServer::parse(&c)
                            .unwrap_or(ResolverServer::SystemDefault)],
                        strict: true,
                        ..Default::default()
                    }
                };
                let resolver =
                    match tokio::task::spawn_blocking(move || DnsResolver::with_config(config))
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

/// DNS 预检查结果
#[derive(Debug, Clone)]
pub struct DnsCheckResult {
    /// 至少一个配置内的服务器可用
    pub ok: bool,
    /// 诊断文本（成功时为首个应答服务器，失败时为聚合错误）
    pub detail: String,
}

/// 启动前 DNS 预检查：**至少一个**配置服务器可用即通过。
///
/// 对齐上游 `CheckDnsServersAsync` 语义——它从「选出最快的一个并替换配置」
/// 改为「只做可用性体检、配置顺序不变」，因此这里不返回「最佳服务器」，
/// 只回答「这套配置现在能不能解析」。
pub async fn check_resolver_servers(config: &DnsConfig, total_timeout: Duration) -> DnsCheckResult {
    let strict = DnsConfig {
        strict: true,
        ..config.clone()
    };
    if effective_servers(&strict).is_empty() {
        return DnsCheckResult {
            ok: false,
            detail: "未配置任何 DNS 服务器".to_string(),
        };
    }
    // 构造可能在 getaddrinfo 上阻塞（DoH 引导），放到阻塞线程池
    let resolver = match tokio::task::spawn_blocking(move || DnsResolver::with_config(strict)).await
    {
        Ok(r) => r,
        Err(e) => {
            return DnsCheckResult {
                ok: false,
                detail: format!("DNS 预检查任务异常: {e}"),
            }
        }
    };

    match tokio::time::timeout(total_timeout, resolver.resolve(crate::DNS_CHECK_HOST)).await {
        Ok(Ok(ips)) if !ips.is_empty() => DnsCheckResult {
            ok: true,
            detail: format!("{}（{} 个地址）", crate::DNS_CHECK_HOST, ips.len()),
        },
        Ok(Ok(_)) => DnsCheckResult {
            ok: false,
            detail: format!("{} 解析结果为空", crate::DNS_CHECK_HOST),
        },
        Ok(Err(e)) => DnsCheckResult {
            ok: false,
            detail: e.to_string(),
        },
        Err(_) => DnsCheckResult {
            ok: false,
            detail: format!("预检查超时（{}s）", total_timeout.as_secs()),
        },
    }
}

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
            ..Default::default()
        });
        assert!(!resolver.is_doh_active());
        assert_eq!(resolver.backend(), &DnsBackend::Udp("223.5.5.5".into()));
        assert!(
            resolver.doh_error().unwrap().contains("DoH"),
            "应记录 DoH 配置失败：{:?}",
            resolver.doh_error()
        );
    }

    /// 列表解析：三类服务器识别 + 无法识别的项跳过而不是整表失效
    #[test]
    fn test_resolver_server_parse() {
        assert_eq!(
            ResolverServer::parse("System Default"),
            Some(ResolverServer::SystemDefault)
        );
        assert_eq!(
            ResolverServer::parse(" system "),
            Some(ResolverServer::SystemDefault)
        );
        assert_eq!(
            ResolverServer::parse("223.5.5.5"),
            Some(ResolverServer::Udp("223.5.5.5".parse().unwrap()))
        );
        assert_eq!(
            ResolverServer::parse("https://doh.pub/dns-query"),
            Some(ResolverServer::Doh("https://doh.pub/dns-query".into()))
        );

        // 非法项返回 None（由调用方跳过）
        assert_eq!(ResolverServer::parse(""), None);
        assert_eq!(ResolverServer::parse("   "), None);
        assert_eq!(ResolverServer::parse("not-a-server"), None);
        assert_eq!(ResolverServer::parse("http://doh.pub/dns-query"), None);

        // 历史 JSON 端点 → RFC 8484 路径
        assert_eq!(
            ResolverServer::parse("https://dns.google/resolve"),
            Some(ResolverServer::Doh("https://dns.google/dns-query".into()))
        );
        // 非预设的自定义路径保持原样
        assert_eq!(
            ResolverServer::parse("https://example.com/resolve"),
            Some(ResolverServer::Doh("https://example.com/resolve".into()))
        );
    }

    /// 生效列表：去重保序、Hosts 模式替换系统项、超长截断
    #[test]
    fn test_effective_servers_order_and_substitution() {
        let raw = "https://doh.pub/dns-query\n223.5.5.5\nhttps://doh.pub/dns-query\nbad-entry";
        let config = DnsConfig {
            resolver_servers: raw
                .lines()
                .filter_map(ResolverServer::parse)
                .collect::<Vec<_>>(),
            ..Default::default()
        };
        let servers = effective_servers(&config);
        assert_eq!(servers.len(), 2, "重复项应被去重：{servers:?}");
        assert_eq!(servers[0], ResolverServer::Doh("https://doh.pub/dns-query".into()));
        assert_eq!(servers[1], ResolverServer::Udp("223.5.5.5".parse().unwrap()));

        // Hosts 模式：SystemDefault 被替换为公共 DNS，且顺序仍在原位置
        let config = DnsConfig {
            resolver_servers: vec![ResolverServer::SystemDefault],
            prefer_public_dns: true,
            ..Default::default()
        };
        let servers = effective_servers(&config);
        assert_eq!(servers.len(), crate::DEFAULT_DNS_SERVERS.len());
        assert!(servers.iter().all(|s| matches!(s, ResolverServer::Udp(_))));
        assert!(!servers.contains(&ResolverServer::SystemDefault));

        // 截断
        let config = DnsConfig {
            resolver_servers: (1..=20u8)
                .map(|i| ResolverServer::Udp(IpAddr::from([10, 0, 0, i])))
                .collect(),
            ..Default::default()
        };
        assert_eq!(effective_servers(&config).len(), MAX_RESOLVER_SERVERS);
    }

    /// 旧配置合成顺序：勾选 DoH 时 DoH 优先，否则明文优先
    #[test]
    fn test_legacy_config_server_synthesis() {
        let with_doh = DnsConfig {
            use_doh: true,
            custom_doh_address: Some("https://doh.pub/dns-query".into()),
            master_dns: Some("119.29.29.29".into()),
            ..Default::default()
        };
        let servers = effective_servers(&with_doh);
        assert!(matches!(servers[0], ResolverServer::Doh(_)));
        assert_eq!(servers[1], ResolverServer::Udp("119.29.29.29".parse().unwrap()));

        let without_doh = DnsConfig {
            master_dns: Some("119.29.29.29".into()),
            ..Default::default()
        };
        assert_eq!(
            effective_servers(&without_doh),
            vec![ResolverServer::Udp("119.29.29.29".parse().unwrap())]
        );

        // 全空 → 系统默认
        assert_eq!(
            effective_servers(&DnsConfig::default()),
            vec![ResolverServer::SystemDefault]
        );
    }

    /// 严格单端点：构建失败不注入系统兜底（供 DoH 探测如实报错）
    #[test]
    fn test_strict_single_server_has_no_system_fallback() {
        let resolver = DnsResolver::single(ResolverServer::Doh(
            "http://doh.pub/dns-query".into(),
        ));
        // Doh("http://…") 无法构建 → 严格模式不兜底
        assert!(resolver.servers().is_empty());
        assert!(!resolver.is_doh_active());
        assert!(resolver.doh_error().is_some());

        let ok = DnsResolver::single(ResolverServer::Udp("223.5.5.5".parse().unwrap()));
        assert_eq!(
            ok.servers(),
            vec![&ResolverServer::Udp("223.5.5.5".parse().unwrap())]
        );
        assert_eq!(ok.backend(), &DnsBackend::Udp("223.5.5.5".into()));
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
            use_doh: true,
            custom_doh_address: Some("https://doh.pub/dns-query".into()),
            ..Default::default()
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
            use_doh: true,
            custom_doh_address: Some("https://1.12.12.12/dns-query".into()),
            ..Default::default()
        });
        assert!(
            resolver.is_doh_active(),
            "DoH 未生效: {:?}",
            resolver.doh_error()
        );
        let ips = resolver.resolve_clean("example.com").await.unwrap();
        assert!(!ips.is_empty(), "DoH 返回空结果");
    }

    /// 真实网络验证：首个服务器黑洞（TEST-NET-1 不可达）时应自动落到下一个。
    #[tokio::test]
    #[ignore = "需要网络：验证服务器列表逐项回退"]
    async fn test_server_list_falls_back_on_timeout() {
        let resolver = DnsResolver::with_config(DnsConfig {
            resolver_servers: vec![
                ResolverServer::Udp("192.0.2.1".parse().unwrap()),
                ResolverServer::Udp("223.5.5.5".parse().unwrap()),
            ],
            ..Default::default()
        });
        let started = std::time::Instant::now();
        let ips = resolver
            .resolve_clean("example.com")
            .await
            .expect("首个服务器失败后应回退到第二个");
        assert!(!ips.is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(6),
            "回退不应叠加超时，实际 {:?}",
            started.elapsed()
        );
    }
}
