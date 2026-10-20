//! 动态 IP 池：从健康 DNS 服务解析 A 记录 → 本地逐个探测 → 保留可用者写池。
//!
//! # 定位
//!
//! [`crate::fallback::fallback_ips`] 是**内置静态**备用池（人工维护、随版本发布）；
//! 本模块是它的**动态对应物**：用户在「设置 → IP 池」点击刷新后，按当前勾选的
//! 加速项目域名解析出一批候选 IP，逐 IP 在本地做 TCP + TLS 握手探测，只把探测
//! 通过的 IP 按 RTT 升序写入池，并落盘 `{data_dir}/Settings/IpPool.json`。
//!
//! # 与竞速的关系
//!
//! 池内容经 [`dynamic_ips`] 被 `outbound::resolve_candidates` 追加为竞速候选
//! （优先于静态备用池）。出站竞速以「TLS 握手完成」为胜出条件，追加候选不会
//! 增加成功路径的延迟——因此动态池只需保证「写进去的 IP 大概率可用」，
//! 无需保证绝对可用（少数失效者由竞速自动跳过）。
//!
//! # 探测判据
//!
//! 与竞速同层：TCP connect + TLS 握手（同 SNI、同证书校验），只握手不发应用
//! 数据。判据一致是硬约束——「TCP 可达」不等于「服务可用」（存在只放行 TCP、
//! 阻断 TLS 之后流量的网络，见项目记忆「竞速胜出条件必须与可用性判据一致」）。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

/// 单域名池条目
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolEntry {
    /// 探测通过的 IP（RTT 升序）
    pub ips: Vec<IpAddr>,
    /// 刷新时刻（unix 毫秒）
    pub refreshed_at_ms: u64,
}

/// 单个候选 IP 的探测结果（供 UI 展示）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpProbeResult {
    pub ip: IpAddr,
    /// 握手全链路 RTT（毫秒）；None = 未通过
    pub rtt_ms: Option<u64>,
}

/// 单个域名的刷新结果（供 UI 展示）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshHostResult {
    pub host: String,
    /// DNS 解析到的候选数（去重 + 过滤后）
    pub candidates: usize,
    /// 探测通过的候选数
    pub ok: usize,
    /// 全部候选及探测结果（通过的在前、按 RTT 升序）
    pub ips: Vec<IpProbeResult>,
    /// 命中的解析来源（如 `DoH https://223.5.5.5/dns-query` / `DNS 223.5.5.5` / `系统 DNS`）
    pub source: Option<String>,
    /// 失败原因（无候选 / 全部不可达）
    pub error: Option<String>,
}

/// 进程内全局池（静态进程级，与 `fallback` 同为「无需穿透 RelayContext」的共享态）
static POOL: OnceLock<RwLock<HashMap<String, PoolEntry>>> = OnceLock::new();

fn pool() -> &'static RwLock<HashMap<String, PoolEntry>> {
    POOL.get_or_init(|| RwLock::new(HashMap::new()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 规范化域名（去端口 / 尾点、转小写）
fn normalize(host: &str) -> String {
    let host = host.split(':').next().unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// 查询动态池中匹配该 host 的 IP（无匹配为空）。
///
/// 先精确匹配；否则按后缀匹配（`api.figma.com` ← `figma.com`），
/// 取最长后缀（更具体的服务段优先），与 [`crate::fallback::fallback_ips`] 语义一致。
pub fn dynamic_ips(host: &str) -> Vec<IpAddr> {
    let host = normalize(host);
    let map = pool().read().unwrap();
    if let Some(e) = map.get(&host) {
        return e.ips.clone();
    }
    let mut best: Option<(usize, &Vec<IpAddr>)> = None;
    for (key, entry) in map.iter() {
        if entry.ips.is_empty() {
            continue;
        }
        // 后缀匹配：要求 key 之前紧邻 '.'，即 key 是完整域名段而非某段的后半截。
        // 用 strip_suffix 取代手写索引运算——等长 / 更长的 key 天然被排除，
        // 不存在越界可能（原先依赖 `&&` 短路顺序来保证边界安全，过于脆弱）。
        if let Some(prefix) = host.strip_suffix(key.as_str()) {
            if prefix.ends_with('.') && best.map_or(true, |(len, _)| key.len() > len) {
                best = Some((key.len(), &entry.ips));
            }
        }
    }
    best.map(|(_, ips)| ips.clone()).unwrap_or_default()
}

/// 写入/替换某域名的池条目（ips 为空则移除该条目，避免残留失效 IP）
pub fn set_entry(host: &str, ips: Vec<IpAddr>) {
    let host = normalize(host);
    let mut map = pool().write().unwrap();
    if ips.is_empty() {
        map.remove(&host);
    } else {
        map.insert(
            host,
            PoolEntry {
                ips,
                refreshed_at_ms: now_ms(),
            },
        );
    }
}

/// 当前池快照（host → 条目），供落盘 / 诊断
pub fn snapshot() -> HashMap<String, PoolEntry> {
    pool().read().unwrap().clone()
}

/// 某域名的池内 IP（**精确匹配**，不做后缀匹配；管理页编辑/探测用）。
///
/// 与 [`dynamic_ips`] 的区别：后者服务出站竞速（子域要能继承父域池），
/// 本函数只回该域名自己的条目，避免「编辑 api.figma.com 却被 figma.com 的 IP 干扰」。
pub fn entry_ips(host: &str) -> Vec<IpAddr> {
    let host = normalize(host);
    pool()
        .read()
        .unwrap()
        .get(&host)
        .map(|e| e.ips.clone())
        .unwrap_or_default()
}

/// 某域名的池条目（精确匹配；含刷新时刻），不存在为 None
pub fn entry(host: &str) -> Option<PoolEntry> {
    let host = normalize(host);
    pool().read().unwrap().get(&host).cloned()
}

/// 清空池（诊断用）
pub fn clear() {
    pool().write().unwrap().clear();
}

/// 落盘（best-effort，失败仅 warn）
pub fn save_to(path: &Path) {
    #[derive(Serialize)]
    struct Doc {
        version: u32,
        hosts: HashMap<String, PoolEntry>,
    }
    let doc = Doc {
        version: 1,
        hosts: snapshot(),
    };
    let json = match serde_json::to_string_pretty(&doc) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("IP 池序列化失败: {e}");
            return;
        }
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, json) {
        tracing::warn!("IP 池落盘失败: {e}");
    }
}

/// 从 JSON 加载（best-effort，不存在/损坏静默）
pub fn load_from(path: &Path) {
    #[derive(Deserialize)]
    struct Doc {
        #[serde(default)]
        hosts: HashMap<String, PoolEntry>,
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    match serde_json::from_str::<Doc>(&text) {
        Ok(doc) => {
            *pool().write().unwrap() = doc.hosts;
        }
        Err(e) => tracing::warn!("IP 池文件损坏，忽略: {}", e),
    }
}

/// 过滤明显不可用的 IP（回环 / 私有 / 链路本地 / 未指定 / 组播 / 文件用途 / v6 ULA）
pub fn is_usable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg & 0xfe00) == 0xfc00 // fc00::/7 唯一本地
                || (seg & 0xffc0) == 0xfe80) // fe80::/10 链路本地
        }
    }
}

/// 由域名规则推导需要刷新的 host 列表（含通配基域，去重）。
///
/// `*.github.com` → `github.com`（后缀匹配可覆盖全部子域）；
/// 具体域名原样保留；跳过空串/纯通配/无点项。
pub fn hosts_from_rules(rules: &[watt_config::DomainRule]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for rule in rules {
        for raw in rule
            .match_domain_names
            .iter()
            .chain(rule.listening_domain_names.iter())
        {
            let d = raw.trim().trim_start_matches("*.").trim_end_matches('.');
            let d = d.to_ascii_lowercase();
            if d.is_empty() || !d.contains('.') || d.contains('*') {
                continue;
            }
            if seen.insert(d.clone()) {
                out.push(d);
            }
        }
    }
    out
}

/// 探测单个候选 IP：TCP connect + TLS 握手（同 SNI、同证书校验），返回全链路 RTT。
///
/// 与竞速（`outbound::race_tls_once`）同层——探测通过者竞速必然可通过。
pub async fn probe_ip(host: &str, ip: IpAddr, port: u16, timeout: Duration) -> Option<u64> {
    let name = crate::sni::server_name(host)?;
    let connector = crate::sni::outbound_tls_connector(crate::sni::OutboundVerify::Standard, None);
    let start = Instant::now();
    let stream =
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .ok()?
            .ok()?;
    tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .ok()?
        .ok()?;
    Some(start.elapsed().as_millis() as u64)
}

/// 刷新多个域名：逐域名用解析器链解析（首个非空者胜）→ 过滤 → 并发探测 → 写池。
///
/// `resolvers` 顺序即优先级（用户配置的 DNS/DoH 在前，公共 DNS 兜底）。
/// 解析走 `resolve_clean`（绕过 hosts）：Hosts 模式下引擎会把加速域名写成
/// `127.0.0.1`，若读 hosts 会把候选解析成回环地址。
pub async fn refresh_hosts(
    hosts: &[String],
    resolvers: &[Arc<watt_dns::DnsResolver>],
    port: u16,
    probe_timeout: Duration,
) -> Vec<RefreshHostResult> {
    /// 域名间并发上限
    const HOST_CONCURRENCY: usize = 6;
    /// 候选探测并发上限（全局，跨域名）
    const PROBE_CONCURRENCY: usize = 16;

    let host_sem = Arc::new(Semaphore::new(HOST_CONCURRENCY));
    let probe_sem = Arc::new(Semaphore::new(PROBE_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();

    for host in hosts {
        let host = host.clone();
        let resolvers = resolvers.to_vec();
        let host_sem = host_sem.clone();
        let probe_sem = probe_sem.clone();
        set.spawn(async move {
            let _permit = host_sem.acquire_owned().await;
            refresh_one(&host, &resolvers, port, probe_timeout, probe_sem).await
        });
    }

    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(r) = joined {
            out.push(r);
        }
    }
    out.sort_by(|a, b| a.host.cmp(&b.host));
    out
}

/// 单个解析器的外层硬超时：慢/不可达的解析器直接跳过，不得拖死整次刷新
const RESOLVER_TIMEOUT: Duration = Duration::from_secs(2);

async fn refresh_one(
    host: &str,
    resolvers: &[Arc<watt_dns::DnsResolver>],
    port: u16,
    probe_timeout: Duration,
    probe_sem: Arc<Semaphore>,
) -> RefreshHostResult {
    let mut source: Option<String> = None;
    let mut candidates: Vec<IpAddr> = Vec::new();

    for resolver in resolvers {
        // 外层硬超时：任一解析器卡住（不可达的公共 DNS / 网络抖动）都不得拖死整次刷新
        let ips = match tokio::time::timeout(RESOLVER_TIMEOUT, resolver.resolve_clean(host)).await {
            Ok(Ok(ips)) if !ips.is_empty() => ips,
            _ => continue,
        };
        let mut seen = HashSet::new();
        let filtered: Vec<IpAddr> = ips
            .into_iter()
            .filter(is_usable_ip)
            .filter(|ip| seen.insert(*ip))
            .collect();
        if filtered.is_empty() {
            continue; // 该解析器只返回不可用地址 → 换下一个
        }
        candidates = filtered;
        source = Some(describe_resolver(resolver));
        break;
    }

    if candidates.is_empty() {
        // 无候选 → 清掉该域名的旧池条目（避免残留失效 IP）
        set_entry(host, Vec::new());
        return RefreshHostResult {
            host: host.to_string(),
            candidates: 0,
            ok: 0,
            ips: Vec::new(),
            source: None,
            error: Some("dns_resolve_empty".into()),
        };
    }

    // 并发探测全部候选
    let mut set = tokio::task::JoinSet::new();
    for ip in &candidates {
        let ip = *ip;
        let host = host.to_string();
        let sem = probe_sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let rtt = probe_ip(&host, ip, port, probe_timeout).await;
            (ip, rtt)
        });
    }

    let mut probed: Vec<(IpAddr, Option<u64>)> = Vec::with_capacity(candidates.len());
    while let Some(joined) = set.join_next().await {
        if let Ok(v) = joined {
            probed.push(v);
        }
    }
    // RTT 升序（未通过者沉底）
    probed.sort_by_key(|(_, rtt)| rtt.unwrap_or(u64::MAX));

    let survivors: Vec<IpAddr> = probed.iter().filter_map(|(ip, rtt)| rtt.map(|_| *ip)).collect();
    let ok = survivors.len();

    // 写池：有通过者则更新，全灭则移除旧条目
    set_entry(host, survivors);

    RefreshHostResult {
        host: host.to_string(),
        candidates: candidates.len(),
        ok,
        ips: probed
            .into_iter()
            .map(|(ip, rtt_ms)| IpProbeResult { ip, rtt_ms })
            .collect(),
        source,
        error: (ok == 0).then(|| "all_unreachable".to_string()),
    }
}

/// 解析器来源描述（用于 UI 展示「IP 来自哪个 DNS」）
fn describe_resolver(resolver: &watt_dns::DnsResolver) -> String {
    let c = resolver.config();
    if c.use_doh {
        let url = c.custom_doh_address.clone().unwrap_or_default();
        format!("DoH {url}")
    } else if let Some(master) = c.master_dns.as_deref().filter(|s| !s.is_empty()) {
        format!("DNS {master}")
    } else {
        "系统 DNS".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 池是进程级全局态，测试默认并行执行会互相污染 → 用互斥锁串行化
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dynamic_ips_exact_and_suffix_match() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        set_entry("figma.com", vec![ip("18.65.14.118")]);
        // 精确命中
        assert_eq!(dynamic_ips("figma.com"), vec![ip("18.65.14.118")]);
        // 后缀命中
        assert_eq!(dynamic_ips("www.figma.com"), vec![ip("18.65.14.118")]);
        assert_eq!(dynamic_ips("api.figma.com:443"), vec![ip("18.65.14.118")]);
        // 形似但非目标不得命中
        assert!(dynamic_ips("notfigma.com").is_empty());
        // 更具体的段优先
        set_entry("api.figma.com", vec![ip("13.35.190.56")]);
        assert_eq!(dynamic_ips("api.figma.com"), vec![ip("13.35.190.56")]);
        clear();
    }

    #[test]
    fn dynamic_ips_boundary_keys_no_oob() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        // key 与查询域等长（内容不同）：后缀匹配前缀为空，不得越界，也不得命中
        set_entry("zzzzzzzz", vec![ip("9.9.9.9")]);
        // key 比查询域更长：同样不得命中
        set_entry("zzzzzzzzzzzz", vec![ip("9.9.9.9")]);
        assert!(dynamic_ips("abcabcab").is_empty());
        assert!(dynamic_ips("abc.com").is_empty());
        clear();
    }

    #[test]
    fn set_entry_empty_removes_stale() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        set_entry("example.com", vec![ip("1.2.3.4")]);
        assert_eq!(dynamic_ips("example.com").len(), 1);
        set_entry("example.com", Vec::new());
        assert!(dynamic_ips("example.com").is_empty());
        clear();
    }

    #[test]
    fn usable_ip_filters_non_global() {
        assert!(is_usable_ip(&ip("18.65.14.118")));
        assert!(!is_usable_ip(&ip("127.0.0.1")));
        assert!(!is_usable_ip(&ip("10.0.0.1")));
        assert!(!is_usable_ip(&ip("192.168.1.1")));
        assert!(!is_usable_ip(&ip("169.254.1.1")));
        assert!(!is_usable_ip(&ip("0.0.0.0")));
        assert!(!is_usable_ip(&ip("fe80::1")));
        assert!(!is_usable_ip(&ip("fd00::1")));
    }

    #[test]
    fn hosts_from_rules_strips_wildcard_and_dedups() {
        let mut r1 = watt_config::DomainRule::default();
        r1.match_domain_names = vec!["*.github.com".into(), "api.github.com".into()];
        let mut r2 = watt_config::DomainRule::default();
        r2.match_domain_names = vec!["github.com".into(), "*.github.com".into()];
        let hosts = hosts_from_rules(&[r1, r2]);
        assert_eq!(hosts, vec!["github.com", "api.github.com"]);
    }

    #[test]
    fn load_save_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        set_entry("figma.com", vec![ip("18.65.14.118"), ip("18.65.14.71")]);
        let dir = std::env::temp_dir().join("watt-ip-pool-test");
        let path = dir.join("IpPool.json");
        save_to(&path);
        clear();
        assert!(dynamic_ips("www.figma.com").is_empty());
        load_from(&path);
        assert_eq!(
            dynamic_ips("www.figma.com"),
            vec![ip("18.65.14.118"), ip("18.65.14.71")]
        );
        let _ = std::fs::remove_file(&path);
        clear();
    }
}
