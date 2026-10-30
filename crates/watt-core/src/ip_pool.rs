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
    /// 动态刷新探测通过的 IP（RTT 升序）；刷新失败时保留旧值
    pub ips: Vec<IpAddr>,
    /// 用户手工维护的 IP：动态刷新不覆盖，避免刷新失败/换池丢失手工数据
    #[serde(default)]
    pub manual_ips: Vec<IpAddr>,
    /// 刷新时刻（unix 毫秒）
    pub refreshed_at_ms: u64,
}

impl PoolEntry {
    /// 生效候选（手工在前，动态在后，去重）
    pub fn all_ips(&self) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = Vec::with_capacity(self.manual_ips.len() + self.ips.len());
        for ip in self.manual_ips.iter().chain(self.ips.iter()) {
            if !out.contains(ip) {
                out.push(*ip);
            }
        }
        out
    }
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
        return e.all_ips();
    }
    let mut best: Option<(usize, Vec<IpAddr>)> = None;
    for (key, entry) in map.iter() {
        let ips = entry.all_ips();
        if ips.is_empty() {
            continue;
        }
        // 后缀匹配：要求 key 之前紧邻 '.'，即 key 是完整域名段而非某段的后半截。
        // 用 strip_suffix 取代手写索引运算——等长 / 更长的 key 天然被排除，
        // 不存在越界可能（原先依赖 `&&` 短路顺序来保证边界安全，过于脆弱）。
        if let Some(prefix) = host.strip_suffix(key.as_str()) {
            if prefix.ends_with('.') && best.as_ref().is_none_or(|(len, _)| key.len() > *len) {
                best = Some((key.len(), ips));
            }
        }
    }
    best.map(|(_, ips)| ips).unwrap_or_default()
}

/// 写入/替换某域名的**动态**池（手工 IP 保留；ips 为空只清动态部分）
pub fn set_entry(host: &str, ips: Vec<IpAddr>) {
    let host = normalize(host);
    let mut map = pool().write().unwrap();
    if ips.is_empty() {
        let remove = match map.get_mut(&host) {
            Some(entry) => {
                entry.ips.clear();
                entry.manual_ips.is_empty()
            }
            None => false,
        };
        if remove {
            map.remove(&host);
        }
    } else {
        let entry = map.entry(host).or_insert_with(|| PoolEntry {
            ips: Vec::new(),
            manual_ips: Vec::new(),
            refreshed_at_ms: now_ms(),
        });
        entry.ips = ips;
        entry.refreshed_at_ms = now_ms();
    }
}

/// 写入/替换某域名的**手工** IP（管理页保存入口；动态部分保留）
pub fn set_manual_entry(host: &str, ips: Vec<IpAddr>) {
    let host = normalize(host);
    let mut map = pool().write().unwrap();
    if ips.is_empty() {
        let remove = match map.get_mut(&host) {
            Some(entry) => {
                entry.manual_ips.clear();
                entry.ips.is_empty()
            }
            None => false,
        };
        if remove {
            map.remove(&host);
        }
    } else {
        let entry = map.entry(host).or_insert_with(|| PoolEntry {
            ips: Vec::new(),
            manual_ips: Vec::new(),
            refreshed_at_ms: now_ms(),
        });
        entry.manual_ips = ips;
        entry.refreshed_at_ms = now_ms();
    }
}

/// 删除某域名的全部池条目（动态 + 手工）
pub fn remove_entry(host: &str) {
    pool().write().unwrap().remove(&normalize(host));
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
        .map(|e| e.all_ips())
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

/// 落盘（best-effort，失败仅 warn）：先写临时文件再替换，避免截断损坏整份池
pub fn save_to(path: &Path) {
    #[derive(Serialize)]
    struct Doc {
        version: u32,
        hosts: HashMap<String, PoolEntry>,
    }
    let doc = Doc {
        version: 2,
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
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &json) {
        tracing::warn!("IP 池临时文件写入失败: {e}");
        return;
    }
    // Windows rename 不能覆盖已存在文件；先删除旧文件（失败窗口极小）
    #[cfg(windows)]
    {
        let _ = std::fs::remove_file(path);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!("IP 池落盘失败: {e}");
        let _ = std::fs::remove_file(&tmp);
    }
}

/// 从 JSON 加载（best-effort；损坏文件改名保留，便于诊断）
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
        Err(e) => {
            tracing::warn!("IP 池文件损坏，已保留为 .corrupt 并忽略: {e}");
            let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
        }
    }
}

/// 过滤明显不可用的 IP（回环 / 私有 / 链路本地 / 未指定 / 组播 / 文件用途 / v6 ULA）
///
/// 该函数同时是本地 XHR 桥的 SSRF 闸门（`local_domain::handle_xhr`），因此除
/// `IpAddr` 标准库判定外，还覆盖以下容易漏网的保留段：
/// - `0.0.0.0/8`（本网络）、`100.64.0.0/10`（CGNAT / 运营商内网）、
///   `192.0.0.0/24`（IETF 协议分配）、`198.18.0.0/15`（基准测试）、`240.0.0.0/4`（保留）
/// - IPv4-mapped IPv6（`::ffff:127.0.0.1` 等）必须先还原为 IPv4 再判定，
///   否则 `::ffff:169.254.169.254` 可绕过回环/链路本地检查访问云元数据
pub fn is_usable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_usable_v4(*v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped / IPv4-compatible：按内嵌 IPv4 判定，防绕过
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_usable_v4(v4);
            }
            let seg = v6.segments();
            // IPv6 转换/隧道前缀：可承载任意 IPv4（含云元数据 169.254.169.254），
            // 不能仅凭「IPv6 公网段」放行。
            let transition = (seg[0] == 0x0064 && seg[1] == 0xff9b) // NAT64 64:ff9b::/96
                || seg[0] == 0x2002 // 6to4 2002::/16
                || (seg[0] == 0x2001 && seg[1] == 0x0000) // Teredo 2001::/32
                || seg[..6] == [0, 0, 0, 0, 0, 0]; // IPv4-compatible ::/96（已废弃）
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || transition
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 唯一本地
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 链路本地
                || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 站点本地（已废弃）
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)) // 2001:db8::/32 文档
        }
    }
}

fn is_usable_v4(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation()
        || octets[0] == 0 // 0.0.0.0/8
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18) // 198.18.0.0/15 基准测试
        || octets[0] >= 240) // 240.0.0.0/4 保留（含广播）
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
        // 无候选（断网/DNS 被阻断）→ 保留旧池，不清空（手工 IP 更是不能丢）
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

    // 写池：仅在有通过者时更新；全灭保留旧值（刷新失败不代表旧 IP 全部失效）
    if !survivors.is_empty() {
        set_entry(host, survivors);
    }

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

/// 解析器来源描述（用于 UI 展示「IP 来自哪个 DNS」）。
/// 按实际生效后端展示：DoH 配置失效会回退，不能只信 settings。
fn describe_resolver(resolver: &watt_dns::DnsResolver) -> String {
    match resolver.backend() {
        watt_dns::DnsBackend::Doh(url) => format!("DoH {url}"),
        watt_dns::DnsBackend::Udp(ip) => format!("DNS {ip}"),
        watt_dns::DnsBackend::System => "系统 DNS".to_string(),
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

    /// SSRF 闸门回归：常见保留段与 IPv4-mapped IPv6 绕过
    #[test]
    fn usable_ip_filters_reserved_and_mapped() {
        for s in [
            "0.1.2.3",        // 0.0.0.0/8
            "100.64.0.1",     // CGNAT
            "100.127.255.254", // CGNAT 上界
            "192.0.0.8",      // IETF 协议分配
            "198.18.0.1",     // 基准测试
            "198.19.255.254", // 基准测试上界
            "240.0.0.1",      // 保留
            "255.255.255.254",
            "::ffff:127.0.0.1",       // IPv4-mapped 回环
            "::ffff:169.254.169.254", // IPv4-mapped 链路本地（云元数据）
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe", // NAT64 → 169.254.169.254
            "2002:a9fe:a9fe::1",  // 6to4 → 169.254.169.254
            "2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
            "::a9fe:a9fe",        // IPv4-compatible ::/96
            "fec0::1",            // 站点本地
            "2001:db8::1",        // 文档段
        ] {
            assert!(!is_usable_ip(&ip(s)), "{s} 应判定为不可用");
        }
        // 边界外的公网地址仍可用
        assert!(is_usable_ip(&ip("100.63.255.254"))); // CGNAT 前一段
        assert!(is_usable_ip(&ip("100.128.0.1"))); // CGNAT 后一段
        assert!(is_usable_ip(&ip("198.20.0.1")));
        assert!(is_usable_ip(&ip("2606:4700::1111")));
    }

    #[test]
    fn hosts_from_rules_strips_wildcard_and_dedups() {
        let r1 = watt_config::DomainRule {
            match_domain_names: vec!["*.github.com".into(), "api.github.com".into()],
            ..Default::default()
        };
        let r2 = watt_config::DomainRule {
            match_domain_names: vec!["github.com".into(), "*.github.com".into()],
            ..Default::default()
        };
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

    #[test]
    fn manual_ips_survive_dynamic_clear_and_replace() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        set_manual_entry("example.com", vec![ip("1.1.1.1")]);
        // 动态清空（刷新失败路径）不得丢掉手工 IP
        set_entry("example.com", Vec::new());
        assert_eq!(entry_ips("example.com"), vec![ip("1.1.1.1")]);
        // 动态刷新成功只替换动态部分
        set_entry("example.com", vec![ip("2.2.2.2")]);
        let all = entry_ips("example.com");
        assert!(all.contains(&ip("1.1.1.1")));
        assert!(all.contains(&ip("2.2.2.2")));
        // 显式删除才清空全部
        remove_entry("example.com");
        assert!(entry_ips("example.com").is_empty());
        clear();
    }
}
