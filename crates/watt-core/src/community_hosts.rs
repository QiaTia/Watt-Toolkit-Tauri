//! 社区维护的 GitHub Hosts 源（默认 `https://hosts.gitcdn.top/hosts.json`）。
//!
//! # 这个模块做什么
//!
//! 拉取社区维护的 GitHub hosts 清单（格式 `[["ip","host"], ...]`），**本地实测**
//! 每个候选，把通过的 IP 追加进动态 IP 池作为额外候选。出站竞速时它和 DNS
//! 解析结果平权参与，谁先握手成功用谁，因此不会给常规路径增加延迟。
//!
//! # 三条硬约束
//!
//! 1. **绝不写 hosts 文件**。社区源是第三方数据，写进 hosts 等于把域名解析权
//!    交给它；只进 IP 池，最坏情况是一个无效候选被竞速丢弃。
//! 2. **必须本地探测**。`probe_ip` 走完整 TLS 握手并按 SNI 校验证书，因此即使
//!    源里被塞了恶意 IP（`github.com → 攻击者服务器`），证书校验也会失败而被丢弃
//!    ——这是本模块唯一的信任边界，不能为了省时间跳过。
//! 3. **只补不删**。合并走 [`crate::ip_pool::add_dynamic_ips`]（并集），不能用
//!    `set_entry`（替换），否则会和 DNS 刷新互相清空对方的结果。
//!
//! # 失败语义
//!
//! 拉取/解析失败不影响任何既有功能：池里原有的候选照常工作。调用方把失败原因
//! 写进设置里的 `last_summary` 供 UI 展示即可，不弹窗、不阻断启动。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

/// 探测端口：社区源给的是 HTTPS 入口，沿用 443
pub const DEFAULT_PROBE_PORT: u16 = 443;
/// 响应体上限：正常约 2KB；给足余量，同时防止被投毒的超大响应拖死内存
const MAX_BODY_BYTES: usize = 512 * 1024;
/// 每个域名从社区源最多并入的 IP 数
const MAX_IPS_PER_HOST: usize = 4;
/// 动态池每域名的总上限（DNS 结果 + 社区源共享）。留出余量让两者共存：
/// 若按 4 截断，DNS 已有 4 个时社区 IP 会被全数拒之门外。
const MAX_DYNAMIC_IPS: usize = 8;
/// 探测并发上限
const PROBE_CONCURRENCY: usize = 12;
/// HTTP 超时
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// 一条 hosts 映射
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMapping {
    pub host: String,
    pub ip: IpAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum CommunityError {
    #[error("拉取社区源失败: {0}")]
    Fetch(String),
    #[error("社区源内容无法解析: {0}")]
    Parse(String),
}

/// 单次拉取的结果（面向 UI 展示）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchOutcome {
    pub source: String,
    /// 拉取时刻（unix 毫秒）
    pub fetched_at_ms: u64,
    /// 源里的条目总数
    pub entries: usize,
    /// 过滤掉保留地址/非法域名后剩余
    pub usable: usize,
    /// 本地探测通过的条数
    pub probed_ok: usize,
    /// 实际写入池的域名数
    pub hosts_touched: usize,
    /// 实际写入池的 IP 数
    pub ips_merged: usize,
}

/// 拉取并合并。失败时不修改池内任何数据。
pub async fn fetch_and_merge(
    url: &str,
    port: u16,
    probe_timeout: Duration,
) -> Result<FetchOutcome, CommunityError> {
    let text = http_get(url).await?;
    let mappings = parse_mappings(&text)?;
    let entries = mappings.len();

    // 去重（同一 host+ip 重复出现）+ 过滤保留地址
    let mut seen: Vec<HostMapping> = Vec::with_capacity(mappings.len());
    for m in mappings {
        if !crate::ip_pool::is_usable_ip(&m.ip) {
            continue;
        }
        if seen.iter().any(|s| s.host == m.host && s.ip == m.ip) {
            continue;
        }
        seen.push(m);
    }
    let usable = seen.len();
    if usable == 0 {
        return Err(CommunityError::Parse(
            "源中的条目全部被过滤（保留地址或非法域名）".into(),
        ));
    }

    // 本地实测：TLS 握手 + 证书校验，通不过的一律丢弃
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for m in seen {
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let rtt = crate::ip_pool::probe_ip(&m.host, m.ip, port, probe_timeout).await?;
            Some((m, rtt))
        });
    }

    let mut by_host: BTreeMap<String, Vec<(u64, IpAddr)>> = BTreeMap::new();
    let mut probed_ok = 0usize;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Some((m, rtt))) => {
                probed_ok += 1;
                by_host.entry(m.host).or_default().push((rtt, m.ip));
            }
            Ok(None) => {}
            Err(e) => tracing::debug!(error = %e, "社区源探测任务异常，已跳过"),
        }
    }

    let mut ips_merged = 0usize;
    let hosts_touched = by_host.len();
    for (host, mut list) in by_host {
        // RTT 升序：池内动态部分有上限，慢的候选先被截掉
        list.sort_by_key(|(rtt, _)| *rtt);
        list.truncate(MAX_IPS_PER_HOST);
        let ips: Vec<IpAddr> = list.into_iter().map(|(_, ip)| ip).collect();
        ips_merged += ips.len();
        crate::ip_pool::add_dynamic_ips(&host, &ips, MAX_DYNAMIC_IPS);
    }

    tracing::info!(
        source = url,
        entries,
        usable,
        probed_ok,
        hosts_touched,
        ips_merged,
        "社区 hosts 源已并入备选 IP 池"
    );

    Ok(FetchOutcome {
        source: url.to_string(),
        fetched_at_ms: now_ms(),
        entries,
        usable,
        probed_ok,
        hosts_touched,
        ips_merged,
    })
}

/// 拉取文本（直连，不继承系统代理/环境变量代理）。
///
/// 加速模式下系统代理指向本进程，若走系统代理会形成自环；引擎同时会把
/// `http_proxy` 注入终端配置，环境变量代理同理。因此显式 `no_proxy()`。
async fn http_get(url: &str) -> Result<String, CommunityError> {
    // rustls-no-provider 不自动安装 crypto provider（进程级、幂等）
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .user_agent(concat!("WattToolkit/", env!("CARGO_PKG_VERSION")))
        .timeout(HTTP_TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|e| CommunityError::Fetch(format!("客户端构建失败: {e}")))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CommunityError::Fetch(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(CommunityError::Fetch(format!("HTTP {status}")));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_BODY_BYTES as u64 {
            return Err(CommunityError::Fetch(format!(
                "响应过大（{len} 字节，上限 {MAX_BODY_BYTES}）"
            )));
        }
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| CommunityError::Fetch(e.to_string()))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(CommunityError::Fetch(format!(
            "响应过大（{} 字节，上限 {MAX_BODY_BYTES}）",
            body.len()
        )));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// 解析 hosts 清单。
///
/// 支持两种历史格式，且**不依赖字段顺序**：
/// - 数组：`[["1.2.3.4","github.com"], ...]`（社区源当前格式，IP 在前）
/// - 对象：`[{"ip":"1.2.3.4","host":"github.com"}, ...]`
///
/// 顺序按「哪一侧能解析成 IP」判定而非写死下标：源格式从 `[ip,host]` 换成
/// `[host,ip]` 时，写死下标会静默产出空池——比直接报错更难排查。
pub fn parse_mappings(text: &str) -> Result<Vec<HostMapping>, CommunityError> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| CommunityError::Parse(format!("JSON 解析失败: {e}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| CommunityError::Parse("顶层必须是数组".into()))?;

    let mut out = Vec::with_capacity(arr.len());
    let mut skipped = 0usize;
    for item in arr {
        match mapping_from_value(item) {
            Some(m) => out.push(m),
            None => skipped += 1,
        }
    }
    if out.is_empty() {
        return Err(CommunityError::Parse(format!(
            "{} 项均无法解析出 (ip, host)",
            arr.len().max(skipped)
        )));
    }
    if skipped > 0 {
        tracing::debug!(skipped, total = arr.len(), "社区源部分条目无法解析，已跳过");
    }
    Ok(out)
}

fn mapping_from_value(v: &serde_json::Value) -> Option<HostMapping> {
    if let Some(pair) = v.as_array() {
        if pair.len() != 2 {
            return None;
        }
        let a = pair[0].as_str()?.trim();
        let b = pair[1].as_str()?.trim();
        return match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
            (Ok(ip), Err(_)) => clean_host(b).map(|host| HostMapping { host, ip }),
            (Err(_), Ok(ip)) => clean_host(a).map(|host| HostMapping { host, ip }),
            _ => None,
        };
    }
    let obj = v.as_object()?;
    let ip: IpAddr = obj.get("ip")?.as_str()?.trim().parse().ok()?;
    let host = obj
        .get("host")
        .or_else(|| obj.get("domain"))?
        .as_str()?;
    clean_host(host).map(|host| HostMapping { host, ip })
}

/// 域名规范化 + 可用性判断。
///
/// 社区源是第三方数据，域名会进入出站候选（参与 SNI 与证书校验），
/// 因此这里只放行「看起来就是普通域名」的值，拒绝把奇怪内容带进上层。
fn clean_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // 单标签名（localhost 等）不该出现在公共 hosts 源
    if !host.contains('.') {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    ok.then_some(host)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_community_format() {
        // 摘自 https://hosts.gitcdn.top/hosts.json 的真实片段
        let text = r#"[["140.82.112.25","alive.github.com"],["20.6.7.17","github.com"],["185.199.111.133","raw.githubusercontent.com"]]"#;
        let m = parse_mappings(text).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[1].host, "github.com");
        assert_eq!(m[1].ip, "20.6.7.17".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_reversed_order() {
        // 源若把顺序换成 [host, ip] 也必须能读（不能静默产空池）
        let text = r#"[["github.com","20.6.7.17"]]"#;
        let m = parse_mappings(text).unwrap();
        assert_eq!(m[0].host, "github.com");
        assert_eq!(m[0].ip, "20.6.7.17".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_object_format() {
        let text = r#"[{"ip":"1.2.3.4","host":"example.com"},{"ip":"5.6.7.8","domain":"b.example.com"}]"#;
        let m = parse_mappings(text).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[1].host, "b.example.com");
    }

    #[test]
    fn skips_malformed_entries_but_keeps_valid() {
        let text = r#"[
            ["1.2.3.4","ok.example.com"],
            ["not-an-ip","also-bad"],
            ["1.2.3.4"],
            ["1.2.3.4","localhost"],
            ["1.2.3.4","1.2.3.5"],
            ["1.2.3.4","bad host.com"],
            "just a string"
        ]"#;
        let m = parse_mappings(text).unwrap();
        assert_eq!(m.len(), 1, "只有合法项应保留: {m:?}");
        assert_eq!(m[0].host, "ok.example.com");
    }

    #[test]
    fn rejects_non_array_and_garbage() {
        assert!(parse_mappings(r#"{"a":1}"#).is_err());
        assert!(parse_mappings("not json").is_err());
        // 全部不可解析 → 报错而不是返回空列表（空列表会被误当成「源正常但没有数据」）
        assert!(parse_mappings(r#"[["x","y"]]"#).is_err());
    }

    #[test]
    fn normalizes_host_case_and_trailing_dot() {
        let text = r#"[["1.2.3.4","GitHub.COM."]]"#;
        let m = parse_mappings(text).unwrap();
        assert_eq!(m[0].host, "github.com");
    }

    #[test]
    fn rejects_host_with_scheme_or_path() {
        // 防止源里混入 URL 让上游把整串当域名用
        for bad in ["https://github.com", "github.com/x", "github.com:443"] {
            let text = format!(r#"[["1.2.3.4","{bad}"]]"#);
            assert!(parse_mappings(&text).is_err(), "{bad} 不应被接受");
        }
    }
}
