//! 候选 IP 探测结果缓存（对齐 doc/ip-probe-prefetch-plan.md §4.2）。
//!
//! 启动预探测（probe.rs）把各候选的握手 RTT 写入本缓存；竞速（outbound.rs
//! `connect`）读取并按 RTT 升序排列健康候选——最快者最先 spawn，
//! 首个 TLS 完成者大概率即全局最快者。探测是 best-effort：缺失/过期
//! 的条目视为未探测（沉底但仍在场，行为与无探测时一致）。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// 探测摘要（供 UI 展示「已择优」；IPC 直传）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeSummary {
    /// 本次探测的域名数
    pub hosts: usize,
    /// 候选总数
    pub candidates: usize,
    /// 握手成功的候选数
    pub ok: usize,
    /// 最快候选 RTT（毫秒）
    pub fastest_ms: Option<u64>,
    /// 是否完整跑完（超预算截断为 false）
    pub finished: bool,
}

/// 探测条目：握手全链路 RTT（毫秒）与探测时刻
#[derive(Debug, Clone, Copy)]
pub struct ProbeEntry {
    pub rtt_ms: u64,
    pub at: Instant,
}

/// 条目有效期：5 分钟（探测是预择优而非权威判定，真实可用性仍以
/// CandidateHealth 与竞速结果为准，故 TTL 不宜过长）
pub const PROBE_TTL: Duration = Duration::from_secs(300);

/// 容量上限（防极端场景内存膨胀；清理时顺带淘汰过期条目）
const CAPACITY: usize = 4096;

/// 探测缓存：key 为 (host, ip)，进程内共享（engine 级 Arc）
#[derive(Default)]
pub struct ProbeCache {
    entries: Mutex<HashMap<(String, IpAddr), ProbeEntry>>,
    /// 最近一次探测摘要（UI 查询；IPC 直传）
    summary: Mutex<Option<ProbeSummary>>,
}

impl ProbeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录探测结果
    pub fn put(&self, host: &str, ip: IpAddr, rtt_ms: u64) {
        let mut map = self.entries.lock().unwrap();
        map.insert(
            (host.to_ascii_lowercase(), ip),
            ProbeEntry {
                rtt_ms,
                at: Instant::now(),
            },
        );
        if map.len() > CAPACITY {
            map.retain(|_, e| e.at.elapsed() < PROBE_TTL);
        }
        // 兜底：清理后仍超限（全部新鲜）则清空，宁可丢缓存不可无限增长
        if map.len() > CAPACITY {
            map.clear();
        }
    }

    /// 读取有效条目（TTL 内）；None = 未探测或已过期
    pub fn get(&self, host: &str, ip: IpAddr) -> Option<u64> {
        let map = self.entries.lock().unwrap();
        let e = map.get(&(host.to_ascii_lowercase(), ip))?;
        (e.at.elapsed() < PROBE_TTL).then_some(e.rtt_ms)
    }

    /// 排序候选：已探测按 RTT 升序在前，未探测沉底（保持原相对顺序）。
    ///
    /// key 为 (是否未探测, rtt)：已探测(false) 整体排在未探测(true) 前，
    /// 已探测内部按 RTT 升序。稳定排序保证同组保持原序。
    /// 竞速语义不依赖顺序（并发胜出），排序只影响 spawn 先后与胜出倾向。
    pub fn sort_addrs(&self, host: &str, addrs: &mut [SocketAddr]) {
        addrs.sort_by_cached_key(|a| match self.get(host, a.ip()) {
            Some(rtt_ms) => (false, rtt_ms),
            None => (true, 0),
        });
    }

    /// 记录最近一次探测摘要（周期刷新会覆盖）
    pub fn record_summary(&self, summary: ProbeSummary) {
        *self.summary.lock().unwrap() = Some(summary);
    }

    /// 读取最近一次探测摘要（无 = 尚未探测）
    pub fn latest_summary(&self) -> Option<ProbeSummary> {
        self.summary.lock().unwrap().clone()
    }

    // —————————————————————— 落盘持久化（P2，默认关；EngineConfig 开关控制） ——————————————————————

    /// 保存到 JSON（条目带 age_secs，加载时换算为 at）；best-effort，失败仅 warn
    pub fn save_to(&self, path: &Path) {
        #[derive(Serialize)]
        struct Persist<'a> {
            version: u32,
            entries: &'a [(String, IpAddr, u64, u64)],
        }
        // 快照时统一加锁，避免逐条 lock 的不一致视图
        let snapshot = {
            let map = self.entries.lock().unwrap();
            map.iter()
                .map(|((h, ip), e)| (h.clone(), *ip, e.rtt_ms, e.at.elapsed().as_secs()))
                .collect::<Vec<_>>()
        };
        let doc = Persist {
            version: 1,
            entries: &snapshot,
        };
        match serde_json::to_string_pretty(&doc) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::warn!("探测缓存落盘失败: {e}");
                }
            }
            Err(e) => tracing::warn!("探测缓存序列化失败: {e}"),
        }
    }

    /// 从 JSON 加载（P2 热启动：重启后首请求即有排序）；best-effort，失败/不存在静默
    pub fn load_from(&self, path: &Path) {
        #[derive(Deserialize)]
        struct Persist {
            entries: Vec<(String, IpAddr, u64, u64)>,
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            return; // 不存在 = 首次运行，正常
        };
        let Ok(doc) = serde_json::from_str::<Persist>(&text) else {
            tracing::warn!("探测缓存文件损坏，忽略: {}", path.display());
            return;
        };
        let now = Instant::now();
        let mut map = self.entries.lock().unwrap();
        for (host, ip, rtt_ms, age_secs) in doc.entries {
            // age 超过 TTL 的条目加载即视为过期（读时同样会过滤），此处仍可装入：
            // get 的 TTL 判定是权威的
            let at = now - Duration::from_secs(age_secs.min(PROBE_TTL.as_secs() * 2));
            map.insert((host.to_ascii_lowercase(), ip), ProbeEntry { rtt_ms, at });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn put_get_roundtrip() {
        let cache = ProbeCache::new();
        cache.put("github.com", ip("140.82.112.3"), 42);
        assert_eq!(cache.get("github.com", ip("140.82.112.3")), Some(42));
        assert_eq!(cache.get("github.com", ip("140.82.112.4")), None);
        assert_eq!(cache.get("other.com", ip("140.82.112.3")), None);
    }

    #[test]
    fn host_case_insensitive() {
        let cache = ProbeCache::new();
        cache.put("GitHub.com", ip("140.82.112.3"), 42);
        assert_eq!(cache.get("github.COM", ip("140.82.112.3")), Some(42));
    }

    #[test]
    fn expired_entry_reads_as_none() {
        let cache = ProbeCache::new();
        // 直接写入一条已过期条目（模拟 TTL 到期）
        cache.entries.lock().unwrap().insert(
            ("github.com".into(), ip("140.82.112.3")),
            ProbeEntry {
                rtt_ms: 42,
                at: Instant::now() - PROBE_TTL - Duration::from_secs(1),
            },
        );
        assert_eq!(cache.get("github.com", ip("140.82.112.3")), None);
    }

    #[test]
    fn sort_addrs_rtt_ascending_unprobed_sink() {
        let cache = ProbeCache::new();
        cache.put("github.com", ip("20.205.243.166"), 10);
        cache.put("github.com", ip("140.82.112.4"), 5);
        // 20.27.177.113 未探测 → 沉底
        let mut addrs = vec![
            SocketAddr::new(ip("20.27.177.113"), 443),
            SocketAddr::new(ip("20.205.243.166"), 443),
            SocketAddr::new(ip("140.82.112.4"), 443),
        ];
        cache.sort_addrs("github.com", &mut addrs);
        let order: Vec<_> = addrs.iter().map(|a| a.ip().to_string()).collect();
        assert_eq!(
            order,
            vec![
                "140.82.112.4",  // RTT 5
                "20.205.243.166", // RTT 10
                "20.27.177.113", // 未探测，沉底
            ]
        );
    }

    #[test]
    fn sort_addrs_empty_cache_keeps_order() {
        let cache = ProbeCache::new();
        let mut addrs = vec![
            SocketAddr::new(ip("1.1.1.1"), 443),
            SocketAddr::new(ip("2.2.2.2"), 443),
        ];
        cache.sort_addrs("example.com", &mut addrs);
        // 全未探测：稳定排序保持原序（不是无序重排）
        assert_eq!(addrs[0].ip().to_string(), "1.1.1.1");
        assert_eq!(addrs[1].ip().to_string(), "2.2.2.2");
    }

    #[test]
    fn summary_serializes_camel_case() {
        // 前端按 fastestMs 消费；字段名不一致会恒显示「最快 0ms」
        let summary = ProbeSummary {
            hosts: 2,
            candidates: 5,
            ok: 3,
            fastest_ms: Some(88),
            finished: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"fastestMs\":88"), "实际 JSON: {json}");
        assert!(json.contains("\"hosts\":2"), "实际 JSON: {json}");
    }
}
