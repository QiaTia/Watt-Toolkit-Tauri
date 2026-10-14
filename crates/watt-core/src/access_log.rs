//! 代理访问日志：记录每个经本地代理转发的请求（环形缓冲，供 UI 查询）。
//!
//! 记录点在 `http_relay::RelayContext::handle_request`（所有代理请求的统一入口）。
//! 存储为定长环形缓冲：超出上限时丢弃最旧条目，内存占用恒定；查询支持关键字 /
//! 方法 / 状态码区间 / 处置分类过滤，倒序（最新在前）分页返回。
//!
//! 与 `FlowStats` 一致：日志存储由 `ProxyEngine` 持有（`new()` 时创建、跨重启常驻），
//! 克隆进每份 `RelayContext`，命令层经 `engine.access_logs()` 读取。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 默认环形缓冲上限（条）
pub const DEFAULT_CAPACITY: usize = 5000;

/// 请求处置分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Disposition {
    /// 命中具体加速规则
    Matched,
    /// 走 default 规则（未命中具体加速项）
    Default,
    /// 未匹配任何规则（含全局转发 / 404）
    Unmatched,
    /// 本地域名 / 注入脚本短路
    Local,
}

/// 单条访问日志
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogEntry {
    /// Unix 毫秒时间戳
    pub ts_ms: u64,
    /// 目标主机
    pub host: String,
    /// HTTP 方法
    pub method: String,
    /// 路径（含 query）
    pub path: String,
    /// 响应状态码
    pub status: u16,
    /// 上行字节（请求体，取 Content-Length）
    pub up_bytes: u64,
    /// 下行字节（响应体长度）
    pub down_bytes: u64,
    /// 处理耗时（毫秒）
    pub latency_ms: u64,
    /// 处置分类
    pub disposition: Disposition,
}

/// 查询过滤条件（字段为空即不限制）
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogFilter {
    /// 关键字（匹配 host 或 path，大小写不敏感）
    pub keyword: Option<String>,
    /// 方法（大小写不敏感）
    pub method: Option<String>,
    /// 状态码下界（含）
    pub status_min: Option<u16>,
    /// 状态码上界（含）
    pub status_max: Option<u16>,
    /// 处置分类
    pub disposition: Option<Disposition>,
}

/// 分页结果
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessLogPage {
    pub items: Vec<AccessLogEntry>,
    /// 过滤后总条数（用于分页）
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

/// 环形缓冲日志存储（线程安全；push/query 均为短临界区，无 await）
pub struct AccessLogStore {
    cap: usize,
    inner: Mutex<VecDeque<AccessLogEntry>>,
}

impl AccessLogStore {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            inner: Mutex::new(VecDeque::new()),
        }
    }

    /// 追加一条日志（超出上限丢弃最旧）
    pub fn push(&self, entry: AccessLogEntry) {
        let mut q = self.inner.lock().unwrap();
        if q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// 清空
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// 当前条数
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 过滤 + 倒序分页查询（page 从 1 起；page_size 上限 500）
    pub fn query(&self, filter: &AccessLogFilter, page: usize, page_size: usize) -> AccessLogPage {
        let kw = filter
            .keyword
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let method = filter
            .method
            .as_deref()
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty());

        let q = self.inner.lock().unwrap();
        let mut total = 0usize;
        let page = page.max(1);
        let page_size = page_size.clamp(1, 500);
        let start = (page - 1) * page_size;
        let end = start + page_size;

        let mut items = Vec::new();
        // 倒序遍历（最新在前），边过滤边分页，避免整表收集
        for e in q.iter().rev() {
            if !matches_filter(e, &kw, &method, filter) {
                continue;
            }
            if total >= start && total < end {
                items.push(e.clone());
            }
            total += 1;
        }

        AccessLogPage {
            items,
            total,
            page,
            page_size,
        }
    }
}

/// 单条命中判定
fn matches_filter(
    e: &AccessLogEntry,
    kw: &Option<String>,
    method: &Option<String>,
    filter: &AccessLogFilter,
) -> bool {
    if let Some(k) = kw {
        if !e.host.to_ascii_lowercase().contains(k) && !e.path.to_ascii_lowercase().contains(k) {
            return false;
        }
    }
    if let Some(m) = method {
        if !e.method.eq_ignore_ascii_case(m) {
            return false;
        }
    }
    if let Some(lo) = filter.status_min {
        if e.status < lo {
            return false;
        }
    }
    if let Some(hi) = filter.status_max {
        if e.status > hi {
            return false;
        }
    }
    if let Some(d) = filter.disposition {
        if e.disposition != d {
            return false;
        }
    }
    true
}

/// 当前 Unix 毫秒时间戳
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(host: &str, method: &str, status: u16, disp: Disposition) -> AccessLogEntry {
        AccessLogEntry {
            ts_ms: now_ms(),
            host: host.to_string(),
            method: method.to_string(),
            path: "/".to_string(),
            status,
            up_bytes: 0,
            down_bytes: 0,
            latency_ms: 0,
            disposition: disp,
        }
    }

    #[test]
    fn test_ring_buffer_caps_at_capacity() {
        let store = AccessLogStore::new(3);
        for i in 0..5 {
            store.push(entry(&format!("h{i}.com"), "GET", 200, Disposition::Matched));
        }
        assert_eq!(store.len(), 3);
        // 最旧两条被丢弃，剩 h2/h3/h4，倒序返回 h4 在前
        let page = store.query(&AccessLogFilter::default(), 1, 10);
        assert_eq!(page.total, 3);
        assert_eq!(page.items[0].host, "h4.com");
        assert_eq!(page.items[2].host, "h2.com");
    }

    #[test]
    fn test_filter_keyword_method_status_disposition() {
        let store = AccessLogStore::new(100);
        store.push(entry("github.com", "GET", 200, Disposition::Matched));
        store.push(entry("api.github.com", "POST", 500, Disposition::Default));
        store.push(entry("example.com", "GET", 404, Disposition::Unmatched));

        // 关键字匹配 host
        let f = AccessLogFilter {
            keyword: Some("github".into()),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 1, 10).total, 2);

        // 方法
        let f = AccessLogFilter {
            method: Some("post".into()),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 1, 10).total, 1);

        // 状态码区间
        let f = AccessLogFilter {
            status_min: Some(400),
            status_max: Some(499),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 1, 10).total, 1);

        // 处置分类
        let f = AccessLogFilter {
            disposition: Some(Disposition::Unmatched),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 1, 10).total, 1);
    }

    #[test]
    fn test_pagination() {
        let store = AccessLogStore::new(100);
        for i in 0..25 {
            store.push(entry(&format!("h{i}.com"), "GET", 200, Disposition::Matched));
        }
        let p2 = store.query(&AccessLogFilter::default(), 2, 10);
        assert_eq!(p2.total, 25);
        assert_eq!(p2.items.len(), 10);
        // 倒序：第 1 页首条为 h24，第 2 页首条为 h14
        assert_eq!(p2.items[0].host, "h14.com");
        let p3 = store.query(&AccessLogFilter::default(), 3, 10);
        assert_eq!(p3.items.len(), 5);
        // 越界页返回空
        assert!(store.query(&AccessLogFilter::default(), 9, 10).items.is_empty());
    }

    #[test]
    fn test_clear() {
        let store = AccessLogStore::new(10);
        store.push(entry("a.com", "GET", 200, Disposition::Matched));
        assert!(!store.is_empty());
        store.clear();
        assert!(store.is_empty());
    }
}
