//! 运行日志：把 `tracing` 事件收集进环形缓冲，供 UI「运行日志」页查询/筛选/分页。
//!
//! 采用自定义 `tracing_subscriber::Layer`（`RuntimeLogLayer`）在 `on_event` 中把每条
//! 日志格式化为「消息 + key=value 字段」写入全局环形缓冲；存储为进程级单例，
//! 与日志订阅器同时初始化，命令层通过 `runtime_log()` 读取。

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Mutex, OnceLock};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// 环形缓冲上限（条）
pub const DEFAULT_CAPACITY: usize = 3000;

/// 单条运行日志
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLogEntry {
    /// Unix 毫秒时间戳
    pub ts_ms: u64,
    /// 级别（ERROR/WARN/INFO/DEBUG/TRACE）
    pub level: String,
    /// 目标（模块路径）
    pub target: String,
    /// 格式化后的消息（含 key=value 字段）
    pub message: String,
}

/// 查询过滤条件
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLogFilter {
    /// 关键字（匹配 message 或 target，大小写不敏感）
    pub keyword: Option<String>,
    /// 最低级别（含）：ERROR/WARN/INFO/DEBUG/TRACE，空=不限
    pub min_level: Option<String>,
}

/// 分页结果
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLogPage {
    pub items: Vec<RuntimeLogEntry>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

/// 级别 → 数值（越小越严重；用于「最低级别」过滤，避免依赖 Level 的 Ord 语义）
fn level_num(level: &str) -> u8 {
    match level {
        "ERROR" => 1,
        "WARN" => 2,
        "INFO" => 3,
        "DEBUG" => 4,
        "TRACE" => 5,
        _ => 0,
    }
}

/// 环形缓冲日志存储（线程安全；push/query 短临界区）
pub struct RuntimeLogStore {
    cap: usize,
    inner: Mutex<VecDeque<RuntimeLogEntry>>,
}

impl RuntimeLogStore {
    fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            inner: Mutex::new(VecDeque::new()),
        }
    }

    /// 追加一条（超限丢弃最旧）
    pub fn push(&self, entry: RuntimeLogEntry) {
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
    pub fn query(
        &self,
        filter: &RuntimeLogFilter,
        page: usize,
        page_size: usize,
    ) -> RuntimeLogPage {
        let kw = filter
            .keyword
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let threshold = filter
            .min_level
            .as_deref()
            .map(|s| level_num(&s.trim().to_ascii_uppercase()))
            .filter(|n| *n > 0);

        let q = self.inner.lock().unwrap();
        let page = page.max(1);
        let page_size = page_size.clamp(1, 500);
        let start = (page - 1) * page_size;
        let end = start + page_size;

        let mut total = 0usize;
        let mut items = Vec::new();
        for e in q.iter().rev() {
            if let Some(k) = &kw {
                if !e.message.to_ascii_lowercase().contains(k)
                    && !e.target.to_ascii_lowercase().contains(k)
                {
                    continue;
                }
            }
            if let Some(th) = threshold {
                if level_num(&e.level) > th {
                    continue;
                }
            }
            if total >= start && total < end {
                items.push(e.clone());
            }
            total += 1;
        }

        RuntimeLogPage {
            items,
            total,
            page,
            page_size,
        }
    }
}

/// 全局运行日志存储（tracing 层写入、命令层查询）
static RUNTIME_LOG: OnceLock<RuntimeLogStore> = OnceLock::new();

/// 获取全局运行日志存储（首次调用时惰性初始化）
pub fn runtime_log() -> &'static RuntimeLogStore {
    RUNTIME_LOG.get_or_init(|| RuntimeLogStore::new(DEFAULT_CAPACITY))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `tracing` 采集层：把每个事件写入全局环形缓冲
pub struct RuntimeLogLayer;

impl<S: Subscriber> Layer<S> for RuntimeLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut v = MsgVisitor {
            message: String::new(),
            extras: String::new(),
        };
        event.record(&mut v);
        let message = match (v.message.is_empty(), v.extras.is_empty()) {
            (_, true) => v.message,
            (true, _) => v.extras,
            _ => format!("{} {}", v.message, v.extras),
        };
        runtime_log().push(RuntimeLogEntry {
            ts_ms: now_ms(),
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message,
        });
    }
}

/// 事件字段访问器：分离 `message` 与其余 key=value 字段
struct MsgVisitor {
    message: String,
    extras: String,
}

impl MsgVisitor {
    fn push_extra(&mut self, name: &str, value: String) {
        if !self.extras.is_empty() {
            self.extras.push(' ');
        }
        self.extras.push_str(name);
        self.extras.push('=');
        self.extras.push_str(&value);
    }
}

impl Visit for MsgVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        if field.name() == "message" {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&format!("{value:?}"));
        } else {
            self.push_extra(field.name(), format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(value);
        } else {
            self.push_extra(field.name(), value.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(level: &str, target: &str, message: &str) -> RuntimeLogEntry {
        RuntimeLogEntry {
            ts_ms: now_ms(),
            level: level.to_string(),
            target: target.to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn test_level_filter() {
        let store = RuntimeLogStore::new(100);
        store.push(entry("ERROR", "a", "boom"));
        store.push(entry("WARN", "b", "careful"));
        store.push(entry("INFO", "c", "hello"));
        store.push(entry("DEBUG", "d", "detail"));

        // WARN 及以上 → ERROR + WARN
        let f = RuntimeLogFilter {
            min_level: Some("WARN".into()),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 1, 10).total, 2);
        // ERROR 仅 → 1
        let f = RuntimeLogFilter {
            min_level: Some("ERROR".into()),
            ..Default::default()
        };
        assert_eq!(store.query(&f, 1, 10).total, 1);
        // 不限 → 4
        assert_eq!(store.query(&RuntimeLogFilter::default(), 1, 10).total, 4);
    }

    #[test]
    fn test_keyword_and_pagination() {
        let store = RuntimeLogStore::new(100);
        for i in 0..12 {
            store.push(entry("INFO", &format!("mod{i}"), &format!("line {i}")));
        }
        let f = RuntimeLogFilter {
            keyword: Some("mod1".into()),
            ..Default::default()
        };
        // mod1 / mod10 / mod11 → 3 条（message 不含 mod1，target 含）
        assert_eq!(store.query(&f, 1, 10).total, 3);

        let p2 = store.query(&RuntimeLogFilter::default(), 2, 5);
        assert_eq!(p2.total, 12);
        assert_eq!(p2.items.len(), 5);
        // 倒序：首条为 line 11，第 2 页首条为 line 6
        assert_eq!(p2.items[0].message, "line 6");
    }

    #[test]
    fn test_ring_cap_and_clear() {
        let store = RuntimeLogStore::new(3);
        for i in 0..5 {
            store.push(entry("INFO", "t", &format!("m{i}")));
        }
        assert_eq!(store.len(), 3);
        assert_eq!(store.query(&RuntimeLogFilter::default(), 1, 10).items[0].message, "m4");
        store.clear();
        assert!(store.is_empty());
    }
}
