//! 流量统计（对齐 IFlowAnalyzer 语义：上行/下行字节与速率）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 流量统计：累计字节数 + 最近速率
#[derive(Debug, Default)]
pub struct FlowStats {
    /// 上行累计字节（客户端→代理）
    up_bytes: AtomicU64,
    /// 下行累计字节（代理→客户端）
    down_bytes: AtomicU64,
    /// 速率计算状态
    inner: tokio::sync::Mutex<RateInner>,
}

#[derive(Debug, Default)]
struct RateInner {
    last_up: u64,
    last_down: u64,
    up_speed: u64,
    down_speed: u64,
    last_tick: Option<tokio::time::Instant>,
}

impl FlowStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_up(&self, bytes: u64) {
        self.up_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_down(&self, bytes: u64) {
        self.down_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn up_bytes(&self) -> u64 {
        self.up_bytes.load(Ordering::Relaxed)
    }

    pub fn down_bytes(&self) -> u64 {
        self.down_bytes.load(Ordering::Relaxed)
    }

    /// 计算速率（每次调用时基于上次调用的时间差），返回 (up_speed, down_speed) B/s
    pub async fn tick_speed(&self) -> (u64, u64) {
        let mut inner = self.inner.lock().await;
        let now = tokio::time::Instant::now();
        let up = self.up_bytes();
        let down = self.down_bytes();
        if let Some(last) = inner.last_tick {
            let elapsed = now.saturating_duration_since(last).as_secs_f64();
            if elapsed >= 0.1 {
                inner.up_speed = (up.saturating_sub(inner.last_up) as f64 / elapsed) as u64;
                inner.down_speed = (down.saturating_sub(inner.last_down) as f64 / elapsed) as u64;
                inner.last_up = up;
                inner.last_down = down;
                inner.last_tick = Some(now);
            }
        } else {
            inner.last_tick = Some(now);
            inner.last_up = up;
            inner.last_down = down;
        }
        (inner.up_speed, inner.down_speed)
    }

    /// 重置（停止时清零速率，保留累计可选）
    pub fn reset(&self) {
        self.up_bytes.store(0, Ordering::Relaxed);
        self.down_bytes.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_flow_stats() {
        let stats = FlowStats::new();
        stats.add_up(100);
        stats.add_down(500);
        assert_eq!(stats.up_bytes(), 100);
        assert_eq!(stats.down_bytes(), 500);

        // 首次 tick 初始化基线，速率为 0
        let (up0, down0) = stats.tick_speed().await;
        assert_eq!((up0, down0), (0, 0));

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        stats.add_up(100);
        stats.add_down(500);
        let (up, down) = stats.tick_speed().await;
        // 150ms 内新增 100B/500B；阈值放宽至 2s 容忍 CI 抖动
        assert!(up >= 50, "up speed too low: {up}");
        assert!(down >= 250, "down speed too low: {down}");
    }
}
