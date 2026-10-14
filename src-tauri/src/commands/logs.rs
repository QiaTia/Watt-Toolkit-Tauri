//! 日志命令：代理访问日志 + 应用运行日志的查询/清空。
//!
//! 访问日志来自引擎（`engine.access_logs()`，随引擎常驻）；运行日志来自全局
//! tracing 采集缓冲（`runtime_log()`）。两者均为环形缓冲，查询支持过滤 + 分页。

use watt_core::access_log::{AccessLogFilter, AccessLogPage};

use crate::runtime_log::{runtime_log, RuntimeLogFilter, RuntimeLogPage};
use crate::AppState;

/// 查询代理访问日志（倒序：最新在前）
#[tauri::command]
pub async fn proxy_access_logs(
    state: tauri::State<'_, AppState>,
    filter: AccessLogFilter,
    page: usize,
    page_size: usize,
) -> Result<AccessLogPage, String> {
    let engine = state.engine.lock().await;
    Ok(engine.access_logs().query(&filter, page, page_size))
}

/// 清空代理访问日志
#[tauri::command]
pub async fn proxy_access_logs_clear(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let engine = state.engine.lock().await;
    engine.access_logs().clear();
    Ok(())
}

/// 查询应用运行日志（tracing 采集，倒序：最新在前）
#[tauri::command]
pub fn runtime_logs(
    filter: RuntimeLogFilter,
    page: usize,
    page_size: usize,
) -> RuntimeLogPage {
    runtime_log().query(&filter, page, page_size)
}

/// 清空应用运行日志
#[tauri::command]
pub fn runtime_logs_clear() {
    runtime_log().clear();
}
