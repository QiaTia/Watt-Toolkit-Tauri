//! 迁移命令：首启迁移报告查询。

use crate::migrate::MigrationReport;
use crate::AppState;

/// 首启迁移报告（旧版设置/CA 导入结果与提示）
#[tauri::command]
pub async fn migration_get_report(
    state: tauri::State<'_, AppState>,
) -> Result<MigrationReport, String> {
    Ok(state.migration.clone())
}
