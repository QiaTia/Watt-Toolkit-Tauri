//! 应用信息命令

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    /// 平台（windows / macos / linux）
    pub platform: String,
    /// 数据目录
    pub data_dir: String,
}

#[tauri::command]
pub fn get_app_info(state: tauri::State<crate::AppState>) -> AppInfo {
    AppInfo {
        name: "Watt Toolkit".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: std::env::consts::OS.into(),
        data_dir: state.data_dir.to_string_lossy().into_owned(),
    }
}
