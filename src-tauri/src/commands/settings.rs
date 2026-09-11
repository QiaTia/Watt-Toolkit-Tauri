//! 设置命令：代理设置读写（持久化 `{AppData}/Settings/ProxySettings.json`）。

use watt_config::ProxySettings;

use crate::AppState;

/// 读取代理设置（不存在返回默认值；与保存同目录：{data_dir}/Settings）
#[tauri::command]
pub async fn settings_get_proxy(
    state: tauri::State<'_, AppState>,
) -> Result<ProxySettings, String> {
    let dir = state.data_dir.join("Settings");
    watt_config::settings::load_proxy_settings_in(&dir).map_err(|e| e.to_string())
}

/// 保存代理设置
#[tauri::command]
pub async fn settings_save_proxy(
    state: tauri::State<'_, AppState>,
    settings: ProxySettings,
) -> Result<(), String> {
    let dir = state.data_dir.join("Settings");
    watt_config::settings::save_proxy_settings_in(&dir, &settings).map_err(|e| e.to_string())
}
