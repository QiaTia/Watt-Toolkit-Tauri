//! 设置命令：代理设置读写（持久化 `{AppData}/Settings/ProxySettings.json`）。

use watt_config::ProxySettings;

use crate::AppState;

/// 读取代理设置（不存在返回默认值；与保存同目录：{data_dir}/Settings）
#[tauri::command]
pub async fn settings_get_proxy(
    state: tauri::State<'_, AppState>,
) -> Result<ProxySettings, String> {
    // 写侧在 Windows 上存在「删除旧文件 → rename」的极短窗口，读侧持同一把锁
    // 可避免读到「文件不存在」而返回默认值（随后保存会覆盖真实配置）。
    let _guard = state.settings_lock.lock().await;
    let dir = state.data_dir.join("Settings");
    watt_config::settings::load_proxy_settings_in(&dir).map_err(|e| e.to_string())
}

/// 保存代理设置
#[tauri::command]
pub async fn settings_save_proxy(
    state: tauri::State<'_, AppState>,
    settings: ProxySettings,
) -> Result<(), String> {
    // 与 accelerate_set_enabled 串行：两者都是 ProxySettings.json 的读-改-写，
    // 并发保存会以后写者为准，可能丢掉刚保存的另一半配置。
    let _guard = state.settings_lock.lock().await;
    let dir = state.data_dir.join("Settings");
    watt_config::settings::save_proxy_settings_in(&dir, &settings).map_err(|e| e.to_string())
}
