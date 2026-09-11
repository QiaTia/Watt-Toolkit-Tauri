//! 云端加速项目本地缓存：`{data_dir}/Accelerate/accelerate_projects.json`。
//!
//! 对齐旧版 `ProxyService.InitializeAccelerateAsync()`：优先在线拉取，
//! 失败（离线 / 云端改版）时降级读取上次缓存，保证启动不阻断。

use std::fs;
use std::path::PathBuf;

use crate::model::AccelerateCatalog;

/// 缓存文件名（相对 `{data_dir}/Accelerate/`）
pub const CACHE_FILE_NAME: &str = "accelerate_projects.json";

/// 缓存目录（默认 `{data_dir}/Accelerate`）
fn default_cache_dir() -> PathBuf {
    watt_config::settings::app_data_dir().join("Accelerate")
}

/// 缓存文件路径
pub fn cache_path(cache_dir: Option<&std::path::Path>) -> PathBuf {
    cache_dir
        .map(|d| d.join(CACHE_FILE_NAME))
        .unwrap_or_else(|| default_cache_dir().join(CACHE_FILE_NAME))
}

/// 读取缓存目录（不存在或解析失败返回 None）
pub fn load_cached(cache_dir: Option<&std::path::Path>) -> Option<AccelerateCatalog> {
    let path = cache_path(cache_dir);
    let text = fs::read_to_string(&path).ok()?;
    match serde_json::from_str(&text) {
        Ok(catalog) => Some(catalog),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "加速项目缓存解析失败");
            None
        }
    }
}

/// 写入缓存目录（目录自动创建；失败仅告警不阻断）
pub fn save_cached(catalog: &AccelerateCatalog, cache_dir: Option<&std::path::Path>) {
    let path = cache_path(cache_dir);
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            tracing::warn!(dir = %parent.display(), error = %e, "创建缓存目录失败");
            return;
        }
    }
    match serde_json::to_string_pretty(catalog) {
        Ok(text) => {
            if let Err(e) = fs::write(&path, text) {
                tracing::warn!(path = %path.display(), error = %e, "写入加速项目缓存失败");
            }
        }
        Err(e) => tracing::warn!(error = %e, "序列化加速项目缓存失败"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("watt-cloud-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cache_dir = dir.as_path();

        assert!(load_cached(Some(cache_dir)).is_none());

        let json = include_str!("../tests/fixtures/accelerate_all.json");
        let rsp: crate::dto::ApiRsp<Vec<crate::dto::AccelerateProjectGroupDto>> =
            serde_json::from_str(json).unwrap();
        let groups = rsp
            .content
            .unwrap()
            .iter()
            .filter_map(crate::model::AccelerateProjectGroup::from_dto)
            .collect();
        let catalog = AccelerateCatalog::new(groups);

        save_cached(&catalog, Some(cache_dir));
        let loaded = load_cached(Some(cache_dir)).expect("缓存应可读回");
        assert_eq!(loaded.project_count(), catalog.project_count());
        assert_eq!(loaded.groups[0].items[0].name, "Steam 图片");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_corrupted_cache_returns_none() {
        let dir = std::env::temp_dir().join(format!("watt-cloud-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(cache_path(Some(&dir)), "{ not json").unwrap();
        assert!(load_cached(Some(&dir)).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
