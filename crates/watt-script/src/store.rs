//! 已安装脚本存储：`{data_dir}/Scripts/scripts.json` 持久化 + 旧版缓存目录扫描导入。
//!
//! 新版布局：脚本文件 `{data_dir}/Scripts/{md5}.js`（从旧版 `Plugins/Accelerator/Scripts`
//! 复制而来，与旧安装解耦），元数据清单 `scripts.json`。
//! 旧版启用状态存于数据库（LocalId 集合），文件扫描无法还原，导入后默认启用，
//! 由迁移报告提示用户重新确认（对齐「忽略脚本 Enable 启动标签默认启动」）。

use crate::model::ScriptConfig;
use crate::userscript::{parse_userscript, UserScriptMeta};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 已安装脚本记录（scripts.json 单项）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledScript {
    /// 本地 ID（= 文件名 md5，注入路径 /WattToolkit_Inject/{local_id}.js）
    pub local_id: String,
    /// 显示名
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    /// 脚本文件名（{md5}.js，相对脚本目录）
    pub file_name: String,
    /// 是否启用
    pub enabled: bool,
    /// 匹配域名（@match，空则 @include）
    pub match_domain_names: Vec<String>,
    /// 排除域名（@exclude）
    pub exclude_domain_names: Vec<String>,
    /// 执行顺序
    pub order: i32,
}

impl InstalledScript {
    /// 由 UserScript 头元数据构建（文件名即 local_id）
    pub fn from_meta(meta: &UserScriptMeta, file_name: &str, order: i32) -> Self {
        Self {
            local_id: file_name.trim_end_matches(".js").to_string(),
            name: meta.name.clone(),
            version: meta.version.clone(),
            description: meta.description.clone(),
            author: meta.author.clone(),
            file_name: file_name.to_string(),
            enabled: true,
            match_domain_names: meta.effective_match_domains().to_vec(),
            exclude_domain_names: meta.exclude_domains.clone(),
            order,
        }
    }

    /// 引擎侧脚本配置（scripts_dir 为新版脚本目录，cache_path 解析为绝对路径）
    pub fn to_script_config(&self, scripts_dir: &Path) -> ScriptConfig {
        ScriptConfig {
            local_id: self.local_id.clone(),
            cache_path: scripts_dir
                .join(&self.file_name)
                .to_string_lossy()
                .to_string(),
            match_domain_names: self.match_domain_names.clone(),
            exclude_domain_names: self.exclude_domain_names.clone(),
            order: self.order,
        }
    }
}

/// 脚本目录中的清单文件
pub const MANIFEST_NAME: &str = "scripts.json";

/// 清单路径：{scripts_dir}/scripts.json
pub fn manifest_path(scripts_dir: &Path) -> PathBuf {
    scripts_dir.join(MANIFEST_NAME)
}

/// 加载已安装脚本清单（目录或文件不存在返回空表）
pub fn load_installed(scripts_dir: &Path) -> Vec<InstalledScript> {
    let path = manifest_path(scripts_dir);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str(&content).unwrap_or_else(|e| {
        tracing::warn!("脚本清单解析失败（{}）：{e}", path.display());
        Vec::new()
    })
}

/// 保存已安装脚本清单
pub fn save_installed(scripts_dir: &Path, scripts: &[InstalledScript]) -> Result<(), String> {
    std::fs::create_dir_all(scripts_dir).map_err(|e| e.to_string())?;
    let path = manifest_path(scripts_dir);
    let content = serde_json::to_string_pretty(scripts).map_err(|e| e.to_string())?;
    std::fs::write(path, content).map_err(|e| e.to_string())
}

/// 旧版缓存目录扫描结果
#[derive(Debug, Default)]
pub struct ScanResult {
    /// 成功导入的脚本
    pub imported: Vec<InstalledScript>,
    /// 跳过（无 UserScript 头/读取失败）的文件名
    pub skipped: Vec<String>,
}

/// 扫描旧版脚本目录（{md5}.js 文件集合）→ 解析 UserScript 头 → 构建清单。
/// order 按文件名排序稳定分配（旧版 Order 存于数据库，此处仅保序）。
pub fn scan_legacy_dir(legacy_dir: &Path) -> ScanResult {
    let mut result = ScanResult::default();
    let Ok(entries) = std::fs::read_dir(legacy_dir) else {
        return result;
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("js"))
        })
        .collect();
    files.sort();

    for path in files {
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        match std::fs::read_to_string(&path) {
            Ok(content) => match parse_userscript(&content) {
                Some(meta) => {
                    let order = result.imported.len() as i32;
                    result
                        .imported
                        .push(InstalledScript::from_meta(&meta, file_name, order));
                }
                None => result.skipped.push(file_name.to_string()),
            },
            Err(e) => {
                tracing::warn!("脚本读取失败（{}）：{e}", path.display());
                result.skipped.push(file_name.to_string());
            }
        }
    }
    result
}

/// 将旧版脚本文件复制到新版脚本目录（覆盖同名），返回首个失败原因
pub fn copy_scripts(legacy_dir: &Path, target_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;
    for entry in std::fs::read_dir(legacy_dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("js"))
        {
            let Some(name) = path.file_name() else {
                continue;
            };
            let target = target_dir.join(name);
            std::fs::copy(&path, &target).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_script(dir: &Path, name: &str, header: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(name),
            format!("// ==UserScript==\n{header}// ==/UserScript==\nvar x=1;"),
        )
        .unwrap();
    }

    #[test]
    fn test_scan_and_roundtrip() {
        let dir = std::env::temp_dir().join(format!("watt-script-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let legacy = dir.join("legacy");
        write_script(
            &legacy,
            "aaa111.js",
            "// @name ScriptA\n// @version 1.0\n// @match *.a.com\n",
        );
        write_script(
            &legacy,
            "bbb222.js",
            "// @name ScriptB\n// @match b.com\n// @exclude x.b.com\n",
        );
        write_script(&legacy, "ccc333.js", "// @name ScriptC\n");
        // 无 UserScript 头 → 跳过
        std::fs::write(legacy.join("ddd444.js"), "var y=2;").unwrap();

        let result = scan_legacy_dir(&legacy);
        assert_eq!(result.imported.len(), 3);
        assert_eq!(result.skipped, vec!["ddd444.js"]);

        // 名称与匹配域名
        let a = &result.imported[0];
        assert_eq!(a.name, "ScriptA");
        assert_eq!(a.local_id, "aaa111");
        assert_eq!(a.match_domain_names, vec!["*.a.com"]);
        let b = &result.imported[1];
        assert_eq!(b.exclude_domain_names, vec!["x.b.com"]);
        // C 无 match/include → 空匹配（不注入任何域）
        assert!(result.imported[2].match_domain_names.is_empty());

        // 复制 + 保存 + 回读
        let target = dir.join("new");
        copy_scripts(&legacy, &target).unwrap();
        save_installed(&target, &result.imported).unwrap();
        let loaded = load_installed(&target);
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].name, "ScriptA");

        // 引擎配置指向新目录文件
        let config = loaded[1].to_script_config(&target);
        assert!(config.cache_path.ends_with("bbb222.js"));
        assert_eq!(config.match_domain_names, vec!["b.com"]);
        assert!(target.join("bbb222.js").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_missing_dir() {
        assert!(load_installed(Path::new("Z:/nonexistent")).is_empty());
    }
}
