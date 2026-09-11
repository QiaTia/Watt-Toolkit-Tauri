//! 首启迁移：检测旧版（C# Steam++）安装并导入设置与 CA PFX。
//!
//! 触发条件（两项独立判断、天然幂等）：
//! - 设置：新设置文件不存在且旧版 `Settings/ProxySettings.json` 存在
//! - CA：新证书目录无 PEM 且旧版 `SteamTools.Certificate.pfx` 存在
//!
//! 迁移本身即标记（新文件落地后不再重试）；任何失败仅降级为默认/新生成，
//! 不阻断启动。结果汇总进 MigrationReport，前端可查询展示。

use std::path::Path;
use watt_config::migrate::LegacyPaths;

/// 首启迁移报告
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    /// 检测到旧版安装
    pub legacy_detected: bool,
    /// 已导入旧版设置
    pub settings_migrated: bool,
    /// 已导入旧版 CA（指纹不变，系统信任保持）
    pub ca_migrated: bool,
    /// 提示与警告（模式回退、导入失败等）
    pub warnings: Vec<String>,
}

/// 首启迁移入口（setup 中同步调用，任何失败仅记录不抛出）
pub fn run_startup_migration(data_dir: &Path) -> MigrationReport {
    let mut report = MigrationReport::default();
    let Some(legacy) = LegacyPaths::detect() else {
        tracing::debug!("未检测到旧版安装，跳过迁移");
        return report;
    };
    report.legacy_detected = true;
    tracing::info!("检测到旧版数据目录：{}", legacy.root.display());

    migrate_settings(data_dir, &legacy, &mut report);
    migrate_ca(data_dir, &legacy, &mut report);

    tracing::info!(
        "首启迁移完成：settings_migrated={} ca_migrated={} warnings={}",
        report.settings_migrated,
        report.ca_migrated,
        report.warnings.len()
    );
    report
}

/// 设置迁移：新设置文件不存在时导入旧版 ProxySettings.json
fn migrate_settings(data_dir: &Path, legacy: &LegacyPaths, report: &mut MigrationReport) {
    let settings_dir = data_dir.join("Settings");
    let new_path = settings_dir.join("ProxySettings.json");
    if new_path.exists() {
        return; // 已有设置（或此前已迁移）
    }
    let legacy_path = legacy.settings_path();
    if !legacy_path.exists() {
        return;
    }

    let result = (|| -> Result<(), String> {
        let json = std::fs::read_to_string(&legacy_path).map_err(|e| e.to_string())?;
        let outcome = watt_config::migrate_legacy_settings(&json).map_err(|e| e.to_string())?;

        report.warnings.extend(outcome.warnings);

        watt_config::settings::save_proxy_settings_in(&settings_dir, &outcome.settings)
            .map_err(|e| e.to_string())?;
        report.settings_migrated = true;
        Ok(())
    })();

    match result {
        Ok(()) => tracing::info!("已迁移旧版设置：{}", legacy_path.display()),
        Err(e) => {
            report
                .warnings
                .push(format!("旧版设置迁移失败（{e}），已使用默认设置"));
            tracing::warn!("旧版设置迁移失败：{e}");
        }
    }
}

/// CA 迁移：新证书目录为空时导入旧版 PFX（保持系统已信任的指纹）
fn migrate_ca(data_dir: &Path, legacy: &LegacyPaths, report: &mut MigrationReport) {
    let cert_dir = data_dir.join("Certificates");
    let has_ca = watt_cert::ca::CaCertificate::cert_path(&cert_dir).exists()
        && watt_cert::ca::CaCertificate::key_path(&cert_dir).exists();
    if has_ca {
        return; // 已有 CA（或此前已处理）
    }

    let Some(pfx) = legacy.pfx_candidates().into_iter().find(|p| p.exists()) else {
        return;
    };

    match watt_cert::import_pfx(&pfx, "", &cert_dir) {
        Ok(_) => {
            report.ca_migrated = true;
            tracing::info!("已导入旧版 CA：{}", pfx.display());
        }
        Err(e) => {
            report
                .warnings
                .push("旧版证书导入失败，已生成新证书，需重新安装信任".into());
            tracing::warn!("旧版 CA 导入失败（{}）：{e}", pfx.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 无旧版环境（或 CI）：legacy_detected=false，零副作用
    #[test]
    fn test_report_serializes_camel_case() {
        let report = MigrationReport {
            legacy_detected: true,
            settings_migrated: true,
            ca_migrated: false,
            warnings: vec!["测试".into()],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"legacyDetected\":true"));
        assert!(json.contains("\"settingsMigrated\":true"));
        assert!(json.contains("\"caMigrated\":false"));
        assert!(json.contains("\"warnings\""));
    }
}
