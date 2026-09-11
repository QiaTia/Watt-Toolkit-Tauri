//! 旧版（C# Watt Toolkit）数据迁移：设置文件（PascalCase JSON）→ 新版 ProxySettings。
//!
//! 旧版设置文件：`{LocalAppData}/Steam++/Settings/ProxySettings.json`
//! 旧版枚举经 JsonStringEnumConverter 序列化为字符串（兼容数字）：
//! - ProxyMode: DNSIntercept(0) / Hosts(1) / System(2) / VPN(3) / ProxyOnly(4) / PAC(5)
//! - ExternalProxyType: Http(0) / Socks4(1) / Socks5(2)

use crate::settings::{ProxyMode, ProxySettings};
use serde::Deserialize;
use std::path::PathBuf;

/// 旧版数据目录（`%LocalAppData%\Steam++`，见 WindowsFileSystem.AppDataDirectory）
#[derive(Debug, Clone)]
pub struct LegacyPaths {
    /// 旧版根目录（AppData）
    pub root: PathBuf,
    /// 旧版缓存目录（`%TMP%\Steam++`）
    pub cache_root: PathBuf,
}

impl LegacyPaths {
    /// 检测旧版安装（根目录存在即视为旧版数据可用）
    pub fn detect() -> Option<Self> {
        let root = dirs::data_local_dir()?.join("Steam++");
        let cache_root = std::env::temp_dir().join("Steam++");
        root.is_dir().then_some(Self { root, cache_root })
    }

    /// 旧版代理设置文件
    pub fn settings_path(&self) -> PathBuf {
        self.root.join("Settings").join("ProxySettings.json")
    }

    /// 旧版 CA PFX 候选路径（3.0.207+ 迁移至 Plugins/Accelerator；更早版本在根目录）
    pub fn pfx_candidates(&self) -> Vec<PathBuf> {
        vec![
            self.root
                .join("Plugins")
                .join("Accelerator")
                .join("SteamTools.Certificate.pfx"),
            self.root.join("SteamTools.Certificate.pfx"),
        ]
    }
}

/// 旧版设置 JSON（PascalCase 字段，全部可缺省）
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct LegacyProxySettings {
    #[serde(default)]
    pub support_proxy_services_status: Option<Vec<String>>,
    #[serde(default)]
    pub system_proxy_port_id: Option<u16>,
    #[serde(default)]
    pub system_proxy_ip: Option<String>,
    #[serde(default)]
    pub proxy_master_dns: Option<String>,
    #[serde(default)]
    pub enable_http_proxy_to_https: Option<bool>,
    #[serde(default)]
    pub socks5_proxy_enable: Option<bool>,
    #[serde(default)]
    pub socks5_proxy_port_id: Option<u16>,
    #[serde(default)]
    pub two_level_agent_enable: Option<bool>,
    #[serde(default)]
    pub two_level_agent_proxy_type: Option<String>,
    #[serde(default)]
    pub two_level_agent_ip: Option<String>,
    #[serde(default)]
    pub two_level_agent_port_id: Option<u16>,
    #[serde(default)]
    pub two_level_agent_user_name: Option<String>,
    #[serde(default)]
    pub two_level_agent_password: Option<String>,
    #[serde(default)]
    pub proxy_mode: Option<LegacyProxyMode>,
    /// 显式 rename：C# 属性名为 IsProxyGOG（全大写 GOG，rename_all 会得到 IsProxyGog）
    #[serde(default, rename = "IsProxyGOG")]
    pub is_proxy_gog: Option<bool>,
    #[serde(default)]
    pub use_doh: Option<bool>,
    #[serde(default)]
    pub custom_doh_addres2: Option<String>,
    /// 显式 rename：C# 属性名为 ProxyBeforeDNSCheck（全大写 DNS）
    #[serde(default, rename = "ProxyBeforeDNSCheck")]
    pub proxy_before_dnscheck: Option<bool>,
}

/// 旧版 ProxyMode：字符串（JsonStringEnumConverter）或数字（MessagePack 路径）兼容
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LegacyProxyMode {
    Name(String),
    Value(i64),
}

impl LegacyProxyMode {
    fn to_new(&self) -> (Option<ProxyMode>, Option<&'static str>) {
        match self {
            // 数字路径（MessagePack 兼容）：对齐 ProxyMode.from_legacy
            LegacyProxyMode::Value(v) => ProxyMode::from_legacy(*v as i32),
            // 字符串路径（JsonStringEnumConverter）：枚举名
            LegacyProxyMode::Name(s) => match s.as_str() {
                "DNSIntercept" => (
                    Some(ProxyMode::Hosts),
                    Some("旧版网络拦截模式已合并为 hosts 模式"),
                ),
                "Hosts" => (Some(ProxyMode::Hosts), None),
                "System" => (Some(ProxyMode::System), None),
                "VPN" => (
                    None,
                    Some("旧版 VPN 模式在当前版本不受支持，已回退 hosts 模式"),
                ),
                "ProxyOnly" => (Some(ProxyMode::ProxyOnly), None),
                "PAC" => (Some(ProxyMode::Pac), None),
                _ => (
                    Some(ProxyMode::Hosts),
                    Some("未知旧版代理模式，已回退 hosts 模式"),
                ),
            },
        }
    }
}

/// 迁移结果：新设置 + 警告（不可映射项说明）
#[derive(Debug, Clone)]
pub struct MigrationOutcome {
    pub settings: ProxySettings,
    /// 迁移警告（模式回退等）
    pub warnings: Vec<String>,
}

/// 解析旧版设置 JSON 字符串并转换为新版设置
pub fn migrate_legacy_settings(json: &str) -> Result<MigrationOutcome, serde_json::Error> {
    let legacy: LegacyProxySettings = serde_json::from_str(json)?;
    Ok(legacy.into())
}

impl From<LegacyProxySettings> for MigrationOutcome {
    fn from(legacy: LegacyProxySettings) -> Self {
        let mut warnings = Vec::new();
        let mut settings = ProxySettings::default();

        // 代理模式
        match legacy.proxy_mode.as_ref().map(|m| m.to_new()) {
            Some((Some(mode), warn)) => {
                settings.proxy_mode = mode;
                if let Some(w) = warn {
                    warnings.push(w.into());
                }
            }
            Some((None, warn)) => {
                // VPN 等不支持模式：回退 Hosts
                settings.proxy_mode = ProxyMode::Hosts;
                if let Some(w) = warn {
                    warnings.push(w.into());
                }
            }
            None => {}
        }

        // 端口/IP
        if let Some(port) = legacy.system_proxy_port_id {
            settings.system_proxy_port = if port == 0 {
                crate::constants::DEFAULT_HTTP_PROXY_PORT
            } else {
                port
            };
        }
        settings.system_proxy_ip = legacy.system_proxy_ip;
        settings.socks5_proxy_enable = legacy.socks5_proxy_enable.unwrap_or(false);
        settings.socks5_proxy_port = legacy
            .socks5_proxy_port_id
            .unwrap_or(crate::constants::DEFAULT_SOCKS5_PROXY_PORT);
        settings.enable_http_proxy_to_https = legacy.enable_http_proxy_to_https.unwrap_or(false);

        // 二级代理
        let old_type = legacy
            .two_level_agent_proxy_type
            .as_deref()
            .map(normalize_proxy_type)
            .unwrap_or_else(|| {
                crate::constants::DEFAULT_TWO_LEVEL_AGENT_PROXY_TYPE_STRING.to_string()
            });
        settings.two_level_agent = crate::settings::TwoLevelAgentSettings {
            enable: legacy.two_level_agent_enable.unwrap_or(false),
            proxy_type: Some(old_type),
            ip: legacy.two_level_agent_ip,
            port: legacy.two_level_agent_port_id.unwrap_or(0),
            username: legacy.two_level_agent_user_name,
            password: legacy.two_level_agent_password,
        };

        // DNS
        settings.dns = crate::settings::DnsSettings {
            before_dns_check: legacy.proxy_before_dnscheck.unwrap_or(false),
            master_dns: legacy.proxy_master_dns,
            use_doh: legacy.use_doh.unwrap_or(false),
            custom_doh_address: legacy.custom_doh_addres2,
        };

        // GOG
        settings.is_proxy_gog = legacy.is_proxy_gog.unwrap_or(false);

        // 加速项目勾选状态（字符串 Id 集合，可完整迁移）
        if let Some(ids) = legacy.support_proxy_services_status {
            let ids: Vec<String> = ids.into_iter().filter(|s| !s.is_empty()).collect();
            if !ids.is_empty() {
                settings.enabled_accelerate_ids = ids;
            }
        }

        MigrationOutcome { settings, warnings }
    }
}

/// 旧版 ExternalProxyType 字符串（Http/Socks4/Socks5）或数字字符串归一化
fn normalize_proxy_type(value: &str) -> String {
    let v = value.trim();
    match v.to_ascii_uppercase().as_str() {
        "HTTP" | "0" => "HTTP".into(),
        "SOCKS4" | "1" => "SOCKS4".into(),
        "SOCKS5" | "2" => "SOCKS5".into(),
        _ => crate::constants::DEFAULT_TWO_LEVEL_AGENT_PROXY_TYPE_STRING.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 旧版实际导出的 PascalCase JSON 结构（字符串枚举）
    #[test]
    fn test_migrate_full_pascalcase_json() {
        let json = r#"{
            "SupportProxyServicesStatus": ["steam", "github"],
            "SystemProxyPortId": 26501,
            "SystemProxyIp": "127.0.0.1",
            "ProxyMasterDns": "223.5.5.5",
            "EnableHttpProxyToHttps": true,
            "Socks5ProxyEnable": true,
            "Socks5ProxyPortId": 8868,
            "TwoLevelAgentEnable": true,
            "TwoLevelAgentProxyType": "Socks5",
            "TwoLevelAgentIp": "192.168.1.1",
            "TwoLevelAgentPortId": 1080,
            "TwoLevelAgentUserName": "user",
            "TwoLevelAgentPassword": "pass",
            "ProxyMode": "PAC",
            "IsProxyGOG": true,
            "UseDoh": true,
            "CustomDohAddres2": "https://dns.alidns.com/dns-query",
            "ProxyBeforeDNSCheck": true
        }"#;
        let outcome = migrate_legacy_settings(json).unwrap();
        let s = outcome.settings;
        assert_eq!(s.proxy_mode, ProxyMode::Pac);
        assert_eq!(s.system_proxy_port, 26501);
        assert_eq!(s.system_proxy_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(s.socks5_proxy_enable, true);
        assert_eq!(s.socks5_proxy_port, 8868);
        assert_eq!(s.enable_http_proxy_to_https, true);
        assert!(s.two_level_agent.enable);
        assert_eq!(
            s.two_level_agent.typed_proxy_type(),
            crate::settings::ExternalProxyType::Socks5
        );
        assert_eq!(s.two_level_agent.ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(s.two_level_agent.port, 1080);
        assert_eq!(s.dns.master_dns.as_deref(), Some("223.5.5.5"));
        assert!(s.dns.use_doh);
        assert_eq!(
            s.dns.custom_doh_address.as_deref(),
            Some("https://dns.alidns.com/dns-query")
        );
        assert!(s.dns.before_dns_check);
        assert!(s.is_proxy_gog);
        assert_eq!(s.enabled_accelerate_ids, vec!["steam", "github"]);
        assert!(outcome.warnings.is_empty());
    }

    /// 数字枚举（MessagePack 路径）与字段缺失容错
    #[test]
    fn test_migrate_numeric_mode_and_defaults() {
        let json = r#"{"ProxyMode": 3, "SystemProxyPortId": 0}"#;
        let outcome = migrate_legacy_settings(json).unwrap();
        // VPN → 回退 Hosts + 警告
        assert_eq!(outcome.settings.proxy_mode, ProxyMode::Hosts);
        assert_eq!(outcome.warnings.len(), 1);
        // 端口 0 → 新默认
        assert_eq!(
            outcome.settings.system_proxy_port,
            crate::constants::DEFAULT_HTTP_PROXY_PORT
        );
        // 其余字段保持新默认
        assert!(!outcome.settings.two_level_agent.enable);
    }

    /// 空对象 → 全默认（旧文件存在但全空）
    #[test]
    fn test_migrate_empty_object() {
        let outcome = migrate_legacy_settings("{}").unwrap();
        assert_eq!(outcome.settings.proxy_mode, ProxyMode::Hosts);
        assert!(outcome.warnings.is_empty());
        assert!(outcome.settings.enabled_accelerate_ids.is_empty());
    }

    /// 数字字符串代理类型兼容
    #[test]
    fn test_normalize_proxy_type() {
        assert_eq!(normalize_proxy_type("Http"), "HTTP");
        assert_eq!(normalize_proxy_type("Socks4"), "SOCKS4");
        assert_eq!(normalize_proxy_type("Socks5"), "SOCKS5");
        assert_eq!(normalize_proxy_type("0"), "HTTP");
        assert_eq!(normalize_proxy_type("2"), "SOCKS5");
        assert_eq!(normalize_proxy_type("unknown"), "SOCKS5");
    }
}
