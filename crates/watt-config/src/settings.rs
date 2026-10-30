//! 代理设置：对齐原 .NET IProxySettings（PersistentConfig 持久化为 JSON）。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 代理模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProxyMode {
    /// hosts 模式：修改 hosts 将域名指向本地 443 反向代理
    #[default]
    Hosts,
    /// 系统代理模式：设置系统代理走本地正向代理端口
    System,
    /// PAC 模式
    Pac,
    /// 仅代理端口模式（手动配置）
    ProxyOnly,
}

impl ProxyMode {
    /// 旧版 ProxyMode 枚举数值映射
    /// DNSIntercept(0)→Hosts+提示, Hosts(1)→Hosts, System(2)→System,
    /// VPN(3)→不支持(提示), ProxyOnly(4)→ProxyOnly, PAC(5)→Pac
    pub fn from_legacy(value: i32) -> (Option<ProxyMode>, Option<&'static str>) {
        match value {
            0 => (
                Some(ProxyMode::Hosts),
                Some("旧版网络拦截模式已合并为 hosts 模式"),
            ),
            1 => (Some(ProxyMode::Hosts), None),
            2 => (Some(ProxyMode::System), None),
            3 => (None, Some("旧版 VPN 模式在当前版本不受支持")),
            4 => (Some(ProxyMode::ProxyOnly), None),
            5 => (Some(ProxyMode::Pac), None),
            _ => (Some(ProxyMode::Hosts), None),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyMode::Hosts => "Hosts",
            ProxyMode::System => "System",
            ProxyMode::Pac => "Pac",
            ProxyMode::ProxyOnly => "ProxyOnly",
        }
    }
}

/// 二级代理（上游代理）类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalProxyType {
    Http,
    Socks4,
    Socks5,
}

impl ExternalProxyType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "HTTP" | "HTTPCONNECT" => Some(ExternalProxyType::Http),
            "SOCKS4" => Some(ExternalProxyType::Socks4),
            "SOCKS5" => Some(ExternalProxyType::Socks5),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExternalProxyType::Http => "HTTP",
            ExternalProxyType::Socks4 => "SOCKS4",
            ExternalProxyType::Socks5 => "SOCKS5",
        }
    }
}

/// 二级代理（上游代理链）设置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TwoLevelAgentSettings {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub proxy_type: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl TwoLevelAgentSettings {
    pub fn typed_proxy_type(&self) -> ExternalProxyType {
        self.proxy_type
            .as_deref()
            .and_then(ExternalProxyType::parse)
            .unwrap_or(ExternalProxyType::Socks5)
    }

    pub fn is_valid(&self) -> bool {
        self.enable && self.ip.as_deref().map(|s| !s.is_empty()).unwrap_or(false) && self.port != 0
    }
}

/// DNS 设置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsSettings {
    /// 启动前 DNS 检查/竞速
    #[serde(default)]
    pub before_dns_check: bool,
    /// 主 DNS
    #[serde(default)]
    pub master_dns: Option<String>,
    /// 使用 DoH
    #[serde(default)]
    pub use_doh: bool,
    /// 自定义 DoH 地址
    #[serde(default)]
    pub custom_doh_address: Option<String>,
}

/// 顶层代理设置（持久化 JSON）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    #[serde(default)]
    pub proxy_mode: ProxyMode,
    /// 正向代理监听 IP（空=自动）
    #[serde(default)]
    pub system_proxy_ip: Option<String>,
    /// 正向代理端口（0=默认 26501）
    #[serde(default)]
    pub system_proxy_port: u16,
    /// SOCKS5
    #[serde(default)]
    pub socks5_proxy_enable: bool,
    #[serde(default)]
    pub socks5_proxy_port: u16,
    /// HTTP→HTTPS 重定向（80 端口）
    #[serde(default)]
    pub enable_http_proxy_to_https: bool,
    /// 二级代理
    #[serde(default)]
    pub two_level_agent: TwoLevelAgentSettings,
    /// DNS
    #[serde(default)]
    pub dns: DnsSettings,
    /// 加速 GOG
    #[serde(default)]
    pub is_proxy_gog: bool,
    /// 勾选的加速项目 Id 集合（对齐旧版 SupportProxyServicesStatus）
    #[serde(default)]
    pub enabled_accelerate_ids: Vec<String>,
    /// 勾选集合是否已初始化：区分「首次运行」与「用户主动清空」
    #[serde(default)]
    pub enabled_accelerate_ids_initialized: bool,
    /// 终端（CLI）代理环境变量 + 证书注入（默认开）
    #[serde(default = "default_true")]
    pub terminal_proxy_enable: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            proxy_mode: ProxyMode::Hosts,
            system_proxy_ip: None,
            system_proxy_port: crate::constants::DEFAULT_HTTP_PROXY_PORT,
            socks5_proxy_enable: false,
            socks5_proxy_port: crate::constants::DEFAULT_SOCKS5_PROXY_PORT,
            enable_http_proxy_to_https: false,
            two_level_agent: TwoLevelAgentSettings::default(),
            dns: DnsSettings::default(),
            is_proxy_gog: false,
            enabled_accelerate_ids: Vec::new(),
            enabled_accelerate_ids_initialized: false,
            terminal_proxy_enable: true,
        }
    }
}

/// 设置存储：`{AppData}/Settings/ProxySettings.json`
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// 应用数据目录：`{AppData}/WattToolkit`
pub fn app_data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("WattToolkit")
}

/// 设置目录
pub fn settings_dir() -> PathBuf {
    app_data_dir().join("Settings")
}

/// 加载代理设置（不存在则返回默认值）
pub fn load_proxy_settings() -> Result<ProxySettings, SettingsError> {
    load_proxy_settings_in(&settings_dir())
}

/// 保存代理设置
pub fn save_proxy_settings(settings: &ProxySettings) -> Result<(), SettingsError> {
    save_proxy_settings_in(&settings_dir(), settings)
}

/// 从指定目录加载代理设置（目录即 Settings 目录）
pub fn load_proxy_settings_in(dir: &Path) -> Result<ProxySettings, SettingsError> {
    let path = dir.join("ProxySettings.json");
    if !path.exists() {
        return Ok(ProxySettings::default());
    }
    let content = std::fs::read_to_string(path)?;
    let settings: ProxySettings = serde_json::from_str(&content)?;
    Ok(settings)
}

/// 保存代理设置到指定目录（原子替换，避免崩溃/断电留下半截 JSON）
pub fn save_proxy_settings_in(dir: &Path, settings: &ProxySettings) -> Result<(), SettingsError> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("ProxySettings.json");
    let content = serde_json::to_string_pretty(settings)?;
    write_atomic(&path, content.as_bytes())?;
    Ok(())
}

/// 原子写文件：同目录临时文件 → fsync → rename 替换。
///
/// 直接 `fs::write` 会先截断目标文件，进程在写入中途退出（崩溃 / 断电 / 强杀）
/// 会留下半截 JSON，下次启动解析失败即丢失全部配置。rename 在同一文件系统内
/// 是原子的：要么看到完整旧文件，要么看到完整新文件。
///
/// Windows 下 `rename` 不能覆盖已存在文件，退化为「删除后重命名」——仍有极小的
/// 丢文件窗口，但远小于直接截断写入；失败时保留临时文件便于诊断。
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    // 同进程并发写（如「保存设置」与「保存勾选」同时触发）必须使用不同临时文件，
    // 否则会互相截断临时文件、把半截内容 rename 成正式配置。单实例插件保证
    // 跨进程不会并发写同一目录。
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{seq}",
        std::process::id()
    ));

    let write_result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            // 配置文件可能包含二级代理密码；Unix 下限定仅属主可读写
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(first_err) => {
            #[cfg(windows)]
            {
                // Windows 的 rename 已带替换语义；失败通常是杀软/其他进程短暂持有
                // 目标文件。重试即可，**绝不先删旧文件**——否则重试再失败会同时
                // 失去旧配置和新内容，后续按默认值加载并回写。
                for _ in 0..3 {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    if std::fs::rename(&tmp, path).is_ok() {
                        return Ok(());
                    }
                }
            }
            let _ = std::fs::remove_file(&tmp);
            Err(first_err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings_roundtrip() {
        let settings = ProxySettings::default();
        let json = serde_json::to_string(&settings).unwrap();
        let parsed: ProxySettings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.proxy_mode, ProxyMode::Hosts);
        assert_eq!(
            parsed.system_proxy_port,
            crate::constants::DEFAULT_HTTP_PROXY_PORT
        );
    }

    #[test]
    fn test_legacy_mode_mapping() {
        let (mode, warn) = ProxyMode::from_legacy(1);
        assert_eq!(mode, Some(ProxyMode::Hosts));
        assert!(warn.is_none());

        let (mode, warn) = ProxyMode::from_legacy(3);
        assert!(mode.is_none());
        assert!(warn.is_some());

        let (mode, _) = ProxyMode::from_legacy(5);
        assert_eq!(mode, Some(ProxyMode::Pac));
    }

    #[test]
    fn test_two_level_agent_defaults() {
        let s = TwoLevelAgentSettings {
            enable: true,
            proxy_type: None,
            ip: Some("127.0.0.1".into()),
            port: 1080,
            ..Default::default()
        };
        assert_eq!(s.typed_proxy_type(), ExternalProxyType::Socks5);
    }

    /// 指定目录读写 roundtrip + 不存在目录返回默认值
    #[test]
    fn test_load_save_settings_in_dir() {
        let dir = std::env::temp_dir().join(format!("watt-settings-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // 空目录 → 默认
        let loaded = load_proxy_settings_in(&dir).unwrap();
        assert_eq!(loaded.proxy_mode, ProxyMode::Hosts);

        // 保存后回读一致
        let settings = ProxySettings {
            system_proxy_port: 26502,
            enabled_accelerate_ids: vec!["steam".into()],
            ..Default::default()
        };
        save_proxy_settings_in(&dir, &settings).unwrap();
        let reloaded = load_proxy_settings_in(&dir).unwrap();
        assert_eq!(reloaded.system_proxy_port, 26502);
        assert_eq!(reloaded.enabled_accelerate_ids, vec!["steam"]);
        assert_eq!(reloaded.proxy_mode, ProxyMode::Hosts);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_atomic_replaces_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("watt-atomic-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.json");

        write_atomic(&path, br#"{"v":1}"#).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"v":1}"#);

        // 覆盖写入：内容完整替换，旧内容不残留
        write_atomic(&path, br#"{"v":2}"#).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"v":2}"#);

        // 同目录不残留临时文件
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "残留临时文件: {leftovers:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
