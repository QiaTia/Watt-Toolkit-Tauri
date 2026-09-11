//! 领域模型：代理模式、域名规则、代理设置。
//! 对齐原 .NET 实现 IDomainConfig / IProxySettings / AccelerateProjectDTO。

pub mod domain_rule;
pub mod migrate;
pub mod settings;

pub use domain_rule::{DomainRule, DomainRuleFields, DomainRules, StaticResponse, SubRule};
pub use migrate::{migrate_legacy_settings, LegacyPaths, MigrationOutcome};
pub use settings::{
    DnsSettings, ExternalProxyType, ProxyMode, ProxySettings, TwoLevelAgentSettings,
};

/// 常量（与原实现保持一致）
pub mod constants {
    /// 本地域名（脚本 XHR 桥与脚本文件服务）
    pub const LOCAL_DOMAIN: &str = "local.steampp.net";
    /// 注入脚本路径前缀
    pub const INJECT_SCRIPT_PATH_PREFIX: &str = "/WattToolkit_Inject/";
    /// HTTPS MITM 端口
    pub const HTTPS_PORT: u16 = 443;
    /// 正向代理默认端口
    pub const DEFAULT_HTTP_PROXY_PORT: u16 = 26501;
    /// SOCKS5 默认端口
    pub const DEFAULT_SOCKS5_PROXY_PORT: u16 = 8868;
    /// 默认二级代理类型
    pub const DEFAULT_TWO_LEVEL_AGENT_PROXY_TYPE_STRING: &str = "SOCKS5";
}
