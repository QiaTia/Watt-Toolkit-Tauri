//! 领域模型：代理模式、域名规则、代理设置。
//! 对齐原 .NET 实现 IDomainConfig / IProxySettings / AccelerateProjectDTO。

pub mod domain_rule;
pub mod migrate;
pub mod settings;

pub use domain_rule::{DomainRule, DomainRuleFields, DomainRules, StaticResponse, SubRule};
pub use migrate::{migrate_legacy_settings, LegacyPaths, MigrationOutcome};
pub use settings::{
    CommunityHostsSettings, DnsSettings, ExternalProxyType, ProxyMode, ProxySettings,
    TwoLevelAgentSettings,
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
    /// 社区维护的 GitHub Hosts 源（格式：`[["ip","host"], ...]`）
    ///
    /// 该源由社区定期更新，提供 GitHub 各子域当前可用的入口 IP，用作备选 IP 池
    /// 的额外候选来源（仍需本地探测通过才会入池）。
    pub const DEFAULT_COMMUNITY_HOSTS_URL: &str = "https://hosts.gitcdn.top/hosts.json";
}
