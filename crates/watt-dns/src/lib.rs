//! DNS 域：普通解析 / DoH / 最快 DNS 竞速 / 污染判定。
//! 对齐原 IDnsAnalysisService。

pub mod pollution;
pub mod resolver;

pub use pollution::is_polluted_ip;
pub use resolver::{
    check_resolver_servers, effective_servers, parse_server_list, DnsBackend, DnsCheckResult,
    DnsConfig, DnsResolver, ResolverServer,
};

/// 默认 DoH 地址（对齐原 Dnspod 默认）
pub const DEFAULT_DOH_ADDRESS: &str = "https://doh.pub/dns-query";

/// DNS 竞速探测域名（对齐 dnscheck-test.steampp.net）
pub const DNS_CHECK_HOST: &str = "dnscheck-test.steampp.net";

/// 内置 DoH 服务器列表（顺序即优先级，对齐上游 `DefaultDohServerList`）
pub const DEFAULT_DOH_SERVERS: &[&str] = &[
    "https://doh.pub/dns-query",
    "https://dns.alidns.com/dns-query",
    "https://dns.google/dns-query",
];

/// 内置明文 DNS 列表（对齐上游 `DefaultDnsServerList`）
pub const DEFAULT_DNS_SERVERS: &[&str] = &["223.5.5.5", "119.29.29.29", "114.114.114.114"];

/// 单个解析服务器的查询超时：DoH 多一次 TLS 往返，给多一点
pub const UDP_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
pub const DOH_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
