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

/// 单次解析的**总**预算（所有服务器串行回退之和的上限）。
///
/// 每项各有自己的超时（DoH 3s / UDP 2s），列表里全失败时会累加：3 DoH + 3 UDP
/// 最坏约 15s，8 个 DoH 则 24s。而出站解析（`outbound::resolve_addrs`）外侧没有
/// 超时兜底，断网时表现就是「网页卡十几秒才报错」。
///
/// 取 6s 的权衡：正常情况首个服务器毫秒级返回，只有全失败才吃满预算；6s 仍够
/// 覆盖「前两个 DoH 各超时、第三个 UDP 成功」这类常见回退深度，同时把最坏等待
/// 压到浏览器能接受的范围。宁可少试几个后端，也不要让整个请求挂十几秒。
pub const TOTAL_LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(6);
