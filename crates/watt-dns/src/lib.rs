//! DNS 域：普通解析 / DoH / 最快 DNS 竞速 / 污染判定。
//! 对齐原 IDnsAnalysisService。

pub mod pollution;
pub mod resolver;

pub use pollution::is_polluted_ip;
pub use resolver::{DnsConfig, DnsResolver};

/// 默认 DoH 地址（对齐原 Dnspod 默认）
pub const DEFAULT_DOH_ADDRESS: &str = "https://doh.pub/dns-query";

/// DNS 竞速探测域名（对齐 dnscheck-test.steampp.net）
pub const DNS_CHECK_HOST: &str = "dnscheck-test.steampp.net";
