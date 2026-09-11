//! DNS 污染判定：未配置域名解析到回环地址视为污染（对齐 HttpReverseProxyMiddleware L100-111）。

use std::net::IpAddr;

/// 判断 IP 是否为回环（127.0.0.0/8 或 ::1）
pub fn is_polluted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// 污染错误响应体（对齐原文案）
pub fn pollution_error_body(host: &str) -> String {
    format!("域名 {host} 可能已经被 DNS 污染，如果域名为本机域名，请解析为非回环 IP。")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_polluted() {
        assert!(is_polluted_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_polluted_ip(&"127.0.0.8".parse().unwrap()));
        assert!(is_polluted_ip(&"::1".parse().unwrap()));
        assert!(!is_polluted_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_polluted_ip(&"104.103.5.1".parse().unwrap()));
    }
}
