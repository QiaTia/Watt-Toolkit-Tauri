//! DNS 诊断命令：验证 DoH 端点是否真正可用。
//!
//! 设置页勾选 DoH 后，若端点非法/不可达，引擎会静默回退到系统 DNS。
//! 本命令把「是否生效 + 能否解析」变成可点击的显式检查，避免用户误以为
//! 正在使用加密 DNS。

use serde::Serialize;
use std::time::Instant;
use watt_dns::{DnsConfig, DnsResolver};

/// DoH 探测结果
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DohProbeDto {
    /// 实际使用的端点
    pub endpoint: String,
    /// 探测域名
    pub host: String,
    /// 解析得到的 IP
    pub ips: Vec<String>,
    /// 端到端耗时（毫秒）
    pub elapsed_ms: u64,
}

/// 探测 DoH 连通性（含 TLS 握手 + 真实查询）。
///
/// `endpoint` 为空时使用默认端点。Err 表示端点不可用（地址非法、引导解析
/// 失败或 TLS/DNS 握手失败）；不会像引擎启动那样静默回退。
#[tauri::command]
pub async fn dns_probe_doh(endpoint: Option<String>) -> Result<DohProbeDto, String> {
    let endpoint = endpoint
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| watt_dns::DEFAULT_DOH_ADDRESS.to_string());

    let probe_endpoint = endpoint.clone();
    let resolver = tokio::task::spawn_blocking(move || {
        DnsResolver::with_config(DnsConfig {
            master_dns: None,
            use_doh: true,
            custom_doh_address: Some(probe_endpoint),
        })
    })
    .await
    .map_err(|e| format!("DoH 探测任务异常: {e}"))?;
    if !resolver.is_doh_active() {
        return Err(format!(
            "DoH 端点未生效：{}",
            resolver.doh_error().unwrap_or("未知原因")
        ));
    }

    // example.com 由公共 DNS 稳定解析，且不会被加速引擎写入 hosts
    let host = "example.com";
    let started = Instant::now();
    let ips = resolver
        .resolve_clean(host)
        .await
        .map_err(|e| format!("DoH 查询失败：{e}"))?;
    if ips.is_empty() {
        return Err("DoH 查询返回空结果".to_string());
    }

    Ok(DohProbeDto {
        endpoint,
        host: host.to_string(),
        ips: ips.iter().map(ToString::to_string).collect(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 前端按 camelCase 读取 elapsedMs
    #[test]
    fn probe_dto_serializes_camel_case() {
        let dto = DohProbeDto {
            endpoint: "https://doh.pub/dns-query".into(),
            host: "example.com".into(),
            ips: vec!["93.184.215.14".into()],
            elapsed_ms: 12,
        };
        let value = serde_json::to_value(dto).unwrap();
        assert_eq!(value["elapsedMs"], 12);
        assert!(value.get("elapsed_ms").is_none());
        assert_eq!(value["ips"][0], "93.184.215.14");
    }

    /// 非法端点必须显式报错，而不是像引擎启动那样静默回退
    #[tokio::test]
    async fn rejects_invalid_endpoint() {
        let err = dns_probe_doh(Some("http://doh.pub/dns-query".into()))
            .await
            .unwrap_err();
        assert!(err.contains("https://"), "unexpected error: {err}");
        assert!(err.contains("未生效"));
    }

    /// 真实网络验证：默认 DoH 端点可完成 TLS 握手并返回解析结果
    #[tokio::test]
    #[ignore = "需要网络：验证 dns_probe_doh 端到端"]
    async fn probes_live_endpoint() {
        let r = dns_probe_doh(Some("https://doh.pub/dns-query".into()))
            .await
            .unwrap();
        assert!(!r.ips.is_empty());
        assert_eq!(r.host, "example.com");
        assert!(r.endpoint.starts_with("https://"));
    }
}
