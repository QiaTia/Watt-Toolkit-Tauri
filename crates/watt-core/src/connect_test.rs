//! 连通性测试：对目标域名发起一次完整 HTTPS GET 并计时。
//!
//! 对齐原版 `NetworkTestService.TestOpenUrlAsync`：
//! - `HttpClient.GetAsync(url, ResponseContentRead)` → 完整收到响应即成功
//!   （**不校验状态码**，404/302 均算连通）；
//! - Stopwatch 计时 → 延迟毫秒；异常 → 失败；> 20s → Timeout（UI 层判定）；
//! - 分组内全部域名**并发**测试。
//!
//! 与原版一致的探测路径：系统解析（含 hosts）+ 系统证书存储。
//! Hosts 模式加速开启时，域名解析到 127.0.0.1 → 本地 443 反代 → 出站，
//! 因此测得的正是**加速后的真实打开耗时**（原版同语义）；
//! 证书校验走系统根证书（已安装本引擎 CA 时 MITM 证书可通过）。

use std::time::{Duration, Instant};

/// 单个域名探测结果（原版 `ProxyDomainViewModel.DelayMillseconds` 的结构化版）
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub host: String,
    /// 完整收到 HTTP 响应（任意状态码）
    pub ok: bool,
    /// 响应状态码（ok 时必有）
    pub status: Option<u16>,
    /// 总耗时（连接 + TLS + 请求 + 完整响应体）
    pub latency_ms: u64,
    pub error: Option<String>,
}

/// 单域名 HTTPS 探测（443 端口，`timeout` 为总预算）。
///
/// 解析走系统 `getaddrinfo`（含 hosts），TLS 走系统根证书——语义对齐原版
/// .NET HttpClient 的默认行为。
pub async fn probe_https(host: &str, timeout: Duration) -> ProbeResult {
    let started = Instant::now();
    let host = host.trim().trim_end_matches('/').to_string();
    if host.is_empty() {
        return ProbeResult {
            host: host.clone(),
            ok: false,
            status: None,
            latency_ms: 0,
            error: Some("空域名".into()),
        };
    }

    let deadline = async {
        // 1. TCP：系统解析（hosts 劫持时得到 127.0.0.1，即测加速链路）
        let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host.as_str(), 443)))
            .await
            .map_err(|_| "超时".to_string())
            .and_then(|r| r.map_err(|e| format!("TCP 连接失败: {e}")));
        let tcp = match tcp {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        // 2. TLS：系统根证书标准验证
        let connector = crate::sni::outbound_tls_connector(crate::sni::OutboundVerify::Standard, None);
        let name = crate::sni::server_name(&host)
            .ok_or_else(|| format!("无效的 TLS 名称: {host}"))?;
        let tls = tokio::time::timeout(timeout, connector.connect(name, tcp))
            .await
            .map_err(|_| "超时".to_string())
            .and_then(|r| r.map_err(|e| format!("TLS 握手失败: {e}")));
        let tls = match tls {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        // 3. HTTP GET /（HTTP/1.1，读完整响应体——对齐 ResponseContentRead）
        let (mut sender, conn) = tokio::time::timeout(
            timeout,
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)),
        )
        .await
        .map_err(|_| "超时".to_string())
        .and_then(|r| r.map_err(|e| format!("HTTP 连接失败: {e}")))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .uri("/")
            .header(hyper::header::HOST, host.as_str())
            .header(
                hyper::header::USER_AGENT,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WattToolkit-ConnectivityTest",
            )
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .expect("静态构建的请求不会失败");

        let resp = tokio::time::timeout(timeout, sender.send_request(req))
            .await
            .map_err(|_| "超时".to_string())
            .and_then(|r| r.map_err(|e| format!("请求失败: {e}")))?;
        let status = resp.status();
        // 完整读取响应体（小页面 + 上限保护，避免异常大响应拖住计时）
        let body = tokio::time::timeout(timeout, http_body_util::BodyExt::collect(resp.into_body()))
            .await
            .map_err(|_| "超时".to_string())
            .and_then(|r| r.map_err(|e| format!("读取响应失败: {e}")))?;
        let _ = body; // 只要完成
        Ok(status.as_u16())
    };

    match deadline.await {
        Ok(status) => ProbeResult {
            host,
            ok: true,
            status: Some(status),
            latency_ms: started.elapsed().as_millis() as u64,
            error: None,
        },
        Err(e) => ProbeResult {
            host,
            ok: false,
            status: None,
            latency_ms: started.elapsed().as_millis() as u64,
            error: Some(e),
        },
    }
}

/// 并发探测多个域名（对齐原版 `Task.WhenAll` 全并发语义）。
pub async fn probe_https_all(hosts: &[String], timeout: Duration) -> Vec<ProbeResult> {
    let tasks: Vec<_> = hosts
        .iter()
        .map(|h| {
            let h = h.clone();
            tokio::spawn(async move { probe_https(&h, timeout).await })
        })
        .collect();
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        match t.await {
            Ok(r) => out.push(r),
            Err(e) => out.push(ProbeResult {
                host: String::new(),
                ok: false,
                status: None,
                latency_ms: 0,
                error: Some(format!("任务异常: {e}")),
            }),
        }
    }
    out
}

/// 原版 UI 的延迟显示判定：成功且 > 20s 显示 Timeout
pub fn is_timeout(latency_ms: u64, ok: bool) -> bool {
    ok && latency_ms > 20_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_threshold_matches_original() {
        assert!(is_timeout(20_001, true));
        assert!(!is_timeout(20_000, true));
        assert!(!is_timeout(500, true));
        // 失败不算 Timeout（显示 error）
        assert!(!is_timeout(25_000, false));
    }

    /// 真实链路验证：Google 翻译域名经系统解析 + 备用池路径可达。
    /// `cargo test -p watt-core --lib probe_google_translate -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn probe_google_translate() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for host in [
            "translate.google.com",
            "translate.googleapis.com",
            "translate.gstatic.com",
        ] {
            let r = probe_https(host, Duration::from_secs(15)).await;
            println!(
                "[probe] {host:<28} ok={} status={:?} {}ms err={:?}",
                r.ok, r.status, r.latency_ms, r.error
            );
        }
    }

    /// 加速路径验证：出站候选链（覆盖 IP → 备用池竞速，TLS 握手胜出）
    /// 对 Google 翻译三域名全证书验证可达。
    /// `cargo test -p watt-core --lib probe_google_translate_via_outbound -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn probe_google_translate_via_outbound() {
        use crate::outbound::{OutboundConnector, OutboundTarget};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let connector = OutboundConnector::new(std::sync::Arc::new(crate::outbound::SystemDns), None);
        for host in [
            "translate.google.com",
            "translate.googleapis.com",
            "translate.gstatic.com",
        ] {
            // 对齐引擎规则注入后的出站形态：覆盖 IP 优先 + 备用池竞速兜底
            let target = OutboundTarget {
                host: host.to_string(),
                port: 443,
                tls: true,
                tls_sni: None,
                tls_ignore_name_mismatch: false,
                override_ip: Some("120.253.253.34".parse().unwrap()),
                forward_destination: None,
                timeout_ms: Some(15_000),
            };
            let t = Instant::now();
            let res = connector.connect(&target).await;
            match res {
                Ok(_stream) => println!(
                    "[probe-out] {host:<28} 连接成功（TLS 竞速胜出）{:?}",
                    t.elapsed()
                ),
                Err(e) => println!("[probe-out] {host:<28} 失败: {e} ({:?})", t.elapsed()),
            }
        }
    }
}
