//! 连通性测试：对目标域名发起一次完整 HTTPS GET 并计时。
//!
//! 对齐原版 `NetworkTestService.TestOpenUrlAsync`：
//! - `HttpClient.GetAsync(url, ResponseContentRead)` → 完整收到响应即成功
//!   （**不校验状态码**，404/302 均算连通）；
//! - Stopwatch 计时 → 延迟毫秒；异常 → 失败；> 20s → Timeout（UI 层判定）；
//! - 分组内全部域名**并发**测试。
//!
//! 与原版一致的探测路径：系统解析（含 hosts）+ 系统证书存储 + **系统代理**。
//! Hosts 模式加速开启时，域名解析到 127.0.0.1 → 本地 443 反代 → 出站；
//! System/PAC/ProxyOnly 模式加速开启时，系统代理指向本引擎正向代理，
//! 探测经 CONNECT 隧道走加速链路——两种模式测得的都是**加速后的真实打开耗时**。

use std::time::{Duration, Instant};

/// 当前系统代理地址（`host:port`），对齐原版 .NET HttpClient 的默认行为：
/// HttpClientHandler 默认遵循 WinINET 系统代理设置（含 PAC）。
///
/// - `ProxyEnable=1` → 解析 `ProxyServer`（支持 `host:port` 与 `http=..;https=..` 两种形态）
/// - 否则若有 `AutoConfigURL` 且指向**本引擎 PAC**（回环地址）→ 取其端口
///   （完整 PAC 求值不做：本工具的 PAC 只会把加速域名导向本引擎正向代理，
///   而被测域名必然是加速域名，直接走正向代理即等价）
/// - 都没有 → None（直连，原语义）
pub fn system_proxy_addr() -> Option<(String, u16)> {
    let (enabled, server, pac_url) = crate::system_proxy::get_system_proxy_status();

    let parse_host_port = |s: &str| -> Option<(String, u16)> {
        let (h, p) = s.rsplit_once(':')?;
        let h = h.trim().trim_matches(['[', ']']).to_string();
        if h.is_empty() {
            return None;
        }
        p.trim().parse::<u16>().ok().map(|p| (h, p))
    };

    if enabled {
        if let Some(s) = server {
            // ProxyServer 形态 1：host:port；形态 2：http=host:port;https=host:port;...
            if s.contains('=') {
                for part in s.split(';') {
                    let part = part.trim();
                    let rest = part
                        .strip_prefix("https=")
                        .or_else(|| part.strip_prefix("http="))
                        .or_else(|| part.strip_prefix("socks="));
                    if let Some(rest) = rest {
                        if let Some(v) = parse_host_port(rest) {
                            return Some(v);
                        }
                    }
                }
            } else if let Some(v) = parse_host_port(&s) {
                return Some(v);
            }
        }
    }

    // PAC：仅识别本引擎写入的回环地址 PAC
    if let Some(url) = pac_url {
        // 形如 http://127.0.0.1:26501/pac
        let rest = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))?;
        let authority = rest.split('/').next()?;
        let (h, p) = authority.rsplit_once(':')?;
        let is_loopback = h == "127.0.0.1" || h.eq_ignore_ascii_case("localhost");
        if is_loopback {
            if let Ok(port) = p.parse::<u16>() {
                return Some(("127.0.0.1".into(), port));
            }
        }
    }

    None
}

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

/// 经 HTTP 正向代理建立 CONNECT 隧道（对齐 HttpClient 走系统代理的路径）。
async fn connect_via_http_proxy(
    proxy: &(String, u16),
    host: &str,
    timeout: Duration,
) -> Result<tokio::net::TcpStream, String> {
    let mut tcp = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect((proxy.0.as_str(), proxy.1)),
    )
    .await
    .map_err(|_| "代理连接超时".to_string())?
    .map_err(|e| format!("代理连接失败: {e}"))?;

    let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(timeout, tcp.write_all(req.as_bytes()))
        .await
        .map_err(|_| "CONNECT 写入超时".to_string())?
        .map_err(|e| format!("CONNECT 写入失败: {e}"))?;

    // 读到响应头结束（\r\n\r\n），校验 2xx
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let n = tokio::time::timeout(timeout, tcp.read(&mut chunk))
            .await
            .map_err(|_| "CONNECT 响应超时".to_string())?
            .map_err(|e| format!("CONNECT 响应读取失败: {e}"))?;
        if n == 0 {
            return Err("代理提前关闭连接".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err("CONNECT 响应异常".into());
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status_ok = head
        .split_whitespace()
        .nth(1)
        .map(|c| c.starts_with('2'))
        .unwrap_or(false);
    if !status_ok {
        return Err(format!("隧道建立失败: {}", head.lines().next().unwrap_or("")));
    }
    Ok(tcp)
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
        // 1. TCP：系统代理存在（含本引擎 PAC）→ 走代理隧道，测得「浏览器真实打开」路径；
        //    否则直连系统解析（hosts 劫持时即 Hosts 模式加速链路）
        let tcp = match system_proxy_addr() {
            Some(proxy) => connect_via_http_proxy(&proxy, &host, timeout).await,
            None => tokio::time::timeout(
                timeout,
                tokio::net::TcpStream::connect((host.as_str(), 443)),
            )
            .await
            .map_err(|_| "超时".to_string())
            .and_then(|r| r.map_err(|e| format!("TCP 连接失败: {e}"))),
        };
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

    #[test]
    fn test_parse_proxy_server_forms() {
        // 形态 1：host:port
        assert_eq!(
            parse_for_test("127.0.0.1:26501"),
            Some(("127.0.0.1".into(), 26501))
        );
        // 形态 2：分协议
        assert_eq!(
            parse_for_test("http=127.0.0.1:8888;https=127.0.0.1:8888"),
            Some(("127.0.0.1".into(), 8888))
        );
        // 端口缺失 → None
        assert_eq!(parse_for_test("127.0.0.1"), None);
    }

    /// 仅测解析逻辑（不触注册表）：提取 system_proxy_addr 内的解析分支
    fn parse_for_test(s: &str) -> Option<(String, u16)> {
        let parse_host_port = |s: &str| -> Option<(String, u16)> {
            let (h, p) = s.rsplit_once(':')?;
            let h = h.trim().trim_matches(['[', ']']).to_string();
            if h.is_empty() {
                return None;
            }
            p.trim().parse::<u16>().ok().map(|p| (h, p))
        };
        if s.contains('=') {
            for part in s.split(';') {
                let part = part.trim();
                let rest = part
                    .strip_prefix("https=")
                    .or_else(|| part.strip_prefix("http="));
                if let Some(rest) = rest {
                    if let Some(v) = parse_host_port(rest) {
                        return Some(v);
                    }
                }
            }
            None
        } else {
            parse_host_port(s)
        }
    }

    #[test]
    fn test_pac_url_parse_loopback() {
        // 本引擎 PAC：回环 → 取端口
        let url = "http://127.0.0.1:26501/pac";
        let rest = url.strip_prefix("http://").unwrap();
        let authority = rest.split('/').next().unwrap();
        let (h, p) = authority.rsplit_once(':').unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p.parse::<u16>().unwrap(), 26501);
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
