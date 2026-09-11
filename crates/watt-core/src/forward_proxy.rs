//! 正向代理监听（System/PAC/ProxyOnly 模式，默认端口 26501）。
//!
//! 对齐 C# 监听管道：HttpProxyMiddleware（请求行分发）→ TlsInvade（TLS 识别）
//! → UseTls（MITM 动态证书）→ TunnelMiddleware（纯隧道）→ HTTP 管道
//! （PAC 下发 / 反向代理转发）。
//!
//! 连接协议分发：
//! - `CONNECT host:port` → 回 200 后嗅探首字节：
//!   - TLS ClientHello 且域名需要加速/注入 → MITM（动态叶子证书）→ http_relay
//!   - 其余（未匹配域名 / 非 TLS 协议）→ 纯隧道直连（规则 IP/DNS/二级代理链）
//! - 绝对 URI（`GET http://host/path`）→ 改写 origin-form → http_relay
//! - 裸路径请求（`GET /pac`）→ PAC 脚本下发（Content-Type: application/x-ns-proxy-autoconfig）
//!
//! 与 C# 的差异：C# MITM 全部 TLS（客户端必须信任根证书，否则全部 HTTPS 失败）；
//! 本实现仅对「规则匹配或脚本注入匹配」的域名 MITM，未匹配域名纯隧道直连——
//! 客户端未安装根证书时普通站点仍可正常访问（对应验收：未匹配域名纯隧道直连）。

use crate::http_relay::{RelayContext, RelayDnsAdapter};
use crate::listener::RelayService;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper::Request;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 正向代理监听主循环
///
/// `proxy_authority`：PAC 脚本中的代理地址（如 `127.0.0.1:26501`）
pub async fn run_forward_proxy_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    proxy_authority: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let ctx = ctx.clone();
                let tls_acceptor = tls_acceptor.clone();
                let proxy_authority = proxy_authority.clone();
                tokio::spawn(async move {
                    let _ = handle_forward_connection(stream, ctx, tls_acceptor, proxy_authority).await;
                });
            }
        }
    }
}

/// 单连接处理：解析请求行 → 分发
async fn handle_forward_connection(
    mut stream: tokio::net::TcpStream,
    ctx: Arc<RelayContext>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    proxy_authority: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = stream.set_nodelay(true);

    // peek 请求行（不消费字节；非 CONNECT 请求交由 hyper 从完整流解析）
    let Some(line) = peek_request_line(&mut stream).await? else {
        return Ok(()); // 对端在请求行前关闭
    };
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    if method == "CONNECT" {
        // 消费请求头（CONNECT 客户端等待 200 后才发送隧道数据）
        let _head = read_request_head(&mut stream).await?;
        handle_connect(stream, ctx, tls_acceptor, &target).await
    } else if target.starts_with("http://") || target.starts_with("https://") {
        // 绝对 URI：流未被消费，hyper 解析完整请求 → origin-form 改写 → http_relay
        handle_absolute_uri_request(stream, ctx, &target).await
    } else {
        // 裸路径（ProxyProtocol.None）→ PAC 下发（对齐 HttpProxyPacMiddleware）
        let _head = read_request_head(&mut stream).await?;
        serve_pac(&mut stream, &ctx, &proxy_authority).await
    }
}

/// peek 请求行（至 \r\n，不消费；EOF 返回 None）
async fn peek_request_line(
    stream: &mut tokio::net::TcpStream,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.peek(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        if let Some(pos) = chunk[..n].windows(2).position(|w| w == b"\r\n") {
            return Ok(Some(String::from_utf8_lossy(&chunk[..pos]).into_owned()));
        }
        if n >= chunk.len() {
            return Err("请求行过大".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
}

/// CONNECT 隧道：200 → 嗅探 → MITM 或纯隧道
async fn handle_connect(
    mut stream: tokio::net::TcpStream,
    ctx: Arc<RelayContext>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    target: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 解析 host:port
    let (host, port) = split_host_port(target, 443);

    // 回 200
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // 嗅探首字节（peek 不消费）
    let mut probe = [0u8; 2];
    let n = stream.peek(&mut probe).await?;
    let is_tls = n >= 2 && probe[0] == 0x16 && probe[1] == 0x03;

    if is_tls && should_mitm(&ctx, &host) {
        // MITM：动态叶子证书 → 明文 HTTP → http_relay
        let tls_stream = match tls_acceptor.accept(stream).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("正向代理 MITM 握手失败 {host}: {e}");
                return Ok(());
            }
        };
        let scheme = "https".to_string();
        let service = RelayService { ctx, scheme };
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, service)
            .await?;
        return Ok(());
    }

    // 纯隧道直连（规则 IP / DNS / 二级代理链）
    tunnel_to(&mut stream, &ctx, &host, port).await
}

/// MITM 判定：规则匹配（或脚本注入匹配/本地域名）
fn should_mitm(ctx: &RelayContext, host: &str) -> bool {
    // 规则匹配（OnlyEnableProxyScript 时跳过规则）
    if !ctx.only_enable_proxy_script && ctx.rules.find(host).is_some() {
        return true;
    }
    // 脚本注入匹配（含本地域名 → 本地服务）
    let scripts = ctx.local.scripts();
    if !scripts.is_empty() {
        if host.eq_ignore_ascii_case(watt_config::constants::LOCAL_DOMAIN) {
            return true;
        }
        let pseudo_url = format!("https://{host}/");
        if scripts
            .iter()
            .any(|s| watt_script::model::script_matches_url(s, &pseudo_url))
        {
            return true;
        }
    }
    false
}

/// 纯隧道：建立出站连接后双向拷贝
async fn tunnel_to(
    stream: &mut tokio::net::TcpStream,
    ctx: &RelayContext,
    host: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dns = Arc::new(RelayDnsAdapter(ctx.dns.clone()));
    let outbound = crate::outbound::OutboundConnector::new(dns, ctx.upstream.clone());
    let target = crate::outbound::OutboundTarget {
        host: host.to_string(),
        port,
        tls: false,
        tls_sni: None,
        tls_ignore_name_mismatch: false,
        override_ip: ctx.rules.find(host).and_then(|r| r.fields.ip_address),
        forward_destination: None,
        timeout_ms: Some(15000),
    };

    match outbound.connect(&target).await {
        Ok(mut remote) => {
            let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
            Ok(())
        }
        Err(e) => {
            tracing::warn!("正向代理隧道建立失败 {host}:{port}: {e}");
            // 502（对齐 C# HandleErrorAsync 语义）
            let _ = stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            Ok(())
        }
    }
}

/// 绝对 URI 请求（`GET http://host/path HTTP/1.1`）：改写 origin-form → http_relay
async fn handle_absolute_uri_request(
    stream: tokio::net::TcpStream,
    ctx: Arc<RelayContext>,
    target: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let uri: hyper::Uri = target.parse()?;
    let scheme = uri.scheme_str().unwrap_or("http").to_string();

    let service = ForwardProxyService { ctx, scheme };
    let io = hyper_util::rt::TokioIo::new(stream);
    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// 绝对 URI → origin-form 改写服务
#[derive(Clone)]
struct ForwardProxyService {
    ctx: Arc<RelayContext>,
    scheme: String,
}

impl Service<Request<Incoming>> for ForwardProxyService {
    type Response = hyper::Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<hyper::Response<Full<Bytes>>, std::convert::Infallible>,
                > + Send,
        >,
    >;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        let ctx = self.ctx.clone();
        let scheme = self.scheme.clone();
        Box::pin(async move {
            // 绝对 URI → origin-form（Host 头已存在，交由 http_relay 按域名分流）
            if let Some(pq) = req.uri().path_and_query() {
                if let Ok(origin) = pq.as_str().parse() {
                    *req.uri_mut() = origin;
                }
            }
            let resp = ctx.handle_request(req, &scheme).await;
            Ok(resp)
        })
    }
}

/// PAC 下发
async fn serve_pac(
    stream: &mut tokio::net::TcpStream,
    ctx: &RelayContext,
    proxy_authority: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pac = crate::pac::generate_pac(proxy_authority, &ctx.rules, ctx.local.scripts());
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Disposition: attachment;filename=proxy.pac\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        crate::pac::PAC_CONTENT_TYPE,
        pac.len(),
        pac
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// 读取请求头（至 \r\n\r\n）
async fn read_request_head(
    stream: &mut tokio::net::TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err("连接在请求头结束前关闭".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 16 * 1024 {
            return Err("请求头过大".into());
        }
    }
}

/// 解析请求行：method / target / version
#[cfg(test)]
fn parse_request_line(
    head: &[u8],
) -> Result<(String, String, u8), Box<dyn std::error::Error + Send + Sync>> {
    let text = std::str::from_utf8(head)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("空请求")?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or("无 method")?.to_string();
    let target = parts.next().ok_or("无 target")?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1");
    let minor = if version.ends_with("1.0") { 0 } else { 1 };
    Ok((method, target, minor))
}

/// host:port 拆分（默认端口回退）
fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    // [IPv6]:port
    if let Some(rest) = target.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }
    match target.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(p) => (host.to_string(), p),
            Err(_) => (target.to_string(), default_port),
        },
        None => (target.to_string(), default_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_host_port() {
        assert_eq!(
            split_host_port("steamcommunity.com:443", 8080),
            ("steamcommunity.com".into(), 443)
        );
        assert_eq!(
            split_host_port("example.com", 443),
            ("example.com".into(), 443)
        );
        assert_eq!(split_host_port("[::1]:8443", 80), ("::1".into(), 8443));
        // 无端口后缀但含冒号的畸形目标
        assert_eq!(split_host_port("bad:port", 443), ("bad:port".into(), 443));
    }

    #[test]
    fn test_parse_request_line() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (method, target, _) = parse_request_line(head).unwrap();
        assert_eq!(method, "CONNECT");
        assert_eq!(target, "example.com:443");

        let head = b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (method, target, _) = parse_request_line(head).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target, "http://example.com/path?q=1");

        let head = b"GET /pac HTTP/1.0\r\nHost: 127.0.0.1:26501\r\n\r\n";
        let (method, target, ver) = parse_request_line(head).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target, "/pac");
        assert_eq!(ver, 0);
    }

    #[test]
    fn test_should_mitm() {
        let ctx = RelayContext::new(
            watt_config::DomainRules::new(vec![watt_config::DomainRule {
                match_domain_names: vec!["accel.example.com".into()],
                ..Default::default()
            }]),
            crate::local_domain::LocalDomainHandler::new(vec![]),
            None,
        );
        assert!(should_mitm(&ctx, "accel.example.com"));
        assert!(!should_mitm(&ctx, "unmatched.example.com"));

        // 脚本域名 → MITM
        let script = watt_script::ScriptConfig {
            local_id: "s".into(),
            cache_path: "/tmp/s.js".into(),
            match_domain_names: vec!["script.example.com".into()],
            exclude_domain_names: vec![],
            order: 0,
        };
        let ctx2 = RelayContext::new(
            watt_config::DomainRules::new(vec![]),
            crate::local_domain::LocalDomainHandler::new(vec![script]),
            None,
        );
        assert!(should_mitm(&ctx2, "script.example.com"));
        assert!(should_mitm(&ctx2, watt_config::constants::LOCAL_DOMAIN));
        assert!(!should_mitm(&ctx2, "other.example.com"));
    }
}
