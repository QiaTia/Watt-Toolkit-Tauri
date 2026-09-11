//! 端口监听与协议分发：
//! - 443：TLS MITM → ALPN h2/http1.1 → http_relay
//! - 80：HTTP → 301 HTTPS（EnableHttpProxyToHttps）
//! - 26501：正向代理（CONNECT 隧道 / HTTP 代理 / PAC）
//! - 8868：SOCKS5 入站

use crate::http_relay::RelayContext;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::Service;
use hyper::Request;
use std::sync::Arc;

/// MITM HTTPS 监听（443）
pub async fn run_mitm_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
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
                let (stream, peer) = match accepted {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("443 accept 失败: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let ctx = ctx.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let _ = handle_mitm_connection(stream, ctx, tls_acceptor).await;
                    let _ = peer;
                });
            }
        }
    }
}

async fn handle_mitm_connection(
    stream: tokio::net::TcpStream,
    ctx: Arc<RelayContext>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = stream.set_nodelay(true);
    let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("TLS 握手失败: {e}");
            return Ok(());
        }
    };

    // 统计流量（TLS 层字节近似：按应用层统计，见 http_relay）
    let scheme = "https".to_string();
    let service = RelayService { ctx, scheme };
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

/// HTTP 明文监听（80：重定向 / 可扩展）
pub async fn run_http_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
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
                tokio::spawn(async move {
                    let scheme = "http".to_string();
                    let service = RelayService { ctx, scheme };
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await;
                });
            }
        }
    }
}

/// 反向代理服务（hyper Service 适配）
#[derive(Clone)]
pub struct RelayService {
    pub ctx: Arc<RelayContext>,
    pub scheme: String,
}

impl Service<Request<Incoming>> for RelayService {
    type Response = hyper::Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<hyper::Response<Full<Bytes>>, std::convert::Infallible>,
                > + Send,
        >,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let ctx = self.ctx.clone();
        let scheme = self.scheme.clone();
        Box::pin(async move {
            let resp = ctx.handle_request(req, &scheme).await;
            Ok(resp)
        })
    }
}

/// SOCKS5 入站监听（8868）—— Phase 5 实现
pub async fn run_socks5_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
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
                tokio::spawn(async move {
                    let _ = handle_socks5_connection(stream, ctx).await;
                });
            }
        }
    }
}

/// 最小 SOCKS5 服务端（CONNECT）：匹配域名 → MITM/http_relay；未匹配 → 直连隧道
async fn handle_socks5_connection(
    mut stream: tokio::net::TcpStream,
    ctx: Arc<RelayContext>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. 握手
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Ok(());
    }
    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;
    // 无认证
    stream.write_all(&[0x05, 0x00]).await?;

    // 2. CONNECT 请求
    let mut req_head = [0u8; 4];
    stream.read_exact(&mut req_head).await?;
    if req_head[1] != 0x01 {
        // 仅支持 CONNECT
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let target_host = match req_head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::IpAddr::from(ip).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::IpAddr::from(ip).to_string()
        }
        _ => return Ok(()),
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    // SOCKS5 直连隧道（匹配域名走规则 IP；TLS 由客户端在隧道内进行，无法注入）
    let outbound = crate::outbound::OutboundConnector::new(
        std::sync::Arc::new(crate::outbound::SystemDns),
        ctx.upstream.clone(),
    );
    let target = crate::outbound::OutboundTarget {
        host: target_host.clone(),
        port,
        tls: false,
        tls_sni: None,
        tls_ignore_name_mismatch: false,
        override_ip: ctx
            .rules
            .find(&target_host)
            .and_then(|r| r.fields.ip_address),
        forward_destination: None,
        timeout_ms: Some(15000),
    };

    match outbound.connect(&target).await {
        Ok(mut remote) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            // 双向转发
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
            Ok(())
        }
        Err(_) => {
            let _ = stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Ok(())
        }
    }
}
