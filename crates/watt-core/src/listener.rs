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

/// 协议握手超时：慢连接不得永久占用任务与 fd
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// 并发连接上限（防本地端口被大量慢连接耗尽 fd）
const MAX_CONNECTIONS: usize = 256;

/// MITM HTTPS 监听（443）
pub async fn run_mitm_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // sender 被丢弃时 changed() 立即返回 Err；必须退出，
                // 否则旧监听任务会在 accept/changed 之间 100% CPU 空转
                if changed.is_err() || *shutdown.borrow() {
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
                let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
                    tracing::warn!("443 连接数达到上限，拒绝新连接");
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
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
    let tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tls_acceptor.accept(stream)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!("TLS 握手失败: {e}");
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("TLS 握手超时（慢连接已断开）");
            return Ok(());
        }
    };

    // 统计流量（TLS 层字节近似：按应用层统计，见 http_relay）
    let scheme = "https".to_string();
    let service = RelayService { ctx, scheme };
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    // 必须用 serve_connection_with_upgrades：WebSocket 的 101 响应会被 hyper
    // 视为 last（写侧关闭），普通 serve_connection 会直接 shutdown 底层 IO，
    // 客户端收到 UnexpectedEof（症状：wss 1006）。upgrade 变体把 IO 所有权
    // 交还给 OnUpgrade future，由 upgrade 模块接管隧道。
    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await?;
    Ok(())
}

/// HTTP 明文监听（80：重定向 / 可扩展）
pub async fn run_http_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // sender 被丢弃时 changed() 立即返回 Err；必须退出，
                // 否则旧监听任务会在 accept/changed 之间 100% CPU 空转
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let ctx = ctx.clone();
                let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
                    tracing::warn!("HTTP 监听连接数达到上限，拒绝新连接");
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    let scheme = "http".to_string();
                    let service = RelayService { ctx, scheme };
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection_with_upgrades(io, service)
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
    type Response = crate::http_relay::RelayResponse;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output =
                        Result<crate::http_relay::RelayResponse, std::convert::Infallible>,
                > + Send,
        >,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let ctx = self.ctx.clone();
        let scheme = self.scheme.clone();
        Box::pin(async move {
            // —— WebSocket / HTTP Upgrade 短路 ——
            // 升级请求没有可收集的 body（101 后即裸字节流），
            // 走 http_relay 的 collect() 会挂死；改为直接隧道透传。
            if crate::upgrade::is_upgrade_request(&req) {
                let host = crate::http_relay::request_host(&req);
                match upgrade_target(&ctx, &host, &req) {
                    Ok((target, authority)) => {
                        match crate::upgrade::handle_upgrade(
                            req,
                            target,
                            authority,
                            ctx.dns.clone(),
                            ctx.upstream.clone(),
                        )
                        .await
                        {
                            Ok(resp) => return Ok(resp.map(crate::http_relay::boxed_full)),
                            Err(e) => {
                                tracing::warn!("Upgrade 隧道失败 {host}: {e}");
                                return Ok(upgrade_error_response(&e));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Upgrade 目标解析失败 {host}: {e}");
                        return Ok(upgrade_error_response(&e));
                    }
                }
            }
            let resp = ctx.handle_request(req, &scheme).await;
            Ok(resp)
        })
    }
}

/// Upgrade 路径的出站目标解析（与 http_relay::forward 的规则语义一致）
pub fn upgrade_target_pub(
    ctx: &Arc<RelayContext>,
    host: &str,
    req: &Request<Incoming>,
) -> Result<(crate::outbound::OutboundTarget, String), String> {
    upgrade_target(ctx, host, req)
}

fn upgrade_target(
    ctx: &Arc<RelayContext>,
    host: &str,
    req: &Request<Incoming>,
) -> Result<(crate::outbound::OutboundTarget, String), String> {
    let url = format!("https://{host}{}", req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"));
    let rule = ctx
        .rules
        .find_by_url(&url, host)
        .cloned()
        .unwrap_or_default();
    let destination_uri = crate::http_relay::resolve_destination_pub("https", host, req.uri().clone(), rule.fields.destination.as_deref());
    let dest_host = destination_uri
        .host()
        .map(|h| h.to_string())
        .unwrap_or_else(|| host.to_string());
    let authority = destination_uri
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_else(|| host.to_string());
    let target = crate::outbound::OutboundTarget {
        host: dest_host,
        port: destination_uri.port_u16().unwrap_or(
            if destination_uri.scheme_str() == Some("https") {
                443
            } else {
                80
            },
        ),
        tls: destination_uri.scheme_str() == Some("https"),
        tls_sni: crate::http_relay::resolve_tls_sni(&rule, host),
        tls_ignore_name_mismatch: rule.fields.tls_ignore_name_mismatch,
        tls_skip_verify: rule.fields.tls_skip_verify,
        override_ip: rule.fields.ip_address,
        forward_destination: rule.fields.forward_destination.clone(),
        timeout_ms: rule.fields.timeout_ms,
    };
    Ok((target, authority))
}

/// Upgrade 失败响应（对齐 http_relay 的错误页语义：500 + 纯文本）
pub fn upgrade_error_response_pub(msg: &str) -> crate::http_relay::RelayResponse {
    upgrade_error_response(msg)
}

fn upgrade_error_response(msg: &str) -> crate::http_relay::RelayResponse {
    let body = crate::http_relay::boxed_full(Full::new(Bytes::from(format!("转发失败: {msg}"))));
    let mut resp = hyper::Response::new(body);
    *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

/// SOCKS5 入站监听（8868）—— Phase 5 实现
pub async fn run_socks5_listener(
    listener: tokio::net::TcpListener,
    ctx: Arc<RelayContext>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // sender 被丢弃时 changed() 立即返回 Err；必须退出，
                // 否则旧监听任务会在 accept/changed 之间 100% CPU 空转
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let ctx = ctx.clone();
                let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
                    tracing::warn!("SOCKS5 连接数达到上限，拒绝新连接");
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
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

    // 1-2. 握手 + CONNECT 请求解析（整体限时，防慢连接永久占用任务）
    let handshake = async {
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err("非 SOCKS5 请求".into());
        }
        let n_methods = head[1] as usize;
        let mut methods = vec![0u8; n_methods];
        stream.read_exact(&mut methods).await?;
        // 无认证
        stream.write_all(&[0x05, 0x00]).await?;

        let mut req_head = [0u8; 4];
        stream.read_exact(&mut req_head).await?;
        if req_head[1] != 0x01 {
            // 仅支持 CONNECT
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err("仅支持 SOCKS5 CONNECT".into());
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
            _ => return Err("不支持的 SOCKS5 地址类型".into()),
        };
        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        Ok::<(String, u16), Box<dyn std::error::Error + Send + Sync>>((target_host, port))
    };

    let (target_host, port) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => return Ok(()),
        Err(_) => {
            tracing::debug!("SOCKS5 握手超时（慢连接已断开）");
            return Ok(());
        }
    };

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
        tls_skip_verify: false,
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
