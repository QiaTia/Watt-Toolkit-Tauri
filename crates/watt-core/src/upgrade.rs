//! WebSocket / HTTP Upgrade 隧道支持。
//!
//! # 背景
//!
//! Figma 的实时协作走 `wss://www.figma.com/api/livegraph`（WebSocket）。MITM 反代
//! 把 TLS 解密后交给 `http_relay` 按普通 HTTP 转发，而 WebSocket 握手请求带
//! `Upgrade: websocket` 头、服务端回 **101 Switching Protocols** 且**此后不再有
//! HTTP 语义**——连接转为双向裸字节流。
//!
//! 原有 `http_relay::forward` 的收尾逻辑是 `resp_body.collect().await`：101 响应
//! 没有 body 且连接不会关闭，collect 会一直挂起，直到对端（或浏览器）超时断开。
//! 症状与日志一致：
//! - `WebSocket connection to 'wss://www.figma.com/api/livegraph' failed:`
//! - `[Livegraph] Connection closed. Code: 1006`（异常关闭，无关闭帧）
//! - 连带 `POST /api/session/login 500`（登录流程中的 Arkose 人验依赖 monitor 通道）
//!
//! # 方案
//!
//! 在 MITM 明文层识别 Upgrade 请求（`Upgrade` 头非空且 `Connection` 含
//! `upgrade`，或 HTTP/2 的 Extended CONNECT `:protocol = websocket`），
//! **不经 http_relay**，改为：
//! 1. 按域名规则建出站连接（覆盖 IP / DNS / 二级代理，与普通转发一致）；
//! 2. 把 Upgrade 请求原样写给出站（保留 `Sec-WebSocket-Key` 等全部头）；
//! 3. 读服务端响应：非 101 → 原样回给客户端后关闭；101 → 回给客户端，随后
//!    `copy_bidirectional` 双向拷贝，直到任一端关闭。
//!
//! 出站侧用裸 TCP + 可选 TLS 手工拼 HTTP/1.1  Upgrade 请求（hyper 的
//! http1 client 不暴露 Upgrade API），因此本模块直接操作字节流。
//!
//! # 与迁移一致性的关系
//!
//! 原版 C# 的 MITM 管道对 Upgrade 请求直接透传隧道（不解析 HTTP 语义），
//! 本模块对齐该行为；同时保留域名规则（覆盖 IP / 备用池竞速）的加速能力。

use crate::outbound::{OutboundConnector, OutboundTarget};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 等待上游响应头的累计上限：升级目标可能静默挂死，不能无限占用连接槽位
const UPSTREAM_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// 出站 IO 统一枚举（tokio 的 AsyncWrite 有泛型方法，不能进 trait object）
enum OutboundIo {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for OutboundIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for OutboundIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 判定请求是否为协议升级（WebSocket 等）。
///
/// - HTTP/1.1：`Upgrade` 头非空且 `Connection` 头含 `upgrade` 令牌（大小写不敏感）
/// - HTTP/2：Extended CONNECT（`:protocol` 伪头，hyper 映射到
///   `extensions` 之外无直接暴露；实践中浏览器对 wss 仍多走 h1 CONNECT 隧道，
///   进入本模块时已是明文 HTTP/1.1 升级请求）
pub fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    let has_upgrade = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    if !has_upgrade {
        return false;
    }
    // Connection 头需含 upgrade 令牌（RFC 9110：大小写不敏感的逗号分隔列表）
    req.headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
}

/// 处理 Upgrade 请求：建立出站隧道并完成 101 握手。
///
/// `target` 由调用方按域名规则解析（覆盖 IP / destination / 端口 / TLS 语义），
/// 与普通转发保持一致——否则规则里配了 destination 镜像的域名会连错目标。
/// `outbound_authority` 为出站请求的 Host 头（destination 的 authority）。
///
/// 返回的响应带 `on_upgrade` 回调：hyper 在客户端侧完成升级后会调用它，
/// 届时把客户端流与出站流双向拷贝。
pub async fn handle_upgrade(
    req: Request<Incoming>,
    target: OutboundTarget,
    outbound_authority: String,
    dns: Arc<watt_dns::DnsResolver>,
    upstream: Option<crate::outbound::UpstreamProxy>,
) -> Result<Response<Full<Bytes>>, String> {
    let (mut parts, _body) = req.into_parts();

    // 客户端侧升级句柄必须从**请求** extensions 取：
    // hyper 的 h1 dispatch 在读到带 Upgrade 头的请求时，会自己创建 OnUpgrade
    // 并插入请求 extensions。对响应调 `upgrade::on` 会与之冲突（debug_assert
    // "OnUpgrade already set"），且我方的 future 永远收不到升级完成通知。
    let client_upgrade = parts
        .extensions
        .remove::<hyper::upgrade::OnUpgrade>()
        .ok_or_else(|| "请求缺少 OnUpgrade 扩展（非升级请求？）".to_string())?;
    tracing::debug!(
        "Upgrade → {}:{} 已取得客户端 OnUpgrade",
        target.host,
        target.port
    );

    let connector =
        OutboundConnector::new(Arc::new(crate::http_relay::RelayDnsAdapter(dns)), upstream);
    let stream = connector
        .connect(&target)
        .await
        .map_err(|e| format!("Upgrade 出站连接失败: {e}"))?;

    // 把客户端的升级请求还原为 HTTP/1.1 报文写出（只保留必要的头）
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        parts.method.as_str(),
        parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/"),
        outbound_authority
    );
    for (k, v) in parts.headers.iter() {
        // Host 已写；Connection/Upgrade 原样保留
        if k == hyper::header::HOST {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            head.push_str(&format!("{}: {}\r\n", k.as_str(), vs));
        }
    }
    head.push_str("\r\n");

    // OutboundStream 两种变体类型不同（TcpStream / Box<TlsStream>），
    // 而 tokio 的 AsyncWrite 因泛型方法不能进 trait object，
    // 故用枚举统一，读写时 match 分发。
    let mut outbound = match stream {
        crate::outbound::OutboundStream::Plain(s) => OutboundIo::Plain(s),
        crate::outbound::OutboundStream::Tls(s) => OutboundIo::Tls(s),
    };
    outbound
        .write_all(head.as_bytes())
        .await
        .map_err(|e| format!("Upgrade 写出站请求失败: {e}"))?;

    // 读服务端响应头（至 \r\n\r\n）；累计截止时间防僵尸上游无限挂起
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + UPSTREAM_HEADER_TIMEOUT;
    let header_end = loop {
        let n = tokio::time::timeout_at(deadline, outbound.read(&mut chunk))
            .await
            .map_err(|_| "Upgrade 等待上游响应头超时".to_string())?
            .map_err(|e| format!("Upgrade 读上游响应失败: {e}"))?;
        if n == 0 {
            return Err("Upgrade 上游在响应头结束前关闭".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(buf.len());
        }
        if buf.len() > 16 * 1024 {
            return Err("Upgrade 上游响应头过大".into());
        }
    };

    let head_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let status = parse_status(&head_text).unwrap_or(StatusCode::OK);

    // 非 101：服务端拒绝了升级 → 把响应原样转给客户端，读到的多余字节一并带回
    if status != StatusCode::SWITCHING_PROTOCOLS {
        let mut builder = Response::builder().status(status);
        for line in head_text.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                let v = v.trim();
                if k.eq_ignore_ascii_case("content-length")
                    || k.eq_ignore_ascii_case("transfer-encoding")
                {
                    continue;
                }
                builder = builder.header(k, v);
            }
        }
        let mut body_bytes = buf.split_off(header_end);
        // 尽力读一小段 body（非 101 通常有 JSON 错误体，读到即止）
        let mut extra = [0u8; 8192];
        if let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_millis(500), outbound.read(&mut extra))
                .await
        {
            if n > 0 {
                body_bytes.extend_from_slice(&extra[..n]);
            }
        }
        builder = builder.header(hyper::header::CONTENT_LENGTH, body_bytes.len());
        return builder
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| e.to_string());
    }

    // 101：客户端升级完成后，把客户端流与出站流双向拼接。
    //
    // 响应带 `Connection: Upgrade` + `Upgrade: websocket`（RFC 6455 要求），
    // 其余头透传上游。`connection_close()` 只匹配 "close" 令牌，故 Upgrade
    // 不会把连接判为 keep-alive=false。
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "Upgrade")
        .header(hyper::header::UPGRADE, "websocket");
    for line in head_text.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("connection")
                || k.eq_ignore_ascii_case("upgrade")
                || k.eq_ignore_ascii_case("content-length")
                || k.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            builder = builder.header(k, v);
        }
    }

    let resp = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    // 客户端升级完成后，把客户端流与出站流双向拼接。
    // `Upgraded` 内部用 Rewind 保存预读字节，隧道数据不会丢。
    tokio::spawn(async move {
        match client_upgrade.await {
            Ok(client_io) => {
                let mut client = hyper_util::rt::TokioIo::new(client_io);
                let _ = tokio::io::copy_bidirectional(&mut client, &mut outbound).await;
            }
            Err(e) => {
                tracing::debug!("Upgrade 客户端升级失败: {e}");
            }
        }
    });
    Ok(resp)
}

/// 解析 HTTP 状态行首行的状态码
fn parse_status(head: &str) -> Option<StatusCode> {
    let first = head.lines().next()?;
    let code = first.split_whitespace().nth(1)?;
    StatusCode::from_u16(code.parse::<u16>().ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_upgrade_request_http11() {
        let req = Request::builder()
            .method("GET")
            .uri("/api/livegraph")
            .header(hyper::header::HOST, "www.figma.com")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::CONNECTION, "Upgrade")
            .body(())
            .unwrap();
        assert!(is_upgrade_request(&req));
    }

    #[test]
    fn test_is_upgrade_request_connection_list() {
        // Connection 为多令牌列表（keep-alive, Upgrade）
        let req = Request::builder()
            .uri("/ws")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::CONNECTION, "keep-alive, Upgrade")
            .body(())
            .unwrap();
        assert!(is_upgrade_request(&req));
    }

    #[test]
    fn test_not_upgrade_without_connection_token() {
        // 有 Upgrade 头但 Connection 不含 upgrade → 不是升级
        let req = Request::builder()
            .uri("/ws")
            .header(hyper::header::UPGRADE, "websocket")
            .header(hyper::header::CONNECTION, "keep-alive")
            .body(())
            .unwrap();
        assert!(!is_upgrade_request(&req));
    }

    #[test]
    fn test_not_upgrade_plain_get() {
        let req = Request::builder()
            .uri("/")
            .header(hyper::header::HOST, "www.figma.com")
            .body(())
            .unwrap();
        assert!(!is_upgrade_request(&req));
    }

    #[test]
    fn test_parse_status() {
        assert_eq!(
            parse_status("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"),
            Some(StatusCode::SWITCHING_PROTOCOLS)
        );
        assert_eq!(
            parse_status("HTTP/1.1 200 OK\r\n\r\n"),
            Some(StatusCode::OK)
        );
        assert_eq!(parse_status("garbage"), None);
    }
}
