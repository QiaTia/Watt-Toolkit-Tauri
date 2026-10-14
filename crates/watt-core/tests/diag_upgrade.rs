//! WebSocket / HTTP Upgrade 隧道诊断（`#[ignore]`，需本地回环，不依赖外网）。
//!
//! # 背景
//!
//! Figma 实时协作走 `wss://www.figma.com/api/livegraph`。MITM 反代原先把
//! Upgrade 请求当普通 HTTP 转发，`http_relay::forward` 的收尾
//! `resp_body.collect().await` 对 101 响应会一直挂起（无 body 且连接不关闭），
//! 浏览器表现为 `WebSocket connection failed` + `Connection closed. Code: 1006`，
//! 并连带登录流程的 `POST /api/session/login` 500。
//!
//! 本测试用一个本地「WS 回声服务」复现完整链路：
//! 客户端(TLS) → MITM 反代 → 出站(覆盖 IP 指向回环) → 回声服务。
//! 验证 Upgrade 请求经反代后拿到 101，且双向字节流可通行。
//!
//! 手动运行：
//! ```text
//! cargo test -p watt-core --test diag_upgrade -- --ignored --nocapture
//! ```

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_core::http_relay::RelayContext;
use watt_core::listener;

/// 启动本地「WS 回声服务」：回 101，之后把收到的每个字节原样回写。
async fn spawn_ws_echo_server() -> (String, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // 读请求头
                let mut buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                    if buf.len() > 16 * 1024 {
                        return;
                    }
                };
                // 回 101（带 Sec-WebSocket-Accept 占位，客户端不校验值）
                let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
                if stream.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // 预读的 WS 帧先回写，再进入双向回声
                let pre = &buf[header_end..];
                if !pre.is_empty() && stream.write_all(pre).await.is_err() {
                    return;
                }
                let mut rest = [0u8; 8192];
                while let Ok(n) = stream.read(&mut rest).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&rest[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    ("127.0.0.1".to_string(), port)
}

#[tokio::test]
#[ignore]
async fn diag_upgrade_tunnel_via_mitm() {
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let (echo_host, echo_port) = spawn_ws_echo_server().await;

    // 规则：把 www.figma.com 的覆盖 IP 指向本地回声服务（TLS 仍由反代发出，
    // 但出站 tls=false —— 通过规则的 destination 模板强制 http 语义）。
    // 这里直接构造一条指向回环的明文规则：scheme 由 destination 决定。
    let rules = vec![watt_config::DomainRule {
        match_domain_names: vec!["ws.example.com".to_string()],
        listening_domain_names: vec!["ws.example.com".to_string()],
        order: 0,
        fields: watt_config::DomainRuleFields {
            ip_address: Some(echo_host.parse().unwrap()),
            // destination 指向 http（明文），端口即回声服务端口
            destination: Some(format!("http://{echo_host}:{echo_port}")),
            ..Default::default()
        },
    }];

    let ctx = Arc::new(RelayContext::new(
        watt_config::DomainRules::new(rules),
        watt_core::local_domain::LocalDomainHandler::new(vec![]),
        None,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(listener::run_mitm_listener(
        listener,
        ctx,
        watt_core::sni::mitm_tls_acceptor(ca.clone()),
        rx,
    ));

    // 客户端：TLS 到反代，发 WebSocket 升级请求
    let connector = {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
            .unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    };

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("ws.example.com".to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("MITM 握手失败");

    // 标准 WS 握手请求
    let ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
    tls.write_all(
        format!(
            "GET /api/livegraph HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    // 读 101 响应头
    let mut resp_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut chunk))
            .await
            .expect("读 101 响应超时")
            .unwrap();
        if n == 0 {
            panic!("反代在 101 响应前关闭连接");
        }
        resp_buf.extend_from_slice(&chunk[..n]);
        if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break resp_buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .unwrap()
                + 4;
        }
    };
    let head = String::from_utf8_lossy(&resp_buf[..header_end]).to_string();
    println!("[diag-upgrade] 响应头:\n{head}");
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "应拿到 101 Switching Protocols，实际首行: {:?}",
        head.lines().next()
    );
    assert!(
        head.to_ascii_lowercase().contains("upgrade: websocket"),
        "响应应带 Upgrade: websocket 头"
    );

    // 101 之后连接即 WS 双向流：发一帧「假数据」，回声服务应原样回写。
    // 用非 WebSocket 帧格式的裸字节即可验证隧道连通性（回声服务不解析帧）。
    let payload = b"\x81\x05hello";
    tls.write_all(payload).await.unwrap();
    let mut echo = [0u8; 32];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut echo)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => panic!("读回声数据失败（错误）: {e}"),
        Err(_) => panic!("读回声数据超时（隧道未连通）"),
    };
    assert_eq!(
        &echo[..n],
        payload,
        "回声服务应原样回写（隧道双向连通）"
    );
    println!("[diag-upgrade] WS 隧道双向连通，回声 {n} 字节一致");

    // 关闭：客户端断开后隧道应随之结束（不再挂起）
    drop(tls);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    println!("[diag-upgrade] 客户端断开，隧道结束");
}
