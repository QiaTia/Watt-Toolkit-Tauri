//! 真实链路诊断（`#[ignore]`，需联网）：
//! Hosts 模式引擎 start() → MITM(空闲端口) → 出站候选链 → **真实 github.com**。
//!
//! 手动运行：
//! ```text
//! cargo test -p watt-core --test diag_github -- --ignored --nocapture
//! ```
//!
//! 该测试不触碰系统 hosts（注入临时路径）、不使用 443（用空闲端口），
//! 因此可以安全地在开发机上验证「Hosts 模式 + 真实站点」的端到端可用性。

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_config::{DomainRule, DomainRuleFields, ProxyMode};
use watt_core::{EngineConfig, EngineState, ProxyEngine};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 信任指定 CA 的 TLS 客户端（模拟已安装根证书的浏览器）
fn ca_trusting_connector(ca: &CaCertificate) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
#[ignore]
async fn diag_github_via_hosts_mode() {
    let ca = Arc::new(CaCertificate::generate().unwrap());

    // 临时 hosts（绝不触碰系统 hosts 文件）
    let dir = std::env::temp_dir().join(format!("watt-diag-gh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hosts_path = dir.join("hosts");
    std::fs::write(&hosts_path, "127.0.0.1 localhost\r\n").unwrap();

    let https_port = free_port();
    let rule = DomainRule {
        match_domain_names: vec!["github.com".into()],
        listening_domain_names: vec!["github.com".into(), "api.github.com".into()],
        fields: DomainRuleFields::default(),
        order: 1,
        ..Default::default()
    };

    let mut engine = ProxyEngine::new();
    engine
        .start(EngineConfig {
            mode: ProxyMode::Hosts,
            https_port,
            rules: vec![rule],
            ca: ca.clone(),
            hosts_path: Some(hosts_path.clone()),
            ..Default::default()
        })
        .await
        .expect("引擎启动失败");
    assert!(matches!(engine.state(), EngineState::Running { .. }));

    // 1) hosts 已写入（Hosts 模式的接入面）
    let hosts = std::fs::read_to_string(&hosts_path).unwrap();
    assert!(hosts.contains("github.com"), "hosts 未写入:\n{hosts}");
    println!("[diag] hosts 已写入 github.com");

    // 2) 经 MITM 请求真实 github.com
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", https_port))
        .await
        .unwrap();
    let connector = ca_trusting_connector(&ca);
    let mut tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("github.com".to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("MITM 握手失败");
    tls.write_all(
        b"GET / HTTP/1.1\r\nHost: github.com\r\nUser-Agent: watt-diag\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf).await;
    let resp = String::from_utf8_lossy(&buf);
    let first_line = resp.lines().next().unwrap_or("<empty>").to_string();
    println!("[diag] github.com 响应: {first_line}");
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "经 MITM 访问 github.com 失败，首行: {first_line}"
    );
    assert!(
        resp.to_ascii_lowercase().contains("github"),
        "响应体不含 github 标记（可能被中间页替换）"
    );

    // 3) stop 后必须还原 hosts（不留黑洞）
    engine.stop().await.unwrap();
    assert_eq!(engine.state(), EngineState::Stopped);
    let after = std::fs::read_to_string(&hosts_path).unwrap();
    assert!(!after.contains("github.com"), "stop 后 hosts 未还原:\n{after}");
    println!("[diag] stop 后 hosts 已还原");

    let _ = std::fs::remove_dir_all(&dir);
}

/// 浏览器真实路径：同一个 MITM 反代，但客户端按 ALPN 协商为 **HTTP/2**。
///
/// HTTP/2 没有 `Host` 头，目标主机只在 `:authority` 伪头。修复前 `handle_request` 只读
/// `Host` 头 → host 为空 → 规则失配 → 404 空响应，Chromium 渲染成
/// 「找不到此 github.com 页 / HTTP ERROR 404」，而 curl（HTTP/1.1）却正常。
///
/// 手动运行：
/// ```text
/// cargo test -p watt-core --test diag_github -- --ignored --nocapture diag_github_via_mitm_http2
/// ```
#[tokio::test]
#[ignore]
async fn diag_github_via_mitm_http2() {
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let rule = DomainRule {
        match_domain_names: vec!["github.com".into()],
        order: 1,
        ..Default::default()
    };
    let ctx = Arc::new(watt_core::http_relay::RelayContext::new(
        watt_config::DomainRules::new(vec![rule]),
        watt_core::local_domain::LocalDomainHandler::new(vec![]),
        None,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(watt_core::listener::run_mitm_listener(
        listener,
        ctx,
        watt_core::sni::mitm_tls_acceptor(ca.clone()),
        rx,
    ));

    // 浏览器行为：ALPN 只给 h2
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("github.com".to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("MITM 握手失败");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "应协商为 h2"
    );
    println!("[diag-h2] (0) MITM TLS 完成，ALPN=h2，监听 {addr}");

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    println!("[diag-h2] (1) h2 握手完成");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // 关键：uri 携带 authority → 客户端不发 Host 头（与浏览器一致）
    let req = hyper::Request::builder()
        .uri("https://github.com/")
        .header(hyper::header::USER_AGENT, "watt-diag-h2")
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .unwrap();
    println!("[diag-h2] (2) 发送请求…");
    let resp = match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        sender.send_request(req),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("send_request 失败: {e}"),
        Err(_) => panic!("send_request 超时 20s —— 请求已到达代理但未回响应"),
    };
    println!("[diag-h2] (3) 收到响应头: {}", resp.status());
    let status = resp.status();
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    println!(
        "[diag-h2] (4) github.com :status = {status}  body = {} bytes",
        body.len()
    );
    assert_eq!(
        status, 200,
        "HTTP/2 经 MITM 访问 github.com 应为 200（修复前为 404 空页）"
    );
    assert!(body.len() > 10_000, "响应体过小: {} bytes", body.len());
}
