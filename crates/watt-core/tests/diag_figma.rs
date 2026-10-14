//! 真实链路诊断（`#[ignore]`，需联网）：
//! Figma 内置分组（`watt_cloud::builtin::figma_group`）→ 引擎规则 →
//! Hosts 模式 MITM(空闲端口) → 出站候选链（覆盖 IP + 备用池竞速）→ **真实 figma.com**。
//!
//! 手动运行：
//! ```text
//! cargo test -p watt-core --test diag_figma -- --ignored --nocapture
//! ```
//!
//! 该测试不触碰系统 hosts（注入临时路径）、不使用 443（用空闲端口），
//! 因此可以安全地在开发机上验证「Hosts 模式 + 真实站点」的端到端可用性。
//! 覆盖 IP 选型依据见 `watt-cloud/src/builtin.rs` 模块文档（2026-10 实测）。

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_config::ProxyMode;
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

/// 经 MITM 发起 HTTP/1.1 GET，返回完整响应文本
async fn mitm_get(
    connector: &tokio_rustls::TlsConnector,
    port: u16,
    host: &str,
    path: &str,
) -> String {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("MITM 握手失败");
    tls.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: watt-diag\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(25), tls.read_to_end(&mut buf))
        .await
        .expect("读取响应超时");
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
#[ignore]
async fn diag_figma_via_hosts_mode() {
    let ca = Arc::new(CaCertificate::generate().unwrap());

    // 生产路径：内置 Figma 分组 → 勾选全部 7 项 → 引擎规则
    let group = watt_cloud::builtin::figma_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let catalog = watt_cloud::model::AccelerateCatalog::new(vec![group]);
    let rules = catalog.to_domain_rules(Some(&ids));
    assert_eq!(rules.len(), 7, "Figma 分组应展平为 7 条规则");

    // 临时 hosts（绝不触碰系统 hosts 文件）
    let dir = std::env::temp_dir().join(format!("watt-diag-figma-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hosts_path = dir.join("hosts");
    std::fs::write(&hosts_path, "127.0.0.1 localhost\r\n").unwrap();

    let https_port = free_port();
    let mut engine = ProxyEngine::new();
    engine
        .start(EngineConfig {
            mode: ProxyMode::Hosts,
            https_port,
            rules,
            ca: ca.clone(),
            hosts_path: Some(hosts_path.clone()),
            ..Default::default()
        })
        .await
        .expect("引擎启动失败");
    assert!(matches!(engine.state(), EngineState::Running { .. }));

    // 1) hosts 已写入 7 个 figma 加速域
    let hosts = std::fs::read_to_string(&hosts_path).unwrap();
    for domain in [
        "www.figma.com",
        "api.figma.com",
        "s3-alpha-sig.figma.com",
        "static.figma.com",
        "cdn.figma.com",
        "verify.figma.com",
        "errors.figma.com",
    ] {
        assert!(hosts.contains(domain), "hosts 未写入 {domain}:\n{hosts}");
    }
    println!("[diag-figma] hosts 已写入 7 个 figma 加速域");

    let connector = ca_trusting_connector(&ca);

    // 2) 主站：经覆盖 IP（CloudFront）应拿到 200
    let resp = mitm_get(&connector, https_port, "www.figma.com", "/").await;
    let first_line = resp.lines().next().unwrap_or("<empty>").to_string();
    println!("[diag-figma] www.figma.com 响应: {first_line}");
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "经 MITM 访问 www.figma.com 失败，首行: {first_line}"
    );

    // 3) API：未带鉴权 → 401 即证明 TLS + HTTP 全链路可达
    let resp = mitm_get(&connector, https_port, "api.figma.com", "/v1/me").await;
    let first_line = resp.lines().next().unwrap_or("<empty>").to_string();
    println!("[diag-figma] api.figma.com 响应: {first_line}");
    assert!(
        resp.starts_with("HTTP/1.1 401"),
        "经 MITM 访问 api.figma.com 应为 401（未鉴权），首行: {first_line}"
    );

    // 4) 静态资源：403（根路径拒绝）即证明 CDN 分发可达
    let resp = mitm_get(&connector, https_port, "static.figma.com", "/").await;
    let first_line = resp.lines().next().unwrap_or("<empty>").to_string();
    println!("[diag-figma] static.figma.com 响应: {first_line}");
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "经 MITM 访问 static.figma.com 应为 403（根路径拒绝），首行: {first_line}"
    );

    // 5) 人验域：Arkose 帧经 CF 覆盖 IP 应 200（日志症状 ERR_CONNECTION_CLOSED）
    let resp = mitm_get(&connector, https_port, "verify.figma.com", "/arkose_frame.html").await;
    let first_line = resp.lines().next().unwrap_or("<empty>").to_string();
    println!("[diag-figma] verify.figma.com 响应: {first_line}");
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "经 MITM 访问 verify.figma.com/arkose_frame.html 应为 200，首行: {first_line}"
    );

    // 6) Sentry 上报域：403（根路径拒绝）即证明 S3 分发可达
    let resp = mitm_get(&connector, https_port, "errors.figma.com", "/").await;
    let first_line = resp.lines().next().unwrap_or("<empty>").to_string();
    println!("[diag-figma] errors.figma.com 响应: {first_line}");
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "经 MITM 访问 errors.figma.com 应为 403（根路径拒绝），首行: {first_line}"
    );

    // 7) stop 后必须还原 hosts（不留黑洞）
    engine.stop().await.unwrap();
    assert_eq!(engine.state(), EngineState::Stopped);
    let after = std::fs::read_to_string(&hosts_path).unwrap();
    assert!(!after.contains("figma.com"), "stop 后 hosts 未还原:\n{after}");
    println!("[diag-figma] stop 后 hosts 已还原");

    let _ = std::fs::remove_dir_all(&dir);
}

/// 浏览器真实路径：ALPN 协商为 **HTTP/2**（无 Host 头，目标主机仅在
/// `:authority` 伪头）。验证 Figma 规则在 h2 语义下同样命中覆盖 IP。
///
/// 手动运行：
/// ```text
/// cargo test -p watt-core --test diag_figma -- --ignored --nocapture diag_figma_via_mitm_http2
/// ```
#[tokio::test]
#[ignore]
async fn diag_figma_via_mitm_http2() {
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let group = watt_cloud::builtin::figma_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let catalog = watt_cloud::model::AccelerateCatalog::new(vec![group]);
    let rules = catalog.to_domain_rules(Some(&ids));

    let ctx = Arc::new(watt_core::http_relay::RelayContext::new(
        watt_config::DomainRules::new(rules),
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
            rustls::pki_types::ServerName::try_from("www.figma.com".to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("MITM 握手失败");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "应协商为 h2"
    );
    println!("[diag-figma-h2] (0) MITM TLS 完成，ALPN=h2，监听 {addr}");

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .uri("https://www.figma.com/")
        .header(hyper::header::USER_AGENT, "watt-diag-h2")
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .unwrap();
    let resp = match tokio::time::timeout(
        std::time::Duration::from_secs(25),
        sender.send_request(req),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => panic!("send_request 失败: {e}"),
        Err(_) => panic!("send_request 超时 25s"),
    };
    let status = resp.status();
    println!("[diag-figma-h2] (1) www.figma.com :status = {status}");
    assert_eq!(status, 200, "HTTP/2 经 MITM 访问 www.figma.com 应为 200");
}
