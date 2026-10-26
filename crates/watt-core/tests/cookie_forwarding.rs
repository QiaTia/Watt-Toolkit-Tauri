//! 出站 Cookie 合并的端到端验证（**纯本地，无外网依赖**，可进 CI）。
//!
//! 背景：下游 HTTP/2 允许把 `Cookie` 拆成多个字段（RFC 9113 §8.2.3，Chrome 在
//! h2 下确实会拆）；本链路出站恒为 HTTP/1.1，因此必须按 RFC 7540 §8.1.2.5
//! 用 `"; "` 合并成**单条**再发，否则只读第一条 `Cookie` 的上游（Java Servlet
//! `getHeader`、部分 WAF）会丢登录态 cookie。
//!
//! 本测试模拟一个「严格上游」：只取第一条 `Cookie`（`get_all()[0]`），因此
//! 一旦合并逻辑缺失（多行透传），它拿到的就只有 `a=1` → 断言失败。
//!
//! 链路：h2 客户端 → MITM（本机 TLS）→ 规则 destination 指向本机明文 h1 上游。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::header::{COOKIE, USER_AGENT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_config::{DomainRule, DomainRuleFields, DomainRules};

/// 极简 h1 上游：抓取请求头里**每一条** `cookie:` 行，然后回 200。
async fn spawn_strict_upstream() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_task = seen.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let seen = seen_task.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                {
                    let mut got = seen.lock().unwrap();
                    for line in head.lines() {
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("cookie") {
                                got.push(value.trim().to_string());
                            }
                        }
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });

    (port, seen)
}

/// 起 MITM 监听（不写 hosts、不占 443）
async fn spawn_mitm(
    ca: &Arc<CaCertificate>,
    rules: Vec<DomainRule>,
) -> (u16, tokio::sync::watch::Sender<bool>) {
    let ctx = Arc::new(watt_core::http_relay::RelayContext::new(
        DomainRules::new(rules),
        watt_core::local_domain::LocalDomainHandler::new(vec![]),
        None,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(watt_core::listener::run_mitm_listener(
        listener,
        ctx,
        watt_core::sni::mitm_tls_acceptor(ca.clone()),
        rx,
    ));
    (port, tx)
}

/// 经 MITM 发 h2 请求，`cookies` 逐条作为独立 `cookie` 字段（模拟 h2 拆段）
async fn h2_get_with_split_cookies(
    port: u16,
    ca: &CaCertificate,
    host: &str,
    path: &str,
    cookies: &[&str],
) -> u16 {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("MITM h2 握手失败");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "必须协商到 h2，否则测不到拆段场景"
    );

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder()
        .uri(format!("https://{host}{path}"))
        .header(USER_AGENT, "watt-test");
    for c in cookies {
        builder = builder.header(COOKIE, *c);
    }
    let resp = sender
        .send_request(
            builder
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("h2 请求失败");
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    status
}

/// h2 拆出的多个 `Cookie` 必须被合并成**一条**，且两段值都在。
#[tokio::test]
async fn split_cookie_is_merged_into_single_field_for_h1_upstream() {
    let (upstream_port, seen) = spawn_strict_upstream().await;

    let ca = Arc::new(CaCertificate::generate().unwrap());
    let rule = DomainRule {
        match_domain_names: vec!["probe.local".to_string()],
        listening_domain_names: vec![],
        order: 0,
        fields: DomainRuleFields {
            // 出站指向本机明文上游（http），避免依赖外网与 TLS
            destination: Some(format!("http://127.0.0.1:{upstream_port}")),
            ..Default::default()
        },
    };
    let (mitm_port, tx) = spawn_mitm(&ca, vec![rule]).await;

    let status = h2_get_with_split_cookies(mitm_port, &ca, "probe.local", "/echo", &[
        "figma.sid=aaa",
        "figma.csrf=bbb",
    ])
    .await;
    assert_eq!(status, 200);

    // 等上游把请求头解析完（极简实现，通常立刻完成）
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while seen.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = tx.send(true);

    let got = seen.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "严格上游只能收到一条 Cookie 字段（否则只读第一条的实现会丢值）：{got:?}"
    );
    assert_eq!(
        got[0], "figma.sid=aaa; figma.csrf=bbb",
        "合并必须用 \"; \" 且顺序保持、值不丢"
    );
}
