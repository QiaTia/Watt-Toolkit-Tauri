//! 诊断（`#[ignore]`，需联网）：**登录态相关 Cookie 是否被 MITM 吃掉了**。
//!
//! 做法：同一条请求分别走两条链路，比较响应头里的 `Set-Cookie` 集合：
//! - A 直连：系统 DNS 解析 `www.figma.com` → 真实 TLS（webpki 根）
//! - B 经引擎 Hosts 模式 MITM（注入临时 hosts、空闲端口，不碰系统 hosts/443）
//!
//! 若 B 的 cookie 名字集合缺项 → 代理链路有缺陷（登录态丢失的机制层原因）；
//! 若两者一致 → 掉登录不是「cookie 被吞」，需从服务端风控 / 会话校验失败方向查。
//!
//! 运行：
//! ```text
//! cargo test -p watt-core --test diag_figma_cookie -- --ignored --nocapture
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_config::ProxyMode;
use watt_core::{EngineConfig, ProxyEngine};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 从原始响应文本里抽取 `Set-Cookie` 的「名字」（`k=v` 的 k，去掉 `__Host-`/`__Secure-` 前缀保留原名）
fn set_cookie_names(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .filter_map(|l| l.split(':').nth(1))
        .filter_map(|v| v.split('=').next())
        .map(|name| name.trim().to_string())
        .collect()
}

fn status_line(raw: &str) -> String {
    raw.lines().next().unwrap_or("<empty>").to_string()
}

/// 直连：系统 DNS + 标准根证书
async fn direct_get(host: &str, path: &str) -> String {
    use watt_dns::DnsResolver;
    let resolver = DnsResolver::system();
    let ips = resolver.resolve_clean(host).await.expect("DNS 解析失败");
    assert!(!ips.is_empty(), "{host} 未解析到地址");

    let connector = watt_core::sni::outbound_tls_connector(
        watt_core::sni::OutboundVerify::Standard,
        None,
    );
    let mut last_err = String::new();
    for ip in ips {
        match tokio::net::TcpStream::connect((ip, 443u16)).await {
            Ok(tcp) => {
                let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
                match connector.connect(name, tcp).await {
                    Ok(mut tls) => {
                        tls.write_all(
                            format!(
                                "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: watt-diag\r\n\
                                 Accept: text/html\r\nConnection: close\r\n\r\n"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                        let mut buf = Vec::new();
                        let _ =
                            tokio::time::timeout(std::time::Duration::from_secs(20), tls.read_to_end(&mut buf))
                                .await;
                        return String::from_utf8_lossy(&buf).to_string();
                    }
                    Err(e) => last_err = format!("TLS 握手失败（{ip}）: {e}"),
                }
            }
            Err(e) => last_err = format!("连接 {ip} 失败: {e}"),
        }
    }
    panic!("直连 {host} 全部候选失败: {last_err}");
}

/// 经 MITM：信任被测 CA 的客户端
async fn mitm_get(port: u16, ca: &CaCertificate, host: &str, path: &str) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let mut tls = connector.connect(name, tcp).await.expect("MITM 握手失败");
    tls.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: watt-diag\r\n\
             Accept: text/html\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(25), tls.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).to_string()
}

#[tokio::test]
#[ignore]
async fn diag_figma_set_cookie_through_mitm() {
    const HOST: &str = "www.figma.com";
    const PATH: &str = "/login";

    // —— A 直连 ——
    let direct = direct_get(HOST, PATH).await;
    let direct_cookies = set_cookie_names(&direct);
    println!("[cookie-diag] 直连 {}: {}", PATH, status_line(&direct));
    println!("[cookie-diag] 直连 Set-Cookie = {direct_cookies:?}");

    // —— B 经 MITM ——
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let group = watt_cloud::builtin::figma_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let catalog = watt_cloud::model::AccelerateCatalog::new(vec![group]);
    let rules = catalog.to_domain_rules(Some(&ids));

    let dir = std::env::temp_dir().join(format!("watt-diag-cookie-{}", std::process::id()));
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

    let via_mitm = mitm_get(https_port, &ca, HOST, PATH).await;
    let mitm_cookies = set_cookie_names(&via_mitm);
    println!("[cookie-diag] MITM: {}", status_line(&via_mitm));
    println!("[cookie-diag] MITM Set-Cookie = {mitm_cookies:?}");

    let _ = engine.stop().await;
    let _ = std::fs::remove_dir_all(&dir);

    // —— 比较：经 MITM 不得丢任何直连能拿到的 cookie ——
    let missing: Vec<&String> = direct_cookies.difference(&mitm_cookies).collect();
    println!(
        "[cookie-diag] 结论：直连 {} 个 / MITM {} 个，缺失 = {missing:?}",
        direct_cookies.len(),
        mitm_cookies.len()
    );
    assert!(
        missing.is_empty(),
        "经 MITM 丢失了 Set-Cookie: {missing:?}（直连={direct_cookies:?} MITM={mitm_cookies:?}）"
    );
}

/* ===================== 追加：h2 链路与拆分 Cookie 的端到端验证 ===================== */

use http_body_util::BodyExt;
use hyper::header::{COOKIE, USER_AGENT};
use watt_config::{DomainRule, DomainRuleFields, DomainRules};

/// 起一个只做 MITM 的监听（不写 hosts、不占 443）
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

/// 用 ALPN=h2 连接 MITM，返回 (状态码, 全部 set-cookie 值, 响应体文本)
async fn h2_get(
    port: u16,
    ca: &CaCertificate,
    host: &str,
    path: &str,
    cookies: &[&str],
) -> (u16, Vec<String>, String) {
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
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

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
        .header(USER_AGENT, "watt-diag-h2");
    for c in cookies {
        // 模拟 HTTP/2 把 Cookie 拆成多个字段（RFC 9113 §8.2.3）
        builder = builder.header(COOKIE, *c);
    }
    let resp = sender.send_request(builder.body(http_body_util::Empty::<bytes::Bytes>::new()).unwrap())
        .await
        .expect("h2 请求失败");
    let status = resp.status().as_u16();
    let cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string())
        .collect();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, cookies, String::from_utf8_lossy(&body).to_string())
}

/// ① Chrome/Edge 走 h2：经 MITM 后 Figma 的 Set-Cookie 是否仍完整
#[tokio::test]
#[ignore]
async fn diag_figma_set_cookie_over_http2() {
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let group = watt_cloud::builtin::figma_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let rules = watt_cloud::model::AccelerateCatalog::new(vec![group]).to_domain_rules(Some(&ids));
    let (port, tx) = spawn_mitm(&ca, rules).await;

    let (status, cookies, _) = h2_get(port, &ca, "www.figma.com", "/login", &[]).await;
    let names: BTreeSet<String> = cookies
        .iter()
        .filter_map(|c| c.split('=').next())
        .map(|s| s.trim().to_string())
        .collect();
    println!("[cookie-h2] status={status} set-cookie={names:?}");
    let _ = tx.send(true);

    assert_eq!(status, 200);
    for expected in ["__Host-figma.did", "figma.session", "product_locale"] {
        assert!(names.contains(expected), "h2 链路丢失 {expected}：{names:?}");
    }
}

/// ② 拆分的多个 Cookie 请求头是否都被转发到上游（postman-echo 回显每个 cookie）
#[tokio::test]
#[ignore]
async fn diag_split_cookie_headers_reach_upstream() {
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let rule = DomainRule {
        match_domain_names: vec!["postman-echo.com".to_string()],
        listening_domain_names: vec![],
        order: 0,
        fields: DomainRuleFields::default(),
    };
    let (port, tx) = spawn_mitm(&ca, vec![rule]).await;

    let (status, _, body) = h2_get(
        port,
        &ca,
        "postman-echo.com",
        "/cookies",
        &["a=1", "b=2"],
    )
    .await;
    println!("[cookie-split] status={status} body={body}");
    let _ = tx.send(true);

    assert_eq!(status, 200);
    assert!(body.contains("\"a\""), "上游未收到第一段 cookie：{body}");
    assert!(body.contains("\"b\""), "上游未收到第二段 cookie：{body}");
}

/// ③ 系统代理模式真实路径：`CONNECT` → MITM → ALPN=h2（Chrome/Edge 的实际行为）
///
/// 用 `ProxyOnly` 模式起引擎（同样监听正向代理端口，但不写注册表，避免污染本机）。
#[tokio::test]
#[ignore]
async fn diag_figma_via_forward_proxy_connect_h2() {
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let group = watt_cloud::builtin::figma_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let rules = watt_cloud::model::AccelerateCatalog::new(vec![group]).to_domain_rules(Some(&ids));
    let port = free_port();

    let mut engine = ProxyEngine::new();
    engine
        .start(EngineConfig {
            mode: ProxyMode::ProxyOnly,
            forward_proxy_port: port,
            rules,
            ca: ca.clone(),
            ..Default::default()
        })
        .await
        .expect("引擎启动失败");

    // 1) CONNECT 建隧道
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    tcp.write_all(b"CONNECT www.figma.com:443 HTTP/1.1\r\nHost: www.figma.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head_text = String::from_utf8_lossy(&head).to_string();
    println!("[cookie-fwd] CONNECT 响应: {}", head_text.lines().next().unwrap_or(""));
    assert!(head_text.starts_with("HTTP/1.1 200"));

    // 2) 隧道内做 TLS（ALPN=h2）→ 就是我们 MITM 的浏览器视角
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(
            rustls::pki_types::ServerName::try_from("www.figma.com".to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("CONNECT 隧道内 TLS 握手失败");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender
        .send_request(
            hyper::Request::builder()
                .uri("https://www.figma.com/login")
                .header(USER_AGENT, "watt-diag-fwd")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("forward proxy h2 请求失败");

    let status = resp.status().as_u16();
    let cookies: BTreeSet<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split('=').next())
        .map(|s| s.trim().to_string())
        .collect();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    println!(
        "[cookie-fwd] status={status} set-cookie={cookies:?} body={} bytes",
        body.len()
    );

    let _ = engine.stop().await;

    assert_eq!(status, 200);
    for expected in ["__Host-figma.did", "figma.session", "product_locale"] {
        assert!(
            cookies.contains(expected),
            "系统代理链路丢失 {expected}：{cookies:?}"
        );
    }
}
