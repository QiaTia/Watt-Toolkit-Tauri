//! POST 请求体转发诊断（`#[ignore]`，纯本地回环，不依赖外网）。
//!
//! # 背景
//!
//! 实测：经反代的 POST，请求体 > ~1.2KB 时**必然失败**（本引擎回 500
//! `转发失败: 请求失败: connection error`，耗时约 19.4s），而 ≤1024 字节正常。
//! 浏览器登录 Figma 的凭据 JSON 远大于该阈值，因此表现为「无法登录」。
//!
//! 本测试用**本地 origin** 复现同一条链路，并由 origin 打印它实际收到的
//! 请求头 + body 字节数，从而判定机制是「本引擎截断请求体」还是别的环节：
//!
//! 客户端(TLS/h2) → 正向代理 26501(CONNECT + MITM) → http_relay → 本地 origin
//!
//! 手动运行：
//! ```text
//! cargo test -p watt-core --test diag_post_body -- --ignored --nocapture
//! ```

use http_body_util::BodyExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_config::{DomainRule, DomainRuleFields, DomainRules};
use watt_core::forward_proxy::run_forward_proxy_listener;
use watt_core::http_relay::RelayContext;
use watt_core::listener::run_mitm_listener;
use watt_core::sni::mitm_tls_acceptor;

const HOST: &str = "post.body.example.com";
const READ_TIMEOUT: Duration = Duration::from_secs(25);

/// 本地 origin：打印收到的请求头，按 Content-Length / chunked 读 body，
/// 回报**实际收到的字节数**（这是判定「是否被截断」的关键证据）。
async fn spawn_echo_origin() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                let header_end = loop {
                    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
                        Ok(Ok(n)) if n > 0 => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p + 4;
                            }
                            if buf.len() > 128 * 1024 {
                                println!("[origin] 请求头过大，放弃");
                                return;
                            }
                        }
                        _ => {
                            println!("[origin] 未读到完整请求头即结束");
                            return;
                        }
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).replace("\r\n", " | ");
                let lower = head.to_ascii_lowercase();
                let cl: Option<usize> = lower
                    .split(" | ")
                    .filter_map(|l| l.strip_prefix("content-length:"))
                    .filter_map(|v| v.trim().parse::<usize>().ok())
                    .last();
                let chunked = lower.contains("transfer-encoding: chunked")
                    || lower.contains("transfer-encoding:chunked");
                let mut body_len = buf.len() - header_end;
                let mut closed = false;
                let mut timed_out = false;
                loop {
                    let done = match (cl, chunked) {
                        (Some(n), _) => body_len >= n,
                        // chunked：以终止块 0\r\n\r\n 判定完整
                        (None, true) => buf[header_end..].windows(5).any(|w| w == b"0\r\n\r\n"),
                        (None, false) => false,
                    };
                    if done {
                        break;
                    }
                    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
                        Ok(Ok(0)) => {
                            closed = true;
                            break;
                        }
                        Ok(Ok(n)) => {
                            buf.extend_from_slice(&chunk[..n]);
                            body_len += n;
                        }
                        Ok(Err(_)) => {
                            closed = true;
                            break;
                        }
                        Err(_) => {
                            timed_out = true;
                            break;
                        }
                    }
                }
                println!("[origin] head: {head}");
                println!(
                    "[origin] 收到 body {body_len} 字节 (cl={cl:?} chunked={chunked} closed={closed} timed_out={timed_out})"
                );
                let info = format!(
                    "origin-body={body_len} cl={cl:?} chunked={chunked} closed={closed} timeout={timed_out}"
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{info}",
                    info.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn relay_ctx(rules: Vec<DomainRule>) -> Arc<RelayContext> {
    Arc::new(RelayContext::new(
        DomainRules::new(rules),
        watt_core::local_domain::LocalDomainHandler::new(vec![]),
        None,
    ))
}

fn rule_to_origin(port: u16) -> DomainRule {
    DomainRule {
        match_domain_names: vec![HOST.to_string()],
        listening_domain_names: vec![HOST.to_string()],
        order: 0,
        fields: DomainRuleFields {
            destination: Some(format!("http://127.0.0.1:{port}/")),
            ..Default::default()
        },
    }
}

async fn spawn_forward_proxy(
    ctx: Arc<RelayContext>,
    ca: Arc<CaCertificate>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_forward_proxy_listener(
        listener,
        ctx,
        mitm_tls_acceptor(ca),
        "127.0.0.1:26501".to_string(),
        rx,
    ));
    addr
}

fn ca_connector(ca: &CaCertificate, alpn: Vec<Vec<u8>>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn read_until_empty_line<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 经正向代理 CONNECT + MITM 建立到 host 的 TLS 连接
async fn connect_mitm(
    addr: std::net::SocketAddr,
    ca: &CaCertificate,
    host: &str,
    alpn: Vec<Vec<u8>>,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let resp = read_until_empty_line(&mut stream).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "CONNECT 应回 200: {resp}");
    ca_connector(ca, alpn)
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            stream,
        )
        .await
        .expect("MITM TLS 握手失败")
}

/// 读响应至 EOF（`Connection: close`）
async fn read_to_end<S: AsyncReadExt + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tokio::time::timeout(READ_TIMEOUT, s.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                println!("[client] 读失败: {e}");
                break;
            }
            Err(_) => {
                println!("[client] 读响应超时 {READ_TIMEOUT:?}");
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// HTTP/1.1 POST（`chunked` 决定 framing；`extra` 追加额外请求头）
async fn post_h1_ex<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    s: &mut S,
    host: &str,
    path: &str,
    body_len: usize,
    chunked: bool,
    extra: &[(&str, &str)],
) -> (String, u128) {
    let payload = vec![b'x'; body_len];
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nConnection: close\r\n"
    )
    .into_bytes();
    for (k, v) in extra {
        req.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if chunked {
        req.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        req.extend_from_slice(format!("{body_len:x}\r\n").as_bytes());
        req.extend_from_slice(&payload);
        req.extend_from_slice(b"\r\n0\r\n\r\n");
    } else {
        req.extend_from_slice(format!("Content-Length: {body_len}\r\n\r\n").as_bytes());
        req.extend_from_slice(&payload);
    }
    s.write_all(&req).await.unwrap();
    let t0 = Instant::now();
    let resp = read_to_end(s).await;
    (resp, t0.elapsed().as_millis())
}

/// HTTP/1.1 POST（`chunked` 决定 framing）
async fn post_h1<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    s: &mut S,
    path: &str,
    body_len: usize,
    chunked: bool,
) -> (String, u128) {
    post_h1_ex(s, HOST, path, body_len, chunked, &[]).await
}

/// HTTP/2 POST（浏览器真实路径：ALPN=h2，无 Host 头，长度靠 :authority/帧层）
async fn post_h2(
    addr: std::net::SocketAddr,
    ca: &CaCertificate,
    path: &str,
    body_len: usize,
) -> (String, u128) {
    let tls = connect_mitm(addr, ca, HOST, vec![b"h2".to_vec()]).await;
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
        .method(hyper::Method::POST)
        .uri(format!("https://{HOST}{path}"))
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(vec![
            b'x'; body_len
        ])))
        .unwrap();
    let t0 = Instant::now();
    let resp = match tokio::time::timeout(READ_TIMEOUT, sender.send_request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return (format!("h2 send_request 失败: {e}"), t0.elapsed().as_millis()),
        Err(_) => {
            return (
                format!("h2 send_request 超时 {READ_TIMEOUT:?}"),
                t0.elapsed().as_millis(),
            )
        }
    };
    let status = resp.status();
    let body = match tokio::time::timeout(READ_TIMEOUT, resp.into_body().collect()).await {
        Ok(Ok(b)) => String::from_utf8_lossy(&b.to_bytes()).into_owned(),
        Ok(Err(e)) => format!("<读 body 失败: {e}>"),
        Err(_) => "<读 body 超时>".to_string(),
    };
    (
        format!("HTTP {status} body={body}"),
        t0.elapsed().as_millis(),
    )
}

const SIZES: [usize; 4] = [200, 1024, 1400, 2000];

/// 方向一：HTTP/1.1 客户端经正向代理 26501——Content-Length framing
#[tokio::test]
#[ignore]
async fn diag_post_body_forward_proxy_h1_content_length() {
    let port = spawn_echo_origin().await;
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let ctx = relay_ctx(vec![rule_to_origin(port)]);
    let addr = spawn_forward_proxy(ctx, ca.clone()).await;

    let mut failures = Vec::new();
    for n in SIZES {
        let mut tls = connect_mitm(addr, &ca, HOST, vec![]).await;
        let (resp, ms) = post_h1(&mut tls, "/api/figment-proxy/monitor", n, false).await;
        let first = resp.lines().next().unwrap_or("<空响应>").to_string();
        let ok = first.starts_with("HTTP/1.1 200") && resp.contains(&format!("origin-body={n} "));
        println!("[h1-proxy/cl] body={n} 耗时={ms}ms ok={ok} 首行={first}");
        if !ok {
            failures.push(format!("body={n} -> {first}"));
        }
    }
    assert!(failures.is_empty(), "以下请求体大小失败: {failures:#?}");
}

/// 方向二：HTTP/1.1 客户端经正向代理 26501——Transfer-Encoding: chunked
#[tokio::test]
#[ignore]
async fn diag_post_body_forward_proxy_h1_chunked() {
    let port = spawn_echo_origin().await;
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let ctx = relay_ctx(vec![rule_to_origin(port)]);
    let addr = spawn_forward_proxy(ctx, ca.clone()).await;

    let mut failures = Vec::new();
    for n in SIZES {
        let mut tls = connect_mitm(addr, &ca, HOST, vec![]).await;
        let (resp, ms) = post_h1(&mut tls, "/api/session/login", n, true).await;
        let first = resp.lines().next().unwrap_or("<空响应>").to_string();
        let ok = first.starts_with("HTTP/1.1 200");
        println!("[h1-proxy/chunked] body={n} 耗时={ms}ms ok={ok} 首行={first}");
        if !ok {
            failures.push(format!("body={n} -> {first}"));
        }
    }
    assert!(failures.is_empty(), "chunked 以下请求体大小失败: {failures:#?}");
}

/// 方向三：HTTP/2 客户端经正向代理 26501（浏览器真实路径）
#[tokio::test]
#[ignore]
async fn diag_post_body_forward_proxy_h2() {
    let port = spawn_echo_origin().await;
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let ctx = relay_ctx(vec![rule_to_origin(port)]);
    let addr = spawn_forward_proxy(ctx, ca.clone()).await;

    let mut failures = Vec::new();
    for n in SIZES {
        let (resp, ms) = post_h2(addr, &ca, "/api/figment-proxy/monitor", n).await;
        let ok = resp.contains("HTTP 200") && resp.contains(&format!("origin-body={n} "));
        println!("[h2-proxy] body={n} 耗时={ms}ms ok={ok} resp={resp}");
        if !ok {
            failures.push(format!("body={n} -> {resp}"));
        }
    }
    assert!(failures.is_empty(), "h2 以下请求体大小失败: {failures:#?}");
}

/// 方向四：不经正向代理，直接走 MITM 监听（Hosts 模式路径），隔离 26501 那一跳
#[tokio::test]
#[ignore]
async fn diag_post_body_mitm_direct_h1() {
    let port = spawn_echo_origin().await;
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let ctx = relay_ctx(vec![rule_to_origin(port)]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_mitm_listener(
        listener,
        ctx,
        mitm_tls_acceptor(ca.clone()),
        rx,
    ));

    let mut failures = Vec::new();
    for n in SIZES {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = ca_connector(&ca, vec![])
            .connect(
                rustls::pki_types::ServerName::try_from(HOST.to_string()).unwrap(),
                tcp,
            )
            .await
            .expect("MITM 握手失败");
        let (resp, ms) = post_h1(&mut tls, "/api/figment-proxy/monitor", n, false).await;
        let first = resp.lines().next().unwrap_or("<空响应>").to_string();
        let ok = first.starts_with("HTTP/1.1 200");
        println!("[h1-mitm-direct] body={n} 耗时={ms}ms ok={ok} 首行={first}");
        if !ok {
            failures.push(format!("body={n} -> {first}"));
        }
    }
    assert!(failures.is_empty(), "MITM 直连以下请求体大小失败: {failures:#?}");
}

/// 方向五：**真实 www.figma.com**（需联网）——回归测试。
///
/// 覆盖 IP 为 `18.65.14.118`（CloudFront 标准边缘），小/大请求体均应拿到源站
/// 4xx。历史缺陷：覆盖 IP 为 `99.86.18.30`（同族黑洞段）时，body=2000 会拿到
/// `500 转发失败: 请求失败: connection error`（约 19s）。
#[tokio::test]
#[ignore]
async fn diag_post_body_real_figma() {
    const REAL: &str = "www.figma.com";
    let ca = Arc::new(CaCertificate::generate().unwrap());
    let group = watt_cloud::builtin::figma_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let catalog = watt_cloud::model::AccelerateCatalog::new(vec![group]);
    let rules = catalog.to_domain_rules(Some(&ids));
    let ctx = relay_ctx(rules);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_mitm_listener(
        listener,
        ctx,
        mitm_tls_acceptor(ca.clone()),
        rx,
    ));
    println!("[diag-real-figma] MITM 监听 {addr}");

    let mut failures = Vec::new();
    for (n, expect) in [(200usize, false), (2000, false), (2000, true), (200, true)] {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = ca_connector(&ca, vec![])
            .connect(
                rustls::pki_types::ServerName::try_from(REAL.to_string()).unwrap(),
                tcp,
            )
            .await
            .expect("MITM 握手失败");
        let extra: Vec<(&str, &str)> = if expect {
            vec![("Expect", "100-continue")]
        } else {
            vec![]
        };
        let (resp, ms) =
            post_h1_ex(&mut tls, REAL, "/api/figment-proxy/monitor", n, false, &extra).await;
        let first = resp.lines().next().unwrap_or("<空响应>").to_string();
        let body: String = resp
            .split_once("\r\n\r\n")
            .map(|x| x.1)
            .unwrap_or("")
            .chars()
            .take(160)
            .collect();
        println!("[diag-real-figma] body={n} expect={expect} 耗时={ms}ms 首行={first} body={body}");
        // 源站对伪造路径返回 4xx；出现 5xx / 连接错误即说明上行负载未送达。
        // 带 `Expect: 100-continue` 时响应流中含临时 100 行，故按整段判定。
        if !resp.contains("HTTP/1.1 4") || resp.contains("HTTP/1.1 5") {
            failures.push(format!("body={n} expect={expect} -> {first} {body}"));
        }
    }
    assert!(
        failures.is_empty(),
        "真实 Figma POST 以下用例未得到源站 4xx（覆盖 IP 选型失败）: {failures:#?}"
    );
}

/// 对照组：**直连覆盖 IP**（不经引擎），同样的 POST —— 用于判定责任在网络还是引擎。
///
/// 对照 `99.86.18.30`（历史黑洞段）与 `18.65.14.118`（现选型）：前者对大请求体
/// 静默黑洞（约 19s 后连接被重置），后者正常返回 4xx。该对照是「覆盖 IP 选型
/// 铁律」的取证依据（详见 `watt-cloud::builtin` 模块文档）。
#[tokio::test]
#[ignore]
async fn diag_post_body_real_figma_direct_control() {
    const REAL: &str = "www.figma.com";
    let mut roots = rustls::RootCertStore::empty();
    if let Ok(certs) = rustls_native_certs::load_native_certs() {
        roots.add_parsable_certificates(certs);
    }
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    for ip in ["99.86.18.30", "18.65.14.118"] {
        for n in [200usize, 2000] {
            let tcp = match tokio::net::TcpStream::connect(format!("{ip}:443")).await {
                Ok(t) => t,
                Err(e) => {
                    println!("[direct-control] ip={ip} body={n} TCP 失败: {e}");
                    continue;
                }
            };
            let mut tls = match connector
                .connect(
                    rustls::pki_types::ServerName::try_from(REAL.to_string()).unwrap(),
                    tcp,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    println!("[direct-control] ip={ip} body={n} TLS 失败: {e}");
                    continue;
                }
            };
            let (resp, ms) =
                post_h1_ex(&mut tls, REAL, "/api/figment-proxy/monitor", n, false, &[]).await;
            let first = resp.lines().next().unwrap_or("<空响应>").to_string();
            println!("[direct-control] ip={ip} body={n} 耗时={ms}ms 首行={first}");
        }
    }
}
