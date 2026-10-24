//! 微软服务出站诊断（需真实网络，默认 ignore）：
//! `cargo test -p watt-core --test diag_microsoft -- --ignored --nocapture`
//!
//! 复现反代真实出站路径（DNS-only：无覆盖 IP、无 forward_destination），
//! 逐候选区分 TCP/TLS/HTTP 可达性，定位 `转发失败: 请求失败: connection error`。

use std::sync::Arc;
use std::time::Instant;

use watt_core::http_relay::RelayDnsAdapter;
use watt_core::outbound::{OutboundConnector, OutboundTarget};

fn target(host: &str) -> OutboundTarget {
    OutboundTarget {
        host: host.to_string(),
        port: 443,
        tls: true,
        tls_sni: None,
        tls_ignore_name_mismatch: false,
        tls_skip_verify: false,
        override_ip: None, // DNS-only，对齐微软内置分组
        forward_destination: None,
        timeout_ms: Some(15000),
    }
}

#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_login_live_outbound() {
    let host = "login.live.com";

    // 1) resolve_clean 实际拿到的候选（含 IPv6）
    let resolver = Arc::new(watt_dns::DnsResolver::system());
    let dns = Arc::new(RelayDnsAdapter(resolver.clone()));
    let clean = resolver.resolve_clean(host).await.unwrap_or_default();
    println!("[diag] resolve_clean({host}) = {clean:?}");
    let sys = resolver.resolve(host).await.unwrap_or_default();
    println!("[diag] resolve({host})       = {sys:?}");

    // 2) 逐候选 TCP+TLS+HTTP 健康度
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use watt_core::sni::{outbound_tls_connector, server_name, OutboundVerify};
    let connector = outbound_tls_connector(OutboundVerify::Standard, None);
    let name = server_name(host).unwrap();
    for ip in &clean {
        let addr = std::net::SocketAddr::new(*ip, 443);
        let t0 = Instant::now();
        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            tokio::net::TcpStream::connect(addr),
        )
        .await;
        let stream = match tcp {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                println!("  {addr:<28} TCP ✗ ({e})");
                continue;
            }
            Err(_) => {
                println!("  {addr:<28} TCP ✗ (timeout)");
                continue;
            }
        };
        let tcp_ms = t0.elapsed().as_millis();
        let t1 = Instant::now();
        let tls = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            connector.connect(name.clone(), stream),
        )
        .await;
        let mut s = match tls {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                println!("  {addr:<28} TCP ✓({tcp_ms}ms) TLS ✗ ({e})");
                continue;
            }
            Err(_) => {
                println!("  {addr:<28} TCP ✓({tcp_ms}ms) TLS ✗ (timeout)");
                continue;
            }
        };
        let tls_ms = t1.elapsed().as_millis();
        let _ = s
            .write_all(b"GET / HTTP/1.1\r\nHost: login.live.com\r\nConnection: close\r\n\r\n")
            .await;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(6), s.read(&mut buf))
            .await
            .unwrap_or(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timeout",
            )))
            .unwrap_or(0);
        let line = String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!("  {addr:<28} TCP ✓({tcp_ms}ms) TLS ✓({tls_ms}ms) HTTP read={n} [{line}]");
    }

    // 3) 完整反代路径：connect_tracked + http1 handshake + send_request
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Request;
    let ob = OutboundConnector::new(dns.clone(), None);
    let t0 = Instant::now();
    let (stream, winner) = match ob.connect_tracked(&target(host)).await {
        Ok(v) => v,
        Err(e) => {
            println!("[diag] (3) connect_tracked 失败: {e} (耗时 {:?})", t0.elapsed());
            return;
        }
    };
    println!("[diag] (3) connect ok winner={winner:?} in {:?}", t0.elapsed());
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(v) => v,
        Err(e) => {
            println!("[diag] (3) http1 handshake 失败: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri("/")
        .header("Host", host)
        .header("User-Agent", "Mozilla/5.0")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let t1 = Instant::now();
    match sender.send_request(req).await {
        Ok(resp) => println!("[diag] (3) HTTP {} in {:?}", resp.status(), t1.elapsed()),
        Err(e) => println!(
            "[diag] (3) send_request 失败: {e} | incomplete={} closed={} (耗时 {:?})",
            e.is_incomplete_message(),
            e.is_closed(),
            t1.elapsed()
        ),
    }
}

/// 浏览器真实路径：System 代理下浏览器与我们 MITM 协商 ALPN 选 **h2**，
/// 入站 HTTP/2 → relay → 出站 http1。复现完整链路（生产规则）。
#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_login_live_via_mitm_http2() {
    let ca = Arc::new(watt_cert::ca::CaCertificate::generate().unwrap());
    let group = watt_cloud::builtin::microsoft_services_group();
    let ids: Vec<String> = group.items.iter().map(|i| i.id.clone()).collect();
    let catalog = watt_cloud::model::AccelerateCatalog::new(vec![group]);
    let rules = catalog.to_domain_rules(Some(&ids));
    println!("[diag-h2] 微软分组展平规则数 = {}", rules.len());

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

    for host in ["login.live.com", "login.microsoftonline.com", "outlook.live.com"] {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
                tcp,
            )
            .await
            .expect("MITM 握手失败");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "应协商为 h2");
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
            .uri(format!("https://{host}/"))
            .header(hyper::header::USER_AGENT, "watt-diag-h2")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .unwrap();
        let t0 = Instant::now();
        match tokio::time::timeout(std::time::Duration::from_secs(30), sender.send_request(req)).await
        {
            Ok(Ok(r)) => println!("[diag-h2] {host} :status={} in {:?}", r.status(), t0.elapsed()),
            Ok(Err(e)) => println!("[diag-h2] {host} send_request 失败: {e} (耗时 {:?})", t0.elapsed()),
            Err(_) => println!("[diag-h2] {host} send_request 超时 30s"),
        }
    }
}
