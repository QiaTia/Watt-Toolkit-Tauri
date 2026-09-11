//! 出站层诊断（需真实网络，默认 ignore）：
//! `cargo test -p watt-core --test diag_outbound -- --ignored --nocapture`

use std::sync::Arc;
use std::time::Instant;

use watt_core::outbound::{OutboundTarget, OutboundConnector};

fn target(override_ip: Option<&str>) -> OutboundTarget {
    OutboundTarget {
        host: "github.com".to_string(),
        port: 443,
        tls: true,
        tls_sni: None,
        tls_ignore_name_mismatch: false,
        override_ip: override_ip.map(|s| s.parse().unwrap()),
        forward_destination: None,
        timeout_ms: None,
    }
}

#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_github_outbound() {
    // 1) 备用 IP 池是否命中
    let fb = watt_core::fallback::fallback_ips("github.com");
    println!("[diag] fallback_ips(github.com) = {fb:?}");
    assert!(!fb.is_empty(), "fallback 池为空 → 匹配失败");

    let dns = Arc::new(watt_core::http_relay::RelayDnsAdapter(Arc::new(
        watt_dns::DnsResolver::system(),
    )));

    // 2) 纯 DNS 路径（覆盖 IP = None）
    for (name, ov) in [("无覆盖IP", None), ("带失效覆盖IP 20.207.73.82", Some("20.207.73.82"))] {
        let ob = OutboundConnector::new(dns.clone(), None);
        let t0 = Instant::now();
        let r = ob.connect(&target(ov)).await;
        println!(
            "[diag] {name}: ok={} elapsed={:?} err={:?}",
            r.is_ok(),
            t0.elapsed(),
            r.as_ref().err().map(|e| e.to_string())
        );
    }

    // 3) 默认超时值确认
    let ob = OutboundConnector::new(dns.clone(), None);
    let t0 = Instant::now();
    let _ = ob.connect(&target(None)).await;
    println!("[diag] 单次 connect 总耗时 = {:?}", t0.elapsed());

    // 4) 复现反代真实路径：connect 成功后用 hyper http1 发一个 GET /
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Request;

    let ob = OutboundConnector::new(dns.clone(), None);
    let t0 = Instant::now();
    let stream = match ob.connect(&target(Some("20.207.73.82"))).await {
        Ok(s) => s,
        Err(e) => {
            println!("[diag] (4) connect 失败: {e}");
            return;
        }
    };
    println!("[diag] (4) connect ok in {:?}", t0.elapsed());

    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(v) => v,
        Err(e) => {
            println!("[diag] (4) http1 handshake 失败: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .header("Host", "github.com")
        .header("User-Agent", "Mozilla/5.0")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let t1 = Instant::now();
    match sender.send_request(req).await {
        Ok(resp) => println!("[diag] (4) HTTP {} in {:?}", resp.status(), t1.elapsed()),
        Err(e) => println!("[diag] (4) send_request 失败: {e} (耗时 {:?})", t1.elapsed()),
    }
}

/// 候选健康度矩阵：区分「TCP 可达」与「TLS 可达」。
///
/// 这是 github.com 类「加速无效」故障的判据。若多数候选 **TCP 可达但 TLS 不可达**，
/// 那么任何以「TCP 握手成功」为胜出条件的竞速都必然选中死候选 → 20s 超时 / 500。
/// 正确做法是按 TLS 竞速（`outbound::race_tls`）。实测 github.com 12 个候选中
/// 仅 1 个能完成 TLS 握手，正是该形态。
#[tokio::test]
#[ignore = "需要真实网络"]
async fn diag_candidate_health_github() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use watt_core::sni::{outbound_tls_connector, server_name, OutboundVerify};

    let dns = watt_dns::DnsResolver::system();
    let mut addrs: Vec<std::net::SocketAddr> = Vec::new();
    if let Ok(ips) = dns.resolve("github.com").await {
        addrs.extend(
            ips.into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, 443)),
        );
    }
    addrs.extend(
        watt_core::fallback::fallback_ips("github.com")
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, 443)),
    );

    let total = addrs.len();
    let connector = outbound_tls_connector(OutboundVerify::SkipAll, None);
    let name = server_name("github.com").unwrap();

    println!("[health] github.com 候选 {total} 个:");
    let (mut tcp_ok, mut tls_ok) = (0usize, 0usize);
    for addr in addrs {
        let t0 = Instant::now();
        let stream = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => Some(s),
            _ => None,
        };
        let tcp_ms = t0.elapsed().as_millis();
        let Some(stream) = stream else {
            println!("  {addr:<22} TCP ✗ ({tcp_ms}ms)");
            continue;
        };
        tcp_ok += 1;

        let t1 = Instant::now();
        match tokio::time::timeout(
            std::time::Duration::from_secs(6),
            connector.connect(name.clone(), stream),
        )
        .await
        {
            Ok(Ok(mut s)) => {
                tls_ok += 1;
                let _ = s
                    .write_all(b"HEAD / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n")
                    .await;
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                println!(
                    "  {addr:<22} TCP ✓ ({tcp_ms}ms)  TLS ✓ ({}ms)  {line}",
                    t1.elapsed().as_millis()
                );
            }
            _ => println!(
                "  {addr:<22} TCP ✓ ({tcp_ms}ms)  TLS ✗ ({}ms)",
                t1.elapsed().as_millis()
            ),
        }
    }
    println!("[health] TCP 可达 {tcp_ok}/{total} · TLS 可达 {tls_ok}/{total}");
    println!("[health] TCP 可达 ≫ TLS 可达 ⇒ 必须按 TLS 竞速（outbound::race_tls）");
}
