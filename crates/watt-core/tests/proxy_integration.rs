//! 集成测试：验证代理转发全链路。
//!
//! 覆盖场景：
//! 1. 明文 HTTP 反向代理（规则 destination + 路径/查询保留 + 逐跳头剥离）
//! 2. HTTP→HTTPS 301 重定向（EnableHttpProxyToHttps）
//! 3. 静态响应规则
//! 4. 本地域名服务（local.steampp.net status）
//! 5. 脚本注入端到端（HTML 响应注入 /WattToolkit_Inject/{lid}.js）
//! 6. MITM HTTPS 全链路（客户端 TLS 信任 CA → 动态叶子证书 → 明文上游）
//! 7. 出站 TLS（规则 tls_ignore_name_mismatch + ip_address 覆盖 + SNI）
//! 8. SOCKS5 入站隧道（规则 ip 覆盖直连）
//! 9. 引擎全栈编排（start → HTTP 监听 → 301 → stop）
//! 10. 服务端脚本钩子（Phase 4b）
//! 11. 正向代理（Phase 5）：CONNECT 纯隧道直连 / CONNECT MITM / 绝对 URI / PAC 端点

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::Request;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use watt_cert::ca::CaCertificate;
use watt_config::{DomainRule, DomainRuleFields, DomainRules, StaticResponse};
use watt_core::forward_proxy::run_forward_proxy_listener;
use watt_core::http_relay::RelayContext;
use watt_core::listener::{run_http_listener, run_mitm_listener, run_socks5_listener};
use watt_core::sni::mitm_tls_acceptor;
use watt_script::ScriptConfig;

// ———— 测试基础设施 ————

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 构造规则：匹配域名 + destination 前缀
fn rule_for(domain: &str, destination: Option<String>) -> DomainRule {
    DomainRule {
        match_domain_names: vec![domain.to_string()],
        fields: DomainRuleFields {
            destination,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn relay_ctx(rules: Vec<DomainRule>) -> Arc<RelayContext> {
    Arc::new(RelayContext::new(
        DomainRules::new(rules),
        watt_core::local_domain::LocalDomainHandler::new(vec![]),
        None,
    ))
}

/// 启动明文 HTTP 上游：响应 body + 请求 URI 回显（body 中 " uri=" 分隔）
async fn spawn_upstream(body: &'static str, content_type: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .header(hyper::header::CONTENT_TYPE, content_type)
                            .body(Full::new(Bytes::from(format!("{body} uri={}", req.uri()))))
                            .unwrap(),
                    )
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await;
            });
        }
    });
    addr
}

/// 启动 TLS 上游（复用 MITM acceptor 按 SNI 动态签发）
async fn spawn_tls_upstream(ca: Arc<CaCertificate>, body: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = mitm_tls_acceptor(ca);
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .header(hyper::header::CONTENT_TYPE, "text/plain")
                            .body(Full::new(Bytes::from(format!("{body} uri={}", req.uri()))))
                            .unwrap(),
                    )
                });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await;
            });
        }
    });
    addr
}

/// 启动测试代理 HTTP 监听，返回 (代理地址, 关闭句柄)
async fn spawn_http_proxy(
    ctx: Arc<RelayContext>,
) -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_http_listener(listener, ctx, rx));
    (addr, tx)
}

/// 原始 HTTP/1.1 GET 请求（Connection: close）
async fn raw_http_get(addr: SocketAddr, host: &str, path: &str, extra: &[(&str, &str)]) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    read_http_response(&mut stream).await
}

/// 读取完整 HTTP 响应（按 Content-Length 或 EOF 终止）
async fn read_http_response<R: AsyncReadExt + Unpin>(reader: &mut R) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // 读取头部
    loop {
        let n = reader.read(&mut chunk).await.unwrap();
        if n == 0 {
            return String::from_utf8_lossy(&buf).into_owned();
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
            let content_length = head.lines().find_map(|l| {
                l.strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            });
            match content_length {
                Some(0) => return String::from_utf8_lossy(&buf).into_owned(),
                Some(len) => {
                    // 继续读取至 body 完整
                    let total = pos + 4 + len;
                    while buf.len() < total {
                        let n = reader.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    return String::from_utf8_lossy(&buf).into_owned();
                }
                None => continue, // 无 Content-Length，读到 EOF
            }
        }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 信任指定 CA 的 TLS 客户端连接器（模拟已安装根证书的浏览器）
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

async fn with_timeout<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(std::time::Duration::from_secs(10), f)
        .await
        .expect("测试超时")
}

// ———— 1. 明文 HTTP 反向代理 ————

#[tokio::test]
async fn test_http_reverse_proxy_full_chain() {
    with_timeout(async {
        let upstream = spawn_upstream("upstream-ok", "text/plain").await;
        let rule = rule_for(
            "test.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let (proxy_addr, _shutdown) = spawn_http_proxy(relay_ctx(vec![rule])).await;

        let resp = raw_http_get(proxy_addr, "test.example.com", "/hello?x=1&y=2", &[]).await;

        // 状态行 200
        assert!(resp.starts_with("HTTP/1.1 200"), "响应状态行异常: {resp}");
        // 路径与查询完整保留到上游
        assert!(
            resp.contains("upstream-ok uri=/hello?x=1&y=2"),
            "路径/查询未保留: {resp}"
        );
    })
    .await;
}

// ———— 2. HTTP→HTTPS 重定向 ————

#[tokio::test]
async fn test_http_to_https_redirect() {
    with_timeout(async {
        let rule = rule_for("redirect.example.com", None);
        let mut ctx = RelayContext::new(
            DomainRules::new(vec![rule]),
            watt_core::local_domain::LocalDomainHandler::new(vec![]),
            None,
        );
        ctx.enable_http_to_https = true;
        let (proxy_addr, _shutdown) = spawn_http_proxy(Arc::new(ctx)).await;

        let resp = raw_http_get(proxy_addr, "redirect.example.com", "/page?q=1", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 302"), "应为 302: {resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains(&"location: https://redirect.example.com/page?q=1".to_ascii_lowercase()),
            "Location 头异常: {resp}"
        );
    })
    .await;
}

// ———— 3. 静态响应规则 ————

#[tokio::test]
async fn test_static_response_rule() {
    with_timeout(async {
        let rule = DomainRule {
            match_domain_names: vec!["static.example.com".to_string()],
            fields: DomainRuleFields {
                response: Some(StaticResponse {
                    status_code: 200,
                    body: "static-ok".to_string(),
                    headers: vec![("X-Custom".to_string(), "watt".to_string())],
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let (proxy_addr, _shutdown) = spawn_http_proxy(relay_ctx(vec![rule])).await;

        let resp = raw_http_get(proxy_addr, "static.example.com", "/anything", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(resp.contains("static-ok"), "静态响应体异常: {resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains(&"x-custom: watt".to_ascii_lowercase()),
            "自定义响应头缺失: {resp}"
        );
    })
    .await;
}

// ———— 4. 本地域名服务 ————

#[tokio::test]
async fn test_local_domain_status() {
    with_timeout(async {
        let (proxy_addr, _shutdown) = spawn_http_proxy(relay_ctx(vec![])).await;

        let resp = raw_http_get(
            proxy_addr,
            "local.steampp.net",
            "/",
            &[("requestType", "status")],
        )
        .await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(resp.ends_with("OK"), "status 响应体应为 OK: {resp}");
    })
    .await;
}

// ———— 5. 脚本注入端到端 ————

#[tokio::test]
async fn test_script_injection_end_to_end() {
    with_timeout(async {
        // 脚本缓存文件
        let dir = std::env::temp_dir().join(format!("watt-core-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script_path = dir.join("421.js");
        std::fs::write(&script_path, "// injected test script").unwrap();

        let upstream = spawn_upstream(
            "<html><head></head><body>store page</body></html>",
            "text/html; charset=utf-8",
        )
        .await;
        let rule = rule_for(
            "inject.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let script = ScriptConfig {
            local_id: "421".to_string(),
            cache_path: script_path.to_string_lossy().to_string(),
            match_domain_names: vec!["inject.example.com".to_string()],
            exclude_domain_names: vec![],
            order: 0,
        };
        let ctx = Arc::new(RelayContext::new(
            DomainRules::new(vec![rule]),
            watt_core::local_domain::LocalDomainHandler::new(vec![script]),
            None,
        ));
        let (proxy_addr, _shutdown) = spawn_http_proxy(ctx).await;

        let resp = raw_http_get(proxy_addr, "inject.example.com", "/store", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(
            resp.contains(r#"src="/WattToolkit_Inject/421.js""#),
            "注入标签缺失: {resp}"
        );
        assert!(resp.contains("store page"), "原内容缺失: {resp}");

        // 注入脚本可通过本地路径获取（local_domain 脚本文件服务）
        let script_resp = raw_http_get(
            proxy_addr,
            "inject.example.com",
            "/WattToolkit_Inject/421.js",
            &[],
        )
        .await;
        assert!(
            script_resp.contains("// injected test script"),
            "脚本内容服务异常: {script_resp}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    })
    .await;
}

// ———— 6. MITM HTTPS 全链路 ————

#[tokio::test]
async fn test_mitm_https_chain() {
    with_timeout(async {
        let upstream = spawn_upstream("secure-ok", "text/plain").await;
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let rule = rule_for(
            "secure.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let ctx = relay_ctx(vec![rule]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(run_mitm_listener(
            listener,
            ctx,
            mitm_tls_acceptor(ca.clone()),
            shutdown_rx,
        ));

        // 客户端 TLS（信任 CA，SNI = 域名）
        let connector = ca_trusting_connector(&ca);
        let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("secure.example.com".to_string()).unwrap(),
                tcp,
            )
            .await
            .expect("MITM TLS 握手失败（叶子证书签发异常）");

        let req = "GET /doc?v=2 HTTP/1.1\r\nHost: secure.example.com\r\nConnection: close\r\n\r\n";
        tls.write_all(req.as_bytes()).await.unwrap();
        let resp = read_http_response(&mut tls).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(
            resp.contains("secure-ok uri=/doc?v=2"),
            "MITM 转发链路异常: {resp}"
        );
        shutdown_tx.send_replace(true);
    })
    .await;
}

// ———— 7. 出站 TLS（上游 HTTPS）————

#[tokio::test]
async fn test_outbound_tls_chain() {
    with_timeout(async {
        let upstream_ca = Arc::new(CaCertificate::generate().unwrap());
        let upstream = spawn_tls_upstream(upstream_ca, "tls-ok").await;

        // 规则：destination 指向域名（携带 SNI），ip_address 覆盖为本地，忽略证书校验
        let rule = DomainRule {
            match_domain_names: vec!["tls.example.com".to_string()],
            fields: DomainRuleFields {
                destination: Some(format!("https://upstream.example.com:{}/", upstream.port())),
                ip_address: Some("127.0.0.1".parse().unwrap()),
                tls_ignore_name_mismatch: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let (proxy_addr, _shutdown) = spawn_http_proxy(relay_ctx(vec![rule])).await;

        let resp = raw_http_get(proxy_addr, "tls.example.com", "/secure-path", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(
            resp.contains("tls-ok uri=/secure-path"),
            "出站 TLS 链路异常: {resp}"
        );
    })
    .await;
}

// ———— 8. SOCKS5 入站隧道 ————

#[tokio::test]
async fn test_socks5_tunnel() {
    with_timeout(async {
        let upstream = spawn_upstream("socks-ok", "text/plain").await;
        // 规则：ip 覆盖为 127.0.0.1（SOCKS5 目标域名按规则 IP 直连）
        let rule = DomainRule {
            match_domain_names: vec!["socks.example.com".to_string()],
            fields: DomainRuleFields {
                ip_address: Some("127.0.0.1".parse().unwrap()),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = relay_ctx(vec![rule]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(run_socks5_listener(listener, ctx, shutdown_rx));

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

        // SOCKS5 握手（无认证）
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00], "SOCKS5 握手失败");

        // CONNECT socks.example.com:upstream_port（域名远程解析形式）
        let host = b"socks.example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&upstream.port().to_be_bytes());
        stream.write_all(&req).await.unwrap();
        let mut resp_head = [0u8; 10];
        stream.read_exact(&mut resp_head).await.unwrap();
        assert_eq!(resp_head[1], 0x00, "SOCKS5 CONNECT 失败");

        // 隧道内发送 HTTP
        stream
            .write_all(
                b"GET /tunnel HTTP/1.1\r\nHost: socks.example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let resp = read_http_response(&mut stream).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(
            resp.contains("socks-ok uri=/tunnel"),
            "SOCKS5 隧道转发异常: {resp}"
        );
        shutdown_tx.send_replace(true);
    })
    .await;
}

// ———— 9. 引擎全栈 ————

#[tokio::test]
async fn test_engine_full_stack_http() {
    use watt_core::{EngineConfig, EngineState, ProxyEngine};

    with_timeout(async {
        let https_port = free_port();
        let http_port = free_port();
        let mut engine = ProxyEngine::new();
        engine
            .start(EngineConfig {
                https_port,
                http_port: Some(http_port),
                enable_http_to_https: true,
                rules: vec![rule_for("engine.example.com", None)],
                ..Default::default()
            })
            .await
            .unwrap();

        assert!(matches!(engine.state(), EngineState::Running { .. }));

        let resp = raw_http_get(
            SocketAddr::from(([127, 0, 0, 1], http_port)),
            "engine.example.com",
            "/index",
            &[],
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 302"), "应为 302: {resp}");

        engine.stop().await.unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
    })
    .await;
}

// ———— 10. 服务端脚本钩子（Phase 4b）————

/// 构造钩子脚本（写入临时缓存文件）
fn hook_script(source: &str, domain: &str) -> ScriptConfig {
    let dir = std::env::temp_dir().join(format!(
        "watt-core-hook-{}-{}",
        std::process::id(),
        domain.replace('.', "-")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("script.js");
    std::fs::write(&path, source).unwrap();
    ScriptConfig {
        local_id: format!("hook-{domain}"),
        cache_path: path.to_string_lossy().to_string(),
        match_domain_names: vec![domain.to_string()],
        exclude_domain_names: vec![],
        order: 0,
    }
}

/// 构造带钩子引擎的 RelayContext（脚本同时参与注入匹配与钩子执行）
fn hook_ctx(rule: DomainRule, script: ScriptConfig) -> Arc<RelayContext> {
    let mut ctx = RelayContext::new(
        DomainRules::new(vec![rule]),
        watt_core::local_domain::LocalDomainHandler::new(vec![script.clone()]),
        None,
    );
    ctx.hooks = Some(Arc::new(watt_script::hooks::HookEngine::new(
        &[script],
        None,
    )));
    Arc::new(ctx)
}

#[tokio::test]
async fn test_hook_on_request_modify_url() {
    with_timeout(async {
        let upstream = spawn_upstream("hook-upstream", "text/plain").await;
        let rule = rule_for(
            "hook-mod.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let script = hook_script(
            r#"
            function onRequest(ctx) {
                if (ctx.url.indexOf("/original") >= 0) {
                    return { url: ctx.url.replace("/original", "/rewritten") };
                }
            }
            "#,
            "hook-mod.example.com",
        );
        let (proxy_addr, _shutdown) = spawn_http_proxy(hook_ctx(rule, script)).await;

        let resp = raw_http_get(proxy_addr, "hook-mod.example.com", "/original?q=1", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(
            resp.contains("uri=/rewritten?q=1"),
            "onRequest 未改写转发路径: {resp}"
        );
    })
    .await;
}

#[tokio::test]
async fn test_hook_on_request_block() {
    with_timeout(async {
        let upstream = spawn_upstream("should-not-reach", "text/plain").await;
        let rule = rule_for(
            "hook-block.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let script = hook_script(
            r#"
            function onRequest(ctx) {
                return { block: 403, body: "blocked-by-hook" };
            }
            "#,
            "hook-block.example.com",
        );
        let (proxy_addr, _shutdown) = spawn_http_proxy(hook_ctx(rule, script)).await;

        let resp = raw_http_get(proxy_addr, "hook-block.example.com", "/secret", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 403"), "应为 403: {resp}");
        assert!(resp.contains("blocked-by-hook"), "Block 响应体异常: {resp}");
    })
    .await;
}

#[tokio::test]
async fn test_hook_on_response_modify_body() {
    with_timeout(async {
        let upstream = spawn_upstream("original-body", "text/plain").await;
        let rule = rule_for(
            "hook-resp.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let script = hook_script(
            r#"
            function onResponse(ctx) {
                return { body: ctx.body + "|hooked" };
            }
            "#,
            "hook-resp.example.com",
        );
        let (proxy_addr, _shutdown) = spawn_http_proxy(hook_ctx(rule, script)).await;

        let resp = raw_http_get(proxy_addr, "hook-resp.example.com", "/", &[]).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "状态异常: {resp}");
        assert!(
            resp.contains("original-body uri=/|hooked"),
            "onResponse 未修改响应体: {resp}"
        );
    })
    .await;
}

#[tokio::test]
async fn test_hook_error_degrades_to_passthrough() {
    with_timeout(async {
        let upstream = spawn_upstream("degrade-ok", "text/plain").await;
        let rule = rule_for(
            "hook-err.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let script = hook_script(
            "function onRequest(ctx) { throw new Error('boom'); }",
            "hook-err.example.com",
        );
        let (proxy_addr, _shutdown) = spawn_http_proxy(hook_ctx(rule, script)).await;

        let resp = raw_http_get(proxy_addr, "hook-err.example.com", "/pass", &[]).await;

        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "脚本异常应降级放行: {resp}"
        );
        assert!(
            resp.contains("degrade-ok uri=/pass"),
            "降级后转发异常: {resp}"
        );
    })
    .await;
}

// ———— 11. 正向代理（Phase 5：System/PAC/ProxyOnly 模式）————

/// 启动正向代理监听，返回 (代理地址, 关闭句柄)
async fn spawn_forward_proxy(
    ctx: Arc<RelayContext>,
    ca: Arc<CaCertificate>,
    proxy_authority: &str,
) -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(run_forward_proxy_listener(
        listener,
        ctx,
        mitm_tls_acceptor(ca),
        proxy_authority.to_string(),
        rx,
    ));
    (addr, tx)
}

/// 读取 CONNECT 响应头（至空行）
async fn read_connect_response(stream: &mut tokio::net::TcpStream) -> String {
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

/// CONNECT 未匹配域名：纯隧道直连（不 MITM，字节透传）
#[tokio::test]
async fn test_forward_proxy_connect_tunnel_direct() {
    with_timeout(async {
        let upstream = spawn_upstream("tunnel-direct", "text/plain").await;
        // 无匹配规则 → 不 MITM，纯隧道
        let ctx = relay_ctx(vec![]);
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let (proxy_addr, _shutdown) = spawn_forward_proxy(ctx, ca, "127.0.0.1:26501").await;

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    upstream.port(),
                    upstream.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        let resp = read_connect_response(&mut stream).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "CONNECT 应回 200: {resp}");

        // 隧道内明文 HTTP 直达上游（字节透传）
        stream
            .write_all(b"GET /via-tunnel HTTP/1.1\r\nHost: anything\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let http_resp = read_http_response(&mut stream).await;
        assert!(
            http_resp.starts_with("HTTP/1.1 200"),
            "隧道转发异常: {http_resp}"
        );
        assert!(
            http_resp.contains("tunnel-direct uri=/via-tunnel"),
            "隧道内容异常: {http_resp}"
        );
    })
    .await;
}

/// CONNECT 匹配域名：MITM（客户端信任代理 CA → 动态叶子证书 → http_relay 转发）
#[tokio::test]
async fn test_forward_proxy_connect_mitm() {
    with_timeout(async {
        let upstream = spawn_upstream("fwd-mitm-ok", "text/plain").await;
        let rule = rule_for(
            "fwd-mitm.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let ctx = relay_ctx(vec![rule]);
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let (proxy_addr, _shutdown) = spawn_forward_proxy(ctx, ca.clone(), "127.0.0.1:26501").await;

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(b"CONNECT fwd-mitm.example.com:443 HTTP/1.1\r\nHost: fwd-mitm.example.com:443\r\n\r\n")
            .await
            .unwrap();
        let resp = read_connect_response(&mut stream).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "CONNECT 应回 200: {resp}");

        // 客户端 TLS（信任代理 CA；若走纯隧道则握手对象为真实上游而失败）
        let connector = ca_trusting_connector(&ca);
        let tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("fwd-mitm.example.com".to_string())
                    .unwrap(),
                stream,
            )
            .await
            .expect("MITM TLS 握手失败");

        let req = "GET /mitm-path?q=1 HTTP/1.1\r\nHost: fwd-mitm.example.com\r\nConnection: close\r\n\r\n";
        let mut tls = tls;
        tls.write_all(req.as_bytes()).await.unwrap();
        let resp = read_http_response(&mut tls).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "MITM 转发异常: {resp}");
        assert!(
            resp.contains("fwd-mitm-ok uri=/mitm-path?q=1"),
            "MITM 链路内容异常: {resp}"
        );
    })
    .await;
}

/// 绝对 URI 请求（`GET http://host/path`）：origin-form 改写 → http_relay 转发
#[tokio::test]
async fn test_forward_proxy_absolute_uri() {
    with_timeout(async {
        let upstream = spawn_upstream("abs-uri-ok", "text/plain").await;
        let rule = rule_for(
            "abs.example.com",
            Some(format!("http://127.0.0.1:{}/", upstream.port())),
        );
        let ctx = relay_ctx(vec![rule]);
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let (proxy_addr, _shutdown) = spawn_forward_proxy(ctx, ca, "127.0.0.1:26501").await;

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(
                b"GET http://abs.example.com/abs/path?k=v HTTP/1.1\r\nHost: abs.example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let resp = read_http_response(&mut stream).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "绝对 URI 转发异常: {resp}");
        assert!(
            resp.contains("abs-uri-ok uri=/abs/path?k=v"),
            "origin-form 改写异常: {resp}"
        );
    })
    .await;
}

/// PAC 端点：裸路径请求 → PAC 脚本下发（规则 + 脚本域名 + 本地域名）
#[tokio::test]
async fn test_forward_proxy_pac_endpoint() {
    with_timeout(async {
        let rule = DomainRule {
            match_domain_names: vec!["pacrule.example.com".to_string()],
            ..Default::default()
        };
        let script = ScriptConfig {
            local_id: "pac-s".to_string(),
            cache_path: "/tmp/pac-s.js".to_string(),
            match_domain_names: vec!["pacscript.example.com".to_string()],
            exclude_domain_names: vec![],
            order: 0,
        };
        let ctx = Arc::new(RelayContext::new(
            DomainRules::new(vec![rule]),
            watt_core::local_domain::LocalDomainHandler::new(vec![script]),
            None,
        ));
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let (proxy_addr, _shutdown) = spawn_forward_proxy(ctx, ca, "127.0.0.1:26501").await;

        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(b"GET /pac HTTP/1.1\r\nHost: 127.0.0.1:26501\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let resp = read_http_response(&mut stream).await;

        assert!(resp.starts_with("HTTP/1.1 200"), "PAC 端点异常: {resp}");
        assert!(
            resp.to_ascii_lowercase()
                .contains(&"content-type: application/x-ns-proxy-autoconfig".to_ascii_lowercase()),
            "PAC Content-Type 异常: {resp}"
        );
        assert!(
            resp.contains("var pac = 'PROXY 127.0.0.1:26501';"),
            "{resp}"
        );
        assert!(
            resp.contains("shExpMatch(host, 'pacrule.example.com')"),
            "规则域名缺失: {resp}"
        );
        assert!(
            resp.contains("shExpMatch(host, 'pacscript.example.com')"),
            "脚本域名缺失: {resp}"
        );
        assert!(
            resp.contains(&format!(
                "shExpMatch(host, '{}')",
                watt_config::constants::LOCAL_DOMAIN
            )),
            "本地域名缺失: {resp}"
        );
        assert!(resp.contains("return 'DIRECT';"), "{resp}");
    })
    .await;
}

// ———— 12. HTTP/2 经 MITM（浏览器真实协商结果）————

/// HTTP/2 没有 `Host` 头，目标主机只存在于 `:authority` 伪头（hyper 映射到 `uri.authority()`）。
///
/// 回归缺陷：`handle_request` 原先只读 `Host` 头，浏览器（ALPN 协商 h2）的请求因此得到空
/// host → 域名规则失配且不满足 default 规则的 `host.contains('.')` 判定 → 回落
/// `not_found_response()`（404 + 空 body）。Chromium 会把「404 + 空 body」渲染成自己的
/// 错误页「找不到此 <域名> 页 / HTTP ERROR 404」，症状是加速后所有网站都打不开，
/// 而 curl（该构建不含 h2，只能走 HTTP/1.1）却一直正常 —— 极难定位。
#[tokio::test]
async fn test_forward_proxy_mitm_http2_authority_without_host_header() {
    with_timeout(async {
        let rule = DomainRule {
            match_domain_names: vec!["h2.example.com".to_string()],
            fields: DomainRuleFields {
                response: Some(StaticResponse {
                    status_code: 200,
                    body: "h2-ok".to_string(),
                    headers: vec![],
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = relay_ctx(vec![rule]);
        let ca = Arc::new(CaCertificate::generate().unwrap());
        let (proxy_addr, _shutdown) = spawn_forward_proxy(ctx, ca.clone(), "127.0.0.1:26501").await;

        // 1) CONNECT 建隧道
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        stream
            .write_all(b"CONNECT h2.example.com:443 HTTP/1.1\r\nHost: h2.example.com:443\r\n\r\n")
            .await
            .unwrap();
        let connect_resp = read_connect_response(&mut stream).await;
        assert!(
            connect_resp.starts_with("HTTP/1.1 200"),
            "CONNECT 应回 200: {connect_resp}"
        );

        // 2) TLS 握手：ALPN 只给 h2，强制 HTTP/2（与浏览器一致）
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                ca.cert_der.clone(),
            ))
            .unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from("h2.example.com").unwrap();
        let tls = connector.connect(name, stream).await.unwrap();
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(&b"h2"[..]),
            "应协商为 h2"
        );

        // 3) HTTP/2 请求：uri 携带 authority，客户端不会发送 Host 头
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(tls),
        )
        .await
        .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .uri("https://h2.example.com/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(
            resp.status(),
            200,
            "HTTP/2 经 MITM 应按域名规则返回 200（修复前为 404 空页）"
        );
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"h2-ok");
    })
    .await;
}
