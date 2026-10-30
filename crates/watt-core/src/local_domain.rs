//! 本地域名服务：local.steampp.net 与 /WattToolkit_Inject/ 路径。
//! 对齐 HttpLocalRequestMiddleware。
//!
//! 功能：
//! - `/WattToolkit_Inject/{lid}.js` → 脚本文件内容（application/javascript）
//! - `local.steampp.net` OPTIONS → CORS 预检
//! - `requestType: status` → "OK"
//! - `requestType: xhr` → XHR 桥（转发请求至目标 URL，还原 `-steamtool` 后缀头）
//! - `/{lid}` → 脚本内容（兼容路径）

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use watt_script::ScriptConfig;

/// XHR 桥请求/响应体上限（防内存放大）
const MAX_XHR_BODY: usize = 8 * 1024 * 1024;
/// XHR 桥目标解析超时（DNS 可能被恶意/异常目标拖慢，必须独立限时）
const XHR_DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// XHR 桥整体超时（连接 + 请求 + 读响应），防止慢目标长期占用连接
const XHR_TIMEOUT: Duration = Duration::from_secs(30);

/// XHR 桥响应处理
pub struct LocalDomainHandler {
    scripts: Vec<ScriptConfig>,
    /// 脚本内容缓存（lid → JS 内容）
    script_contents: HashMap<String, String>,
}

impl LocalDomainHandler {
    pub fn new(scripts: Vec<ScriptConfig>) -> Self {
        let mut script_contents = HashMap::new();
        for s in &scripts {
            // 读取脚本文件内容（缓存）
            match std::fs::read_to_string(&s.cache_path) {
                Ok(content) => {
                    script_contents.insert(s.local_id.clone(), content);
                }
                Err(e) => {
                    tracing::warn!("脚本文件读取失败 {}: {e}", s.cache_path);
                }
            }
        }
        Self {
            scripts,
            script_contents,
        }
    }

    pub fn scripts(&self) -> &[ScriptConfig] {
        &self.scripts
    }

    /// 是否处理该请求（Host 为 local.steampp.net 或路径为注入前缀）
    pub fn should_handle(host: &str, path: &str) -> bool {
        host.eq_ignore_ascii_case(watt_config::constants::LOCAL_DOMAIN)
            || starts_with_ignore_case(path, watt_config::constants::INJECT_SCRIPT_PATH_PREFIX)
    }

    /// 处理本地请求
    pub async fn handle<B>(&self, req: Request<B>, host: &str) -> Response<Full<Bytes>>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // 1. 注入脚本路径 /WattToolkit_Inject/{lid}.js
        if let Some(lid) = extract_inject_script_lid(&path) {
            return self.handle_script_request(&lid);
        }

        // 2. 仅 local.steampp.net 域
        if host.eq_ignore_ascii_case(watt_config::constants::LOCAL_DOMAIN) {
            let request_type = req
                .headers()
                .get("requestType")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();

            // 存活检查无副作用，保留给注入脚本/诊断使用
            if request_type == "status" {
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from_static(b"OK")))
                    .unwrap_or_else(|_| internal_error());
            }

            // 其余入口（含 XHR 桥与预检）都服务于注入脚本：
            // 脚本为空时整体关闭，避免任意网页借无鉴权桥读取内网响应。
            if self.scripts.is_empty() {
                return not_found();
            }

            // CORS 预检：只接受被脚本匹配域名覆盖的 http(s) 来源
            if method == Method::OPTIONS {
                let Some(origin) = self.allowed_origin(&req) else {
                    return forbidden();
                };
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("Access-Control-Allow-Origin", origin)
                    .header("Access-Control-Allow-Headers", "*")
                    .header("Access-Control-Allow-Methods", "*")
                    .header("Access-Control-Allow-Credentials", "true")
                    .header("Vary", "Origin")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|_| internal_error());
            }

            match request_type.as_str() {
                "xhr" => self.handle_xhr(req).await,
                _ => {
                    // 默认：路径为 /{lid} 的脚本请求
                    let lid = path.trim_matches('/');
                    if !lid.is_empty() && lid.bytes().all(|b| b.is_ascii_digit()) && lid != "0" {
                        self.handle_script_request(lid)
                    } else {
                        not_found()
                    }
                }
            }
        } else {
            not_found()
        }
    }

    fn handle_script_request(&self, lid: &str) -> Response<Full<Bytes>> {
        if let Some(content) = self.script_contents.get(lid) {
            if !content.is_empty() {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        hyper::header::CONTENT_TYPE,
                        "application/javascript;charset=UTF-8",
                    )
                    .body(Full::new(Bytes::from(content.clone())))
                    .unwrap_or_else(|_| internal_error());
            }
        }
        not_found()
    }

    /// XHR 桥：querystring 为 "?request={urlencoded}"
    async fn handle_xhr<B>(&self, req: Request<B>) -> Response<Full<Bytes>>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let method = req.method().clone();
        let headers = req.headers().clone();
        let Some(origin) = self.allowed_origin(&req) else {
            return forbidden();
        };
        let (parts, body) = req.into_parts();

        // 解析目标 URL
        let query = parts.uri.query().unwrap_or_default();
        let Some(url) = query.strip_prefix("request=") else {
            return bad_request("缺少 request 参数");
        };
        let url = urlencoding::decode(url)
            .map(|s| s.to_string())
            .unwrap_or_default();
        let target: hyper::Uri = match url.parse() {
            Ok(u) => u,
            Err(_) => return bad_request("无效的 URL"),
        };
        if !matches!(target.scheme_str(), Some("http") | Some("https")) {
            return bad_request("仅支持 http/https 目标");
        }

        // 仅支持 GET / POST（对齐原实现）；POST 需带非空 body（Content-Length > 0）
        let is_get = method == Method::GET;
        let is_post = method == Method::POST;
        let content_length = headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if content_length.is_some_and(|n| n > MAX_XHR_BODY as u64) {
            return bad_request("请求体超过上限");
        }
        let has_body = content_length.is_some_and(|n| n > 0);
        if !(is_get || (is_post && has_body)) {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Access-Control-Allow-Origin", origin)
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| internal_error());
        }

        // 还原 -steamtool 后缀头
        let mut forward_headers = HeaderMap::new();
        for (name, value) in headers.iter() {
            let lower = name.as_str().to_ascii_lowercase();
            if lower.ends_with("-steamtool") {
                let real_name = &lower[..lower.len() - "-steamtool".len()];
                // cookie/referer 特判：原实现将 cookie 加入 CookieContainer、referer 解析 URI
                if real_name == "cookie" || real_name == "referer" {
                    if let Ok(v) = HeaderValue::to_str(value) {
                        if let (Ok(name), Ok(hv)) = (
                            HeaderName::from_bytes(real_name.as_bytes()),
                            HeaderValue::from_str(v),
                        ) {
                            forward_headers.insert(name, hv);
                        }
                    }
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(real_name.as_bytes()) {
                    forward_headers.insert(name, value.clone());
                }
            }
        }
        // UserAgent 原样传递
        if let Some(ua) = headers.get(hyper::header::USER_AGENT) {
            forward_headers.insert(hyper::header::USER_AGENT, ua.clone());
        }

        // 目标地址校验：只允许公网地址，防止任意网页借桥访问内网/环回/云元数据；
        // 解析结果全部可用才放行，并以首个 IP 直连防 DNS 重绑定。
        let target_host = target.host().unwrap_or_default().to_string();
        let target_port = target.port_u16().unwrap_or(if target.scheme_str() == Some("https") {
            443
        } else {
            80
        });
        let addrs: Vec<std::net::SocketAddr> = match tokio::time::timeout(
            XHR_DNS_TIMEOUT,
            tokio::net::lookup_host((target_host.as_str(), target_port)),
        )
        .await
        {
            Ok(Ok(iter)) => iter.collect(),
            Ok(Err(e)) => return bad_request(&format!("目标解析失败: {e}")),
            Err(_) => {
                return bad_request(&format!(
                    "目标解析超时（{}s）",
                    XHR_DNS_TIMEOUT.as_secs()
                ))
            }
        };
        if addrs.is_empty() {
            return bad_request("目标无可用地址");
        }
        if addrs.iter().any(|a| !crate::ip_pool::is_usable_ip(&a.ip())) {
            return forbidden();
        }
        let connect_ip = addrs[0].ip();

        // 转发（直连校验后的 IP）。整段请求加超时：慢目标不能长期占用连接。
        let body = Limited::new(body, MAX_XHR_BODY);
        let outbound_result = match tokio::time::timeout(
            XHR_TIMEOUT,
            forward_xhr(method.clone(), target, forward_headers, body, connect_ip),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!("XHR 桥请求超时（{}s）", XHR_TIMEOUT.as_secs())),
        };

        match outbound_result {
            Ok(resp_parts) => {
                let mut builder = Response::builder()
                    .status(resp_parts.0)
                    .header("Access-Control-Allow-Origin", origin)
                    .header("Access-Control-Allow-Headers", "*")
                    .header("Access-Control-Allow-Methods", "*")
                    .header("Access-Control-Allow-Credentials", "true")
                    .header("Vary", "Origin");
                for (k, v) in resp_parts.1.iter() {
                    builder = builder.header(k, v);
                }
                builder
                    .body(Full::new(resp_parts.2))
                    .unwrap_or_else(|_| internal_error())
            }
            Err(e) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Access-Control-Allow-Origin", origin)
                .body(Full::new(Bytes::from(e)))
                .unwrap_or_else(|_| internal_error()),
        }
    }

    /// 校验 Origin 是否为「运行了注入脚本的页面」。
    ///
    /// 只接受 http(s) 且主机命中某个已启用脚本的 match 规则；`null`、自定义
    /// 协议、未匹配域名一律拒绝。相比旧的「协议前缀」校验，任意被加速但未
    /// 启用脚本的页面不能再借桥发起请求。
    fn allowed_origin<B>(&self, req: &Request<B>) -> Option<HeaderValue> {
        let origin = req.headers().get(hyper::header::ORIGIN)?;
        let value = origin.to_str().ok()?;
        let uri: hyper::Uri = value.parse().ok()?;
        let scheme = uri.scheme_str()?;
        if !matches!(scheme, "http" | "https") {
            return None;
        }
        // Origin 不允许携带 path/query；带 userinfo 的伪 Origin 直接拒绝
        if !uri.path().is_empty() && uri.path() != "/" {
            return None;
        }
        if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
            return None;
        }
        let host = uri.host()?.to_ascii_lowercase();
        let probe = format!("{scheme}://{host}/");
        let matched = self
            .scripts
            .iter()
            .any(|s| watt_script::model::script_matches_url(s, &probe));
        matched.then(|| origin.clone())
    }
}

/// 提取 /WattToolkit_Inject/{lid}.js 的 lid（对齐 TryGetInjectScriptLocalId：前缀/后缀均大小写不敏感）
fn extract_inject_script_lid(path: &str) -> Option<String> {
    let prefix = watt_config::constants::INJECT_SCRIPT_PATH_PREFIX;
    if !starts_with_ignore_case(path, prefix) {
        return None;
    }
    let id_part = &path[prefix.len()..];
    let lower = id_part.to_ascii_lowercase();
    let id = lower.strip_suffix(".js")?;
    if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && id != "0" {
        Some(id.to_string())
    } else {
        None
    }
}

/// 字节级大小写不敏感前缀匹配（对齐 StartsWith OrdinalIgnoreCase）
fn starts_with_ignore_case(haystack: &str, prefix: &str) -> bool {
    let (h, p) = (haystack.as_bytes(), prefix.as_bytes());
    h.len() >= p.len() && h[..p.len()].eq_ignore_ascii_case(p)
}

/// XHR 桥转发：直连目标（对齐 CookieHttpClient.SendAsync 简化版）
async fn forward_xhr<B>(
    method: Method,
    target: hyper::Uri,
    headers: HeaderMap,
    body: B,
    connect_ip: IpAddr,
) -> Result<(StatusCode, HeaderMap, Bytes), String>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // 出站：直连 + TLS
    let host = target.host().ok_or("无 host")?.to_string();
    let port = target
        .port_u16()
        .unwrap_or(if target.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let tls = target.scheme_str() == Some("https");

    let connector =
        crate::outbound::OutboundConnector::new(Arc::new(crate::outbound::SystemDns), None);
    let stream = connector
        .connect(&crate::outbound::OutboundTarget {
            host: host.clone(),
            port,
            tls,
            tls_sni: None,
            tls_ignore_name_mismatch: false,
            tls_skip_verify: false,
            override_ip: Some(connect_ip),
            forward_destination: None,
            timeout_ms: Some(30000),
        })
        .await
        .map_err(|e| e.to_string())?;

    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| format!("出站握手失败: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder().method(method).uri(target);
    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }
    let req = builder
        .body(body)
        .map_err(|e| format!("构造请求失败: {e}"))?;

    let response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("请求失败: {e}"))?;

    let (parts, body) = response.into_parts();
    let bytes = Limited::new(body, MAX_XHR_BODY)
        .collect()
        .await
        .map_err(|e| format!("读取响应失败或超过上限: {e}"))?
        .to_bytes();
    Ok((parts.status, parts.headers, bytes))
}

fn not_found() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::NOT_FOUND;
    resp
}

fn forbidden() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp
}

fn bad_request(msg: &str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(msg.to_string())));
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    resp
}

fn internal_error() -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_inject_script_lid() {
        assert_eq!(
            extract_inject_script_lid("/WattToolkit_Inject/123.js"),
            Some("123".into())
        );
        assert_eq!(
            extract_inject_script_lid("/WattToolkit_Inject/abc.js"),
            None
        );
        assert_eq!(extract_inject_script_lid("/other/123.js"), None);
        assert_eq!(extract_inject_script_lid("/WattToolkit_Inject/0.js"), None);
    }

    #[test]
    fn test_should_handle() {
        assert!(LocalDomainHandler::should_handle("local.steampp.net", "/"));
        assert!(LocalDomainHandler::should_handle(
            "any.com",
            "/WattToolkit_Inject/1.js"
        ));
        assert!(!LocalDomainHandler::should_handle("any.com", "/path"));
    }

    #[tokio::test]
    async fn test_local_status_and_script() {
        let handler = LocalDomainHandler::new(vec![ScriptConfig {
            local_id: "7".into(),
            cache_path: "/nonexistent".into(),
            ..Default::default()
        }]);
        // status
        let req = Request::builder()
            .uri("https://local.steampp.net/status")
            .header("requestType", "status")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = handler.handle(req, "local.steampp.net").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_allowed_origin_requires_script_match() {
        let handler = LocalDomainHandler::new(vec![ScriptConfig {
            local_id: "1".into(),
            match_domain_names: vec!["*.example.com".into(), "example.com".into()],
            ..Default::default()
        }]);
        let req = |origin: &str| {
            Request::builder()
                .header("Origin", origin)
                .body(Full::new(Bytes::new()))
                .unwrap()
        };
        // 命中脚本域名的页面
        assert!(handler.allowed_origin(&req("https://www.example.com")).is_some());
        assert!(handler.allowed_origin(&req("http://example.com")).is_some());
        // 未命中 / null / 自定义协议 / 带路径的伪 Origin
        assert!(handler.allowed_origin(&req("https://evil.com")).is_none());
        assert!(handler.allowed_origin(&req("null")).is_none());
        assert!(handler.allowed_origin(&req("file://example.com")).is_none());
        assert!(handler
            .allowed_origin(&req("https://www.example.com/path"))
            .is_none());
    }
}
