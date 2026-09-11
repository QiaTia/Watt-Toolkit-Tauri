//! HTTP 反向代理主流程（对齐 HttpReverseProxyMiddleware.InvokeAsync）。
//!
//! 流程：脚本匹配 → 域名规则匹配（子规则递归）→ DNS 污染判定 → 静态响应 →
//! HTTP→HTTPS 重定向 → Destination 模板 → UA 替换 → 服务端代理头 → 出站转发 → 脚本注入。

use crate::inject::{inject_scripts, ContentCompression};
use crate::local_domain::LocalDomainHandler;
use crate::outbound::{OutboundConnector, OutboundTarget, UpstreamProxy};
use crate::stats::FlowStats;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, HOST, USER_AGENT};
use hyper::{Method, Request, Response, StatusCode, Uri};
use std::sync::Arc;
use watt_config::domain_rule::DomainRule;
use watt_config::DomainRules;
use watt_script::hooks::{
    FetchResponse, HookEngine, HookFetch, RequestHookOutcome, RequestSnapshot, ResponseHookOutcome,
    ResponseSnapshot,
};

/// 转发请求体：无钩子时保持流式，有钩子时缓冲（避免无谓开销）
type ForwardBody = BoxBody<Bytes, hyper::Error>;

/// 引擎运行时上下文（每引擎一份，请求间共享）
pub struct RelayContext {
    pub rules: DomainRules,
    pub local: LocalDomainHandler,
    pub upstream: Option<UpstreamProxy>,
    pub two_level_agent_enable: bool,
    pub only_enable_proxy_script: bool,
    pub is_only_work_steam_browser: bool,
    pub enable_http_to_https: bool,
    pub server_side_proxy_token: Option<String>,
    pub dns: Arc<watt_dns::DnsResolver>,
    pub stats: Arc<FlowStats>,
    /// 服务端脚本钩子引擎（Phase 4b；None = 无脚本能力）
    pub hooks: Option<Arc<HookEngine>>,
}

impl RelayContext {
    pub fn new(
        rules: DomainRules,
        local: LocalDomainHandler,
        upstream: Option<UpstreamProxy>,
    ) -> Self {
        let two_level_agent_enable = upstream.is_some();
        Self {
            rules,
            local,
            upstream,
            two_level_agent_enable,
            only_enable_proxy_script: false,
            is_only_work_steam_browser: false,
            enable_http_to_https: false,
            server_side_proxy_token: None,
            dns: Arc::new(watt_dns::DnsResolver::system()),
            stats: Arc::new(FlowStats::default()),
            hooks: None,
        }
    }

    /// 处理单个请求（MITM 明文 HTTP 层）
    pub async fn handle_request(
        self: &Arc<Self>,
        req: Request<Incoming>,
        scheme: &str,
    ) -> Response<Full<Bytes>> {
        let host = request_host(&req);

        // —— 本地域名 / 注入脚本路径短路 ——
        if LocalDomainHandler::should_handle(&host, req.uri().path()) {
            return self.local.handle(req, &host).await;
        }

        let url = format!(
            "{scheme}://{host}{}",
            req.uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
        );

        // —— 脚本注入匹配（按 order 排序：注入顺序与钩子执行顺序一致） ——
        let mut matched_scripts: Vec<&watt_script::ScriptConfig> = self
            .local
            .scripts()
            .iter()
            .filter(|s| watt_script::model::script_matches_url(s, &url))
            .collect();
        matched_scripts.sort_by_key(|s| s.order);
        let scripts: Vec<String> = matched_scripts
            .into_iter()
            .map(|s| s.local_id.clone())
            .collect();
        let is_script_inject = !scripts.is_empty();

        // —— 域名规则匹配 ——
        let matched = self.find_domain_config(&url, &host);

        let Some((rule, is_default)) = matched else {
            // 未匹配：二级代理全局转发 或 404
            if self.two_level_agent_enable {
                return self
                    .forward_global(req, scheme, &host)
                    .await
                    .unwrap_or_else(|e| error_response(&format!("转发失败: {e}")));
            }
            return not_found_response();
        };

        // —— DNS 污染判定（default 规则） ——
        // 原版用 DNSPod 公共 DNS 反查（绕过本机 hosts），此处用 clean 解析对齐：
        // 若用读 hosts 的解析器，用户/引擎自身写入的 hosts 条目会被误判为污染。
        if is_default && !self.only_enable_proxy_script {
            if let Some(ip) = self.dns.resolve_first_clean(&host).await {
                if watt_dns::is_polluted_ip(&ip) {
                    return error_response(&watt_dns::pollution::pollution_error_body(&host));
                }
            } else {
                return error_response(&watt_dns::pollution::pollution_error_body(&host));
            }
        }

        // —— 静态响应规则 ——
        if let Some(static_response) = &rule.fields.response {
            let mut builder = Response::builder().status(
                StatusCode::from_u16(static_response.status_code).unwrap_or(StatusCode::OK),
            );
            for (k, v) in &static_response.headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            return builder
                .body(Full::new(Bytes::from(static_response.body.clone())))
                .unwrap_or_else(|_| error_response("静态响应构造失败"));
        }

        // —— HTTP→HTTPS 重定向（对齐原版 Response.Redirect 的 302 临时跳转；
        // 用 301 会被浏览器永久缓存，关闭加速后仍强制 https）——
        if self.enable_http_to_https && scheme == "http" {
            let location = format!(
                "https://{host}{}",
                req.uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
            );
            return Response::builder()
                .status(StatusCode::FOUND)
                .header(hyper::header::LOCATION, location)
                .body(Full::new(Bytes::new()))
                .unwrap();
        }

        // —— 转发 ——
        match self
            .forward(req, scheme, &host, &url, &rule, &scripts, is_script_inject)
            .await
        {
            Ok(resp) => resp,
            Err(e) => error_response(&format!("转发失败: {e}")),
        }
    }

    /// 域名规则匹配（对齐 TryGetDomainConfig + RecursionMatchDomainConfig）
    fn find_domain_config(&self, url: &str, host: &str) -> Option<(DomainRule, bool)> {
        if !self.only_enable_proxy_script {
            if let Some(rule) = self.rules.find_by_url(url, host) {
                // 子规则递归匹配（命中即完整替换字段——对齐原实现语义）
                return Some((effective_rule(url, rule), false));
            }
        }

        // 未配置但为域名 → default 规则（对齐 IsDomain 判定）
        let is_domain = host.parse::<std::net::IpAddr>().is_err() && host.contains('.');
        if is_domain {
            Some((DomainRule::default(), true))
        } else {
            None
        }
    }

    /// 出站转发主流程
    async fn forward(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        host: &str,
        url: &str,
        rule: &DomainRule,
        scripts: &[String],
        is_script_inject: bool,
    ) -> Result<Response<Full<Bytes>>, String> {
        let (mut parts, incoming_body) = req.into_parts();
        let mut scheme = scheme.to_string();
        let mut host = host.to_string();
        let mut body: ForwardBody = incoming_body.boxed();

        // —— 服务端脚本 onRequest 钩子（Phase 4b 新增能力）——
        // 仅当匹配脚本存在请求钩子时缓冲 body；二进制 body 跳过（UTF-8 约定）
        if let Some(hooks) = &self.hooks {
            if hooks.has_request_hooks(scripts) {
                // 缓冲请求体（collect 消耗 body，后续按结果恢复/替换）
                let bytes = body
                    .collect()
                    .await
                    .map_err(|e| format!("读取请求体失败: {e}"))?
                    .to_bytes();
                let outcome = if std::str::from_utf8(&bytes).is_ok() {
                    let snapshot = RequestSnapshot {
                        method: parts.method.as_str().to_string(),
                        url: url.to_string(),
                        headers: header_pairs(&parts.headers),
                        body: bytes.to_vec(),
                    };
                    hooks.on_request(scripts, snapshot).await
                } else {
                    RequestHookOutcome::Passthrough
                };
                match outcome {
                    RequestHookOutcome::Passthrough => {
                        body = Full::new(bytes).map_err(|e| match e {}).boxed();
                    }
                    RequestHookOutcome::Redirect { location } => {
                        return Response::builder()
                            .status(StatusCode::FOUND)
                            .header(hyper::header::LOCATION, location)
                            .body(Full::new(Bytes::new()))
                            .map_err(|e| e.to_string());
                    }
                    RequestHookOutcome::Block { status, body } => {
                        return Response::builder()
                            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
                            .body(Full::new(Bytes::from(body)))
                            .map_err(|e| e.to_string());
                    }
                    RequestHookOutcome::Modified(snap) => {
                        if let Ok(m) = Method::from_bytes(snap.method.as_bytes()) {
                            parts.method = m;
                        }
                        if let Ok(uri) = snap.url.parse::<Uri>() {
                            if let Some(s) = uri.scheme_str() {
                                scheme = s.to_string();
                            }
                            if let Some(h) = uri.host() {
                                host = h.to_string();
                            }
                            if let Some(pq) = uri.path_and_query() {
                                if let Ok(u) = pq.as_str().parse() {
                                    parts.uri = u;
                                }
                            }
                        }
                        parts.headers = headermap_from_pairs(&snap.headers);
                        body = Full::new(Bytes::from(snap.body))
                            .map_err(|e| match e {})
                            .boxed();
                        tracing::debug!(
                            "onRequest 钩子修改请求: {} {scheme}://{host}",
                            parts.method
                        );
                    }
                }
            }
        }

        // —— Destination 模板替换 ——
        let destination = rule.fields.destination.as_deref();
        let destination_uri = resolve_destination(&scheme, &host, parts.uri.clone(), destination);

        // —— UserAgent 替换 ——
        if let Some(ua_rule) = &rule.fields.user_agent {
            let origin_ua = parts
                .headers
                .get(USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let new_ua = ua_rule.replace("${origin}", &origin_ua);
            parts.headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&new_ua).map_err(|e| e.to_string())?,
            );
        }

        // —— 服务端代理头 ——
        if rule.fields.is_server_side_proxy {
            let path_and_query = parts
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            parts.headers.insert(
                "X-Watt-Origin-Dest-Scheme",
                HeaderValue::from_str(&scheme).map_err(|e| e.to_string())?,
            );
            parts.headers.insert(
                "X-Watt-Origin-Dest-Host",
                HeaderValue::from_str(&host).map_err(|e| e.to_string())?,
            );
            parts.headers.insert(
                "X-Watt-Origin-Dest-PathAndQuery",
                HeaderValue::from_str(&path_and_query).map_err(|e| e.to_string())?,
            );
            parts.headers.insert(
                "X-Watt-Token",
                HeaderValue::from_str(self.server_side_proxy_token.as_deref().unwrap_or(""))
                    .map_err(|e| e.to_string())?,
            );
        }

        // —— 出站连接 ——
        // 对齐 C# YARP 语义：连接目标为 Destination URI 的 host（未配置时为原始 host）
        let dest_host = destination_uri
            .host()
            .map(|h| h.to_string())
            .unwrap_or_else(|| host.to_string());
        let target = OutboundTarget {
            host: dest_host,
            port: destination_uri.port_u16().unwrap_or(
                if destination_uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                },
            ),
            tls: destination_uri.scheme_str() == Some("https"),
            tls_sni: resolve_tls_sni(rule, &host),
            tls_ignore_name_mismatch: rule.fields.tls_ignore_name_mismatch,
            override_ip: rule.fields.ip_address,
            forward_destination: rule.fields.forward_destination.clone(),
            timeout_ms: rule.fields.timeout_ms,
        };

        let connector = OutboundConnector::new(
            Arc::new(RelayDnsAdapter(self.dns.clone())),
            self.upstream.clone(),
        );
        let stream = connector
            .connect(&target)
            .await
            .map_err(|e| e.to_string())?;

        // —— HTTP/1.1 出站握手 ——
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|e| format!("出站握手失败: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // 构造出站请求（origin-form，对齐 YARP：请求行仅 path_and_query，Host 指向目标权威）
        let outbound_path = destination_uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let outbound_authority = destination_uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| host.to_string());
        let mut outbound_builder = Request::builder()
            .method(parts.method.clone())
            .uri(outbound_path)
            .header(HOST, &outbound_authority);
        for (k, v) in parts.headers.iter() {
            let name = k.as_str();
            if k == HOST || is_hop_by_hop(name) {
                continue;
            }
            outbound_builder = outbound_builder.header(k, v);
        }
        let outbound_req = outbound_builder.body(body).map_err(|e| e.to_string())?;

        // 统计上行
        self.stats
            .add_up(outbound_req.size_hint().exact().unwrap_or(0));

        let response = sender
            .send_request(outbound_req)
            .await
            .map_err(|e| format!("请求失败: {e}"))?;

        let (mut resp_parts, resp_body) = response.into_parts();
        let mut body_bytes = resp_body
            .collect()
            .await
            .map_err(|e| format!("读取响应失败: {e}"))?
            .to_bytes();

        self.stats.add_down(body_bytes.len() as u64 + 128);

        // —— 服务端脚本 onResponse 钩子（Phase 4b 新增能力）——
        // 二进制/压缩 body 跳过（UTF-8 约定：无法以字符串安全传递）
        if let Some(hooks) = &self.hooks {
            if hooks.has_response_hooks(scripts) && std::str::from_utf8(&body_bytes).is_ok() {
                let snapshot = ResponseSnapshot {
                    status: resp_parts.status.as_u16(),
                    headers: header_pairs(&resp_parts.headers),
                    body: body_bytes.to_vec(),
                };
                match hooks.on_response(scripts, snapshot).await {
                    ResponseHookOutcome::Passthrough => {}
                    ResponseHookOutcome::Modified(snap) => {
                        if let Ok(s) = StatusCode::from_u16(snap.status) {
                            resp_parts.status = s;
                        }
                        resp_parts.headers = headermap_from_pairs(&snap.headers);
                        body_bytes = Bytes::from(snap.body);
                        tracing::debug!("onResponse 钩子修改响应: {}", resp_parts.status);
                    }
                }
            }
        }

        // —— 脚本注入 ——
        let content_encoding = resp_parts
            .headers
            .get(hyper::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let content_type = resp_parts
            .headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        let should_inject = is_script_inject
            && !scripts.is_empty()
            && parts.method == Method::GET
            && resp_parts.status == StatusCode::OK
            && content_type.to_ascii_lowercase().contains("text/html")
            && (!self.is_only_work_steam_browser
                || parts
                    .headers
                    .get(USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|ua| ua.contains("Valve Steam")));

        if should_inject {
            match inject_scripts(
                &body_bytes,
                &content_encoding,
                &content_type,
                scripts,
                &host,
            ) {
                Ok(injected) => {
                    let mut builder = Response::builder().status(resp_parts.status);
                    let mut headers = resp_parts.headers.clone();
                    // 移除 CSP（对齐原实现）
                    headers.remove("Content-Security-Policy");
                    headers.remove(hyper::header::CONTENT_LENGTH);
                    if injected.compression == ContentCompression::None {
                        headers.remove(hyper::header::CONTENT_ENCODING);
                    }
                    for (k, v) in headers.iter() {
                        builder = builder.header(k, v);
                    }
                    return builder
                        .body(Full::new(Bytes::from(injected.body)))
                        .map_err(|e| e.to_string());
                }
                Err(e) => {
                    tracing::warn!("脚本注入失败（原样返回）: {e}");
                }
            }
        }

        // 原样返回
        let mut builder = Response::builder().status(resp_parts.status);
        let mut headers = resp_parts.headers.clone();
        headers.remove(hyper::header::CONTENT_LENGTH);
        headers.remove(hyper::header::TRANSFER_ENCODING);
        for (k, v) in headers.iter() {
            builder = builder.header(k, v);
        }
        builder
            .body(Full::new(body_bytes))
            .map_err(|e| e.to_string())
    }

    /// 未匹配域名的全局二级代理转发
    async fn forward_global(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        host: &str,
    ) -> Result<Response<Full<Bytes>>, String> {
        let default_rule = DomainRule::default();
        // 走默认规则（TlsSni=true）的全局转发
        self.forward(req, scheme, host, "", &default_rule, &[], false)
            .await
    }
}

/// 子规则递归匹配（对齐 RecursionMatchDomainConfig）：命中即完整替换字段
fn effective_rule(url: &str, rule: &DomainRule) -> DomainRule {
    if let Some(sub) = rule
        .fields
        .items
        .iter()
        .find(|s| regex_matches(&s.regex, url))
    {
        // 二级嵌套（少见）：继续向下
        if let Some(nested) = sub.rule.items.iter().find(|s| regex_matches(&s.regex, url)) {
            return domain_rule_from_fields(&nested.rule, rule);
        }
        return domain_rule_from_fields(&sub.rule, rule);
    }
    rule.clone()
}

/// SNI 覆盖解析（对齐 C# `GetTlsSniPattern().WithDomain(uri.Host).WithRandom()`）
///
/// - `fake_server_name` 为空：沿用 `tls_sni` 开关（false → 空 SNI，true → 目标 host）
/// - `@domain` / `${domain}` / `{origin}` / `${origin}` → 原始请求 host
/// - `${random}` → 随机 DNS 标签（每连接不同，用于规避按 SNI 限速）
/// - 其他值 → 原样下发（CDN 镜像场景：连镜像 IP、报原始站点的 SNI）
pub fn resolve_tls_sni(rule: &DomainRule, host: &str) -> Option<String> {
    let pattern = rule
        .fields
        .fake_server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match pattern {
        Some(p) => {
            let resolved = p
                .replace("@domain", host)
                .replace("${domain}", host)
                .replace("{origin}", host)
                .replace("${origin}", host);
            if resolved.contains("${random}") {
                return Some(resolved.replace("${random}", &random_label()));
            }
            Some(resolved)
        }
        None => {
            if rule.fields.tls_sni {
                None
            } else {
                Some(String::new())
            }
        }
    }
}

/// 随机 DNS 标签（对齐 C# WithRandom：规避按 SNI 精确匹配的限速）
fn random_label() -> String {
    use rand::Rng as _;
    let n: u32 = rand::thread_rng().gen();
    format!("{n:08x}")
}

fn domain_rule_from_fields(
    fields: &watt_config::DomainRuleFields,
    template: &DomainRule,
) -> DomainRule {
    DomainRule {
        match_domain_names: template.match_domain_names.clone(),
        listening_domain_names: template.listening_domain_names.clone(),
        order: template.order,
        fields: fields.clone(),
    }
}

fn regex_matches(pattern: &str, url: &str) -> bool {
    regex::Regex::new(pattern)
        .map(|re| re.is_match(url))
        .unwrap_or(false)
}

/// DNS 适配器：watt-dns → outbound::DnsResolve
///
/// 出站连接必须绕过 hosts：加速引擎自身写入 hosts 劫持条目，若出站解析
/// 读到 127.0.0.1 会回环连接自身（os error 10048）。污染判定走的是
/// `DnsResolver::resolve_first`（保留系统语义），不经过本适配器。
pub struct RelayDnsAdapter(pub Arc<watt_dns::DnsResolver>);

impl crate::outbound::DnsResolve for RelayDnsAdapter {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Vec<std::net::IpAddr>, String>> {
        Box::pin(async move { self.0.resolve_clean(host).await.map_err(|e| e.to_string()) })
    }
}

/// HeaderMap → (名, 值) 列表（供脚本快照使用；非 ASCII 值跳过）
fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect()
}

/// (名, 值) 列表 → HeaderMap（脚本修改结果；无效头跳过并告警）
fn headermap_from_pairs(pairs: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        match (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            (Ok(name), Ok(value)) => {
                map.insert(name, value);
            }
            _ => {
                tracing::warn!("脚本修改的请求头无效，已跳过: {k}");
            }
        }
    }
    map
}

/// 受限 fetch 出站实现（Phase 4b）：脚本内 fetch 走应用出站链路（DNS/二级代理）。
/// 对齐设计：不暴露系统网络栈直连，所有出站均经 OutboundConnector。
pub struct RelayFetch {
    dns: Arc<watt_dns::DnsResolver>,
    upstream: Option<UpstreamProxy>,
}

impl RelayFetch {
    pub fn new(dns: Arc<watt_dns::DnsResolver>, upstream: Option<UpstreamProxy>) -> Self {
        Self { dns, upstream }
    }
}

impl HookFetch for RelayFetch {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        method: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> futures::future::BoxFuture<'a, Result<FetchResponse, String>> {
        Box::pin(async move {
            let uri: Uri = url.parse().map_err(|e| format!("fetch URL 无效: {e}"))?;
            let host = uri
                .host()
                .ok_or_else(|| "fetch URL 缺少 host".to_string())?
                .to_string();
            let tls = uri.scheme_str() != Some("http");
            let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
            let authority = uri
                .authority()
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| host.clone());
            let path = uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());

            let target = OutboundTarget {
                host,
                port,
                tls,
                tls_sni: None,
                tls_ignore_name_mismatch: false,
                override_ip: None,
                forward_destination: None,
                timeout_ms: Some(10_000),
            };
            let connector = OutboundConnector::new(
                Arc::new(RelayDnsAdapter(self.dns.clone())),
                self.upstream.clone(),
            );
            let stream = connector
                .connect(&target)
                .await
                .map_err(|e| format!("fetch 连接失败: {e}"))?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .map_err(|e| format!("fetch 握手失败: {e}"))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header(HOST, authority);
            for (k, v) in headers {
                if k.eq_ignore_ascii_case("host") || is_hop_by_hop(k) {
                    continue;
                }
                builder = builder.header(k.as_str(), v.as_str());
            }
            let req = builder
                .body(Full::new(Bytes::from(body.to_vec())))
                .map_err(|e| format!("fetch 请求构造失败: {e}"))?;
            let response = sender
                .send_request(req)
                .await
                .map_err(|e| format!("fetch 请求失败: {e}"))?;

            let (parts, resp_body) = response.into_parts();
            let bytes = resp_body
                .collect()
                .await
                .map_err(|e| format!("fetch 读取响应失败: {e}"))?
                .to_bytes();
            Ok(FetchResponse {
                status: parts.status.as_u16(),
                headers: header_pairs(&parts.headers),
                body: bytes.to_vec(),
            })
        })
    }
}

/// Destination 解析（对齐 GetDestinationPrefix + YARP MakeDestinationAddress）。
/// 返回完整出站 URI：前缀路径 + 原始请求 path_and_query。
fn resolve_destination(scheme: &str, host: &str, original: Uri, destination: Option<&str>) -> Uri {
    // 原始请求 path_and_query
    let raw = original
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let Some(dest) = destination else {
        // 无 destination：scheme://host + 请求路径（对齐 YARP 前缀 + path 组合）
        return fallback_uri(scheme, host, &raw);
    };

    // @domain/@uri 模板替换（@uri 已含完整路径，直接使用）
    if dest.contains('@') {
        if dest.contains("@uri") {
            let new_url = dest.replace("@domain", host).replace("@uri", &raw);
            return new_url
                .parse()
                .unwrap_or_else(|_| fallback_uri(scheme, host, &raw));
        }
        // 仅 @domain：作为前缀，追加请求路径
        let new_url = dest.replace("@domain", host);
        return format!("{new_url}{raw}")
            .parse()
            .unwrap_or_else(|_| fallback_uri(scheme, host, &raw));
    }

    // 相对/绝对 URI（对齐 new Uri(baseUri, destination) + YARP 路径组合）
    let base =
        resolve_relative(scheme, host, dest).unwrap_or_else(|| fallback_uri(scheme, host, &raw));
    let base_str = base.to_string();
    // 前缀路径 + 请求 path_and_query
    let path = if base_str.ends_with('/') {
        format!("{base_str}{}", raw.trim_start_matches('/'))
    } else {
        format!("{base_str}{raw}")
    };
    path.parse()
        .unwrap_or_else(|_| fallback_uri(scheme, host, &raw))
}

/// 兜底 URI：scheme://host + 原始请求路径
fn fallback_uri(scheme: &str, host: &str, raw: &str) -> Uri {
    format!("{scheme}://{host}{raw}")
        .parse()
        .unwrap_or(Uri::from_static("http://localhost/"))
}

/// 相对 URI 解析（简化版 new Uri(base, relative)：绝对直接用；相对拼到 scheme://host 下）
fn resolve_relative(scheme: &str, host: &str, dest: &str) -> Option<Uri> {
    if dest.starts_with("http://") || dest.starts_with("https://") {
        return dest.parse().ok();
    }
    // 相对路径：基于 scheme://host/
    let path = if dest.starts_with('/') {
        dest.to_string()
    } else {
        format!("/{dest}")
    };
    format!("{scheme}://{host}{path}").parse().ok()
}

fn error_response(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

/// 逐跳头（Connection 及其注册的头 + 常见逐跳头），代理转发时必须剥离
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// 解析请求的目标主机。
///
/// HTTP/1.1（origin-form）的目标主机在 `Host` 头；而 **HTTP/2 没有 `Host` 头**，主机只存在于
/// `:authority` 伪头，hyper 会把它映射到 `uri.authority()`。若这里只看 `Host` 头，浏览器
/// （ALPN 协商为 h2）的请求会得到空 host → 域名规则失配且不满足 default 规则的
/// `host.contains('.')` 判定 → 回落 `not_found_response()`，症状是「加速后所有网站
/// 都返回 404 空页」。故两者都取，Host 头优先以保持 HTTP/1.1 原有行为。
fn request_host<B>(req: &Request<B>) -> String {
    if let Some(host) = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| !h.is_empty())
    {
        return host.to_string();
    }
    req.uri()
        .authority()
        .map(|a| a.host().to_string())
        .unwrap_or_default()
}

fn not_found_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_host_from_host_header() {
        // HTTP/1.1（origin-form）：主机来自 Host 头
        let req = Request::builder()
            .uri("/login")
            .header(HOST, "github.com")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req), "github.com");
    }

    #[test]
    fn test_request_host_from_authority_without_host_header() {
        // HTTP/2：无 Host 头，主机在 :authority（hyper 映射到 uri.authority）
        let req = Request::builder()
            .uri("https://github.com/")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req), "github.com");
    }

    #[test]
    fn test_request_host_strips_port_from_authority() {
        // 显式端口不应进入主机名，否则域名规则失配
        let req = Request::builder()
            .uri("https://github.com:443/")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req), "github.com");
    }

    #[test]
    fn test_request_host_prefers_host_header_over_authority() {
        let req = Request::builder()
            .uri("https://a.example.com/")
            .header(HOST, "b.example.com")
            .body(())
            .unwrap();
        assert_eq!(request_host(&req), "b.example.com");
    }

    #[test]
    fn test_resolve_destination_relative() {
        let uri: Uri = "/path?q=1".parse().unwrap();
        let dest = resolve_destination("https", "a.com", uri, Some("/mirror"));
        assert_eq!(dest.to_string(), "https://a.com/mirror/path?q=1");
    }

    #[test]
    fn test_resolve_destination_template() {
        let uri: Uri = "/store/1?x=2".parse().unwrap();
        let dest = resolve_destination("https", "a.com", uri, Some("https://@domain.cdn.com@uri"));
        assert_eq!(dest.to_string(), "https://a.com.cdn.com/store/1?x=2");
    }

    #[test]
    fn test_resolve_destination_domain_only_template() {
        let uri: Uri = "/p".parse().unwrap();
        let dest = resolve_destination("https", "a.com", uri, Some("https://@domain.cdn.com"));
        assert_eq!(dest.to_string(), "https://a.com.cdn.com/p");
    }

    #[test]
    fn test_resolve_destination_none() {
        let uri: Uri = "/p".parse().unwrap();
        let dest = resolve_destination("https", "a.com", uri, None);
        assert_eq!(dest.to_string(), "https://a.com/p");
    }

    #[test]
    fn test_resolve_destination_absolute() {
        let uri: Uri = "/p".parse().unwrap();
        let dest = resolve_destination("https", "a.com", uri, Some("http://mirror.org/x"));
        assert_eq!(dest.to_string(), "http://mirror.org/x/p");
    }
}
