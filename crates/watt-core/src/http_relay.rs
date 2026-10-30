//! HTTP 反向代理主流程（对齐 HttpReverseProxyMiddleware.InvokeAsync）。
//!
//! 流程：脚本匹配 → 域名规则匹配（子规则递归）→ DNS 污染判定 → 静态响应 →
//! HTTP→HTTPS 重定向 → Destination 模板 → UA 替换 → 服务端代理头 → 出站转发 → 脚本注入。

use crate::inject::{inject_scripts, ContentCompression};
use crate::local_domain::LocalDomainHandler;
use crate::access_log::{now_ms, AccessLogEntry, AccessLogStore, Disposition, DEFAULT_CAPACITY};
use crate::outbound::{CandidateHealth, OutboundConnector, OutboundTarget, UpstreamProxy};
use crate::stats::FlowStats;
use bytes::BytesMut;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, COOKIE, HOST, USER_AGENT};
use hyper::{Method, Request, Response, StatusCode, Uri};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use watt_config::domain_rule::DomainRule;
use watt_config::DomainRules;
use watt_script::hooks::{
    FetchResponse, HookEngine, HookFetch, RequestHookOutcome, RequestSnapshot, ResponseHookOutcome,
    ResponseSnapshot,
};

/// 转发请求体：无钩子时保持流式，有钩子时缓冲（避免无谓开销）
type ForwardBody = BoxBody<Bytes, hyper::Error>;

/// 脚本注入 / onResponse 钩子需要整包缓冲的响应体上限（压缩后大小）。
/// 超过则跳过注入/钩子，退回流式转发，避免大响应或压缩炸弹耗尽内存。
const MAX_SCRIPT_BUFFER: usize = 16 * 1024 * 1024;

/// 代理响应体：静态 / 本地 / 错误响应为 `Full`，**转发响应为流式**（边收边发）。
///
/// 整包缓冲会让浏览器在响应体到齐前收不到任何字节——对 1.8MB 的 Figma 首页
/// 这类大响应，在带宽受限时表现为长时间白屏。改为流式后首字节立刻下发，
/// 浏览器可边收边解析。
pub type RelayBody = BoxBody<Bytes, hyper::Error>;
/// 代理响应（[`RelayBody`]）
pub type RelayResponse = Response<RelayBody>;

/// `Full<Bytes>` → 统一响应体
pub fn boxed_full(b: Full<Bytes>) -> RelayBody {
    b.map_err(|e| match e {}).boxed()
}

/// `Response<Full<Bytes>>` → 统一响应（响应体转 [`RelayBody`]）
pub fn boxed_response(resp: Response<Full<Bytes>>) -> RelayResponse {
    resp.map(boxed_full)
}

/// 流式响应体：边转发边累计下行字节（保持流量统计与整包路径一致）
struct CountingBody {
    inner: RelayBody,
    stats: Arc<FlowStats>,
    head_counted: bool,
}

impl Body for CountingBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        if !this.head_counted {
            this.head_counted = true;
            this.stats.add_down(128);
        }
        match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    this.stats.add_down(d.len() as u64);
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// 缓冲结果：完整读完，或超过上限（保留已读前缀 + 未读 stream）
enum CollectOutcome<B> {
    Complete(Bytes),
    Overflow { prefix: Bytes, rest: B },
}

/// 限长收集：超过上限时不丢弃已读数据，而是返回前缀 + 剩余 body，
/// 调用方可跳过脚本处理并继续流式转发（避免 chunked 大响应/大上传直接 500）。
async fn collect_with_limit<B>(mut body: B, limit: usize) -> Result<CollectOutcome<B>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            if collected.len() + data.len() > limit {
                // 当前 frame 一并放入前缀，最多超出一个 frame，可接受
                collected.extend_from_slice(data);
                return Ok(CollectOutcome::Overflow {
                    prefix: collected.freeze(),
                    rest: body,
                });
            }
            collected.extend_from_slice(data);
        }
    }
    Ok(CollectOutcome::Complete(collected.freeze()))
}

/// 先输出已读前缀，再继续输出原 body（用于超限后转流式）
struct PrefixedBody<B> {
    prefix: Option<Bytes>,
    rest: B,
}

impl<B> Body for PrefixedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(prefix))));
            }
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.rest.size_hint();
        if let Some(prefix) = &self.prefix {
            let extra = prefix.len() as u64;
            let lower = hint.lower().saturating_add(extra);
            let upper = hint.upper().map(|u| u.saturating_add(extra));
            hint = SizeHint::new();
            hint.set_lower(lower);
            if let Some(upper) = upper {
                hint.set_upper(upper);
            }
        }
        hint
    }
}

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
    /// 候选健康度记忆：请求阶段失败的出站候选短期降权（跨请求共享）
    pub candidate_health: Arc<CandidateHealth>,
    /// 候选探测结果缓存：启动预择优写入，竞速按 RTT 排序（跨请求共享）
    pub probe_cache: Arc<crate::probe_cache::ProbeCache>,
    /// top-K 裁剪（P2，默认关= None；仅 probe_cache 启用时生效）
    pub probe_top_k: Option<usize>,
    /// 服务端脚本钩子引擎（Phase 4b；None = 无脚本能力）
    pub hooks: Option<Arc<HookEngine>>,
    /// 代理访问日志（每个经代理的请求记录一条，供 UI 查询）
    pub access_log: Arc<AccessLogStore>,
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
            candidate_health: Arc::new(CandidateHealth::new()),
            probe_cache: Arc::new(crate::probe_cache::ProbeCache::new()),
            probe_top_k: None,
            hooks: None,
            access_log: Arc::new(AccessLogStore::new(DEFAULT_CAPACITY)),
        }
    }

    /// 处理单个请求（MITM 明文 HTTP 层）：计时 + 记录访问日志，主体委派 `handle_request_inner`
    pub async fn handle_request(
        self: &Arc<Self>,
        req: Request<Incoming>,
        scheme: &str,
    ) -> RelayResponse {
        let started = std::time::Instant::now();
        let host = request_host(&req);
        let method = req.method().clone();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let up_bytes = req
            .headers()
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let (resp, disposition) = self.handle_request_inner(req, scheme, &host).await;

        let status = resp.status().as_u16();
        let down_bytes = resp.body().size_hint().exact().unwrap_or(0);
        self.access_log.push(AccessLogEntry {
            ts_ms: now_ms(),
            host,
            method: method.to_string(),
            path,
            status,
            up_bytes,
            down_bytes,
            latency_ms: started.elapsed().as_millis() as u64,
            disposition,
        });
        resp
    }

    /// 请求处理主体：返回响应 + 处置分类（供访问日志记录）
    async fn handle_request_inner(
        self: &Arc<Self>,
        req: Request<Incoming>,
        scheme: &str,
        host: &str,
    ) -> (RelayResponse, Disposition) {
        let host = host.to_string();

        // —— 本地域名 / 注入脚本路径短路 ——
        if LocalDomainHandler::should_handle(&host, req.uri().path()) {
            return (
                self.local.handle(req, &host).await.map(boxed_full),
                Disposition::Local,
            );
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
                return (
                    self.forward_global(req, scheme, &host)
                        .await
                        .unwrap_or_else(|e| error_response(&format!("转发失败: {e}"))),
                    Disposition::Unmatched,
                );
            }
            return (not_found_response(), Disposition::Unmatched);
        };

        // 命中具体规则 or default 规则（供日志处置分类）
        let disp = if is_default {
            Disposition::Default
        } else {
            Disposition::Matched
        };

        // —— DNS 污染判定（default 规则） ——
        // 原版用 DNSPod 公共 DNS 反查（绕过本机 hosts），此处用 clean 解析对齐：
        // 若用读 hosts 的解析器，用户/引擎自身写入的 hosts 条目会被误判为污染。
        if is_default && !self.only_enable_proxy_script {
            if let Some(ip) = self.dns.resolve_first_clean(&host).await {
                if watt_dns::is_polluted_ip(&ip) {
                    return (
                        error_response(&watt_dns::pollution::pollution_error_body(&host)),
                        disp,
                    );
                }
            } else {
                return (
                    error_response(&watt_dns::pollution::pollution_error_body(&host)),
                    disp,
                );
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
            return (
                builder
                    .body(Full::new(Bytes::from(static_response.body.clone())))
                    .map(boxed_response)
                    .unwrap_or_else(|_| error_response("静态响应构造失败")),
                disp,
            );
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
            return (
                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(hyper::header::LOCATION, location)
                    .body(Full::new(Bytes::new()))
                    .map(boxed_response)
                    .unwrap_or_else(|_| {
                        let mut fallback = Response::new(Full::new(Bytes::new()));
                        *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        boxed_response(fallback)
                    }),
                disp,
            );
        }

        // —— 转发 ——
        match self
            .forward(req, scheme, &host, &url, &rule, &scripts, is_script_inject)
            .await
        {
            Ok(resp) => (resp, disp),
            Err(e) => (error_response(&format!("转发失败: {e}")), disp),
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
    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        host: &str,
        url: &str,
        rule: &DomainRule,
        scripts: &[String],
        is_script_inject: bool,
    ) -> Result<RelayResponse, String> {
        let (mut parts, incoming_body) = req.into_parts();
        let mut scheme = scheme.to_string();
        let mut host = host.to_string();
        let mut body: ForwardBody = incoming_body.boxed();

        // —— 服务端脚本 onRequest 钩子（Phase 4b 新增能力）——
        // 仅当匹配脚本存在请求钩子时缓冲 body；二进制 body 跳过（UTF-8 约定）。
        // 请求体同样受 MAX_SCRIPT_BUFFER 限制：已知超限则直接跳过钩子、保持流式。
        let request_too_large = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > MAX_SCRIPT_BUFFER as u64);
        if request_too_large {
            tracing::warn!(
                host = %host,
                limit = MAX_SCRIPT_BUFFER,
                "请求体超过脚本处理上限，跳过 onRequest 钩子"
            );
        }
        if let Some(hooks) = &self.hooks {
            if hooks.has_request_hooks(scripts) && !request_too_large {
                // 缓冲请求体：超限时保留已读前缀 + 剩余流式 body，跳过钩子继续转发
                match collect_with_limit(body, MAX_SCRIPT_BUFFER).await {
                    Ok(CollectOutcome::Complete(bytes)) => {
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
                                    .map(boxed_response)
                                    .map_err(|e| e.to_string());
                            }
                            RequestHookOutcome::Block { status, body } => {
                                return Response::builder()
                                    .status(
                                        StatusCode::from_u16(status)
                                            .unwrap_or(StatusCode::FORBIDDEN),
                                    )
                                    .body(Full::new(Bytes::from(body)))
                                    .map(boxed_response)
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
                    Ok(CollectOutcome::Overflow { prefix, rest }) => {
                        tracing::warn!(
                            host = %host,
                            limit = MAX_SCRIPT_BUFFER,
                            "chunked 请求体超过脚本处理上限，跳过 onRequest 钩子并流式转发"
                        );
                        body = BoxBody::new(PrefixedBody {
                            prefix: Some(prefix),
                            rest,
                        });
                    }
                    Err(e) => return Err(format!("读取请求体失败: {e}")),
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
            tls_skip_verify: rule.fields.tls_skip_verify,
            override_ip: rule.fields.ip_address,
            forward_destination: rule.fields.forward_destination.clone(),
            timeout_ms: rule.fields.timeout_ms,
        };

        let connector = OutboundConnector::new(
            Arc::new(RelayDnsAdapter(self.dns.clone())),
            self.upstream.clone(),
        )
        .with_health(self.candidate_health.clone())
        .with_probe(self.probe_cache.clone());
        // top-K 裁剪（P2，默认关）
        let connector = match self.probe_top_k {
            Some(k) => connector.with_probe_top_k(k),
            None => connector,
        };

        // 构造出站请求模板（origin-form，对齐 YARP：请求行仅 path_and_query，
        // Host 指向目标权威）。headers 每次连接尝试克隆复用。
        let outbound_path = destination_uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let outbound_authority = destination_uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_else(|| host.to_string());
        let template_headers = build_outbound_headers(&parts.headers, &outbound_authority)?;

        // 统计上行
        self.stats.add_up(body.size_hint().exact().unwrap_or(0));

        // —— 转发（连接级失败对幂等请求自动重试一次）——
        // TLS 竞速胜出 ≠ 连接可用：部分网络在握手完成后对首个 HTTP 数据注入 RST
        // （按 SNI 限速/阻断），或 CDN 偶发断连，hyper 表现为「connection closed
        // before message completed」。原版 C# 的 SocketsHttpHandler 对连接级失败
        // 内建自动重试；此处对 GET/HEAD 对齐该语义：换一条新连接（重新竞速出站）再试。
        // 连接建立阶段（connect）失败不重试——竞速已穷尽全部候选，重试只会加倍超时。
        // 失败的候选经 mark_failed 短期降权，重试与其他后续请求不再优先选中它。
        let idempotent = matches!(parts.method, Method::GET | Method::HEAD);
        let header_wait = Duration::from_millis(target.timeout_ms.unwrap_or(30_000));
        // 只有「脚本注入」或「onResponse 钩子」需要完整 body 才能处理；
        // 其余情况一律流式转发（边收边发）——整包缓冲会让浏览器在大响应
        // 到齐前收不到任何字节，在带宽受限链路上表现为长时间白屏。
        let has_resp_hooks = self
            .hooks
            .as_ref()
            .is_some_and(|h| h.has_response_hooks(scripts));
        let mut body_opt = Some(body);
        for attempt in 0..2 {
            let (stream, winner) = connector
                .connect_tracked(&target)
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

            let req_body = body_opt.take().unwrap_or_else(|| {
                // 重试路径：GET/HEAD 实际无 body，补一个空的
                Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
            });
            let mut outbound_builder = Request::builder()
                .method(parts.method.clone())
                .uri(outbound_path.as_str());
            for (k, v) in &template_headers {
                outbound_builder = outbound_builder.header(k, v);
            }
            let outbound_req = outbound_builder.body(req_body).map_err(|e| e.to_string())?;

            // 响应头等待超时：把「僵尸候选静默挂死」从无限等待转为可重试错误。
            // 幂等请求（GET/HEAD）或小 body 请求适用；大 body 上传可能本身就很慢，不设限。
            // body 读取（collect）不设超时，避免误伤大文件下载。
            let small_body = outbound_req
                .body()
                .size_hint()
                .exact()
                .is_some_and(|n| n < 64 * 1024);
            let sent = if idempotent || small_body {
                match tokio::time::timeout(header_wait, sender.send_request(outbound_req)).await {
                    Ok(r) => r,
                    Err(_) => {
                        if let Some(a) = winner {
                            connector.mark_failed(a);
                        }
                        if attempt == 0 && idempotent {
                            tracing::warn!("上游响应头等待超时，换连接重试: {host}");
                            continue;
                        }
                        return Err(format!("等待上游响应头超时（{header_wait:?}）"));
                    }
                }
            } else {
                sender.send_request(outbound_req).await
            };

            match sent {
                Ok(resp) => {
                    let (mut resp_parts, resp_body) = resp.into_parts();
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

                    // 已知超大响应直接跳过脚本处理，保持流式转发：
                    // 否则整包缓冲会给内存带来无上限压力（脚本/钩子路径）。
                    let known_len = resp_parts
                        .headers
                        .get(hyper::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());
                    let too_large = known_len.is_some_and(|n| n > MAX_SCRIPT_BUFFER as u64);
                    if too_large && (has_resp_hooks || should_inject) {
                        tracing::warn!(
                            host = %host,
                            len = known_len.unwrap_or_default(),
                            limit = MAX_SCRIPT_BUFFER,
                            "响应体超过脚本处理上限，跳过注入/钩子并流式转发"
                        );
                    }
                    let should_inject = should_inject && !too_large;
                    let has_resp_hooks = has_resp_hooks && !too_large;

                    if !has_resp_hooks && !should_inject {
                        // —— 流式转发：边收边发，首字节随响应头立刻下发 ——
                        // Content-Length/Transfer-Encoding 交由 hyper 重新决定
                        // （body 长度未知 → chunked）。下行字节在 CountingBody
                        // 内累计，保持与整包路径一致的流量统计。
                        resp_parts.headers.remove(hyper::header::CONTENT_LENGTH);
                        resp_parts.headers.remove(hyper::header::TRANSFER_ENCODING);
                        return Ok(Response::from_parts(
                            resp_parts,
                            BoxBody::new(CountingBody {
                                inner: resp_body.boxed(),
                                stats: self.stats.clone(),
                                head_counted: false,
                            }),
                        ));
                    }

                    // —— 缓冲路径：脚本注入 / onResponse 钩子需要完整 body ——
                    // 加硬上限：Content-Length 未知（chunked）时也不能无限 collect；
                    // 超限则保留已读前缀 + 剩余流，跳过脚本处理后继续流式转发。
                    let mut body_bytes = match collect_with_limit(resp_body, MAX_SCRIPT_BUFFER).await
                    {
                        Ok(CollectOutcome::Complete(bytes)) => bytes,
                        Ok(CollectOutcome::Overflow { prefix, rest }) => {
                            tracing::warn!(
                                host = %host,
                                limit = MAX_SCRIPT_BUFFER,
                                "chunked 响应体超过脚本处理上限，跳过注入/钩子并流式转发"
                            );
                            let mut headers = resp_parts.headers.clone();
                            headers.remove(hyper::header::CONTENT_LENGTH);
                            headers.remove(hyper::header::TRANSFER_ENCODING);
                            let mut builder = Response::builder().status(resp_parts.status);
                            for (k, v) in headers.iter() {
                                builder = builder.header(k, v);
                            }
                            let stream = PrefixedBody {
                                prefix: Some(prefix),
                                rest,
                            };
                            return builder
                                .body(BoxBody::new(CountingBody {
                                    inner: BoxBody::new(stream),
                                    stats: self.stats.clone(),
                                    head_counted: false,
                                }))
                                .map_err(|e| e.to_string());
                        }
                        Err(e) => {
                            // 可重试 = 连接级失败：消息不完整（对端提前关闭）或 IO 错误
                            // （RST 等，hyper display 为「connection error」）。
                            // 注意 is_closed() 只匹配 ChannelClosed（我方通道关闭），不覆盖 Kind::Io。
                            let transient =
                                e.is_incomplete_message() || is_io_error(&e) || e.is_body_write_aborted();
                            if transient {
                                if let Some(a) = winner {
                                    connector.mark_failed(a);
                                }
                            }
                            if attempt == 0 && idempotent && transient {
                                tracing::warn!("出站连接中断，换连接重试: {host} ({e})");
                                continue;
                            }
                            return Err(format!("请求失败: {e}"));
                        }
                    };
                    self.stats.add_down(body_bytes.len() as u64 + 128);

                    // —— 服务端脚本 onResponse 钩子（Phase 4b 新增能力）——
                    // 二进制/压缩 body 跳过（UTF-8 约定：无法以字符串安全传递）
                    if let Some(hooks) = &self.hooks {
                        if hooks.has_response_hooks(scripts)
                            && std::str::from_utf8(&body_bytes).is_ok()
                        {
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
                                    tracing::debug!(
                                        "onResponse 钩子修改响应: {}",
                                        resp_parts.status
                                    );
                                }
                            }
                        }
                    }

                    // —— 脚本注入 ——
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
                                    .map(boxed_response)
                                    .map_err(|e| e.to_string());
                            }
                            Err(e) => {
                                tracing::warn!("脚本注入失败（原样返回）: {e}");
                            }
                        }
                    }

                    // 原样返回（缓冲路径）
                    let mut builder = Response::builder().status(resp_parts.status);
                    let mut headers = resp_parts.headers.clone();
                    headers.remove(hyper::header::CONTENT_LENGTH);
                    headers.remove(hyper::header::TRANSFER_ENCODING);
                    for (k, v) in headers.iter() {
                        builder = builder.header(k, v);
                    }
                    return builder
                        .body(Full::new(body_bytes))
                        .map(boxed_response)
                        .map_err(|e| e.to_string());
                }
                Err(e) => {
                    // 可重试 = 连接级失败：消息不完整（对端提前关闭）或 IO 错误
                    // （RST 等，hyper display 为「connection error」）。
                    // 注意 is_closed() 只匹配 ChannelClosed（我方通道关闭），不覆盖 Kind::Io。
                    let transient =
                        e.is_incomplete_message() || is_io_error(&e) || e.is_body_write_aborted();
                    if transient {
                        if let Some(a) = winner {
                            connector.mark_failed(a);
                        }
                    }
                    if attempt == 0 && idempotent && transient {
                        tracing::warn!("出站连接中断，换连接重试: {host} ({e})");
                        continue;
                    }
                    return Err(format!("请求失败: {e}"));
                }
            }
        }

        Err(format!("{host}: 出站重试后仍失败"))
    }

    /// 未匹配域名的全局二级代理转发
    async fn forward_global(
        &self,
        req: Request<Incoming>,
        scheme: &str,
        host: &str,
    ) -> Result<RelayResponse, String> {
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

/// 子规则正则缓存：云端规则正则固定，避免每请求重复编译。
/// 上限 2048，超限整体清空（规则集远小于此值）。
const MAX_RULE_REGEX_CACHE: usize = 2048;

fn regex_matches(pattern: &str, url: &str) -> bool {
    use once_cell::sync::Lazy;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: Lazy<Mutex<HashMap<String, Option<regex::Regex>>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));

    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = cache.get(pattern) {
        return cached.as_ref().is_some_and(|re| re.is_match(url));
    }
    let compiled = regex::Regex::new(pattern).ok();
    if cache.len() >= MAX_RULE_REGEX_CACHE {
        cache.clear();
    }
    let hit = compiled.as_ref().is_some_and(|re| re.is_match(url));
    cache.insert(pattern.to_string(), compiled);
    hit
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
///
/// 用 `append` 而非 `insert`：`Set-Cookie` 天然是多值的，`insert` 会让后一条
/// 覆盖前一条 —— 登录类响应常同时下发多个 cookie（session + csrf + waf token），
/// 被合并掉一个就会出现「登录成功但刷新即掉登录」。
fn headermap_from_pairs(pairs: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        match (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            (Ok(name), Ok(value)) => {
                map.append(name, value);
            }
            _ => {
                tracing::warn!("脚本修改的请求头无效，已跳过: {k}");
            }
        }
    }
    map
}

/// 构造出站请求头：`Host` 指向目标权威 + 透传原始头（跳过 hop-by-hop）。
///
/// 两条约束共同决定实现：
///
/// 1. **多值头不能用 `insert`**：HTTP/2 允许同一个头拆成多个字段
///    （RFC 9113 §8.2.3），`insert` 会让后一段覆盖前一段。原先此处用 `insert`
///    拷贝，使拆分后的 cookie 只剩最后一段 —— 典型症状是「加速后已登录站点
///    变未登录 / 刷新就掉登录」。
/// 2. **`Cookie` 必须合并成一条**：本链路出站恒为 HTTP/1.1（仅 `http1::handshake`），
///    而 RFC 7540 §8.1.2.5 要求多条 Cookie 在交给非 h2 上下文前用 `"; "` 拼成
///    单条，RFC 6265 §5.4 亦禁止客户端发出多于一个 `Cookie` 字段。若逐条透传，
///    上游（Java Servlet `getHeader`、部分 WAF）只会读到第一条，仍会丢 cookie。
///
/// 其余头一律 `append` 保序保留。`Host` 只允许一个值，故单独 `insert`。
fn build_outbound_headers(
    src: &HeaderMap,
    authority: &str,
) -> Result<HeaderMap, String> {
    let mut out = HeaderMap::new();
    out.insert(
        HOST,
        HeaderValue::from_str(authority).map_err(|e| e.to_string())?,
    );

    // 拆分后的 cookie 段，按原顺序用 "; " 拼回单条
    let mut cookie_parts: Vec<String> = Vec::new();
    // 收到的 Cookie 字段数（>1 说明下游确实拆过段，用于验证 h2 拆包假设）
    let mut cookie_fields = 0usize;

    for (k, v) in src.iter() {
        if k == HOST || is_hop_by_hop(k.as_str()) {
            continue;
        }
        if *k == COOKIE {
            cookie_fields += 1;
            match v.to_str() {
                Ok(s) => cookie_parts.push(s.to_string()),
                // 非可见 ASCII 的 cookie 极罕见：退回逐条透传，宁可多一条也不丢
                Err(_) => {
                    out.append(k.clone(), v.clone());
                }
            }
            continue;
        }
        out.append(k.clone(), v.clone());
    }

    if !cookie_parts.is_empty() {
        let joined = cookie_parts.join("; ");
        out.insert(
            COOKIE,
            HeaderValue::from_str(&joined).map_err(|e| e.to_string())?,
        );
        // 只在真的拆过段时记录，正常单条 Cookie 不产生噪音
        if cookie_fields > 1 {
            tracing::debug!(
                "合并拆分 Cookie：{cookie_fields} 个字段 → 1 条（{} 字节），host={authority}",
                joined.len()
            );
        }
    }

    Ok(out)
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
                tls_skip_verify: false,
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
///
/// `resolve_destination_pub` 为公开包装（供 upgrade 隧道的目标解析复用，
/// 保持两条路径的 destination 语义一致）。
pub fn resolve_destination_pub(
    scheme: &str,
    host: &str,
    original: Uri,
    destination: Option<&str>,
) -> Uri {
    resolve_destination(scheme, host, original, destination)
}

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

fn error_response(msg: &str) -> RelayResponse {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from(msg.to_string())))
        .map(boxed_response)
        .unwrap()
}

/// hyper 未公开 `Kind::Io` 判定（display 为「connection error」）。
/// 沿 cause 链找 `std::io::Error`——Body 类错误也会包裹底层 Io 错误。
fn is_io_error(e: &hyper::Error) -> bool {
    let mut src: &(dyn std::error::Error + 'static) = e;
    while let Some(s) = src.source() {
        if s.is::<std::io::Error>() {
            return true;
        }
        src = s;
    }
    false
}

/// 逐跳头（Connection 及其注册的头 + 常见逐跳头），代理转发时必须剥离
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
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
pub fn request_host<B>(req: &Request<B>) -> String {
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

fn not_found_response() -> RelayResponse {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .map(boxed_response)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prefixed_body_emits_prefix_then_rest() {
        let body = PrefixedBody {
            prefix: Some(Bytes::from_static(b"ab")),
            rest: Full::new(Bytes::from_static(b"cd")),
        };
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"abcd");
    }

    #[tokio::test]
    async fn collect_with_limit_overflow_keeps_prefix_and_rest() {
        use futures::stream;
        use http_body_util::StreamBody;

        let frames = vec![
            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"ab"))),
            Ok(Frame::data(Bytes::from_static(b"cd"))),
            Ok(Frame::data(Bytes::from_static(b"ef"))),
        ];
        let body = StreamBody::new(stream::iter(frames));
        match collect_with_limit(body, 3).await.unwrap() {
            CollectOutcome::Overflow { prefix, rest } => {
                assert_eq!(&prefix[..], b"abcd");
                let rest = rest.collect().await.unwrap().to_bytes();
                assert_eq!(&rest[..], b"ef");
            }
            CollectOutcome::Complete(_) => panic!("应判定为超限"),
        }
    }

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

    /// 下游 h2 把 Cookie 拆成多个字段（RFC 9113 §8.2.3）时，出站必须：
    /// ① 不丢任何一段（原先 `insert` 只留最后一段 → 掉登录）；
    /// ② 按 RFC 7540 §8.1.2.5 用 `"; "` 合并成**单条**，因为出站是 HTTP/1.1，
    ///    逐条透传会让只读第一条 `Cookie` 的服务端丢值。
    #[test]
    fn test_outbound_headers_merge_split_cookie_into_single_field() {
        let mut src = HeaderMap::new();
        src.append("cookie", HeaderValue::from_static("figma.sid=aaa"));
        src.append("cookie", HeaderValue::from_static("figma.csrf=bbb"));
        src.append("accept", HeaderValue::from_static("*/*"));

        let out = build_outbound_headers(&src, "www.figma.com").unwrap();
        let cookies: Vec<&str> = out
            .get_all(COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            vec!["figma.sid=aaa; figma.csrf=bbb"],
            "必须合并为单条 Cookie（顺序保持、值不丢）"
        );
        assert_eq!(out.get(HOST).unwrap(), "www.figma.com");
        assert_eq!(out.get("accept").unwrap(), "*/*");
    }

    /// 单条 Cookie 原样保留，不应被加上分隔符或改写
    #[test]
    fn test_outbound_headers_single_cookie_untouched() {
        let mut src = HeaderMap::new();
        src.insert(COOKIE, HeaderValue::from_static("a=1; b=2"));

        let out = build_outbound_headers(&src, "x.com").unwrap();
        let cookies: Vec<&str> = out
            .get_all(COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies, vec!["a=1; b=2"]);
    }

    /// 多值非 Cookie 头仍需逐条保留（如 `accept-language` 的等价多值），
    /// 合并规则只作用于 `Cookie`。
    #[test]
    fn test_outbound_headers_other_multi_value_kept_apart() {
        let mut src = HeaderMap::new();
        src.append("x-trace", HeaderValue::from_static("1"));
        src.append("x-trace", HeaderValue::from_static("2"));

        let out = build_outbound_headers(&src, "x.com").unwrap();
        let traces: Vec<&str> = out
            .get_all("x-trace")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(traces, vec!["1", "2"]);
    }

    #[test]
    fn test_outbound_headers_host_and_hop_by_hop() {
        let mut src = HeaderMap::new();
        src.insert(HOST, HeaderValue::from_static("origin.example"));
        src.insert("connection", HeaderValue::from_static("keep-alive"));
        src.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        src.insert("x-custom", HeaderValue::from_static("1"));

        let out = build_outbound_headers(&src, "target.example:443").unwrap();
        assert_eq!(out.get(HOST).unwrap(), "target.example:443");
        assert!(out.get("connection").is_none());
        assert!(out.get("transfer-encoding").is_none());
        assert_eq!(out.get("x-custom").unwrap(), "1");
    }

    /// 登录响应常一次下发多个 Set-Cookie（session / csrf / waf token），
    /// 快照还原也必须 append。
    #[test]
    fn test_headermap_from_pairs_keeps_multi_set_cookie() {
        let pairs = vec![
            ("set-cookie".to_string(), "a=1; Path=/".to_string()),
            ("set-cookie".to_string(), "b=2; Path=/".to_string()),
        ];
        let map = headermap_from_pairs(&pairs);
        let values: Vec<&str> = map
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["a=1; Path=/", "b=2; Path=/"]);
    }
}
