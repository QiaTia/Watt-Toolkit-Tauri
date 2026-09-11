//! 服务端脚本钩子引擎（Phase 4b：rquickjs/QuickJS）。
//!
//! 这是新增能力（原版无此 API）：脚本可导出 `onRequest(ctx)` / `onResponse(ctx)`
//! 在代理转发链路上修改请求/响应。
//!
//! JS 侧约定：
//! ```js
//! // 可选导出（检测 typeof === 'function' 才启用）
//! function onRequest(ctx) {
//!   // ctx: { method, url, headers: {小写名: 值}, body: string }
//!   // 返回 undefined → 放行
//!   // 返回 { redirect: "https://..." } → 302 重定向
//!   // 返回 { block: 403, body?: string } → 直接以该状态响应
//!   // 返回 { method?, url?, headers?, body? } → 修改请求
//! }
//! function onResponse(ctx) {
//!   // ctx: { status, headers, body: string }
//!   // 返回 undefined → 放行；返回 { status?, headers?, body? } → 修改
//! }
//! console.log/info/warn/error(...) → tracing
//! fetch(url, { method?, headers?, body? }) → { status, headers, body }（走出站链路）
//! ```
//!
//! 架构：每脚本一个专用 actor 线程（QuickJS 实例非 Send）。
//! - 调用方发送快照 + oneshot 回执，50ms 软超时后放弃结果降级放行
//! - 脚本异常/超时/队列繁忙均降级放行——**脚本错误绝不阻断转发**
//! - 内存上限 8MB/实例；死循环由 interrupt handler 强制打断
//! - body 以 UTF-8 传递（二进制 body 会被跳过修改）

use crate::model::ScriptConfig;
use rquickjs::function::{Func, Opt, Rest};
use rquickjs::{Context, Ctx, Function, Object, Runtime, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// 每钩子软超时（超时放弃结果、放行请求）
pub const HOOK_SOFT_TIMEOUT: Duration = Duration::from_millis(50);
/// 强制中断超时（interrupt handler 打断死循环）
const HOOK_HARD_TIMEOUT_MS: u64 = 200;
/// QuickJS 内存上限（字节）
const MEMORY_LIMIT: usize = 8 * 1024 * 1024;
/// 受限 fetch 出站超时
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// actor 初始化（eval 脚本）等待上限
const INIT_TIMEOUT: Duration = Duration::from_secs(5);

/* ================= 数据快照与结果 ================= */

/// 请求快照（转发前）
#[derive(Debug, Clone)]
pub struct RequestSnapshot {
    pub method: String,
    pub url: String,
    /// 头列表（保留原始大小写）
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 响应快照（转发后）
#[derive(Debug, Clone)]
pub struct ResponseSnapshot {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// onRequest 钩子结果
#[derive(Debug, Clone)]
pub enum RequestHookOutcome {
    /// 放行（未修改）
    Passthrough,
    /// 修改后的完整请求快照
    Modified(RequestSnapshot),
    /// 302 重定向
    Redirect { location: String },
    /// 直接以该状态响应（不转发）
    Block { status: u16, body: Vec<u8> },
}

/// onResponse 钩子结果
#[derive(Debug, Clone)]
pub enum ResponseHookOutcome {
    Passthrough,
    Modified(ResponseSnapshot),
}

/* ================= 受限 fetch ================= */

/// fetch 响应
#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// 受限 fetch 出站实现（由 watt-core 注入，走出站连接器/DNS 链）
pub trait HookFetch: Send + Sync + 'static {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        method: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> futures::future::BoxFuture<'a, Result<FetchResponse, String>>;
}

/* ================= 引擎 ================= */

struct ActorHandle {
    tx: std::sync::mpsc::SyncSender<Job>,
    has_on_request: bool,
    has_on_response: bool,
    /// interrupt deadline（ms 时间戳，0=不限）——Drop 时置 1 强制打断
    interrupt: Arc<AtomicU64>,
}

enum Job {
    Request {
        snapshot: RequestSnapshot,
        reply: tokio::sync::oneshot::Sender<Result<RequestHookOutcome, String>>,
    },
    Response {
        snapshot: ResponseSnapshot,
        reply: tokio::sync::oneshot::Sender<Result<ResponseHookOutcome, String>>,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
struct InitInfo {
    has_on_request: bool,
    has_on_response: bool,
}

/// 钩子引擎：管理每脚本 actor 线程。
pub struct HookEngine {
    actors: HashMap<String, ActorHandle>,
}

impl HookEngine {
    /// 创建引擎：读取脚本源码，为导出钩子的脚本启动 actor 线程。
    ///
    /// `fetch` 为受限 fetch 出站实现（None 则不暴露 fetch）。
    /// 初始化会阻塞等待每个脚本 eval（上限 5s/脚本），应在启动路径调用。
    pub fn new(scripts: &[ScriptConfig], fetch: Option<Arc<dyn HookFetch>>) -> Self {
        let mut actors = HashMap::new();
        let tokio_handle = tokio::runtime::Handle::try_current().ok();

        for script in scripts {
            let Ok(source) = std::fs::read_to_string(&script.cache_path) else {
                tracing::warn!("钩子脚本读取失败 {}: 跳过", script.cache_path);
                continue;
            };

            let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<Job>(16);
            let (init_tx, init_rx) = std::sync::mpsc::channel::<InitInfo>();
            let interrupt = Arc::new(AtomicU64::new(0));

            let builder =
                std::thread::Builder::new().name(format!("watt-hook-{}", script.local_id));
            let init_tx_c = init_tx.clone();
            let interrupt_c = interrupt.clone();
            let fetch_c = fetch.clone();
            let tokio_handle_c = tokio_handle.clone();
            let spawn_result = builder.spawn(move || {
                actor_loop(
                    source,
                    job_rx,
                    init_tx_c,
                    interrupt_c,
                    fetch_c,
                    tokio_handle_c,
                );
            });

            if spawn_result.is_err() {
                tracing::warn!("钩子线程启动失败: {}", script.local_id);
                continue;
            }

            // 等待初始化完成（eval + 导出检测）
            let info = match init_rx.recv_timeout(INIT_TIMEOUT) {
                Ok(info) => info,
                Err(_) => {
                    tracing::warn!("钩子脚本初始化超时: {}", script.local_id);
                    continue;
                }
            };

            if info.has_on_request || info.has_on_response {
                actors.insert(
                    script.local_id.clone(),
                    ActorHandle {
                        tx: job_tx,
                        has_on_request: info.has_on_request,
                        has_on_response: info.has_on_response,
                        interrupt,
                    },
                );
            }
            // 无钩子导出：线程收到 init 后自行退出
        }

        Self { actors }
    }

    /// 是否存在任意请求钩子（避免无谓 body 缓冲）
    pub fn has_request_hooks(&self, lids: &[String]) -> bool {
        lids.iter()
            .any(|l| self.actors.get(l).is_some_and(|a| a.has_on_request))
    }

    /// 是否存在任意响应钩子
    pub fn has_response_hooks(&self, lids: &[String]) -> bool {
        lids.iter()
            .any(|l| self.actors.get(l).is_some_and(|a| a.has_on_response))
    }

    /// 请求钩子管道：按 lid 顺序串行执行，修改累积传递。
    pub async fn on_request(
        &self,
        lids: &[String],
        snapshot: RequestSnapshot,
    ) -> RequestHookOutcome {
        let initial = snapshot.clone();
        let mut current = snapshot;
        let mut modified = false;

        for lid in lids {
            let Some(actor) = self.actors.get(lid) else {
                continue;
            };
            if !actor.has_on_request {
                continue;
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            if actor
                .tx
                .try_send(Job::Request {
                    snapshot: current.clone(),
                    reply: tx,
                })
                .is_err()
            {
                tracing::warn!("脚本 {lid} onRequest 队列繁忙，跳过");
                continue;
            }

            match tokio::time::timeout(HOOK_SOFT_TIMEOUT, rx).await {
                Ok(Ok(Ok(outcome))) => match outcome {
                    RequestHookOutcome::Passthrough => {}
                    RequestHookOutcome::Redirect { location } => {
                        return RequestHookOutcome::Redirect { location }
                    }
                    RequestHookOutcome::Block { status, body } => {
                        return RequestHookOutcome::Block { status, body }
                    }
                    RequestHookOutcome::Modified(snap) => {
                        current = snap;
                        modified = true;
                    }
                },
                Ok(Ok(Err(e))) => {
                    tracing::warn!("脚本 {lid} onRequest 异常（降级放行）: {e}");
                }
                Ok(Err(_)) => tracing::warn!("脚本 {lid} onRequest actor 掉线"),
                Err(_) => tracing::warn!("脚本 {lid} onRequest 超时（降级放行）"),
            }
        }

        if modified {
            RequestHookOutcome::Modified(current)
        } else {
            let _ = initial;
            RequestHookOutcome::Passthrough
        }
    }

    /// 响应钩子管道
    pub async fn on_response(
        &self,
        lids: &[String],
        snapshot: ResponseSnapshot,
    ) -> ResponseHookOutcome {
        let mut current = snapshot;
        let mut modified = false;

        for lid in lids {
            let Some(actor) = self.actors.get(lid) else {
                continue;
            };
            if !actor.has_on_response {
                continue;
            }

            let (tx, rx) = tokio::sync::oneshot::channel();
            if actor
                .tx
                .try_send(Job::Response {
                    snapshot: current.clone(),
                    reply: tx,
                })
                .is_err()
            {
                tracing::warn!("脚本 {lid} onResponse 队列繁忙，跳过");
                continue;
            }

            match tokio::time::timeout(HOOK_SOFT_TIMEOUT, rx).await {
                Ok(Ok(Ok(outcome))) => match outcome {
                    ResponseHookOutcome::Passthrough => {}
                    ResponseHookOutcome::Modified(snap) => {
                        current = snap;
                        modified = true;
                    }
                },
                Ok(Ok(Err(e))) => {
                    tracing::warn!("脚本 {lid} onResponse 异常（降级放行）: {e}");
                }
                Ok(Err(_)) => tracing::warn!("脚本 {lid} onResponse actor 掉线"),
                Err(_) => tracing::warn!("脚本 {lid} onResponse 超时（降级放行）"),
            }
        }

        if modified {
            ResponseHookOutcome::Modified(current)
        } else {
            ResponseHookOutcome::Passthrough
        }
    }
}

impl Drop for HookEngine {
    fn drop(&mut self) {
        for (lid, actor) in &self.actors {
            // 置 1（已过期）强制打断 JS 执行，线程随后收到 Shutdown 退出
            actor.interrupt.store(1, Ordering::Relaxed);
            if actor.tx.try_send(Job::Shutdown).is_err() {
                tracing::warn!("钩子线程 {lid} 关闭信号发送失败（detached）");
            }
        }
    }
}

/* ================= actor 线程 ================= */

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn actor_loop(
    source: String,
    job_rx: std::sync::mpsc::Receiver<Job>,
    init_tx: std::sync::mpsc::Sender<InitInfo>,
    interrupt: Arc<AtomicU64>,
    fetch: Option<Arc<dyn HookFetch>>,
    tokio_handle: Option<tokio::runtime::Handle>,
) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("QuickJS Runtime 创建失败: {e}");
            let _ = init_tx.send(InitInfo {
                has_on_request: false,
                has_on_response: false,
            });
            return;
        }
    };
    rt.set_memory_limit(MEMORY_LIMIT);
    {
        let interrupt = interrupt.clone();
        rt.set_interrupt_handler(Some(Box::new(move || {
            let deadline = interrupt.load(Ordering::Relaxed);
            deadline != 0 && now_ms() > deadline
        })));
    }

    let ctx = match Context::full(&rt) {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::error!("QuickJS Context 创建失败: {e}");
            let _ = init_tx.send(InitInfo {
                has_on_request: false,
                has_on_response: false,
            });
            return;
        }
    };

    // 初始化：console/fetch + eval 脚本 + 导出检测
    let init_result: Result<InitInfo, rquickjs::Error> = ctx.with(|ctx| {
        setup_console(&ctx)?;
        if let (Some(fetch), Some(handle)) = (&fetch, &tokio_handle) {
            setup_fetch(&ctx, fetch.clone(), handle.clone())?;
        }
        ctx.eval::<(), _>(source.as_bytes())?;

        let globals = ctx.globals();
        let has_on_request = is_callable(&globals, "onRequest");
        let has_on_response = is_callable(&globals, "onResponse");
        Ok(InitInfo {
            has_on_request,
            has_on_response,
        })
    });

    let info = match init_result {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!("钩子脚本 eval 失败: {e}");
            InitInfo {
                has_on_request: false,
                has_on_response: false,
            }
        }
    };
    if init_tx.send(info.clone()).is_err() {
        return; // 引擎已丢弃
    }
    if !info.has_on_request && !info.has_on_response {
        return; // 无钩子导出，退出线程
    }

    // job 循环
    while let Ok(job) = job_rx.recv() {
        match job {
            Job::Request { snapshot, reply } => {
                interrupt.store(now_ms() + HOOK_HARD_TIMEOUT_MS, Ordering::Relaxed);
                let result = ctx.with(|ctx| call_request_hook(&ctx, &snapshot));
                interrupt.store(0, Ordering::Relaxed);
                let _ = reply.send(result);
            }
            Job::Response { snapshot, reply } => {
                interrupt.store(now_ms() + HOOK_HARD_TIMEOUT_MS, Ordering::Relaxed);
                let result = ctx.with(|ctx| call_response_hook(&ctx, &snapshot));
                interrupt.store(0, Ordering::Relaxed);
                let _ = reply.send(result);
            }
            Job::Shutdown => break,
        }
    }
}

fn is_callable(globals: &Object<'_>, name: &str) -> bool {
    globals
        .get::<_, Function>(name)
        .map(|f| f.is_function())
        .unwrap_or(false)
}

/* ================= 钩子调用与返回值解析 ================= */

fn call_request_hook(
    ctx: &Ctx<'_>,
    snapshot: &RequestSnapshot,
) -> Result<RequestHookOutcome, String> {
    let func: Function = ctx
        .globals()
        .get("onRequest")
        .map_err(|_| "onRequest 不可用".to_string())?;

    let js_ctx = build_request_ctx(ctx, snapshot).map_err(|e| e.to_string())?;
    let result: Value = func
        .call((js_ctx,))
        .map_err(|e| format!("onRequest 调用失败: {e}"))?;
    parse_request_outcome(result, snapshot)
}

fn call_response_hook(
    ctx: &Ctx<'_>,
    snapshot: &ResponseSnapshot,
) -> Result<ResponseHookOutcome, String> {
    let func: Function = ctx
        .globals()
        .get("onResponse")
        .map_err(|_| "onResponse 不可用".to_string())?;

    let js_ctx = build_response_ctx(ctx, snapshot).map_err(|e| e.to_string())?;
    let result: Value = func
        .call((js_ctx,))
        .map_err(|e| format!("onResponse 调用失败: {e}"))?;
    parse_response_outcome(result, snapshot)
}

/// 构建 onRequest 的 ctx 对象
fn build_request_ctx<'js>(
    ctx: &Ctx<'js>,
    snapshot: &RequestSnapshot,
) -> Result<Object<'js>, rquickjs::Error> {
    let obj = Object::new(ctx.clone())?;
    obj.set("method", snapshot.method.clone())?;
    obj.set("url", snapshot.url.clone())?;
    let headers = Object::new(ctx.clone())?;
    for (k, v) in &snapshot.headers {
        headers.set(k.to_ascii_lowercase(), v.clone())?;
    }
    obj.set("headers", headers)?;
    // body 以 UTF-8 传递（二进制不安全场景由调用方跳过）
    obj.set("body", String::from_utf8_lossy(&snapshot.body).to_string())?;
    Ok(obj)
}

/// 构建 onResponse 的 ctx 对象
fn build_response_ctx<'js>(
    ctx: &Ctx<'js>,
    snapshot: &ResponseSnapshot,
) -> Result<Object<'js>, rquickjs::Error> {
    let obj = Object::new(ctx.clone())?;
    obj.set("status", snapshot.status)?;
    let headers = Object::new(ctx.clone())?;
    for (k, v) in &snapshot.headers {
        headers.set(k.to_ascii_lowercase(), v.clone())?;
    }
    obj.set("headers", headers)?;
    obj.set("body", String::from_utf8_lossy(&snapshot.body).to_string())?;
    Ok(obj)
}

fn parse_request_outcome(
    result: Value,
    original: &RequestSnapshot,
) -> Result<RequestHookOutcome, String> {
    if result.is_undefined() || result.is_null() {
        return Ok(RequestHookOutcome::Passthrough);
    }
    let obj = result
        .into_object()
        .ok_or_else(|| "onRequest 返回值必须为对象或 undefined".to_string())?;

    // redirect: string
    if let Some(location) = obj
        .get::<_, Option<String>>("redirect")
        .map_err(|e| e.to_string())?
    {
        return Ok(RequestHookOutcome::Redirect { location });
    }

    // block: number + body?: string
    if let Some(status) = obj
        .get::<_, Option<u16>>("block")
        .map_err(|e| e.to_string())?
    {
        let body = obj
            .get::<_, Option<String>>("body")
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        return Ok(RequestHookOutcome::Block {
            status,
            body: body.into_bytes(),
        });
    }

    // 修改字段：未提供的字段继承原快照
    let method = obj
        .get::<_, Option<String>>("method")
        .map_err(|e| e.to_string())?;
    let url = obj
        .get::<_, Option<String>>("url")
        .map_err(|e| e.to_string())?;
    let headers = obj
        .get::<_, Option<Object>>("headers")
        .map_err(|e| e.to_string())?
        .map(object_to_headers)
        .transpose()?;
    let body = obj
        .get::<_, Option<String>>("body")
        .map_err(|e| e.to_string())?
        .map(String::into_bytes);

    if method.is_none() && url.is_none() && headers.is_none() && body.is_none() {
        return Ok(RequestHookOutcome::Passthrough);
    }

    let mut snap = original.clone();
    if let Some(m) = method {
        snap.method = m;
    }
    if let Some(u) = url {
        snap.url = u;
    }
    if let Some(h) = headers {
        snap.headers = h;
    }
    if let Some(b) = body {
        snap.body = b;
    }
    Ok(RequestHookOutcome::Modified(snap))
}

fn parse_response_outcome(
    result: Value,
    original: &ResponseSnapshot,
) -> Result<ResponseHookOutcome, String> {
    if result.is_undefined() || result.is_null() {
        return Ok(ResponseHookOutcome::Passthrough);
    }
    let obj = result
        .into_object()
        .ok_or_else(|| "onResponse 返回值必须为对象或 undefined".to_string())?;

    let status = obj
        .get::<_, Option<u16>>("status")
        .map_err(|e| e.to_string())?;
    let headers = obj
        .get::<_, Option<Object>>("headers")
        .map_err(|e| e.to_string())?
        .map(object_to_headers)
        .transpose()?;
    let body = obj
        .get::<_, Option<String>>("body")
        .map_err(|e| e.to_string())?
        .map(String::into_bytes);

    if status.is_none() && headers.is_none() && body.is_none() {
        return Ok(ResponseHookOutcome::Passthrough);
    }

    let mut snap = original.clone();
    if let Some(s) = status {
        snap.status = s;
    }
    if let Some(h) = headers {
        snap.headers = h;
    }
    if let Some(b) = body {
        snap.body = b;
    }
    Ok(ResponseHookOutcome::Modified(snap))
}

/// Object → header 列表（空对象/空字段由上层合并处理）
fn object_to_headers(obj: Object<'_>) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for prop in obj.props::<String, String>() {
        let (k, v) = prop.map_err(|e| e.to_string())?;
        out.push((k, v));
    }
    Ok(out)
}

/* ================= console 与 fetch ================= */

/// 注意：`Ctx`/`Value` 等类型对 `'js` 是不变的（invariant），
/// 因此所有 JS 值参数必须共享同一个命名生命周期（由外层泛型函数提供），
/// 不能在闭包参数里各写各的 `'_`。
fn setup_console<'js>(ctx: &Ctx<'js>) -> Result<(), rquickjs::Error> {
    let global = ctx.globals();
    let console = Object::new(ctx.clone())?;

    console.set(
        "log",
        Func::from(|ctx: Ctx<'js>, args: Rest<Value<'js>>| {
            tracing::info!(target: "watt_script::console", "{}", join_args(&ctx, &args));
            Ok::<(), rquickjs::Error>(())
        }),
    )?;
    console.set(
        "info",
        Func::from(|ctx: Ctx<'js>, args: Rest<Value<'js>>| {
            tracing::info!(target: "watt_script::console", "{}", join_args(&ctx, &args));
            Ok::<(), rquickjs::Error>(())
        }),
    )?;
    console.set(
        "warn",
        Func::from(|ctx: Ctx<'js>, args: Rest<Value<'js>>| {
            tracing::warn!(target: "watt_script::console", "{}", join_args(&ctx, &args));
            Ok::<(), rquickjs::Error>(())
        }),
    )?;
    console.set(
        "error",
        Func::from(|ctx: Ctx<'js>, args: Rest<Value<'js>>| {
            tracing::error!(target: "watt_script::console", "{}", join_args(&ctx, &args));
            Ok::<(), rquickjs::Error>(())
        }),
    )?;

    global.set("console", console)?;
    Ok(())
}

fn join_args<'js>(ctx: &Ctx<'js>, args: &Rest<Value<'js>>) -> String {
    let mut parts = Vec::with_capacity(args.len());
    for v in args.iter() {
        parts.push(value_to_display(ctx, v));
    }
    parts.join(" ")
}

fn value_to_display<'js>(ctx: &Ctx<'js>, v: &Value<'js>) -> String {
    use rquickjs::FromJs;
    // JS ToString 强转（对齐 console 语义：数字/布尔/对象均可显示）
    if let Ok(s) = <rquickjs::Coerced<String>>::from_js(ctx, v.clone()) {
        return s.0;
    }
    match v.type_of() {
        rquickjs::Type::Undefined => "undefined".into(),
        rquickjs::Type::Null => "null".into(),
        _ => v.type_name().to_string(),
    }
}

/// 受限 fetch：同步返回（内部 block_on 出站）
fn setup_fetch<'js>(
    ctx: &Ctx<'js>,
    fetch: Arc<dyn HookFetch>,
    handle: tokio::runtime::Handle,
) -> Result<(), rquickjs::Error> {
    let global = ctx.globals();

    let fetch_fn = Func::from(move |ctx: Ctx<'js>, url: String, opts: Opt<Object<'js>>| {
        // 仅允许 http/https
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(rquickjs::Exception::throw_message(
                &ctx,
                "fetch 仅支持 http/https URL",
            ));
        }

        let method = opts
            .0
            .as_ref()
            .and_then(|o| o.get::<_, String>("method").ok())
            .unwrap_or_else(|| "GET".to_string())
            .to_ascii_uppercase();
        let headers: Vec<(String, String)> = opts
            .0
            .as_ref()
            .and_then(|o| o.get::<_, Object<'js>>("headers").ok())
            .and_then(|h| object_to_headers(h).ok())
            .unwrap_or_default();
        let body: Vec<u8> = opts
            .0
            .as_ref()
            .and_then(|o| o.get::<_, String>("body").ok())
            .map(String::into_bytes)
            .unwrap_or_default();

        let fut = fetch.fetch(&url, &method, &headers, &body);
        // block_on 在 timeout 内执行（顺序不可颠倒：block_on 阻塞至 future 完成）
        let result = handle.block_on(tokio::time::timeout(FETCH_TIMEOUT, fut));

        match result {
            Ok(Ok(resp)) => build_fetch_result(&ctx, resp),
            Ok(Err(e)) => Err(rquickjs::Exception::throw_message(
                &ctx,
                &format!("fetch 失败: {e}"),
            )),
            Err(_) => Err(rquickjs::Exception::throw_message(&ctx, "fetch 超时")),
        }
    });

    global.set("fetch", fetch_fn)?;
    Ok(())
}

fn build_fetch_result<'js>(
    ctx: &Ctx<'js>,
    resp: FetchResponse,
) -> Result<Object<'js>, rquickjs::Error> {
    let obj = Object::new(ctx.clone())?;
    obj.set("status", resp.status)?;
    let headers = Object::new(ctx.clone())?;
    for (k, v) in resp.headers {
        headers.set(k.to_ascii_lowercase(), v)?;
    }
    obj.set("headers", headers)?;
    obj.set("body", String::from_utf8_lossy(&resp.body).to_string())?;
    Ok(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_script(content: &str) -> (tempfile::TempDir, ScriptConfig) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.js");
        std::fs::write(&path, content).unwrap();
        let config = ScriptConfig {
            local_id: "1".into(),
            cache_path: path.to_string_lossy().to_string(),
            match_domain_names: vec!["example.com".into()],
            exclude_domain_names: vec![],
            order: 0,
        };
        (dir, config)
    }

    fn req_snapshot() -> RequestSnapshot {
        RequestSnapshot {
            method: "GET".into(),
            url: "https://example.com/page".into(),
            headers: vec![("User-Agent".into(), "test".into())],
            body: Vec::new(),
        }
    }

    fn resp_snapshot() -> ResponseSnapshot {
        ResponseSnapshot {
            status: 200,
            headers: vec![("Content-Type".into(), "text/html".into())],
            body: b"<html></html>".to_vec(),
        }
    }

    #[tokio::test]
    async fn test_on_request_modify() {
        let (_dir, script) = write_script(
            r#"
            function onRequest(ctx) {
                if (ctx.url.indexOf("/page") >= 0) {
                    return { method: "POST", body: "modified" };
                }
            }
            "#,
        );
        let engine = HookEngine::new(&[script], None);
        let outcome = engine.on_request(&["1".to_string()], req_snapshot()).await;
        match outcome {
            RequestHookOutcome::Modified(snap) => {
                assert_eq!(snap.method, "POST");
                assert_eq!(snap.body, b"modified".to_vec());
            }
            other => panic!("期望 Modified，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_on_request_redirect_and_block() {
        let (_dir, script) = write_script(
            r#"
            function onRequest(ctx) {
                if (ctx.url.indexOf("/redirect-me") >= 0) {
                    return { redirect: "https://other.com/" };
                }
                if (ctx.url.indexOf("/blocked") >= 0) {
                    return { block: 403, body: "forbidden" };
                }
            }
            "#,
        );
        let engine = HookEngine::new(&[script], None);

        let mut snap = req_snapshot();
        snap.url = "https://example.com/redirect-me".into();
        match engine.on_request(&["1".to_string()], snap).await {
            RequestHookOutcome::Redirect { location } => {
                assert_eq!(location, "https://other.com/");
            }
            other => panic!("期望 Redirect，实际 {other:?}"),
        }

        let mut snap = req_snapshot();
        snap.url = "https://example.com/blocked".into();
        match engine.on_request(&["1".to_string()], snap).await {
            RequestHookOutcome::Block { status, body } => {
                assert_eq!(status, 403);
                assert_eq!(body, b"forbidden".to_vec());
            }
            other => panic!("期望 Block，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_passthrough_on_undefined_and_error() {
        // undefined 返回 → 放行
        let (_dir, script) = write_script("function onRequest(ctx) { /* noop */ }");
        let engine = HookEngine::new(&[script], None);
        assert!(matches!(
            engine.on_request(&["1".to_string()], req_snapshot()).await,
            RequestHookOutcome::Passthrough
        ));

        // 异常 → 降级放行
        let (_dir, script) = write_script("function onRequest(ctx) { throw new Error('boom'); }");
        let engine = HookEngine::new(&[script], None);
        assert!(matches!(
            engine.on_request(&["1".to_string()], req_snapshot()).await,
            RequestHookOutcome::Passthrough
        ));
    }

    #[tokio::test]
    async fn test_on_response_modify() {
        let (_dir, script) = write_script(
            r#"
            function onResponse(ctx) {
                if (ctx.body.indexOf("<html>") === 0) {
                    return { status: 200, body: ctx.body + "<!-- hooked -->" };
                }
            }
            "#,
        );
        let engine = HookEngine::new(&[script], None);
        let outcome = engine
            .on_response(&["1".to_string()], resp_snapshot())
            .await;
        match outcome {
            ResponseHookOutcome::Modified(snap) => {
                assert_eq!(snap.body, b"<html></html><!-- hooked -->".to_vec());
            }
            other => panic!("期望 Modified，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_no_hook_script_not_registered() {
        // 无钩子导出的脚本不注册 actor（正常社区脚本）
        let (_dir, script) = write_script("console.log('browser-only script');");
        let engine = HookEngine::new(&[script], None);
        assert!(!engine.has_request_hooks(&["1".to_string()]));
        assert!(!engine.has_response_hooks(&["1".to_string()]));
        assert!(matches!(
            engine.on_request(&["1".to_string()], req_snapshot()).await,
            RequestHookOutcome::Passthrough
        ));
    }

    #[tokio::test]
    async fn test_deadloop_timeout_degrades() {
        // 死循环脚本：软超时降级放行（50ms 后放弃）
        let (_dir, script) = write_script("function onRequest(ctx) { while(true) {} }");
        let engine = HookEngine::new(&[script], None);
        let start = std::time::Instant::now();
        let outcome = engine.on_request(&["1".to_string()], req_snapshot()).await;
        assert!(matches!(outcome, RequestHookOutcome::Passthrough));
        // 50ms 软超时 + 缓冲
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "超时耗时异常: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn test_console_and_header_context() {
        // ctx.headers 小写化可读
        let (_dir, script) = write_script(
            r#"
            var captured = {};
            function onRequest(ctx) {
                captured.userAgent = ctx.headers["user-agent"];
                return { headers: { "x-custom": "yes" } };
            }
            function getCaptured() { return captured; }
            "#,
        );
        let engine = HookEngine::new(&[script], None);
        let outcome = engine.on_request(&["1".to_string()], req_snapshot()).await;
        match outcome {
            RequestHookOutcome::Modified(snap) => {
                assert!(snap
                    .headers
                    .iter()
                    .any(|(k, v)| k == "x-custom" && v == "yes"));
            }
            other => panic!("期望 Modified，实际 {other:?}"),
        }
    }
}
