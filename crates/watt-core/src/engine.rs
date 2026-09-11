//! 代理引擎：启停编排（对齐 ProxyService.Operate / YarpReverseProxyServiceImpl）。
//!
//! 启动时序（对齐 C#）：
//! 1. 模式前置：Hosts → 443 端口预检（Windows 报占用进程名）；
//!    System → 注册表系统代理（失败即中止）；PAC → AutoConfigURL。
//! 2. 构建规则/脚本上下文 → 按模式绑定监听：
//!    - Hosts：443 MITM（+可选 80 重定向）
//!    - System/PAC/ProxyOnly：正向代理端口（CONNECT 隧道/绝对 URI/PAC 端点）
//!    - SOCKS5：可选，与模式无关
//! 3. Hosts 模式：监听启动后写 hosts（失败回滚停止，对齐 C#）。
//!
//! 停止时序：摘除 hosts（失败阻止停止）→ 取消系统代理/PAC → 关闭监听。

use crate::http_relay::RelayContext;
use crate::listener::{run_http_listener, run_mitm_listener, run_socks5_listener};
use crate::local_domain::LocalDomainHandler;
use crate::outbound::UpstreamProxy;
use crate::sni::mitm_tls_acceptor;
use crate::stats::FlowStats;
use std::net::IpAddr;
use std::sync::Arc;
use watt_cert::ca::CaCertificate;
use watt_config::{DomainRule, ProxyMode, TwoLevelAgentSettings};
use watt_script::ScriptConfig;

/// 引擎状态
#[derive(Debug, Clone, PartialEq)]
pub enum EngineState {
    Stopped,
    Starting,
    Running {
        started_at: chrono::DateTime<chrono::Utc>,
        mode: ProxyMode,
    },
    Stopping,
    Error(String),
}

/// 引擎配置（启动时全量传入）
pub struct EngineConfig {
    pub mode: ProxyMode,
    /// 监听 IP（默认 127.0.0.1）
    pub listen_ip: IpAddr,
    /// HTTPS MITM 端口（默认 443；Hosts 模式）
    pub https_port: u16,
    /// HTTP→HTTPS 重定向端口（默认 None=不启用；Hosts 模式）
    pub http_port: Option<u16>,
    /// 正向代理端口（System/PAC/ProxyOnly 模式，默认 26501）
    pub forward_proxy_port: u16,
    /// SOCKS5 端口
    pub socks5_port: Option<u16>,
    pub enable_http_to_https: bool,
    pub only_enable_proxy_script: bool,
    pub is_only_work_steam_browser: bool,
    pub two_level_agent: TwoLevelAgentSettings,
    pub dns: watt_dns::DnsConfig,
    pub server_side_proxy_token: Option<String>,
    /// 域名规则
    pub rules: Vec<DomainRule>,
    /// 启用脚本
    pub scripts: Vec<ScriptConfig>,
    /// CA 证书
    pub ca: Arc<CaCertificate>,
    /// hosts 文件路径（None=系统默认；测试注入）
    pub hosts_path: Option<std::path::PathBuf>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Hosts,
            listen_ip: IpAddr::from([127, 0, 0, 1]),
            https_port: watt_config::constants::HTTPS_PORT,
            http_port: None,
            forward_proxy_port: watt_config::constants::DEFAULT_HTTP_PROXY_PORT,
            socks5_port: None,
            enable_http_to_https: false,
            only_enable_proxy_script: false,
            is_only_work_steam_browser: false,
            two_level_agent: TwoLevelAgentSettings::default(),
            dns: watt_dns::DnsConfig::default(),
            server_side_proxy_token: None,
            rules: Vec::new(),
            scripts: Vec::new(),
            ca: Arc::new(CaCertificate::generate().expect("CA 生成失败")),
            hosts_path: None,
        }
    }
}

/// 代理引擎
pub struct ProxyEngine {
    state: tokio::sync::watch::Sender<EngineState>,
    state_rx: tokio::sync::watch::Receiver<EngineState>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    stats: Arc<FlowStats>,
    running_task: Option<tokio::task::JoinHandle<()>>,
    /// 运行中模式（停止时用于模式化清理）
    running_mode: Option<ProxyMode>,
    /// 本次运行写入的 hosts 文件路径（未写入为 None）
    hosts_written: Option<std::path::PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("端口 {0} 被占用: {1}")]
    BindPortError(u16, String),
    #[error("引擎已在运行")]
    AlreadyRunning,
    #[error("引擎未运行")]
    NotRunning,
    #[error("{0}")]
    Other(String),
}

impl ProxyEngine {
    pub fn new() -> Self {
        let (state_tx, state_rx) = tokio::sync::watch::channel(EngineState::Stopped);
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        Self {
            state: state_tx,
            state_rx,
            shutdown_tx,
            stats: Arc::new(FlowStats::default()),
            running_task: None,
            running_mode: None,
            hosts_written: None,
        }
    }

    pub fn state(&self) -> EngineState {
        self.state_rx.borrow().clone()
    }

    pub fn subscribe_state(&self) -> tokio::sync::watch::Receiver<EngineState> {
        self.state_rx.clone()
    }

    pub fn stats(&self) -> Arc<FlowStats> {
        self.stats.clone()
    }

    /// 异常退出兜底清理（应用启动 / 引擎启动前调用）。
    ///
    /// 进程被强杀、崩溃或开发期热重启时，`hosts_written` / `running_mode` 这些
    /// 运行态记忆随进程消失，但 **hosts 标记块与系统代理是持久化的**，于是会出现
    /// 致命的不一致：Hosts 模式已写下 `域名 → 127.0.0.1`，却没有任何进程监听 443，
    /// 浏览器访问 github/steam 得到「连接被拒绝 / 找不到此网页」。
    ///
    /// 这里只清理确定属于自己的残留：hosts 标记块（`# Steam++ Start/End`），
    /// 以及指向本引擎端口（`proxy_ports`）的系统代理 / PAC，避免误清其他代理软件。
    ///
    /// 返回已清理项，供上层记录日志。
    pub fn cleanup_orphans(
        &self,
        hosts_path: Option<&std::path::Path>,
        proxy_ports: &[u16],
    ) -> Vec<String> {
        let mut cleaned = Vec::new();

        // —— 1. hosts 标记块残留 ——
        let manager = hosts_manager(hosts_path);
        if manager.contains_mark() {
            match manager.remove_hosts_by_tag() {
                Ok(()) => cleaned.push(format!("hosts({})", manager.path().display())),
                Err(e) => tracing::warn!("清理 hosts 残留失败: {e}"),
            }
        }

        // —— 2. 系统代理 / PAC 残留（仅当指向本引擎端口）——
        let (enabled, server, pac_url) = crate::system_proxy::get_system_proxy_status();
        if enabled {
            if let Some(addr) = server.as_deref() {
                if is_own_proxy_addr(addr, proxy_ports) {
                    match crate::system_proxy::set_system_proxy(false, "", 0) {
                        Ok(()) => cleaned.push(format!("system_proxy({addr})")),
                        Err(e) => tracing::warn!("清理系统代理残留失败: {e}"),
                    }
                }
            }
        }
        if let Some(url) = pac_url.as_deref() {
            if !url.is_empty() && is_own_proxy_addr(url, proxy_ports) {
                match crate::system_proxy::set_system_pac(false, "") {
                    Ok(()) => cleaned.push(format!("pac({url})")),
                    Err(e) => tracing::warn!("清理 PAC 残留失败: {e}"),
                }
            }
        }

        cleaned
    }

    /// 进程退出前清理（应用 `RunEvent::Exit` 调用）：
    /// 运行中 → 走正常 `stop`（摘 hosts + 取消系统代理 + 关监听）；
    /// 否则 → 兜底摘除残留，保证退出后本机不留黑洞。
    pub async fn shutdown(&mut self, hosts_path: Option<&std::path::Path>, proxy_ports: &[u16]) {
        if matches!(self.state(), EngineState::Running { .. }) {
            if self.stop().await.is_ok() {
                return;
            }
            tracing::warn!("退出时停止引擎失败，转为兜底清理");
        }
        let cleaned = self.cleanup_orphans(hosts_path, proxy_ports);
        if !cleaned.is_empty() {
            tracing::warn!("退出清理残留代理状态: {}", cleaned.join(", "));
        }
    }

    /// 端口占用预检（对齐原实现启动前检查；绑定失败时带进程名诊断）
    async fn check_port_available(ip: IpAddr, port: u16) -> Result<(), EngineError> {
        match tokio::net::TcpListener::bind((ip, port)).await {
            Ok(_) => Ok(()),
            Err(e) => Err(EngineError::BindPortError(
                port,
                describe_bind_error(e, port),
            )),
        }
    }

    /// 模式前置后的绑定（失败时回滚系统代理设置并置 Error 状态）
    async fn bind_or_fail(
        &self,
        mode: ProxyMode,
        ip: IpAddr,
        port: u16,
    ) -> Result<tokio::net::TcpListener, EngineError> {
        tokio::net::TcpListener::bind((ip, port))
            .await
            .map_err(|e| {
                revert_proxy_settings(mode);
                let err = EngineError::BindPortError(port, describe_bind_error(e, port));
                self.state.send_replace(EngineState::Error(err.to_string()));
                err
            })
    }

    /// 启动引擎
    pub async fn start(&mut self, config: EngineConfig) -> Result<(), EngineError> {
        if matches!(self.state_rx.borrow().clone(), EngineState::Running { .. }) {
            return Err(EngineError::AlreadyRunning);
        }

        self.state.send_replace(EngineState::Starting);
        let mode = config.mode;

        // —— 0. 启动前兜底清理 ——
        // 上次异常退出可能残留 hosts 标记块 / 系统代理：若不清掉，Hosts 模式下会先看到
        // 「域名指向 127.0.0.1 但 443 尚未监听」的短暂黑洞，其他模式则会残留误导性的
        // hosts 劫持（域名走本地却无服务）。这里统一摘除，随后按模式重新接入。
        let cleaned = self.cleanup_orphans(config.hosts_path.as_deref(), &[config.forward_proxy_port]);
        if !cleaned.is_empty() {
            tracing::info!("启动前清理残留代理状态: {}", cleaned.join(", "));
        }

        // —— 1. 模式前置（对齐 C# switch(proxyMode)）——
        // 系统代理/PAC 地址回退：0.0.0.0 → 127.0.0.1（注册表/PAC 不接受 unspecified）
        let proxy_ip = if config.listen_ip.is_unspecified() {
            IpAddr::from([127, 0, 0, 1])
        } else {
            config.listen_ip
        };
        match mode {
            ProxyMode::Hosts => {
                Self::check_port_available(config.listen_ip, config.https_port).await?;
            }
            ProxyMode::System => {
                if let Err(e) = crate::system_proxy::set_system_proxy(
                    true,
                    &proxy_ip.to_string(),
                    config.forward_proxy_port,
                ) {
                    let msg = format!("设置系统代理失败: {e}");
                    self.state.send_replace(EngineState::Error(msg.clone()));
                    return Err(EngineError::Other(msg));
                }
            }
            ProxyMode::Pac => {
                let pac_url = format!(
                    "http://{}/pac",
                    authority(&proxy_ip, config.forward_proxy_port)
                );
                if let Err(e) = crate::system_proxy::set_system_pac(true, &pac_url) {
                    let msg = format!("设置 PAC 系统代理失败: {e}");
                    self.state.send_replace(EngineState::Error(msg.clone()));
                    return Err(EngineError::Other(msg));
                }
            }
            ProxyMode::ProxyOnly => {}
        }

        // —— 2. 构建运行时上下文 ——
        let rules = watt_config::DomainRules::new(config.rules.clone());
        let upstream = UpstreamProxy::from_settings(&config.two_level_agent);
        let local = LocalDomainHandler::new(config.scripts.clone());
        let dns = Arc::new(watt_dns::DnsResolver::with_config(config.dns.clone()));

        // 服务端脚本钩子引擎（Phase 4b）：为导出 onRequest/onResponse 的脚本启动 actor
        let fetch: Arc<dyn watt_script::hooks::HookFetch> = Arc::new(
            crate::http_relay::RelayFetch::new(dns.clone(), upstream.clone()),
        );
        let hooks = Arc::new(watt_script::hooks::HookEngine::new(
            &config.scripts,
            Some(fetch),
        ));

        let two_level_agent_enable = config.two_level_agent.enable && upstream.is_some();
        let ctx = Arc::new(RelayContext {
            rules,
            local,
            upstream,
            two_level_agent_enable,
            only_enable_proxy_script: config.only_enable_proxy_script,
            is_only_work_steam_browser: config.is_only_work_steam_browser,
            enable_http_to_https: config.enable_http_to_https,
            server_side_proxy_token: config.server_side_proxy_token.clone(),
            dns,
            stats: self.stats.clone(),
            hooks: Some(hooks),
        });

        // —— 3. 按模式绑定监听 ——
        // Hosts：443 MITM（+可选 80）；System/PAC/ProxyOnly：正向代理端口
        let use_https_mitm = matches!(mode, ProxyMode::Hosts);

        let https_listener = if use_https_mitm {
            Some(
                self.bind_or_fail(mode, config.listen_ip, config.https_port)
                    .await?,
            )
        } else {
            None
        };

        let http_listener = if use_https_mitm && config.enable_http_to_https {
            let port = config.http_port.unwrap_or(80);
            Some(self.bind_or_fail(mode, config.listen_ip, port).await?)
        } else {
            None
        };

        let forward_listener = if !use_https_mitm {
            Some(
                self.bind_or_fail(mode, config.listen_ip, config.forward_proxy_port)
                    .await?,
            )
        } else {
            None
        };

        let socks5_listener = if let Some(port) = config.socks5_port {
            Some(self.bind_or_fail(mode, config.listen_ip, port).await?)
        } else {
            None
        };

        // —— 4. 启动监听任务 ——
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = shutdown_tx;
        let tls_acceptor = mitm_tls_acceptor(config.ca.clone());
        let proxy_authority = authority(&config.listen_ip, config.forward_proxy_port);

        let mut tasks = Vec::new();
        if let Some(listener) = https_listener {
            tasks.push(tokio::spawn(run_mitm_listener(
                listener,
                ctx.clone(),
                tls_acceptor.clone(),
                shutdown_rx.clone(),
            )));
        }
        if let Some(listener) = http_listener {
            tasks.push(tokio::spawn(run_http_listener(
                listener,
                ctx.clone(),
                shutdown_rx.clone(),
            )));
        }
        if let Some(listener) = forward_listener {
            tasks.push(tokio::spawn(
                crate::forward_proxy::run_forward_proxy_listener(
                    listener,
                    ctx.clone(),
                    tls_acceptor,
                    proxy_authority,
                    shutdown_rx.clone(),
                ),
            ));
        }
        if let Some(listener) = socks5_listener {
            tasks.push(tokio::spawn(run_socks5_listener(
                listener,
                ctx.clone(),
                shutdown_rx,
            )));
        }

        let stats = self.stats.clone();
        let state_tx = self.state.clone();
        let join = tokio::spawn(async move {
            for task in tasks {
                let _ = task.await;
            }
            stats.reset();
            if matches!(*state_tx.borrow(), EngineState::Stopping) {
                state_tx.send_replace(EngineState::Stopped);
            }
        });
        self.running_task = Some(join);

        // —— 5. Hosts 模式：监听启动后写 hosts（对齐 C# 启动成功后 UpdateHosts）——
        if mode == ProxyMode::Hosts {
            let entries = collect_hosts_entries(&config);
            if !entries.is_empty() {
                let manager = hosts_manager(config.hosts_path.as_deref());
                if let Err(e) = manager.update_hosts(&entries) {
                    // 回滚：停止已启动的监听（对齐 C# StopProxyAsync 回滚）
                    self.shutdown_tx.send_replace(true);
                    if let Some(task) = self.running_task.take() {
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
                    }
                    let msg = format!("hosts 写入失败: {e}");
                    self.state.send_replace(EngineState::Error(msg.clone()));
                    return Err(EngineError::Other(msg));
                }
                self.hosts_written = Some(manager.path().to_path_buf());
            }
        }

        self.running_mode = Some(mode);
        self.state.send_replace(EngineState::Running {
            started_at: chrono::Utc::now(),
            mode,
        });
        Ok(())
    }

    /// 停止引擎（先摘除接入再停监听，对齐 C# StopProxyServiceCoreAsync）
    pub async fn stop(&mut self) -> Result<(), EngineError> {
        let prev_state = self.state_rx.borrow().clone();
        if !matches!(prev_state, EngineState::Running { .. }) {
            return Err(EngineError::NotRunning);
        }
        self.state.send_replace(EngineState::Stopping);

        // —— 1. 摘除 hosts（失败阻止停止：避免域名仍指向本地却无服务）——
        if let Some(path) = self.hosts_written.take() {
            let manager = watt_hosts::HostsManager::with_path(path);
            if manager.contains_mark() {
                if let Err(e) = manager.remove_hosts_by_tag() {
                    // 恢复 Running 状态（引擎未停止）
                    self.state.send_replace(prev_state);
                    self.hosts_written = Some(manager.path().to_path_buf());
                    return Err(EngineError::Other(format!("hosts 还原失败: {e}")));
                }
            }
        }

        // —— 2. 取消系统代理 / PAC ——
        if let Some(mode) = self.running_mode {
            match mode {
                ProxyMode::System => {
                    if let Err(e) = crate::system_proxy::set_system_proxy(false, "", 0) {
                        tracing::warn!("取消系统代理失败（继续停止）: {e}");
                    }
                }
                ProxyMode::Pac => {
                    if let Err(e) = crate::system_proxy::set_system_pac(false, "") {
                        tracing::warn!("取消 PAC 代理失败（继续停止）: {e}");
                    }
                }
                _ => {}
            }
        }

        // —— 3. 关闭监听 ——
        self.shutdown_tx.send_replace(true);
        if let Some(task) = self.running_task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }
        self.running_mode = None;
        self.state.send_replace(EngineState::Stopped);
        Ok(())
    }
}

impl Default for ProxyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// ip:port 形式（IPv6 加方括号）
fn authority(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// 绑定失败描述（Windows 附带占用进程名诊断）
fn describe_bind_error(e: std::io::Error, port: u16) -> String {
    match crate::port_diag::find_listener_process(port) {
        Some(p) => format!("{e}（进程 {} / PID {}）", p.name, p.pid),
        None => e.to_string(),
    }
}

/// 撤销模式前置的系统代理设置（启动失败回滚）
fn revert_proxy_settings(mode: ProxyMode) {
    match mode {
        ProxyMode::System => {
            let _ = crate::system_proxy::set_system_proxy(false, "", 0);
        }
        ProxyMode::Pac => {
            let _ = crate::system_proxy::set_system_pac(false, "");
        }
        _ => {}
    }
}

/// 判断注册表 / PAC 里的代理地址是否指向本引擎（仅 127.0.0.1 / localhost / 0.0.0.0 + 本引擎端口）。
///
/// 用于兜底清理：只有确认是自己写下的系统代理才撤销，绝不误伤用户配置的其他代理。
fn is_own_proxy_addr(addr: &str, own_ports: &[u16]) -> bool {
    let lower = addr.trim().to_ascii_lowercase();
    ["127.0.0.1", "localhost", "0.0.0.0"]
        .iter()
        .any(|host| own_ports.iter().any(|p| lower.contains(&format!("{host}:{p}"))))
}

/// hosts 管理器（None=系统默认路径）
fn hosts_manager(path: Option<&std::path::Path>) -> watt_hosts::HostsManager {
    match path {
        Some(p) => watt_hosts::HostsManager::with_path(p),
        None => watt_hosts::HostsManager::new(),
    }
}

/// 收集 hosts 写入条目（对齐 C# ListeningDomainNames 映射）：
/// - 普通条目 → (监听 IP, 域名)
/// - 含空格条目（"ip domain" 反序格式）→ 解析为 (ip, domain)
/// - 启用脚本 → 追加本地域名
fn collect_hosts_entries(config: &EngineConfig) -> Vec<(String, String)> {
    // hosts 中 0.0.0.0 无意义，回退 127.0.0.1（对齐 C# localhost 计算）
    let localhost = if config.listen_ip.is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        config.listen_ip.to_string()
    };

    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    let mut push = |ip: String, domain: String, seen: &mut std::collections::HashSet<String>| {
        if ip.is_empty() || domain.is_empty() {
            return;
        }
        if seen.insert(domain.to_ascii_lowercase()) {
            entries.push((ip, domain));
        }
    };

    for rule in &config.rules {
        for entry in &rule.listening_domain_names {
            if entry.contains(' ') {
                let mut parts = entry.split_whitespace();
                if let (Some(ip), Some(domain)) = (parts.next(), parts.next()) {
                    push(ip.to_string(), domain.to_string(), &mut seen);
                }
            } else {
                push(localhost.clone(), entry.clone(), &mut seen);
            }
        }
    }

    // 启用脚本 → 本地域名（XHR 桥）
    if !config.scripts.is_empty() {
        push(
            localhost,
            watt_config::constants::LOCAL_DOMAIN.to_string(),
            &mut seen,
        );
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_hosts_path(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("watt-engine-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        if !path.exists() {
            std::fs::write(&path, "1.2.3.4 old.example.com\r\n").unwrap();
        }
        path
    }

    #[tokio::test]
    async fn test_engine_start_stop() {
        let mut engine = ProxyEngine::new();
        let config = EngineConfig {
            https_port: 18443,
            ..Default::default()
        };
        engine.start(config).await.unwrap();
        assert!(matches!(engine.state(), EngineState::Running { .. }));
        engine.stop().await.unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
    }

    #[tokio::test]
    async fn test_engine_port_conflict() {
        let mut engine = ProxyEngine::new();
        let config = EngineConfig {
            https_port: 18444,
            ..Default::default()
        };
        engine.start(config).await.unwrap();

        let mut engine2 = ProxyEngine::new();
        let config2 = EngineConfig {
            https_port: 18444,
            ..Default::default()
        };
        let result = engine2.start(config2).await;
        assert!(matches!(result, Err(EngineError::BindPortError(_, _))));

        engine.stop().await.unwrap();
    }

    /// Hosts 模式：hosts 写入/移除时序 + "ip domain" 反序格式
    #[tokio::test]
    async fn test_engine_hosts_mode_write_and_remove() {
        let hosts_path = temp_hosts_path("hosts-mode");
        let mut engine = ProxyEngine::new();
        let config = EngineConfig {
            https_port: 18445,
            rules: vec![DomainRule {
                match_domain_names: vec!["hosts.example.com".into()],
                listening_domain_names: vec![
                    "hosts.example.com".into(),
                    "9.9.9.9 spaced.example.com".into(),
                ],
                ..Default::default()
            }],
            scripts: vec![ScriptConfig {
                local_id: "s".into(),
                cache_path: "/tmp/s.js".into(),
                match_domain_names: vec!["hosts.example.com".into()],
                exclude_domain_names: vec![],
                order: 0,
            }],
            hosts_path: Some(hosts_path.clone()),
            ..Default::default()
        };
        engine.start(config).await.unwrap();

        // hosts 已写入：加速域名 + 反序格式解析 + 本地域名
        let content = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(content.contains("127.0.0.1 hosts.example.com"), "{content}");
        assert!(content.contains("9.9.9.9 spaced.example.com"), "{content}");
        assert!(
            content.contains(&format!(
                "127.0.0.1 {}",
                watt_config::constants::LOCAL_DOMAIN
            )),
            "{content}"
        );

        // 停止 → 摘除标记块，原内容保留
        engine.stop().await.unwrap();
        let content2 = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(!content2.contains(watt_hosts::MARK_START), "{content2}");
        assert!(content2.contains("1.2.3.4 old.example.com"), "{content2}");

        let _ = std::fs::remove_dir_all(hosts_path.parent().unwrap());
    }

    /// Hosts 模式：空规则不写 hosts（不触碰系统文件）
    #[tokio::test]
    async fn test_engine_hosts_mode_empty_rules_no_write() {
        let mut engine = ProxyEngine::new();
        let config = EngineConfig {
            https_port: 18446,
            rules: vec![],
            scripts: vec![],
            ..Default::default()
        };
        engine.start(config).await.unwrap();
        assert!(engine.hosts_written.is_none());
        engine.stop().await.unwrap();
    }

    /// System/PAC/ProxyOnly 模式：绑定正向代理端口（26501 默认；此处用高位端口）
    #[tokio::test]
    async fn test_engine_forward_mode_bind() {
        let port = free_port();
        let mut engine = ProxyEngine::new();
        let config = EngineConfig {
            mode: ProxyMode::ProxyOnly,
            https_port: 18447,
            forward_proxy_port: port,
            ..Default::default()
        };
        engine.start(config).await.unwrap();
        assert!(matches!(
            engine.state(),
            EngineState::Running {
                mode: ProxyMode::ProxyOnly,
                ..
            }
        ));

        // PAC 端点可访问
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("application/x-ns-proxy-autoconfig"), "{resp}");
        assert!(resp.contains("function FindProxyForURL"), "{resp}");

        engine.stop().await.unwrap();
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn test_collect_hosts_entries() {
        let config = EngineConfig {
            listen_ip: "127.0.0.1".parse().unwrap(),
            rules: vec![DomainRule {
                match_domain_names: vec!["a.example.com".into()],
                listening_domain_names: vec![
                    "a.example.com".into(),
                    "8.8.8.8 b.example.com".into(),
                    "a.example.com".into(), // 重复去重
                ],
                ..Default::default()
            }],
            scripts: vec![],
            ..Default::default()
        };
        let entries = collect_hosts_entries(&config);
        assert_eq!(
            entries,
            vec![
                ("127.0.0.1".to_string(), "a.example.com".to_string()),
                ("8.8.8.8".to_string(), "b.example.com".to_string()),
            ]
        );
    }

    #[test]
    fn test_is_own_proxy_addr() {
        let ports = [26501u16];
        assert!(is_own_proxy_addr("127.0.0.1:26501", &ports));
        assert!(is_own_proxy_addr("localhost:26501", &ports));
        assert!(is_own_proxy_addr("http://127.0.0.1:26501/pac", &ports));
        assert!(!is_own_proxy_addr("127.0.0.1:8080", &ports));
        assert!(!is_own_proxy_addr("proxy.corp.example:26501", &ports));
        assert!(!is_own_proxy_addr("", &ports));
    }

    /// 兜底清理：残留 hosts 标记块必须被摘除，否则域名仍指向 127.0.0.1 而无人监听。
    /// proxy_ports 传空数组，确保测试绝不触碰真实系统代理注册表。
    #[test]
    fn test_cleanup_orphans_removes_tagged_hosts() {
        let dir = std::env::temp_dir().join(format!("watt-orphan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(
            &hosts,
            "127.0.0.1 localhost\r\n# Steam++ Start\r\n127.0.0.1 github.com\r\n# Steam++ End\r\n",
        )
        .unwrap();

        let engine = ProxyEngine::new();
        let cleaned = engine.cleanup_orphans(Some(&hosts), &[]);
        assert!(
            cleaned.iter().any(|c| c.starts_with("hosts(")),
            "应报告 hosts 清理: {cleaned:?}"
        );

        let content = std::fs::read_to_string(&hosts).unwrap();
        assert!(!content.contains("Steam++ Start"), "{content}");
        assert!(!content.contains("Steam++ End"), "{content}");
        assert!(!content.contains("github.com"), "{content}");
        // 常规条目保留
        assert!(content.contains("127.0.0.1 localhost"), "{content}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 无残留时不应报告任何清理项（幂等）
    #[test]
    fn test_cleanup_orphans_noop_when_clean() {
        let dir = std::env::temp_dir().join(format!("watt-orphan-clean-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\r\n").unwrap();

        let engine = ProxyEngine::new();
        let cleaned = engine.cleanup_orphans(Some(&hosts), &[]);
        assert!(cleaned.is_empty(), "{cleaned:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
