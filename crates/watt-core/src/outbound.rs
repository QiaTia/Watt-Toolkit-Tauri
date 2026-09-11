//! 出站连接器：目标解析（规则 IP/DNS）、二级代理（HTTP CONNECT/SOCKS4/SOCKS5）。
//! 对齐 ReverseProxyHttpClientHandler 语义。

use crate::sni::{outbound_tls_connector, server_name, OutboundVerify};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use watt_config::{ExternalProxyType, TwoLevelAgentSettings};

/// 出站目标描述
#[derive(Debug, Clone)]
pub struct OutboundTarget {
    /// 目标主机（域名或 IP）
    pub host: String,
    /// 目标端口
    pub port: u16,
    /// 是否 TLS
    pub tls: bool,
    /// TLS SNI（None = 用 host；规则可覆盖）
    pub tls_sni: Option<String>,
    /// 是否忽略 TLS 名称不匹配
    pub tls_ignore_name_mismatch: bool,
    /// 规则指定的 IP（优先于 DNS）
    pub override_ip: Option<IpAddr>,
    /// 转发目标域名（对齐 C# ForwardDestination）：DNS 解析该域名取 IP，
    /// 但仍以 `host` 作为 TLS SNI / Host 头，用于 CDN 镜像加速。
    pub forward_destination: Option<String>,
    /// 超时（毫秒）
    pub timeout_ms: Option<u64>,
}

/// 出站连接流
pub enum OutboundStream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OutboundStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OutboundStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            OutboundStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            OutboundStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OutboundStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            OutboundStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OutboundStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutboundStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("dns resolve failed: {0}")]
    Dns(String),
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("tls failed: {0}")]
    Tls(String),
    #[error("upstream proxy failed: {0}")]
    Upstream(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// DNS 解析 trait（系统 / watt-dns 可插拔）
pub trait DnsResolve: Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Vec<IpAddr>, String>>;
}

/// 系统 DNS 解析（getaddrinfo）
pub struct SystemDns;

impl DnsResolve for SystemDns {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Vec<IpAddr>, String>> {
        Box::pin(async move {
            use tokio::net::lookup_host;
            let addrs: Vec<SocketAddr> = lookup_host((host, 0))
                .await
                .map_err(|e| e.to_string())?
                .collect();
            let ips: Vec<IpAddr> = addrs.into_iter().map(|a| a.ip()).collect();
            if ips.is_empty() {
                return Err(format!("{host}: 无解析结果"));
            }
            Ok(ips)
        })
    }
}

/// 出站连接器
pub struct OutboundConnector {
    pub dns: Arc<dyn DnsResolve>,
    pub upstream: Option<UpstreamProxy>,
}

/// 二级代理配置
#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    pub proxy_type: ExternalProxyType,
    pub addr: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl UpstreamProxy {
    pub fn from_settings(s: &TwoLevelAgentSettings) -> Option<Self> {
        if !s.is_valid() {
            return None;
        }
        let ip = s.ip.as_deref()?;
        let addr: SocketAddr = format!("{ip}:{}", s.port).parse().ok()?;
        Some(Self {
            proxy_type: s.typed_proxy_type(),
            addr,
            username: s.username.clone().filter(|u| !u.is_empty()),
            password: s.password.clone().filter(|p| !p.is_empty()),
        })
    }
}

impl OutboundConnector {
    pub fn new(dns: Arc<dyn DnsResolve>, upstream: Option<UpstreamProxy>) -> Self {
        Self { dns, upstream }
    }

    /// 建立出站连接（含可选 TLS）
    pub async fn connect(&self, target: &OutboundTarget) -> Result<OutboundStream, OutboundError> {
        let timeout = Duration::from_millis(target.timeout_ms.unwrap_or(30000));

        // 二级代理：单一通道，无候选竞速
        if self.upstream.is_some() {
            let stream = self.connect_via_upstream(target, timeout).await?;
            return Self::wrap_tls(target, stream, timeout).await;
        }

        let addrs = self.resolve_candidates(target).await?;

        // —— 竞速的胜出条件必须与「可用性」一致 ——
        // TCP 握手成功 ≠ 服务可达。部分网络只放行 TCP，TLS 之后的流量被阻断，
        // 表现是「TCP 秒连、TLS 卡死」：实测 github.com 的 12 个候选中只有 1 个能
        // 完成 TLS 握手，其余全部 TCP 可达但 TLS 超时。若仅以 TCP 握手作为胜出条件，
        // 竞速会稳定选中「TCP 最快、TLS 已死」的候选 → 必然失败（现象：20s 超时 / 500）。
        // 因此凡是需要 TLS 的目标，一律以「完成 TLS 握手」作为胜出条件。
        if target.tls {
            return Self::race_tls(target, addrs, timeout).await;
        }

        let stream = Self::race_tcp(target, addrs, timeout).await?;
        Ok(OutboundStream::Plain(stream))
    }

    /// 构造 TLS 连接器与 SNI。
    ///
    /// SNI 覆盖（FakeServerName）会使 rustls 以假名做证书名称校验而失败，
    /// 对齐原版 ValidateServerCertificate：名称不匹配时按原始请求域名的 DNS 名
    /// 校验证书（证书链仍验证）；`tls_ignore_name_mismatch` 则完全跳过名称校验。
    fn tls_parts(
        target: &OutboundTarget,
    ) -> Result<
        (
            Arc<tokio_rustls::TlsConnector>,
            rustls::pki_types::ServerName<'static>,
        ),
        OutboundError,
    > {
        let sni_host = target
            .tls_sni
            .clone()
            .unwrap_or_else(|| target.host.clone());
        let sni_override = sni_host != target.host;
        let verify = if target.tls_ignore_name_mismatch || sni_override {
            OutboundVerify::IgnoreNameMismatch
        } else {
            OutboundVerify::Standard
        };
        let alt_name = if sni_override {
            Some(target.host.clone())
        } else {
            None
        };
        let name = server_name(&sni_host)
            .ok_or_else(|| OutboundError::Tls(format!("无效的 ServerName: {sni_host}")))?;
        Ok((outbound_tls_connector(verify, alt_name), name))
    }

    /// 在已建立的 TCP 流上完成 TLS 握手
    async fn wrap_tls(
        target: &OutboundTarget,
        stream: tokio::net::TcpStream,
        timeout: Duration,
    ) -> Result<OutboundStream, OutboundError> {
        let (connector, name) = Self::tls_parts(target)?;
        let tls_stream = tokio::time::timeout(timeout, connector.connect(name, stream))
            .await
            .map_err(|_| OutboundError::Tls("TLS 握手超时".into()))?
            .map_err(|e| OutboundError::Tls(e.to_string()))?;
        Ok(OutboundStream::Tls(Box::new(tls_stream)))
    }

    /// TLS 竞速：候选并发执行「TCP + TLS 握手」，首个完成 TLS 者胜出。
    ///
    /// 用 `JoinSet` 承载候选，胜出后随作用域结束统一 abort，
    /// 避免落败候选的握手在后台继续空跑（TLS 超时可达十几秒）。
    async fn race_tls(
        target: &OutboundTarget,
        addrs: Vec<SocketAddr>,
        timeout: Duration,
    ) -> Result<OutboundStream, OutboundError> {
        let (connector, name) = Self::tls_parts(target)?;
        let mut set = tokio::task::JoinSet::new();

        for addr in addrs {
            let connector = connector.clone();
            let name = name.clone();
            set.spawn(async move {
                let res = async {
                    let stream =
                        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
                            .await
                            .map_err(|_| "TCP 超时".to_string())?
                            .map_err(|e| e.to_string())?;
                    tokio::time::timeout(timeout, connector.connect(name, stream))
                        .await
                        .map_err(|_| "TLS 超时".to_string())?
                        .map_err(|e| format!("TLS: {e}"))
                }
                .await;
                (addr, res)
            });
        }

        let mut last_err = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((_addr, Ok(tls_stream))) => {
                    // 胜出：set 随作用域 drop，其余候选被 abort
                    return Ok(OutboundStream::Tls(Box::new(tls_stream)));
                }
                Ok((addr, Err(e))) => last_err = Some(format!("{addr}: {e}")),
                Err(e) => last_err = Some(format!("候选任务异常: {e}")),
            }
        }

        Err(OutboundError::Connect(format!(
            "{}:{} TLS 连接失败: {}",
            target.host,
            target.port,
            last_err.unwrap_or_else(|| "无可用地址".into())
        )))
    }

    /// 二级代理通道（HTTP CONNECT / SOCKS4 / SOCKS5）
    async fn connect_via_upstream(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream, OutboundError> {
        let upstream = self
            .upstream
            .as_ref()
            .ok_or_else(|| OutboundError::Connect("未配置二级代理".into()))?;
        let mut stream =
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(upstream.addr))
                .await
                .map_err(|_| OutboundError::Connect("连接二级代理超时".into()))?
                .map_err(|e| OutboundError::Connect(format!("二级代理: {e}")))?;
        match upstream.proxy_type {
            ExternalProxyType::Http => {
                http_connect_tunnel(&mut stream, target, upstream, timeout).await?;
            }
            ExternalProxyType::Socks5 => {
                socks5_tunnel(&mut stream, target, upstream, timeout).await?;
            }
            ExternalProxyType::Socks4 => {
                socks4_tunnel(&mut stream, target, timeout).await?;
            }
        }
        Ok(stream)
    }

    /// 候选地址解析（对齐 GetIPEndPointsAsync 并增强容错）：
    /// 覆盖 IP（云端静态值可能失效）→ 转发目标域名 → 原始 host DNS 解析 → 备用 IP 池兜底。
    async fn resolve_candidates(
        &self,
        target: &OutboundTarget,
    ) -> Result<Vec<SocketAddr>, OutboundError> {
        let mut candidate_groups: Vec<Vec<SocketAddr>> = Vec::new();
        if let Some(ip) = target.override_ip {
            candidate_groups.push(vec![SocketAddr::new(ip, target.port)]);
        }
        if let Some(forward) = target
            .forward_destination
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Ok(addrs) = self.resolve_addrs(forward, target.port).await {
                if !addrs.is_empty() {
                    candidate_groups.push(addrs);
                }
            }
        }
        match self.resolve_addrs(&target.host, target.port).await {
            Ok(addrs) if !addrs.is_empty() => candidate_groups.push(addrs),
            _ => {}
        }
        // 备用 IP 池兜底：部分服务的权威 DNS 只返回单个 A 记录，一旦该 IP 被阻断，
        // 上面的覆盖 IP 与 DNS 候选会一起失败（现象为 500 连接失败），但同期该服务的
        // 其他入口 IP 往往仍然可达。竞速下追加候选不增加成功路径的延迟。
        let fallback = crate::fallback::fallback_ips(&target.host);
        if !fallback.is_empty() {
            candidate_groups.push(
                fallback
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .collect(),
            );
        }

        // 去重（保持顺序）：同一地址不重复尝试
        let mut seen = std::collections::HashSet::new();
        let addrs: Vec<SocketAddr> = candidate_groups
            .into_iter()
            .flatten()
            .filter(|a| seen.insert(*a))
            .collect();

        if addrs.is_empty() {
            return Err(OutboundError::Connect(format!(
                "{}:{} 无可用地址",
                target.host, target.port
            )));
        }
        Ok(addrs)
    }

    /// TCP 竞速（happy-eyeballs）：候选并发连接，首个 TCP 握手成功者胜出。
    ///
    /// 仅用于**不需要 TLS** 的目标（如正向代理的纯隧道）；需要 TLS 时改用
    /// [`Self::race_tls`]——TCP 可达并不代表服务可达。
    /// 云端静态 IP 可能失效、真实 IP 可能间歇性阻断，串行尝试代价过高（每个死 IP
    /// 白等一个完整超时）；竞速把总延迟压到「最快可用地址」的连接时间。
    async fn race_tcp(
        target: &OutboundTarget,
        addrs: Vec<SocketAddr>,
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream, OutboundError> {
        let mut set = tokio::task::JoinSet::new();
        for addr in addrs {
            set.spawn(async move {
                let res = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
                    .await
                {
                    Ok(Ok(s)) => Ok(s),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("超时".into()),
                };
                (addr, res)
            });
        }

        let mut last_err = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((_addr, Ok(stream))) => return Ok(stream),
                Ok((addr, Err(e))) => last_err = Some(format!("{addr}: {e}")),
                Err(e) => last_err = Some(format!("候选任务异常: {e}")),
            }
        }
        Err(OutboundError::Connect(format!(
            "{}:{} 连接失败: {}",
            target.host,
            target.port,
            last_err.unwrap_or_else(|| "无可用地址".into())
        )))
    }

    async fn resolve_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, OutboundError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let ips = self.dns.resolve(host).await.map_err(OutboundError::Dns)?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

/// HTTP CONNECT 隧道
async fn http_connect_tunnel(
    stream: &mut tokio::net::TcpStream,
    target: &OutboundTarget,
    upstream: &UpstreamProxy,
    timeout: Duration,
) -> Result<(), OutboundError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let auth = match (&upstream.username, &upstream.password) {
        (Some(u), Some(p)) => {
            use base64::Engine;
            let raw = format!("{u}:{p}");
            Some(format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(raw)
            ))
        }
        _ => None,
    };
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n",
        host = target.host,
        port = target.port,
        auth = auth.unwrap_or_default(),
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    // 读到头部结束
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(OutboundError::Upstream("CONNECT 响应超时".into()));
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(OutboundError::Upstream("连接被关闭".into()));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(OutboundError::Upstream("CONNECT 响应过大".into()));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    if let Some(code) = head.split_whitespace().nth(1) {
        if code.starts_with('2') {
            return Ok(());
        }
        return Err(OutboundError::Upstream(format!(
            "CONNECT 失败: HTTP {code}"
        )));
    }
    Err(OutboundError::Upstream("CONNECT 响应格式错误".into()))
}

/// SOCKS5 隧道（CONNECT，支持用户名密码认证）
async fn socks5_tunnel(
    stream: &mut tokio::net::TcpStream,
    target: &OutboundTarget,
    upstream: &UpstreamProxy,
    timeout: Duration,
) -> Result<(), OutboundError> {
    use tokio::io::AsyncWriteExt;
    let deadline = tokio::time::Instant::now() + timeout;

    // 1. 握手：支持无认证/用户名密码
    let has_auth = upstream.username.is_some() && upstream.password.is_some();
    let methods: &[u8] = if has_auth { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;

    let mut resp = [0u8; 2];
    read_exact_deadline(stream, &mut resp, deadline).await?;
    if resp[0] != 0x05 {
        return Err(OutboundError::Upstream("SOCKS5 版本错误".into()));
    }
    match resp[1] {
        0x00 => {} // 无认证
        0x02 => {
            // 用户名/密码认证（RFC 1929）
            let user = upstream.username.clone().unwrap_or_default();
            let pass = upstream.password.clone().unwrap_or_default();
            if user.len() > 255 || pass.len() > 255 {
                return Err(OutboundError::Upstream("账密过长".into()));
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            let mut auth_resp = [0u8; 2];
            read_exact_deadline(stream, &mut auth_resp, deadline).await?;
            if auth_resp[1] != 0x00 {
                return Err(OutboundError::Upstream("SOCKS5 认证失败".into()));
            }
        }
        0xFF => return Err(OutboundError::Upstream("SOCKS5 无可用认证方式".into())),
        other => {
            return Err(OutboundError::Upstream(format!(
                "SOCKS5 认证方式不支持: {other}"
            )))
        }
    }

    // 2. CONNECT 命令（域名远程解析）
    let host_bytes = target.host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(OutboundError::Upstream("域名过长".into()));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&req).await?;

    // 3. 响应
    let mut head = [0u8; 4];
    read_exact_deadline(stream, &mut head, deadline).await?;
    if head[1] != 0x00 {
        return Err(OutboundError::Upstream(format!(
            "SOCKS5 CONNECT 失败: {}",
            head[1]
        )));
    }
    // 跳过绑定地址
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6]; // 4 IP + 2 port
            read_exact_deadline(stream, &mut rest, deadline).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_deadline(stream, &mut len, deadline).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            read_exact_deadline(stream, &mut rest, deadline).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18]; // 16 IPv6 + 2 port
            read_exact_deadline(stream, &mut rest, deadline).await?;
        }
        other => {
            return Err(OutboundError::Upstream(format!(
                "SOCKS5 地址类型错误: {other}"
            )))
        }
    }
    Ok(())
}

/// SOCKS4 隧道（仅支持 IP 目标；域名走 4a 协议端口 0）
async fn socks4_tunnel(
    stream: &mut tokio::net::TcpStream,
    target: &OutboundTarget,
    timeout: Duration,
) -> Result<(), OutboundError> {
    use tokio::io::AsyncWriteExt;
    let deadline = tokio::time::Instant::now() + timeout;

    // SOCKS4a：IP 为 0.0.0.x 时后面跟域名
    let ip: std::net::Ipv4Addr = target
        .host
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 1));
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&target.port.to_be_bytes());
    req.extend_from_slice(&ip.octets());
    if !ip.octets()[..3].iter().all(|&b| b == 0) {
        // 标准 SOCKS4：IP 直连
    } else {
        // SOCKS4a：追加域名
        req.extend_from_slice(target.host.as_bytes());
    }
    req.push(0); // null 终止（无 user id）
    stream.write_all(&req).await?;

    let mut resp = [0u8; 8];
    read_exact_deadline(stream, &mut resp, deadline).await?;
    if resp[1] != 0x5A {
        return Err(OutboundError::Upstream(format!(
            "SOCKS4 CONNECT 失败: {:#X}",
            resp[1]
        )));
    }
    Ok(())
}

async fn read_exact_deadline(
    stream: &mut tokio::net::TcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<(), OutboundError> {
    use tokio::io::AsyncReadExt;
    let mut filled = 0;
    while filled < buf.len() {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf[filled..]))
            .await
            .map_err(|_| OutboundError::Upstream("读取超时".into()))?
            .map_err(OutboundError::Io)?;
        if n == 0 {
            return Err(OutboundError::Upstream("连接被关闭".into()));
        }
        filled += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_from_settings() {
        let s = TwoLevelAgentSettings {
            enable: true,
            proxy_type: Some("SOCKS5".into()),
            ip: Some("127.0.0.1".into()),
            port: 1080,
            username: Some("user".into()),
            password: Some("pass".into()),
        };
        let u = UpstreamProxy::from_settings(&s).unwrap();
        assert_eq!(u.proxy_type, ExternalProxyType::Socks5);
        assert_eq!(u.addr.port(), 1080);

        // 无效配置
        let s2 = TwoLevelAgentSettings {
            enable: true,
            ip: None,
            port: 1080,
            ..Default::default()
        };
        assert!(UpstreamProxy::from_settings(&s2).is_none());
    }

    /// 回归：TLS 竞速必须跳过「TCP 可达、TLS 死」的候选。
    ///
    /// 真实网络中存在只放行 TCP、阻断 TLS 之后流量的 IP —— 实测 `github.com` 的 12 个
    /// 候选中仅 1 个能完成 TLS 握手，其余全部 TCP 秒连但 TLS 超时。旧实现以「TCP 握手」
    /// 作为胜出条件，因而稳定选中 TLS 死候选，表现为 20s 超时 / 500 连接失败。
    #[tokio::test]
    async fn test_race_tls_skips_tcp_alive_tls_dead_candidate() {
        use std::time::Instant;
        use tokio::io::AsyncReadExt;

        // 黑洞候选：TCP 立刻可连，吞掉数据后不再回应 → TLS 永远握手不上
        let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hole_addr = blackhole.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = blackhole.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });

        // 正常 TLS 候选：自签 CA 动态签发（tls_ignore_name_mismatch → PermissiveVerifier）
        let ca = Arc::new(watt_cert::ca::CaCertificate::generate().unwrap());
        let tls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        let acceptor = crate::sni::mitm_tls_acceptor(ca);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tls_listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });

        let target = OutboundTarget {
            host: "tls.test".into(),
            port: tls_addr.port(),
            tls: true,
            tls_sni: None,
            tls_ignore_name_mismatch: true,
            override_ip: None,
            forward_destination: None,
            timeout_ms: Some(5000),
        };

        // 黑洞排在前：其 TCP 握手更快，正是旧实现会选中的那个
        let started = Instant::now();
        let stream = OutboundConnector::race_tls(
            &target,
            vec![hole_addr, tls_addr],
            Duration::from_secs(5),
        )
        .await
        .expect("应跳过 TLS 死候选，命中可完成 TLS 的候选");

        assert!(matches!(stream, OutboundStream::Tls(_)));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "不应等到黑洞候选超时才成功，实际耗时 {:?}",
            started.elapsed()
        );
    }
}
