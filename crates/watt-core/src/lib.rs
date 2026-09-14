//! watt-core：网络加速代理引擎。
//! 移植自 BD.WTTS.Client.Plugins.Accelerator.ReverseProxy（Kestrel + YARP 实现）。
//!
//! 端口模型（对齐原实现）：
//! - 443：Hosts 模式 HTTPS MITM 反向代理（ALPN h2/http1.1）
//! - 80：可选 HTTP→HTTPS 301 重定向
//! - 26501：系统代理/PAC 模式正向代理（CONNECT 隧道 + HTTP 代理）
//! - 8868：SOCKS5 入站

pub mod connect_test;
pub mod engine;
pub mod fallback;
pub mod forward_proxy;
pub mod http_relay;
pub mod inject;
pub mod listener;
pub mod local_domain;
pub mod outbound;
pub mod pac;
pub mod port_diag;
pub mod sni;
pub mod stats;
pub mod system_proxy;

pub use engine::{EngineConfig, EngineState, ProxyEngine};
pub use stats::FlowStats;
