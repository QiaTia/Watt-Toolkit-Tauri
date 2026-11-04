//! 特权能力探测：哪些接入面需要 root、当前进程是否具备。
//!
//! 背景（macOS 硬约束，2026-10 实机确认）：监听 443 属于**特权端口绑定**，
//! 非 root 进程必然 `EACCES`；而 `osascript ... with administrator privileges`
//! 只能「以 root 执行一条命令」，无法让已经运行的非 root 进程获得绑定权。
//! 因此在 macOS 上 Hosts 模式必须整体以 root 运行（或由特权 helper 代绑端口，
//! 见后续方案），否则用户点一次加速只会收到端口绑定失败。
//!
//! 这里把判定集中到一处，引擎启动前的拦截与前端提示都以此为唯一依据。

/// 当前进程是否具备 root / 管理员级特权。
#[cfg(unix)]
pub fn is_elevated() -> bool {
    // SAFETY: geteuid 仅读取进程有效 UID，无副作用
    unsafe { libc::geteuid() == 0 }
}

/// Windows 上不存在「1044 以下端口仅管理员可绑」的限制（HTTP.SYS 的保留策略除外），
/// 且写 hosts 只要进程有管理员令牌即可，故统一视为已具备。
#[cfg(not(unix))]
pub fn is_elevated() -> bool {
    true
}

/// 当前平台是否**允许非 root 进程绑定特权端口**。
///
/// Linux 可通过 `net.ipv4.ip_unprivileged_port_start=0` 放开，因此返回 `true`
/// 不保证一定能绑成功 —— 真正的判据仍是实际 `bind`，这里只用于「确定不可能」的拦截。
pub fn allows_unprivileged_privileged_port() -> bool {
    cfg!(not(target_os = "macos"))
}

/// Hosts 模式的阻塞原因；`None` 表示当前进程可尝试 Hosts 模式。
///
/// `https_port` / `http_port` 为本次实际要绑定的端口：只有其中出现 <1024 的
/// 特权端口时才可能被系统拒绝。这样端口可配置（测试/自定义高位端口）时，
/// macOS 非 root 也能正常使用 Hosts 模式；仅在「确定绑定会失败」时拦截，
/// 避免误伤 Linux 上通过 sysctl 放开特权端的部署。
pub fn hosts_mode_block_reason(https_port: u16, http_port: Option<u16>) -> Option<String> {
    let binds_privileged_port = https_port < 1024 || http_port.is_some_and(|p| p < 1024);
    if !binds_privileged_port || allows_unprivileged_privileged_port() || is_elevated() {
        return None;
    }
    Some(
        "macOS 上 Hosts 模式需要管理员权限：监听 443 属于特权端口，普通进程无法绑定。\
         请改用「系统代理」或「PAC」模式（无需管理员权限）；\
         如需 Hosts 模式，请从终端以 sudo 启动应用。"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_macos_never_blocks_hosts_mode() {
        // Windows / Linux 不受 macOS 的 443 限制；Linux 由 sysctl 决定，交由真实 bind 判定
        if cfg!(not(target_os = "macos")) {
            assert!(hosts_mode_block_reason(443, Some(80)).is_none());
            assert!(allows_unprivileged_privileged_port());
        }
    }

    #[test]
    fn high_ports_never_block_hosts_mode() {
        // 自定义高位端口不涉及特权端口绑定，任何平台都不应被前置拦截
        assert!(hosts_mode_block_reason(18443, Some(18480)).is_none());
        assert!(hosts_mode_block_reason(18443, None).is_none());
    }

    #[test]
    fn block_reason_is_actionable_when_present() {
        // macOS 非 root 且绑定特权端口时才可能有原因；文案必须给出可直接切换的替代模式
        if let Some(reason) = hosts_mode_block_reason(443, Some(80)) {
            assert!(
                reason.contains("系统代理"),
                "文案应指向系统代理模式: {reason}"
            );
            assert!(reason.contains("PAC"), "文案应指向 PAC 模式: {reason}");
        }
    }
}
