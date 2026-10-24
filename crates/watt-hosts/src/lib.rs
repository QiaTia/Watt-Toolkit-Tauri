//! hosts 域：标记块算法全量移植（对齐 HostsFileServiceImpl.HandleHosts）。
//!
//! 格式：
//! ```text
//! # Steam++ Start
//! 127.0.0.1 steamcommunity.com
//! # Steam++ End
//!
//! # Steam++ Backup Start
//! #3 1.2.3.4 steamcommunity.com
//! # Steam++ Backup End
//! ```

pub mod tagged_block;

#[derive(Debug, thiserror::Error)]
pub enum HostsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("hosts 标记重复: {0}")]
    MarkDuplicate(String),
    #[error("文件大小超过 50MB 限制")]
    FileTooLarge,
    #[error("无权限访问 hosts 文件")]
    Unauthorized,
    /// Windows：进程未以管理员身份运行（或 hosts 被安全软件锁定）。
    /// 应用清单已声明 requireAdministrator，正常情况下不会出现；
    /// 命中说明进程被以 asInvoker 方式拉起（受限终端 / 调试器 / 计划任务）。
    #[error("需要管理员权限才能写入 hosts（请以管理员身份运行 Watt Toolkit 后重试）: {0}")]
    ElevationRequired(String),
    #[error("非法 hosts 条目: {0}")]
    InvalidEntry(String),
    #[error("{0}")]
    Other(String),
}

/// 最大文件大小 50MB（对齐原实现）
pub const MAX_FILE_LENGTH: u64 = 52_428_800;

/// 标记（对齐原实现常量）
pub const MARK_START: &str = "# Steam++ Start";
pub const MARK_END: &str = "# Steam++ End";
pub const BACKUP_MARK_START: &str = "# Steam++ Backup Start";
pub const BACKUP_MARK_END: &str = "# Steam++ Backup End";

/// hosts 文件路径
pub fn hosts_file_path() -> std::path::PathBuf {
    if cfg!(target_os = "windows") {
        std::env::var("SystemRoot")
            .map(|sr| {
                std::path::PathBuf::from(sr)
                    .join("System32")
                    .join("drivers")
                    .join("etc")
                    .join("hosts")
            })
            .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"))
    } else {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// Windows 默认 hosts 内容（对齐 WindowsPlatformServiceImpl）
pub const DEFAULT_HOSTS_CONTENT_WINDOWS: &str = "# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
";

/// Unix 默认 hosts 内容
pub const DEFAULT_HOSTS_CONTENT_UNIX: &str = "127.0.0.1	localhost

# The following lines are desirable for IPv6 capable hosts
::1	localhost ip6-localhost ip6-loopback
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
";

/// 默认 hosts 内容（按平台）
pub fn default_hosts_content() -> &'static str {
    if cfg!(target_os = "windows") {
        DEFAULT_HOSTS_CONTENT_WINDOWS
    } else {
        DEFAULT_HOSTS_CONTENT_UNIX
    }
}

/// 校验一条 hosts 记录：IP 必须可解析，域名只允许主机名字符且非空。
///
/// 云端目录 / 前端规则是外部输入，换行或 `#` 会注入任意解析记录、
/// 伪造 `# Steam++ End` 标记进而触发 hosts 重置。
pub fn validate_hosts_entry(ip: &str, domain: &str) -> Result<(), HostsError> {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(HostsError::InvalidEntry(format!("IP 非法: {ip:?}")));
    }
    validate_hostname(domain)
}

/// 校验域名（hosts 条目语义）：ASCII 字母数字与 `.`/`-`/`_`，不允许空白或标记字符。
///
/// 容忍单个尾点（FQDN 写法，如 `example.com.`）：fallback / ip_pool 等模块已按
/// `trim_end_matches('.')` 归一化，这里若直接拒绝会让这类规则静默漏写 hosts。
pub fn validate_hostname(domain: &str) -> Result<(), HostsError> {
    let value = domain.trim().trim_end_matches('.');
    if value.is_empty() || value.len() > 253 {
        return Err(HostsError::InvalidEntry(format!(
            "域名长度非法: {domain:?}"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(HostsError::InvalidEntry(format!(
            "域名含非法字符: {domain:?}"
        )));
    }
    if value.starts_with('.') {
        return Err(HostsError::InvalidEntry(format!("域名首字符不能是点: {domain:?}")));
    }
    Ok(())
}

/// hosts 文件操作入口：更新/删除/按标记移除。
pub struct HostsManager {
    path: std::path::PathBuf,
}

impl HostsManager {
    pub fn new() -> Self {
        Self {
            path: hosts_file_path(),
        }
    }

    pub fn with_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// 更新/新增 hosts 记录（元组为 (IP, 域名)，对齐 C# UpdateHosts(IEnumerable<(string ip, string domain)>)）
    pub fn update_hosts(&self, hosts: &[(String, String)]) -> Result<(), HostsError> {
        // 校验放在写盘前：域名/IP 来自云端目录或前端规则，任何换行、空白或
        // 标记串都会破坏 hosts 结构（注入任意解析记录或伪造标记块）。
        for (ip, domain) in hosts {
            validate_hosts_entry(ip, domain)?;
        }
        let domain_ip: Vec<(String, String)> = hosts
            .iter()
            .map(|(ip, domain)| (domain.clone(), ip.clone()))
            .collect();
        self.handle_hosts(true, Some(&domain_ip))
    }

    /// 按标记移除全部加速记录（还原备份）
    pub fn remove_hosts_by_tag(&self) -> Result<(), HostsError> {
        self.handle_hosts(false, None)
    }

    /// 核心算法：读取-处理-写回（对齐 HandleHosts；hosts 元组为 (域名, IP)，同 C# 内部字典 domain→ip）
    pub fn handle_hosts(
        &self,
        is_update_or_remove: bool,
        hosts: Option<&[(String, String)]>,
    ) -> Result<(), HostsError> {
        if is_update_or_remove && hosts.is_none() {
            return Err(HostsError::Other("更新模式必须提供 hosts 数据".into()));
        }

        let meta = std::fs::metadata(&self.path)
            .map_err(|e| HostsError::Io(std::io::Error::new(e.kind(), e.to_string())))?;
        if meta.len() > MAX_FILE_LENGTH {
            return Err(HostsError::FileTooLarge);
        }
        let content = std::fs::read_to_string(&self.path)?;

        let newline = if cfg!(target_os = "windows") {
            "\r\n"
        } else {
            "\n"
        };

        let result = tagged_block::handle_hosts(&content, is_update_or_remove, hosts, newline);

        // 标记重复：备份原文件 → 重写默认内容 → 重试一次（对齐原实现）
        let new_content = match result {
            Ok(c) => c,
            Err(HostsError::MarkDuplicate(mark)) => {
                tracing::warn!("hosts 标记重复（{mark}），备份后重置");
                let bak = format!("{}.spp.bak", self.path.display());
                let _ = std::fs::copy(&self.path, &bak);
                let default = default_hosts_content();
                tagged_block::handle_hosts(default, is_update_or_remove, hosts, newline)
                    .map_err(|e| HostsError::Other(format!("重置后重试失败: {e}")))?
            }
            Err(e) => return Err(e),
        };

        write_file(&self.path, &new_content)?;
        Ok(())
    }

    /// 读取全部有效 hosts 记录（元组为 (IP, 域名)，后行覆盖先行；对齐 C# ReadHostsAllLines）
    pub fn read_all(&self) -> Result<Vec<(String, String)>, HostsError> {
        let content = std::fs::read_to_string(&self.path)?;
        Ok(tagged_block::read_hosts_all_lines(&content)
            .into_iter()
            .map(|(domain, ip)| (ip, domain))
            .collect())
    }

    /// 是否存在加速标记块
    pub fn contains_mark(&self) -> bool {
        std::fs::read_to_string(&self.path)
            .map(|c| {
                c.lines()
                    .rev()
                    .any(|l| l.trim_start().starts_with(MARK_END))
            })
            .unwrap_or(false)
    }

    /// 重置为默认内容
    pub fn reset_file(&self) -> Result<(), HostsError> {
        write_file(&self.path, default_hosts_content())?;
        Ok(())
    }
}

/// hosts 落盘：先直写；权限拒绝时（macOS）经临时文件 + 提权单次弹窗完成。
///
/// 提权命令为单条 shell（白名单程序串联，一次弹窗）：
/// `mv <tmp> <path> && chmod 644 <path> && dscacheutil -flushcache && killall -HUP mDNSResponder`
/// ——`mv` 同卷 rename 原子替换（无 `cp` 的 truncate-write 窗口）、修权限、
/// 刷 DNS 缓存一气呵成；临时文件随后删除。
///
/// **部分成功容忍**：`mv`/`chmod`（关键步骤）失败才算写入失败；`dscacheutil`/
/// `killall` 仅刷 DNS 缓存（hosts 修改本身即时生效），其失败由回读校验兜底
/// ——内容已落盘则警告放行。否则调用方会误判失败而回滚：回滚再弹一次窗，
/// 且引擎停监听后 hosts 标记块残留会造成「域名指向 127.0.0.1 但无服务」的黑洞。
/// 用户取消 → [`HostsError::Unauthorized`]（调用方按"无权限"处理，与现有语义一致）。
fn write_file(path: &std::path::Path, content: &str) -> Result<(), HostsError> {
    match std::fs::write(path, content) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            #[cfg(target_os = "macos")]
            {
                write_file_elevated(path, content)
            }
            #[cfg(target_os = "windows")]
            {
                // Windows 无按需提权：hosts 位于受保护目录，只有管理员令牌可写。
                // 正常入口（应用清单 requireAdministrator）不会命中此分支；
                // 命中时给出可执行的中文指引，避免 UI 只看到裸 `os error 5`。
                tracing::error!(path = %path.display(), error = %e, "hosts 写入被拒绝");
                Err(HostsError::ElevationRequired(e.to_string()))
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                Err(HostsError::Io(e))
            }
        }
        Err(e) => Err(HostsError::Io(e)),
    }
}

/// macOS 提权写入（[`write_file`] 的 PermissionDenied 兜底路径）
#[cfg(target_os = "macos")]
fn write_file_elevated(path: &std::path::Path, content: &str) -> Result<(), HostsError> {
    // 临时文件：O_EXCL 创建（create_new），防符号链接/竞争攻击；
    // 文件名只含 PID 与重试序号，无用户可控段
    let tmp = create_exclusive_temp(content)?;

    let tmp_q = watt_elevate::posix_shell_quote(&tmp.display().to_string());
    let path_q = watt_elevate::posix_shell_quote(&path.display().to_string());
    let script = format!(
        "'mv' {tmp_q} {path_q} && 'chown' 'root:wheel' {path_q} && 'chmod' '644' {path_q} && 'dscacheutil' '-flushcache' && 'killall' '-HUP' 'mDNSResponder'"
    );
    let result = watt_elevate::run_as_admin_shell(
        &script,
        Some(watt_elevate::ElevatePurpose::WriteHosts.prompt()),
    );
    // 无论成败都清理临时文件（mv 成功后文件已不在，remove 失败无妨）
    let _ = std::fs::remove_file(&tmp);

    match result {
        Ok(_) => {
            // 双保险：回读验证内容确实落盘（防 rename 假成功等极端情况）
            verify_written(path, content)
        }
        Err(watt_elevate::ElevateError::Cancelled) => Err(HostsError::Unauthorized),
        Err(e) => {
            // 关键步骤可能已成功、仅缓存刷新失败：以回读结果为权威判据，
            // 已落盘则警告放行（见 write_file 文档的黑洞说明）
            match verify_written(path, content) {
                Ok(()) => {
                    tracing::warn!("hosts 提权写入后续步骤失败（{e}），但内容已落盘，按成功处理");
                    Ok(())
                }
                Err(verify_err) => Err(HostsError::Other(format!(
                    "提权写入 hosts 失败: {e}；回读校验也未通过: {verify_err}"
                ))),
            }
        }
    }
}

/// O_EXCL 创建临时文件并写入内容（`create_new` = O_EXCL，拒绝复用已存在路径）
#[cfg(target_os = "macos")]
fn create_exclusive_temp(content: &str) -> Result<std::path::PathBuf, HostsError> {
    use std::io::Write;
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..8u32 {
        let candidate = if attempt == 0 {
            dir.join(format!("watt-hosts-{pid}.tmp"))
        } else {
            dir.join(format!("watt-hosts-{pid}-{attempt}.tmp"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(content.as_bytes()) {
                    // 写失败必须清理已创建的临时文件，避免残留
                    drop(f);
                    let _ = std::fs::remove_file(&candidate);
                    return Err(HostsError::Io(e));
                }
                return Ok(candidate);
            }
            // 已存在（含恶意预建的符号链接）：换后缀重试，绝不覆盖
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(HostsError::Io(e)),
        }
    }
    Err(HostsError::Other(
        "无法创建 hosts 临时文件（重试多次仍被占用）".into(),
    ))
}

/// 回读校验：hosts 文件内容与期望完全一致
#[cfg(target_os = "macos")]
fn verify_written(path: &std::path::Path, expected: &str) -> Result<(), HostsError> {
    let actual = std::fs::read_to_string(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(HostsError::Other("hosts 回读内容与期望不一致".into()))
    }
}

impl Default for HostsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_remove_roundtrip() {
        let dir = std::env::temp_dir().join(format!("watt-hosts-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts_path = dir.join("hosts");
        std::fs::write(
            &hosts_path,
            "1.2.3.4 old.example.com\r\n\r\n# user comment\r\n",
        )
        .unwrap();

        let mgr = HostsManager::with_path(&hosts_path);

        // 更新：加速两个域名（其中一个覆盖用户已有行）
        mgr.update_hosts(&[
            ("127.0.0.1".into(), "steamcommunity.com".into()),
            ("127.0.0.1".into(), "old.example.com".into()),
        ])
        .unwrap();

        let content = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(content.contains(MARK_START));
        assert!(content.contains("127.0.0.1 steamcommunity.com"));
        assert!(content.contains(MARK_END));
        // 原行进备份块（#{N} 格式）
        assert!(content.contains(BACKUP_MARK_START));
        assert!(content.contains("#1 1.2.3.4 old.example.com"));
        assert!(content.contains(BACKUP_MARK_END));

        // 按标记移除：还原备份
        mgr.remove_hosts_by_tag().unwrap();
        let content2 = std::fs::read_to_string(&hosts_path).unwrap();
        assert!(!content2.contains(MARK_START));
        assert!(!content2.contains(BACKUP_MARK_START));
        assert!(content2.contains("1.2.3.4 old.example.com"));
        assert!(content2.contains("# user comment"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_hosts_entry_accepts_normal_entries() {
        assert!(validate_hosts_entry("127.0.0.1", "steamcommunity.com").is_ok());
        assert!(validate_hosts_entry("::1", "localhost").is_ok());
        assert!(validate_hosts_entry("1.2.3.4", "a-b_c.example.com").is_ok());
        // FQDN 尾点：其余模块按 trim_end_matches('.') 归一化，此处不得拒绝
        assert!(validate_hosts_entry("1.2.3.4", "example.com.").is_ok());
        assert!(validate_hosts_entry("1.2.3.4", " example.com ").is_ok());
    }

    #[test]
    fn validate_hosts_entry_rejects_injection() {
        // IP 非法
        assert!(validate_hosts_entry("not-an-ip", "a.com").is_err());
        // 换行 / 制表符 / 注释符 / 标记串均不得进入 hosts
        assert!(validate_hosts_entry("127.0.0.1", "a.com\n0.0.0.0 b.com").is_err());
        assert!(validate_hosts_entry("127.0.0.1", "a.com\t#Steam++ End").is_err());
        assert!(validate_hosts_entry("127.0.0.1", "#Steam++ End").is_err());
        assert!(validate_hosts_entry("127.0.0.1", "a com").is_err());
        assert!(validate_hosts_entry("127.0.0.1", "").is_err());
    }

    #[test]
    fn update_hosts_rejects_invalid_entry_before_write() {
        let dir = std::env::temp_dir().join("watt-hosts-invalid-entry");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        let mgr = HostsManager::with_path(&path);
        let err = mgr
            .update_hosts(&[(
                "127.0.0.1".into(),
                "evil.com\n0.0.0.0 bank.example".into(),
            )])
            .unwrap_err();
        assert!(matches!(err, HostsError::InvalidEntry(_)));
        // 原文件未被修改
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "127.0.0.1 localhost\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
