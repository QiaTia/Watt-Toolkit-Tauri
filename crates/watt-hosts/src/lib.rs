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

        std::fs::write(&self.path, new_content)?;
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
        std::fs::write(&self.path, default_hosts_content())?;
        Ok(())
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
}
