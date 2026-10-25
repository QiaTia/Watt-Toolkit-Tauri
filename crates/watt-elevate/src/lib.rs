//! 跨平台提权通道（对齐 doc/macos-acceleration-plan.md 工作项 2）。
//!
//! - macOS：`osascript -e 'do shell script "..." with administrator privileges'`，
//!   用户取消（退出码 -128）映射 [`ElevateError::Cancelled`]，UI 可区分"取消"与"失败"。
//! - Windows：本期返回 [`ElevateError::Unsupported`]（现有 runas 逻辑在 watt-cert 内自洽，不迁移）。
//! - Linux：预留 `pkexec`，本期返回 [`ElevateError::Unsupported`]。
//!
//! # 安全约定（调用方必须遵守）
//!
//! - 提权命令**只允许白名单程序**（见 [`ALLOWED_PROGRAMS`]）；
//! - 所有参数经 [`posix_shell_quote`] 逐个转义后再拼进 shell 命令，
//!   整体再经 [`applescript_string_quote`] 转义后嵌入 AppleScript 字符串字面量，
//!   **绝不允许拼接未转义的用户可控内容**（域名、路径等）；
//! - 复合命令（`&&` 串联）只允许由本 crate 内部构建（如 hosts 写入），
//!   调用方传入的 script 会经 [`validate_shell_script`] 逐段校验首程序白名单。

use std::fmt;
use std::process::Command;

/// 允许提权执行的程序白名单（按 basename 匹配）
///
/// `mv` 用于 hosts 原子替换（同卷 rename，避免 `cp` 的 truncate-write 窗口）。
pub const ALLOWED_PROGRAMS: &[&str] = &[
    "security", "cp", "mv", "mkdir", "chmod", "chown", "dscacheutil", "killall",
];

/// 提权操作类型（用于选择弹窗 prompt 文案）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevatePurpose {
    /// 安装根证书（MITM 信任）
    InstallCert,
    /// 卸载根证书
    RemoveCert,
    /// 写入 /etc/hosts
    WriteHosts,
}

impl ElevatePurpose {
    /// 弹窗 prompt 文案（AppleScript `with prompt`）
    pub fn prompt(&self) -> &'static str {
        match self {
            Self::InstallCert => "Watt Toolkit 需要管理员权限以安装根证书，启用 HTTPS 加速（MITM）",
            Self::RemoveCert => "Watt Toolkit 需要管理员权限以卸载根证书",
            Self::WriteHosts => "Watt Toolkit 需要管理员权限以写入 /etc/hosts，启用 Hosts 加速",
        }
    }
}

/// 提权错误
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ElevateError {
    /// 当前平台不支持提权（Windows/Linux 本期未接入）
    #[error("当前平台不支持提权操作")]
    Unsupported,
    /// 用户在系统弹窗中取消授权（osascript 退出码 -128）
    #[error("用户取消了管理员授权")]
    Cancelled,
    /// 提权后命令执行失败
    #[error("提权执行失败: {0}")]
    Failed(String),
    /// 程序不在提权白名单
    #[error("程序不在提权白名单: {0}")]
    NotAllowed(String),
}

/// 当前进程是否已具备管理员权限
pub fn is_elevated() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: geteuid 是无副作用的 libc 调用
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(target_os = "windows")]
    {
        // 无额外依赖方案：查询当前进程令牌的完整性等级。
        // 高完整性（S-1-16-12288）或 System（S-1-16-16384）即视为已提权。
        Command::new("whoami")
            .arg("/groups")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.contains("S-1-16-12288") || s.contains("S-1-16-16384"))
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// 提权执行单个程序（白名单校验 + 双层转义）。
///
/// `program` 须在 [`ALLOWED_PROGRAMS`] 内；`args` 逐个做 POSIX shell 转义。
pub fn run_as_admin(program: &str, args: &[&str]) -> Result<String, ElevateError> {
    run_as_admin_with_prompt(program, args, None)
}

/// 同 [`run_as_admin`]，但可指定弹窗 prompt 文案。
pub fn run_as_admin_with_prompt(
    program: &str,
    args: &[&str],
    prompt: Option<&str>,
) -> Result<String, ElevateError> {
    #[cfg(target_os = "macos")]
    {
        ensure_allowed(program)?;
        let cmd = build_shell_command(program, args);
        run_osascript(&cmd, prompt)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (program, args, prompt);
        Err(ElevateError::Unsupported)
    }
}

/// 提权执行复合 shell 命令（`&&` 等多步串联，单次弹窗完成）。
///
/// **仅允许传入本 crate 或可信调用方内部构建的脚本**：函数会逐段校验
/// 每段的首程序在白名单内，但无法理解 shell 语义（如重定向、子 shell）。
/// 用户可控内容必须经 [`posix_shell_quote`] 转义后作为 token 嵌入。
pub fn run_as_admin_shell(script: &str, prompt: Option<&str>) -> Result<String, ElevateError> {
    #[cfg(target_os = "macos")]
    {
        validate_shell_script(script)?;
        run_osascript(script, prompt)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (script, prompt);
        Err(ElevateError::Unsupported)
    }
}

// —————————————————————— 转义与构建（纯函数，跨平台单测） ——————————————————————

/// POSIX shell 单引号转义：整体包一层单引号，内部 `'` 闭合为 `'\''`。
pub fn posix_shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// AppleScript 字符串字面量转义：`\` → `\\`，`"` → `\"`。
pub fn applescript_string_quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 由 program + args 构建 POSIX shell 命令串（每个 token 独立转义）。
pub fn build_shell_command(program: &str, args: &[&str]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(args.len() + 1);
    parts.push(posix_shell_quote(program));
    parts.extend(args.iter().map(|a| posix_shell_quote(a)));
    parts.join(" ")
}

/// 构建 `osascript -e` 所需的 AppleScript 源码。
pub fn build_osascript(cmd: &str, prompt: Option<&str>) -> String {
    let mut script = format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_string_quote(cmd)
    );
    if let Some(p) = prompt {
        script.push_str(" with prompt \"");
        script.push_str(&applescript_string_quote(p));
        script.push('"');
    }
    script
}

/// 校验 program 的 basename 在白名单内。
pub fn ensure_allowed(program: &str) -> Result<(), ElevateError> {
    let base = basename(program);
    if ALLOWED_PROGRAMS.contains(&base) {
        Ok(())
    } else {
        Err(ElevateError::NotAllowed(base.to_string()))
    }
}

/// 校验复合 shell 脚本：按 `&&` / `;` / `|` 分段，逐段取首 token 校验白名单。
///
/// 注意：这是**静态**检查，不理解 shell 语义；脚本必须由可信方构建。
pub fn validate_shell_script(script: &str) -> Result<(), ElevateError> {
    let segments = script
        .split("&&")
        .flat_map(|s| s.split(';'))
        .flat_map(|s| s.split('|'));
    for seg in segments {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let first = seg.split_whitespace().next().unwrap_or("");
        // 脚本由 build_shell_command 构建，program 是单引号包裹的 token，先去引号
        let base = basename(unquote_token(first));
        if base.is_empty() || !ALLOWED_PROGRAMS.contains(&base) {
            return Err(ElevateError::NotAllowed(base.to_string()));
        }
    }
    Ok(())
}

/// 去掉 token 外层包裹的单引号（`'cp'` → `cp`）；非 quoted token 原样返回。
fn unquote_token(t: &str) -> &str {
    let b = t.as_bytes();
    if b.len() >= 2 && b[0] == b'\'' && b[b.len() - 1] == b'\'' {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// 取路径的 basename（无路径分隔符时原样返回）
pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

// —————————————————————— macOS 实现 ——————————————————————

#[cfg(target_os = "macos")]
fn run_osascript(cmd: &str, prompt: Option<&str>) -> Result<String, ElevateError> {
    let script = build_osascript(cmd, prompt);
    tracing::debug!(?script, "osascript 提权执行");

    let output = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| ElevateError::Failed(format!("osascript 启动失败: {e}")))?;

    match output.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&output.stdout).to_string()),
        // osascript 用户取消：userCanceledErr（退出码 -128 或经 WEXITSTATUS 截断的值，
        // 各 macOS 版本行为不完全一致，故对 stderr 文本兜底判定）
        Some(-128) => Err(ElevateError::Cancelled),
        code => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_trim = stderr.trim();
            if is_cancel_message(stderr_trim) {
                return Err(ElevateError::Cancelled);
            }
            Err(ElevateError::Failed(format!(
                "退出码 {:?}: {}",
                code, stderr_trim
            )))
        }
    }
}

/// stderr 是否为「用户取消」类错误（osascript 退出码不稳定时的兜底判定）
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_cancel_message(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("usercanceled") || s.contains("user canceled") || s.contains("-128")
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn run_osascript(cmd: &str, prompt: Option<&str>) -> Result<String, ElevateError> {
    let _ = (cmd, prompt);
    Err(ElevateError::Unsupported)
}

impl fmt::Display for ElevatePurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prompt())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_quote_plain() {
        assert_eq!(posix_shell_quote("security"), "'security'");
        assert_eq!(posix_shell_quote("/etc/hosts"), "'/etc/hosts'");
        assert_eq!(posix_shell_quote("/Library/Keychains/System.keychain"), "'/Library/Keychains/System.keychain'");
    }

    #[test]
    fn posix_quote_single_quote() {
        assert_eq!(posix_shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn posix_quote_empty() {
        assert_eq!(posix_shell_quote(""), "''");
    }

    #[test]
    fn posix_quote_shell_metachars_stay_inert() {
        // 含 shell 元字符的字符串经转义后必须是单个 token，不再有注入面
        let q = posix_shell_quote("evil.com; rm -rf /");
        assert_eq!(q, "'evil.com; rm -rf /'");
        // 反向验证：以该 token 拼出的命令段首程序不是 rm
        let cmd = build_shell_command("security", &["add-trusted-cert", "evil.com; rm -rf /"]);
        assert_eq!(
            cmd,
            "'security' 'add-trusted-cert' 'evil.com; rm -rf /'"
        );
    }

    #[test]
    fn applescript_quote() {
        assert_eq!(applescript_string_quote("a\"b"), "a\\\"b");
        assert_eq!(applescript_string_quote("a\\b"), "a\\\\b");
        assert_eq!(applescript_string_quote("plain"), "plain");
    }

    #[test]
    fn build_osascript_with_and_without_prompt() {
        assert_eq!(
            build_osascript("'cp' '/a' '/b'", None),
            "do shell script \"'cp' '/a' '/b'\" with administrator privileges"
        );
        assert_eq!(
            build_osascript("'cp' '/a' '/b'", Some("需要权限")),
            "do shell script \"'cp' '/a' '/b'\" with administrator privileges with prompt \"需要权限\""
        );
    }

    #[test]
    fn build_osascript_escapes_quote_in_cmd() {
        // 命令里含双引号（转义后）不得破坏 AppleScript 字符串边界：
        // 未被反斜杠转义的引号必须恰好 2 个（字符串起止）
        let cmd = build_shell_command("security", &["add-trusted-cert", "a\"b"]);
        let script = build_osascript(&cmd, None);
        let escaped = script.matches("\\\"").count();
        let total = script.matches('"').count();
        assert_eq!(total - escaped, 2, "AppleScript 边界引号必须只有一对: {script}");
        assert_eq!(escaped, 1, "命令内的引号必须被转义: {script}");
    }

    #[test]
    fn ensure_allowed_basename() {
        assert!(ensure_allowed("security").is_ok());
        assert!(ensure_allowed("/usr/bin/security").is_ok());
        // mv 用于 hosts 原子替换（同卷 rename）
        assert!(ensure_allowed("mv").is_ok());
        assert!(matches!(
            ensure_allowed("rm"),
            Err(ElevateError::NotAllowed(n)) if n == "rm"
        ));
        assert!(matches!(
            ensure_allowed("/bin/rm"),
            Err(ElevateError::NotAllowed(n)) if n == "rm"
        ));
    }

    #[test]
    fn is_cancel_message_detects_osascript_cancel() {
        assert!(is_cancel_message("execution error: User canceled. (-128)"));
        assert!(is_cancel_message("execution error: usercancelederr (-128)"));
        assert!(is_cancel_message("Error: -128"));
        assert!(!is_cancel_message("security: SecTrustEvaluate failed"));
        assert!(!is_cancel_message("cp: permission denied"));
    }

    #[test]
    fn validate_shell_script_ok() {
        assert!(validate_shell_script("'cp' '/tmp/x' '/etc/hosts' && 'chmod' '644' '/etc/hosts' && 'dscacheutil' '-flushcache' && 'killall' '-HUP' 'mDNSResponder'").is_ok());
        assert!(validate_shell_script("'security' 'add-trusted-cert'").is_ok());
        assert!(validate_shell_script("").is_ok());
    }

    #[test]
    fn validate_shell_script_rejects_disallowed() {
        assert!(validate_shell_script("'rm' '-rf' '/").is_err());
        assert!(validate_shell_script("'cp' '/a' '/b' && 'sh' '-c' 'evil'").is_err());
        assert!(validate_shell_script("'security' 'x' | 'tee' '/etc/passwd'").is_err());
    }

    #[test]
    fn run_as_admin_rejects_non_whitelisted_before_spawn() {
        // macOS 上白名单校验先于平台分支，返回 NotAllowed；其它平台无提权实现
        let err = run_as_admin("rm", &["-rf", "/"]).unwrap_err();
        #[cfg(target_os = "macos")]
        assert_eq!(err, ElevateError::NotAllowed("rm".into()));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(err, ElevateError::Unsupported);
    }
}
