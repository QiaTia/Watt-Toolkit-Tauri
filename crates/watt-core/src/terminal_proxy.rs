//! 终端（CLI）接入面：用户级代理环境变量 + CLI 证书注入。
//!
//! # 为什么需要它
//!
//! 系统代理（System/PAC 模式）只写平台系统代理设置（Windows 是 WinINET
//! `HKCU\...\Internet Settings`，macOS 是 networksetup），**只**覆盖遵循系统
//! 代理的应用。`git` / `curl` / `npm` / `pip` / `go` / `python` 都不读这些设置
//! （上游 Watt Toolkit 亦然——其 `WindowsPlatformServiceImpl.SystemProxy.cs`
//! 也只是写同一条注册表），因此「系统代理」模式下终端命令天然不会被代理。
//!
//! 本模块补的是另一条接入面：把代理写进**用户级环境变量**（`HTTP_PROXY` /
//! `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`），并给 CLI 注入 CA 覆盖变量
//! （`CURL_CA_BUNDLE` / `SSL_CERT_FILE` / `GIT_SSL_CAINFO` / `NODE_EXTRA_CA_CERTS`
//! / `REQUESTS_CA_BUNDLE`），让 MITM 后的证书在终端侧也被信任。
//!
//! # 各平台落点
//!
//! - **Windows**：写 `HKCU\Environment`（REG_SZ），广播 `WM_SETTINGCHANGE`。
//! - **macOS / Linux**：环境变量没有用户级注册表，改为在**当前登录 shell**
//!   的启动文件末尾维护一个带标记的块（zsh `~/.zshenv`、bash `~/.bash_profile`、
//!   fish `~/.config/fish/config.fish`、其它 `~/.profile`）。标记块保证可精确
//!   移除，不会破坏用户原有配置；Unset 时按标记删除。
//!
//! Unix 额外处理两点：
//! - 环境变量名**区分大小写**，而 `curl` / `git` 优先读小写变量 → 同时写大小写副本；
//! - 若把 `CURL_CA_BUNDLE` / `SSL_CERT_FILE` 直接指向只含 Watt CA 的文件，
//!   所有**直连**（未加速）域名的 TLS 校验都会失败 → 生成「系统根证书 + Watt CA」
//!   合并 bundle 再注入。
//!
//! # 必须遵守的约定
//!
//! - **先备份再写**：`{Settings}/TerminalProxyEnv.backup.json` 记录被改变的变量
//!   （Windows）或改写的配置文件（Unix），退出/停止时逐项还原，绝不把用户原有
//!   代理配置吞掉。
//! - **与引擎同生命周期**：启用只在引擎启动成功后，停止/退出/孤儿清理时还原。
//! - **刷新**：Windows 需广播 `WM_SETTINGCHANGE`；Unix 由新开的 shell 读取配置，
//!   已打开的终端不受影响——UI 需提示重开终端。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
use std::collections::BTreeMap;

/// 代理环境变量（大写；Windows 环境变量名大小写不敏感，无需小写副本；
/// Unix 由 `unix_targets` 额外补小写副本）
pub const PROXY_ENV_VARS: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// CLI 证书覆盖变量（各工具各自读取的 CA 信任入口）
pub const CA_ENV_VARS: &[&str] = &[
    "NODE_EXTRA_CA_CERTS",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "GIT_SSL_CAINFO",
];

/// 一次注入的计划：由调用方（命令层）按当前模式与端口构造
#[derive(Debug, Clone)]
pub struct TerminalProxyPlan {
    /// 备份文件路径（同时作为「是否处于注入态」的判据）
    pub backup_path: PathBuf,
    /// 正向代理地址（`http://127.0.0.1:26501`）；`None` = 当前模式没有正向代理
    /// 在监听（Hosts 模式），此时只注入 CA 变量、不注入代理变量——否则会让
    /// 终端把流量指向一个没人监听的端口。
    pub proxy_url: Option<String>,
    /// 不走代理的地址（逗号分隔）
    pub no_proxy: String,
    /// CA 证书 PEM 路径（不存在则跳过 CA 注入）
    pub ca_pem: Option<PathBuf>,
}

/// 默认 NO_PROXY：本机 + 内网 CIDR + 官方 API。
///
/// 注意**不能**直接复用系统代理的 bypass 列表：那是 WinINET 语法（`192.168.*`），
/// 而 `NO_PROXY` 环境变量由 libcurl / git / npm 各自解析，它们认 CIDR 与域名后缀
/// （`192.168.0.0/16`、`.steampp.net`），`192.168.*` 这类通配符不会被匹配。
pub fn default_no_proxy() -> String {
    [
        "localhost",
        "127.0.0.1",
        "::1",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "api.steampp.net",
        "shop-api.steampp.net",
    ]
    .join(",")
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEntry {
    /// 注入前该变量是否已存在
    present: bool,
    /// 注入前的值（`present=false` 时为 None）
    #[serde(default)]
    value: Option<String>,
}

/// Windows 备份文件内容：变量名 → 原值
#[cfg(target_os = "windows")]
type Backup = BTreeMap<String, BackupEntry>;

/// Unix 备份文件内容：被改写的 shell 启动文件
#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnixBackup {
    files: Vec<InjectedFile>,
}

/// 一个被写入标记块的配置文件
#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InjectedFile {
    path: PathBuf,
    /// 注入前文件是否不存在（还原时若内容已空则一并删除）
    created: bool,
}

/// 是否处于注入态（备份文件存在即视为已注入）
pub fn is_enabled(backup_path: &Path) -> bool {
    backup_path.exists()
}

/// 计算本次需要写入的变量（纯函数，便于单测）
fn build_targets(plan: &TerminalProxyPlan) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(url) = plan.proxy_url.as_deref() {
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            out.push((var.to_string(), url.to_string()));
        }
        out.push(("NO_PROXY".to_string(), plan.no_proxy.clone()));
    }
    if let Some(ca) = plan.ca_pem.as_deref() {
        if ca.exists() {
            let v = ca.display().to_string();
            for var in CA_ENV_VARS {
                out.push(((*var).to_string(), v.clone()));
            }
        }
    }
    out
}

/// Unix 最终注入项：补小写变量名 + CA 指向合并 bundle
#[cfg(unix)]
fn unix_targets(plan: &TerminalProxyPlan) -> Vec<(String, String)> {
    let mut targets = build_targets(plan);
    let lowercase: Vec<(String, String)> = targets
        .iter()
        .filter(|(name, _)| PROXY_ENV_VARS.contains(&name.as_str()))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    targets.extend(lowercase);

    if let Some(ca) = plan.ca_pem.as_deref().filter(|p| p.exists()) {
        match imp::combined_ca_bundle(ca) {
            Ok(bundle) => {
                let value = bundle.display().to_string();
                for (name, v) in targets.iter_mut() {
                    if CA_ENV_VARS.contains(&name.as_str()) {
                        *v = value.clone();
                    }
                }
            }
            Err(e) => tracing::warn!("生成合并 CA bundle 失败，回退为 Watt CA 单文件: {e}"),
        }
    }
    targets
}

/// 注入终端代理环境变量（幂等：已有备份先还原再重新备份，避免把注入值当原值）
pub fn enable(plan: &TerminalProxyPlan) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let targets = build_targets(plan);
    #[cfg(unix)]
    let targets = unix_targets(plan);

    if targets.is_empty() {
        return Ok(());
    }

    // 若上次注入未还原（崩溃/强杀），先按旧备份还原，保证本次记录的是「真实原值」
    if plan.backup_path.exists() {
        if let Err(e) = disable(&plan.backup_path) {
            tracing::warn!("上一次终端代理环境变量还原失败（继续重新注入）: {e}");
        }
    }

    enable_impl(plan, &targets)?;
    tracing::info!(
        "终端代理已注入：{} 个变量（proxy_url={:?}），仅对新开的终端生效",
        targets.len(),
        plan.proxy_url
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn enable_impl(plan: &TerminalProxyPlan, targets: &[(String, String)]) -> Result<(), String> {
    let mut backup: Backup = BTreeMap::new();
    for (name, _) in targets {
        let current = imp::read(name)?;
        backup.insert(
            name.clone(),
            BackupEntry {
                present: current.is_some(),
                value: current,
            },
        );
    }
    write_backup(&plan.backup_path, &backup)?;

    for (name, value) in targets {
        if let Err(e) = imp::write(name, value) {
            // 半注入立即回滚：否则新开终端会指向一个可能已停的端口
            let rollback = disable(&plan.backup_path);
            tracing::warn!("写入 {name} 失败，回滚终端代理环境变量: {rollback:?}");
            return Err(format!("写入 {name} 失败: {e}"));
        }
    }
    imp::broadcast_change();
    Ok(())
}

#[cfg(unix)]
fn enable_impl(plan: &TerminalProxyPlan, targets: &[(String, String)]) -> Result<(), String> {
    let files = imp::shell_config_files();
    if files.is_empty() {
        return Err("无法确定 shell 启动文件（HOME 未设置）".to_string());
    }
    let entries: Vec<InjectedFile> = files
        .iter()
        .map(|path| InjectedFile {
            path: path.clone(),
            created: !path.exists(),
        })
        .collect();
    // 先落备份再改文件：中途崩溃时下次启动仍能按标记清理
    write_unix_backup(&plan.backup_path, &entries)?;

    if let Err(e) = imp::inject(&files, targets) {
        let rollback = disable(&plan.backup_path);
        tracing::warn!("写入 shell 启动配置失败，回滚终端代理: {rollback:?}");
        return Err(e);
    }
    tracing::info!(
        "终端代理配置已写入: {}",
        files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

/// 还原注入前的环境变量 / shell 启动文件（幂等：备份不存在直接返回 Ok）
pub fn disable(backup_path: &Path) -> Result<(), String> {
    if !backup_path.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(backup_path).map_err(|e| format!("读取备份失败: {e}"))?;
    let count = disable_impl(&text)?;
    std::fs::remove_file(backup_path).map_err(|e| format!("删除备份失败: {e}"))?;
    tracing::info!("终端代理已还原（{count} 项）");
    Ok(())
}

#[cfg(target_os = "windows")]
fn disable_impl(text: &str) -> Result<usize, String> {
    let backup: Backup = serde_json::from_str(text).map_err(|e| format!("解析备份失败: {e}"))?;
    let mut failures: Vec<String> = Vec::new();
    for (name, entry) in &backup {
        let result = match (&entry.present, &entry.value) {
            (true, Some(v)) => imp::write(name, v),
            // 原本不存在 → 删除变量
            _ => imp::remove(name),
        };
        if let Err(e) = result {
            failures.push(format!("{name}: {e}"));
        }
    }
    imp::broadcast_change();
    if !failures.is_empty() {
        // 保留备份文件，便于下次启动重试
        return Err(format!("还原部分失败: {}", failures.join("; ")));
    }
    Ok(backup.len())
}

#[cfg(unix)]
fn disable_impl(text: &str) -> Result<usize, String> {
    let backup: UnixBackup =
        serde_json::from_str(text).map_err(|e| format!("解析备份失败: {e}"))?;
    imp::remove_blocks(&backup.files)?;
    Ok(backup.files.len())
}

#[cfg(target_os = "windows")]
fn write_backup(path: &Path, backup: &Backup) -> Result<(), String> {
    let json = serde_json::to_string_pretty(backup).map_err(|e| e.to_string())?;
    // 原子写：备份是唯一的还原依据，截断损坏会导致环境变量永久残留
    watt_config::settings::write_atomic(path, json.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn write_unix_backup(path: &Path, files: &[InjectedFile]) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&UnixBackup {
        files: files.to_vec(),
    })
    .map_err(|e| e.to_string())?;
    // 原子写：理由同 Windows 分支
    watt_config::settings::write_atomic(path, json.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
mod imp {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ,
    };

    const ENV_SUBKEY: &str = "Environment";

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open_key(access: u32) -> Result<HKEY, String> {
        let subkey = to_wide(ENV_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: 传入的 subkey 以 NUL 结尾；hkey 在使用后由 close_key 释放
        let rc = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut hkey) };
        if rc != ERROR_SUCCESS {
            return Err(format!("打开 HKCU\\Environment 失败（code={rc}）"));
        }
        Ok(hkey)
    }

    fn close_key(hkey: HKEY) {
        // SAFETY: hkey 来自 open_key，且只关闭一次
        unsafe { RegCloseKey(hkey) };
    }

    /// 读取用户环境变量（不存在返回 None）
    pub fn read(name: &str) -> Result<Option<String>, String> {
        let hkey = open_key(KEY_QUERY_VALUE)?;
        let name_w = to_wide(name);
        let mut value_type: u32 = 0;
        let mut size: u32 = 0;
        // 先探长度
        // SAFETY: 输出指针均为有效栈变量；size=0 时 lpData 允许为空
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                std::ptr::null(),
                &mut value_type,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc == ERROR_FILE_NOT_FOUND {
            close_key(hkey);
            return Ok(None);
        }
        if rc != ERROR_SUCCESS {
            close_key(hkey);
            return Err(format!("读取环境变量 {name} 失败（code={rc}）"));
        }
        let mut buf = vec![0u8; size.max(2) as usize];
        // SAFETY: buf 长度取自上一步返回的 size
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                std::ptr::null(),
                &mut value_type,
                buf.as_mut_ptr(),
                &mut size,
            )
        };
        close_key(hkey);
        if rc != ERROR_SUCCESS {
            return Err(format!("读取环境变量 {name} 失败（code={rc}）"));
        }
        // REG_SZ / REG_EXPAND_SZ 均为 UTF-16LE，按 u16 解释并去尾 NUL
        let wide: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let end = wide.iter().position(|c| *c == 0).unwrap_or(wide.len());
        Ok(Some(String::from_utf16_lossy(&wide[..end])))
    }

    /// 写入用户环境变量（REG_SZ）
    pub fn write(name: &str, value: &str) -> Result<(), String> {
        let hkey = open_key(KEY_SET_VALUE)?;
        let name_w = to_wide(name);
        let value_w = to_wide(value);
        // SAFETY: value_w 以 NUL 结尾，字节数按 u16 计算（不含终止符）
        let rc = unsafe {
            RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                REG_SZ,
                value_w.as_ptr() as *const u8,
                (value_w.len() * 2) as u32,
            )
        };
        close_key(hkey);
        if rc != ERROR_SUCCESS {
            return Err(format!("写入环境变量 {name} 失败（code={rc}）"));
        }
        Ok(())
    }

    /// 删除用户环境变量（不存在视为成功）
    pub fn remove(name: &str) -> Result<(), String> {
        let hkey = open_key(KEY_SET_VALUE)?;
        let name_w = to_wide(name);
        // SAFETY: name_w 以 NUL 结尾
        let rc = unsafe { RegDeleteValueW(hkey, name_w.as_ptr()) };
        close_key(hkey);
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
            return Err(format!("删除环境变量 {name} 失败（code={rc}）"));
        }
        Ok(())
    }

    /// 广播 `WM_SETTINGCHANGE`（lParam = "Environment"），让新进程拿到新环境
    pub fn broadcast_change() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };
        let param = to_wide("Environment");
        // SAFETY: 同步广播，lParam 指向在调用期间存活的宽字符串
        unsafe {
            let mut result: usize = 0;
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                param.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                1000,
                &mut result,
            );
        }
    }
}

/// macOS / Linux：通过登录 shell 的启动文件注入环境变量
#[cfg(unix)]
mod imp {
    use super::InjectedFile;
    use std::path::{Path, PathBuf};

    pub(super) const BLOCK_BEGIN: &str = "# >>> Watt Toolkit terminal proxy >>>";
    pub(super) const BLOCK_END: &str = "# <<< Watt Toolkit terminal proxy <<<";

    #[derive(Clone, Copy)]
    pub(super) enum ShellKind {
        Posix,
        Fish,
    }

    /// 当前登录 shell 的启动文件。
    ///
    /// zsh 选 `~/.zshenv`：它对交互/非交互 shell 都生效，且早于 `~/.zshrc`
    /// 加载——用户自己写在 `.zshrc` 里的代理配置仍可覆盖我们，减少侵入。
    pub fn shell_config_files() -> Vec<PathBuf> {
        let (shell, home) = user_shell_and_home();
        let Some(home) = home else {
            return Vec::new();
        };
        let name = Path::new(shell.as_deref().unwrap_or_default())
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let path = match name {
            "zsh" => home.join(".zshenv"),
            "fish" => home.join(".config").join("fish").join("config.fish"),
            "bash" if cfg!(target_os = "macos") => home.join(".bash_profile"),
            "bash" => {
                let rc = home.join(".bashrc");
                if rc.exists() {
                    rc
                } else {
                    home.join(".bash_profile")
                }
            }
            _ => home.join(".profile"),
        };
        vec![path]
    }

    /// 登录 shell 与 home。
    ///
    /// 从 Finder / launchd 启动的 App 环境里可能没有 `SHELL` / `HOME`，
    /// 此时回退到 passwd 数据库，避免把配置写到 zsh 不读取的 `~/.profile`。
    fn user_shell_and_home() -> (Option<String>, Option<PathBuf>) {
        let env_shell = std::env::var("SHELL").ok().filter(|s| !s.trim().is_empty());
        let env_home = std::env::var_os("HOME").map(PathBuf::from);
        if env_shell.is_some() && env_home.is_some() {
            return (env_shell, env_home);
        }
        let (pw_shell, pw_home) = passwd_info();
        (env_shell.or(pw_shell), env_home.or(pw_home))
    }

    /// 通过 `getpwuid_r` 读取当前用户的 shell / home（线程安全版本）
    fn passwd_info() -> (Option<String>, Option<PathBuf>) {
        let mut buf = vec![0; 4096];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: pwd/buf 在调用期间有效；getpwuid_r 成功后 result 指向 pwd，
        // 字符串字段指向 buf。返回前立即拷贝为拥有所有权的 String/PathBuf。
        let rc = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return (None, None);
        }
        let shell = c_ptr_to_string(pwd.pw_shell);
        let home = c_ptr_to_string(pwd.pw_dir).map(PathBuf::from);
        (shell, home)
    }

    fn c_ptr_to_string(ptr: *const libc::c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: passwd 的字符串字段由 getpwuid_r 保证以 NUL 结尾
        let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes();
        (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
    }

    /// 生成「系统根证书 + Watt CA」合并 bundle，供 CLI 的 CA 覆盖变量使用。
    ///
    /// 只指向 Watt CA 会让所有未加速域名的 TLS 校验失败（变量是替换而非追加），
    /// 因此必须与系统根证书合并在同一个文件里。
    pub fn combined_ca_bundle(ca: &Path) -> Result<PathBuf, String> {
        let dir = ca
            .parent()
            .ok_or_else(|| "Watt CA 路径无父目录".to_string())?;
        let out = dir.join("ca-bundle.pem");
        let mut data = Vec::new();
        for candidate in [
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ] {
            if let Ok(bytes) = std::fs::read(candidate) {
                data = bytes;
                break;
            }
        }
        if data.is_empty() {
            return Err("未找到系统 CA bundle".to_string());
        }
        if !data.ends_with(b"\n") {
            data.push(b'\n');
        }
        let pem = std::fs::read(ca).map_err(|e| format!("读取 Watt CA 失败: {e}"))?;
        data.extend_from_slice(&pem);
        write_atomic(&out, &data).map_err(|e| format!("写入合并 CA bundle 失败: {e}"))?;
        Ok(out)
    }

    /// 把标记块写入各配置文件（幂等：先移除旧块再追加）
    pub fn inject(files: &[PathBuf], targets: &[(String, String)]) -> Result<(), String> {
        for path in files {
            let kind = shell_kind(path);
            let block = render_block(kind, targets);
            let existing = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(format!("读取 {} 失败: {e}", path.display())),
            };
            let mut next = strip_block(&existing);
            if !next.is_empty() && !next.ends_with('\n') {
                next.push('\n');
            }
            next.push_str(&block);
            write_atomic(path, next.as_bytes())
                .map_err(|e| format!("写入 {} 失败: {e}", path.display()))?;
        }
        Ok(())
    }

    /// 按备份移除标记块；注入时新建的文件在清空后一并删除
    pub fn remove_blocks(files: &[InjectedFile]) -> Result<(), String> {
        let mut failures: Vec<String> = Vec::new();
        for file in files {
            let existing = match std::fs::read_to_string(&file.path) {
                Ok(s) => s,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    failures.push(format!("{}: {e}", file.path.display()));
                    continue;
                }
            };
            let next = strip_block(&existing);
            let result = if file.created && next.trim().is_empty() {
                match std::fs::remove_file(&file.path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e),
                }
            } else if next == existing {
                Ok(())
            } else {
                write_atomic(&file.path, next.as_bytes())
            };
            if let Err(e) = result {
                failures.push(format!("{}: {e}", file.path.display()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!("还原部分失败: {}", failures.join("; ")))
        }
    }

    fn shell_kind(path: &Path) -> ShellKind {
        if path.file_name().and_then(|s| s.to_str()) == Some("config.fish") {
            ShellKind::Fish
        } else {
            ShellKind::Posix
        }
    }

    pub(super) fn render_block(kind: ShellKind, targets: &[(String, String)]) -> String {
        let mut out = String::new();
        out.push_str(BLOCK_BEGIN);
        out.push('\n');
        for (name, value) in targets {
            match kind {
                ShellKind::Posix => {
                    out.push_str(&format!("export {name}={}\n", posix_quote(value)));
                }
                ShellKind::Fish => {
                    out.push_str(&format!("set -gx {name} {}\n", fish_quote(value)));
                }
            }
        }
        out.push_str(BLOCK_END);
        out.push('\n');
        out
    }

    /// 删除标记块（含标记行）；未闭合的块视为延伸到文件末尾
    pub(super) fn strip_block(content: &str) -> String {
        let mut out = String::with_capacity(content.len());
        let mut in_block = false;
        for line in content.split_inclusive('\n') {
            let marker = line.trim_end_matches(|c| c == '\r' || c == '\n').trim();
            if marker == BLOCK_BEGIN {
                in_block = true;
                continue;
            }
            if in_block && marker == BLOCK_END {
                in_block = false;
                continue;
            }
            if !in_block {
                out.push_str(line);
            }
        }
        out
    }

    fn posix_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn fish_quote(value: &str) -> String {
        let mut out = String::from("'");
        for c in value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\'' => out.push_str("\\'"),
                _ => out.push(c),
            }
        }
        out.push('\'');
        out
    }

    /// 同目录临时文件 + rename，避免写入中途崩溃截断用户的 dotfile
    fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config");
        let tmp = parent.join(format!(".{name}.watt-tmp"));
        std::fs::write(&tmp, bytes)?;
        // 保留原文件权限（dotfile 可能是 0600）
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&tmp, meta.permissions());
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(proxy: Option<&str>, ca: bool) -> TerminalProxyPlan {
        TerminalProxyPlan {
            backup_path: std::env::temp_dir().join("watt-terminal-proxy-test.json"),
            proxy_url: proxy.map(str::to_string),
            no_proxy: "localhost,127.0.0.1".into(),
            ca_pem: ca.then(|| std::env::temp_dir().join("watt-tp-missing-ca.pem")),
        }
    }

    #[test]
    fn no_proxy_includes_loopback_and_private_ranges() {
        let np = default_no_proxy();
        assert!(np.contains("localhost"));
        assert!(np.contains("127.0.0.1"));
        // 必须是 libcurl/npm 认得的 CIDR，而不是 WinINET 通配符
        assert!(np.contains("192.168.0.0/16"));
        assert!(np.contains("10.0.0.0/8"));
        assert!(!np.contains("192.168.*"));
        assert!(np.contains("api.steampp.net"));
    }

    #[test]
    fn targets_skip_proxy_vars_when_no_forward_proxy() {
        // Hosts 模式：没有正向代理在听 → 不得注入代理变量
        let t = build_targets(&plan(None, false));
        assert!(t.is_empty());
    }

    #[test]
    fn targets_include_proxy_and_no_proxy() {
        let t = build_targets(&plan(Some("http://127.0.0.1:26501"), false));
        let names: Vec<&str> = t.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            vec!["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
        );
        assert!(t
            .iter()
            .all(|(k, v)| k == "NO_PROXY" || v == "http://127.0.0.1:26501"));
    }

    #[test]
    fn targets_skip_missing_ca_file() {
        // CA 路径不存在 → 不注入证书变量（避免把无效路径塞给 git/curl）
        let t = build_targets(&plan(Some("http://127.0.0.1:26501"), true));
        assert!(!t.iter().any(|(k, _)| k == "CURL_CA_BUNDLE"));
    }

    #[test]
    fn disable_is_noop_without_backup() {
        let missing = std::env::temp_dir().join("watt-terminal-proxy-not-exist.json");
        let _ = std::fs::remove_file(&missing);
        assert!(disable(&missing).is_ok());
        assert!(!is_enabled(&missing));
    }

    /// 注册表读写往返（只碰自建的临时变量名，不动任何真实代理变量）
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_env_roundtrip_on_temp_var() {
        const NAME: &str = "WATT_TERMINAL_PROXY_SELFTEST";
        let _ = imp::remove(NAME);
        assert_eq!(imp::read(NAME).unwrap(), None);

        imp::write(NAME, "http://127.0.0.1:26501").unwrap();
        assert_eq!(
            imp::read(NAME).unwrap().as_deref(),
            Some("http://127.0.0.1:26501")
        );

        imp::write(NAME, "C:\\临时 目录\\ca.pem").unwrap();
        assert_eq!(
            imp::read(NAME).unwrap().as_deref(),
            Some("C:\\临时 目录\\ca.pem"),
            "含空格/中文的路径必须无损往返"
        );

        imp::remove(NAME).unwrap();
        assert_eq!(imp::read(NAME).unwrap(), None);
    }

    #[cfg(unix)]
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("watt-tp-{tag}-{}-{nanos}", std::process::id()))
    }

    #[cfg(unix)]
    fn sample_targets() -> Vec<(String, String)> {
        vec![
            (
                "HTTP_PROXY".to_string(),
                "http://127.0.0.1:26501".to_string(),
            ),
            (
                "CURL_CA_BUNDLE".to_string(),
                "/tmp/Watt 目录/ca-bundle.pem".to_string(),
            ),
        ]
    }

    #[cfg(unix)]
    #[test]
    fn unix_inject_is_idempotent_and_preserves_existing_content() {
        let dir = temp_dir("inject");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(".zshenv");
        std::fs::write(&file, "export FOO='bar'\n").unwrap();

        let files = vec![file.clone()];
        imp::inject(&files, &sample_targets()).unwrap();
        let once = std::fs::read_to_string(&file).unwrap();
        assert!(once.starts_with("export FOO='bar'\n"));
        assert!(once.contains("export HTTP_PROXY='http://127.0.0.1:26501'"));
        assert!(once.contains(imp::BLOCK_BEGIN));
        assert!(once.contains(imp::BLOCK_END));

        // 再次注入不得叠加标记块
        imp::inject(&files, &sample_targets()).unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), once);

        imp::remove_blocks(&[InjectedFile {
            path: file.clone(),
            created: false,
        }])
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "export FOO='bar'\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_injected_block_is_sourceable_by_posix_shell() {
        let dir = temp_dir("source");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(".profile");
        let ca = dir.join("Watt CA").join("ca-bundle.pem");
        let targets = vec![
            (
                "HTTP_PROXY".to_string(),
                "http://127.0.0.1:26501".to_string(),
            ),
            ("CURL_CA_BUNDLE".to_string(), ca.display().to_string()),
        ];
        imp::inject(&[file.clone()], &targets).unwrap();

        let script = format!(
            ". '{}'; printf '%s|%s' \"$HTTP_PROXY\" \"$CURL_CA_BUNDLE\"",
            file.display().to_string().replace('\'', "'\\''")
        );
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "shell 加载失败: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("http://127.0.0.1:26501|{}", ca.display()),
            "含空格的路径必须能被 shell 正确还原"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_remove_deletes_file_created_by_injection() {
        let dir = temp_dir("created");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(".profile");
        assert!(!file.exists());

        let files = vec![file.clone()];
        imp::inject(&files, &sample_targets()).unwrap();
        assert!(file.exists());

        imp::remove_blocks(&[InjectedFile {
            path: file.clone(),
            created: true,
        }])
        .unwrap();
        assert!(!file.exists(), "注入时新建的配置文件清空后应删除");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn unix_strip_block_drops_unterminated_tail() {
        let content = "before\n# >>> Watt Toolkit terminal proxy >>>\nexport A=1\n";
        assert_eq!(imp::strip_block(content), "before\n");
    }

    #[cfg(unix)]
    #[test]
    fn unix_fish_block_uses_set_gx_and_escapes_quotes() {
        let block = imp::render_block(
            imp::ShellKind::Fish,
            &[("HTTP_PROXY".to_string(), "http://a/b'c".to_string())],
        );
        assert!(block.contains("set -gx HTTP_PROXY 'http://a/b\\'c'"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_targets_add_lowercase_proxy_vars() {
        let t = unix_targets(&plan(Some("http://127.0.0.1:26501"), false));
        let names: Vec<&str> = t.iter().map(|(k, _)| k.as_str()).collect();
        for expected in ["http_proxy", "https_proxy", "all_proxy", "no_proxy"] {
            assert!(names.contains(&expected), "缺少小写变量 {expected}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_ca_bundle_contains_watt_ca() {
        let dir = temp_dir("bundle");
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.cert.pem");
        let pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n";
        std::fs::write(&ca, pem).unwrap();

        // 系统 bundle 不存在时（少见）跳过断言，避免测试依赖宿主环境
        if let Ok(bundle) = imp::combined_ca_bundle(&ca) {
            let data = std::fs::read_to_string(&bundle).unwrap();
            assert!(data.len() > pem.len());
            assert!(data.ends_with(pem));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
