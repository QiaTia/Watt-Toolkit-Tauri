//! 终端（CLI）接入面：用户级代理环境变量 + CLI 证书注入。
//!
//! # 为什么需要它
//!
//! 系统代理（System/PAC 模式）只写 WinINET（`HKCU\...\Internet Settings`），
//! **只**覆盖 IE/Edge/Chrome、部分 .NET/Office 组件。`git` / `curl` / `npm` /
//! `pip` / `go` / `python` 都不读这个键（上游 Watt Toolkit 亦然——其
//! `WindowsPlatformServiceImpl.SystemProxy.cs` 也只是写同一条注册表），因此
//! 「系统代理」模式下终端命令天然不会被代理。
//!
//! 本模块补的是另一条接入面：把代理写进**用户级环境变量**（`HTTP_PROXY` /
//! `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`），并给 CLI 注入 CA 覆盖变量
//! （`CURL_CA_BUNDLE` / `SSL_CERT_FILE` / `GIT_SSL_CAINFO` / `NODE_EXTRA_CA_CERTS`
//! / `REQUESTS_CA_BUNDLE`），让 MITM 后的证书在终端侧也被信任。
//!
//! # 必须遵守的约定
//!
//! - **先备份再写**：`{Settings}/TerminalProxyEnv.backup.json` 记录被改变量的
//!   *原值或「原本不存在」*，退出/停止时逐项还原，绝不把用户原有代理配置吞掉。
//! - **与引擎同生命周期**：启用只在引擎启动成功后，停止/退出/孤儿清理时还原。
//! - **广播刷新**：写完调用 `SendMessageTimeout(WM_SETTINGCHANGE, "Environment")`，
//!   否则 Explorer 缓存会让新开的终端仍拿到旧环境。
//! - 已打开的终端不受影响（Windows 不会热更新已运行进程的环境块）——UI 需提示。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 代理环境变量（大写；Windows 环境变量名大小写不敏感，无需再写小写副本）
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEntry {
    /// 注入前该变量是否已存在
    present: bool,
    /// 注入前的值（`present=false` 时为 None）
    #[serde(default)]
    value: Option<String>,
}

/// 备份文件内容：变量名 → 原值
type Backup = BTreeMap<String, BackupEntry>;

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

/// 注入终端代理环境变量（幂等：已有备份先还原再重新备份，避免把注入值当原值）
pub fn enable(plan: &TerminalProxyPlan) -> Result<(), String> {
    let targets = build_targets(plan);
    if targets.is_empty() {
        return Ok(());
    }

    // 若上次注入未还原（崩溃/强杀），先按旧备份还原，保证本次备份记录的是「真实原值」
    if plan.backup_path.exists() {
        if let Err(e) = disable(&plan.backup_path) {
            tracing::warn!("上一次终端代理环境变量还原失败（继续重新注入）: {e}");
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut backup: Backup = BTreeMap::new();
        for (name, _) in &targets {
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

        for (name, value) in &targets {
            if let Err(e) = imp::write(name, value) {
                // 半注入立即回滚：否则新开终端会指向一个可能已停的端口
                let rollback = disable(&plan.backup_path);
                tracing::warn!("写入 {name} 失败，回滚终端代理环境变量: {rollback:?}");
                return Err(format!("写入 {name} 失败: {e}"));
            }
        }
        imp::broadcast_change();
        tracing::info!(
            "终端代理环境变量已注入：{} 个变量（proxy_url={:?}）",
            targets.len(),
            plan.proxy_url
        );
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = plan;
        Err("当前平台暂不支持终端代理环境变量注入（仅 Windows）".to_string())
    }
}

/// 还原注入前的环境变量（幂等：备份不存在直接返回 Ok）
pub fn disable(backup_path: &Path) -> Result<(), String> {
    if !backup_path.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(backup_path).map_err(|e| format!("读取备份失败: {e}"))?;
    let backup: Backup =
        serde_json::from_str(&text).map_err(|e| format!("解析备份失败: {e}"))?;

    #[cfg(target_os = "windows")]
    {
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
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = &backup;
    }

    let _ = std::fs::remove_file(backup_path);
    tracing::info!("终端代理环境变量已还原（{} 个变量）", backup.len());
    Ok(())
}

fn write_backup(path: &Path, backup: &Backup) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
    }
    let json = serde_json::to_string_pretty(backup).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("写入备份失败: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(proxy: Option<&str>, ca: bool) -> TerminalProxyPlan {
        TerminalProxyPlan {
            backup_path: std::env::temp_dir().join("watt-terminal-proxy-test.json"),
            proxy_url: proxy.map(str::to_string),
            no_proxy: "localhost,127.0.0.1".into(),
            ca_pem: ca.then(|| std::path::PathBuf::from("__missing__.pem")),
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
        assert!(t.iter().all(|(k, v)| k == "NO_PROXY" || v == "http://127.0.0.1:26501"));
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
}
