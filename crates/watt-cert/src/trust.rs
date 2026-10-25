//! 证书信任：三平台根证书安装/移除/查询。对齐 CertificateManagerImpl。
//!
//! - Windows：LocalMachine\Root 存储（CertOpenSystemStore），直接 API 失败时
//!   经 ShellExecute "runas" 提权运行 certutil（对齐原实现子进程提权语义）。
//! - macOS：security add-trusted-cert / remove-trusted-cert。
//! - Linux：/usr/local/share/ca-certificates + update-ca-certificates。
//!
//! 统一接口：入参为 CA PEM 文件路径（Windows 内部转 DER）。

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust: {0}")]
    Trust(String),
    #[error("需要管理员权限且提权被拒绝/失败: {0}")]
    Elevation(String),
}

/// CA 主题 CN（用于按名称删除）
pub const CA_SUBJECT_CN: &str = crate::ca::CA_SUBJECT_CN;

/// SHA-1 指纹（十六进制小写，与 security find-certificate -Z 输出一致）
pub fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 指纹（十六进制大写，与 .NET GetCertHashString(SHA256) 展示一致）
pub fn sha256_hex_upper(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    out.iter().map(|b| format!("{b:02X}")).collect()
}

// —————————————— macOS security 输出的纯逻辑（跨平台可单测） ——————————————

/// macOS `security` 报错是否为「授权系统无法进行交互授权」
///
/// 这是写 **admin 域**信任设置的结构性失败信号：`osascript -e 'do shell script ...
/// with administrator privileges'` 拿到的 AuthorizationRef 只含 `system.privilege.admin`，
/// 不含 trust settings 所需的 right；子进程虽已是 root，却无法再发起交互授权，于是
/// `SecTrustSettingsSetTrustSettings` 直接返回本错误（经 osascript 包装成 `0:290:
/// execution error: ... (1)`）。此时再弹一次管理员密码框**必然同样失败**——
/// 所以必须识别出来、直接给可复制的手动命令，而不是让用户白输一次密码。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_no_interaction_error(stderr: &str) -> bool {
    stderr
        .to_ascii_lowercase()
        .contains("no user interaction was possible")
}

/// 明确与权限无关、重试也不会成功的错误（证书文件不存在 / 格式无效）
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_fatal_security_error(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("no such file")
        || s.contains("unable to load")
        || s.contains("invalid")
        || s.contains("unknown format")
}

/// 抽出文本中的十六进制字符并小写化
///
/// `security dump-trust-settings` 的指纹格式随 macOS 版本变化（可能带冒号分隔），
/// 归一化后只做子串匹配，避免为分隔符差异写脆弱解析。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn normalize_hex(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// dump-trust-settings 输出中是否包含指定 SHA-1 指纹
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn trust_dump_contains(dump: &str, sha1: &str) -> bool {
    let needle = sha1.to_ascii_lowercase();
    !needle.is_empty() && normalize_hex(dump).contains(&needle)
}

/// trust-settings-export 导出的 plist 中是否包含指定 SHA-1
///
/// 新版 macOS 的 `dump-trust-settings` 只列证书名、不输出指纹，无法精确匹配；
/// 而 `trust-settings-export` 的 trustList 直接以 SHA-1（大写）为键。二进制 plist
/// 中的键仍是 ASCII 字节，按字节搜索即可，无需解析 plist。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn trust_export_contains(data: &[u8], sha1: &str) -> bool {
    !sha1.is_empty()
        && String::from_utf8_lossy(data)
            .to_ascii_lowercase()
            .contains(sha1)
}

/// 自动安装失败时的手动兜底指引（含可直接粘贴的命令）
///
/// macOS 的信任设置写入受 Authorization Services 保护，自动化通道被系统拒绝时
/// 只能由用户在 GUI/终端中确认一次。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn manual_install_hint(cert_path: &str, cause: &str) -> String {
    format!(
        "{cause}\nmacOS 拒绝代为授权「证书信任设置」，请任选一种方式手动完成：\n\
         ① 打开「钥匙串访问」→ 拖入 {cert_path} → 双击该证书 → 展开「信任」→ \
         「使用此证书时」选「始终信任」；\n\
         ② 或在「终端」执行（当前用户，无需 sudo；-k 不可省略）：\n\
         security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db \"{cert_path}\"\n\
         ③ 需要整机生效时：sudo security add-trusted-cert -d -r trustRoot \"{cert_path}\""
    )
}

#[cfg(target_os = "windows")]
pub mod platform {
    use super::TrustError;
    use std::path::Path;

    fn load_der_from_pem(cert_pem_path: &Path) -> Result<Vec<u8>, TrustError> {
        let content = std::fs::read_to_string(cert_pem_path)?;
        let der = rustls_pemfile::certs(&mut content.as_bytes())
            .next()
            .ok_or_else(|| TrustError::Trust("PEM 中无证书".into()))?
            .map_err(|e| TrustError::Trust(format!("PEM 解析失败: {e}")))?;
        Ok(der.to_vec())
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 以管理员权限运行命令并等待退出（UAC 弹窗）。
    /// SAFETY: ShellExecuteExW 按 SHELLEXECUTEINFOW 语义管理 hProcess，句柄在函数内关闭。
    fn run_elevated(exe: &str, args: &str) -> Result<(), TrustError> {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        use windows_sys::Win32::UI::Shell::{
            ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

        unsafe {
            let mut exe_w = to_wide(exe);
            let mut args_w = to_wide(args);
            let mut verb_w = to_wide("runas");
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.lpVerb = verb_w.as_mut_ptr();
            info.lpFile = exe_w.as_mut_ptr();
            info.lpParameters = args_w.as_mut_ptr();
            info.nShow = SW_HIDE;

            if ShellExecuteExW(&mut info) == 0 {
                return Err(TrustError::Elevation(
                    "ShellExecuteExW(runas) 失败（用户取消 UAC 或策略禁止）".into(),
                ));
            }
            if info.hProcess.is_null() {
                return Ok(()); // 未返回进程句柄（罕见），按已提交处理
            }
            // 等待提权进程结束（最长 120s，certutil 一般秒级完成）
            let wait = WaitForSingleObject(info.hProcess, 120_000);
            let mut exit_code: u32 = 0;
            GetExitCodeProcess(info.hProcess, &mut exit_code);
            CloseHandle(info.hProcess);
            if wait == WAIT_TIMEOUT {
                return Err(TrustError::Elevation("certutil 执行超时".into()));
            }
            if exit_code != 0 {
                return Err(TrustError::Elevation(format!(
                    "certutil 退出码 {exit_code}"
                )));
            }
            Ok(())
        }
    }

    /// 安装根证书到 LocalMachine\Root（按 thumbprint 去重）
    pub fn install_root_cert(cert_pem_path: &Path) -> Result<(), TrustError> {
        let der = load_der_from_pem(cert_pem_path)?;
        // SAFETY: windows-sys FFI，所有句柄在函数内关闭
        unsafe {
            use windows_sys::Win32::Security::Cryptography::{
                CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreA,
                CERT_STORE_ADD_ALWAYS, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
            };
            let store = CertOpenSystemStoreA(0, c"ROOT".as_ptr() as _);
            if store.is_null() {
                return Err(TrustError::Trust("CertOpenSystemStore(ROOT) 失败".into()));
            }
            let encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
            let result = CertAddEncodedCertificateToStore(
                store,
                encoding,
                der.as_ptr(),
                der.len() as u32,
                CERT_STORE_ADD_ALWAYS, // 系统按 thumbprint 去重
                std::ptr::null_mut(),
            );
            CertCloseStore(store, 0);
            if result != 0 {
                return Ok(());
            }
        }

        // 直接写入失败（通常无管理员权限）→ 提权 certutil
        let path_str = cert_pem_path.to_string_lossy().to_string();
        tracing::warn!("直接写入 Root 存储失败，尝试提权 certutil -addstore");
        run_elevated("certutil", &format!("-f -addstore Root \"{path_str}\""))
    }

    /// 证书主题字符串（CERT_NAME_BLOB → CERT_SIMPLE_NAME_STR）
    /// SAFETY: 调用方保证 ctx 指向有效 context；结果在函数内拷贝为 String。
    unsafe fn cert_subject_string(
        ctx: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
    ) -> String {
        use windows_sys::Win32::Security::Cryptography::{
            CertNameToStrA, CERT_SIMPLE_NAME_STR, X509_ASN_ENCODING,
        };
        let blob = (*(*ctx).pCertInfo).Subject;
        let len = CertNameToStrA(
            X509_ASN_ENCODING,
            &blob,
            CERT_SIMPLE_NAME_STR,
            std::ptr::null_mut(),
            0,
        );
        if len == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; len as usize];
        CertNameToStrA(
            X509_ASN_ENCODING,
            &blob,
            CERT_SIMPLE_NAME_STR,
            buf.as_mut_ptr(),
            len,
        );
        // 返回长度含结尾 NUL
        String::from_utf8_lossy(&buf[..(len as usize).saturating_sub(1)]).into_owned()
    }

    /// 移除根证书（按 Subject CN 枚举删除；未命中/失败时提权 certutil）
    pub fn remove_root_cert() -> Result<(), TrustError> {
        let mut removed = false;
        // SAFETY: CertEnumCertificatesInStore 每次调用释放上一个 context；
        // CertDeleteCertificateFromStore 释放当前 context（随后枚举重置），无泄漏/双重释放。
        unsafe {
            use windows_sys::Win32::Security::Cryptography::{
                CertCloseStore, CertDeleteCertificateFromStore, CertEnumCertificatesInStore,
                CertOpenSystemStoreA, CERT_CONTEXT,
            };
            let store = CertOpenSystemStoreA(0, c"ROOT".as_ptr() as _);
            if store.is_null() {
                return Err(TrustError::Trust("CertOpenSystemStore(ROOT) 失败".into()));
            }
            let cn = super::CA_SUBJECT_CN.to_string();
            let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
            loop {
                // 本次调用释放上一个 ctx（若非空）
                ctx = CertEnumCertificatesInStore(store, ctx);
                if ctx.is_null() {
                    break;
                }
                let subject = cert_subject_string(ctx);
                if subject.contains(&cn) {
                    CertDeleteCertificateFromStore(ctx); // 释放 ctx
                    ctx = std::ptr::null_mut(); // 从头重新枚举
                    removed = true;
                }
            }
            CertCloseStore(store, 0);
        }

        if removed {
            Ok(())
        } else {
            // 未匹配到或无权限删除 → 提权 certutil 按主题删除
            tracing::warn!("直接删除 Root 存储未命中/失败，尝试提权 certutil -delstore");
            run_elevated(
                "certutil",
                &format!("-f -delstore Root \"{}\"", super::CA_SUBJECT_CN),
            )
        }
    }

    /// 检查根证书是否已安装（LocalMachine\Root 中存在同 DER 证书）
    pub fn is_root_cert_installed(cert_pem_path: &Path) -> bool {
        let Ok(der) = load_der_from_pem(cert_pem_path) else {
            return false;
        };
        // SAFETY: 同 remove_root_cert 的枚举所有权约定
        unsafe {
            use windows_sys::Win32::Security::Cryptography::{
                CertCloseStore, CertEnumCertificatesInStore, CertFreeCertificateContext,
                CertOpenSystemStoreA, CERT_CONTEXT,
            };
            let store = CertOpenSystemStoreA(0, c"ROOT".as_ptr() as _);
            if store.is_null() {
                return false;
            }
            let mut found = false;
            let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
            loop {
                ctx = CertEnumCertificatesInStore(store, ctx);
                if ctx.is_null() {
                    break;
                }
                let encoded_ptr = (*ctx).pbCertEncoded as *const u8;
                let encoded_len = (*ctx).cbCertEncoded as usize;
                if encoded_ptr.is_null() || encoded_len == 0 {
                    continue;
                }
                let bytes = std::slice::from_raw_parts(encoded_ptr, encoded_len);
                if bytes == der.as_slice() {
                    found = true;
                    // 终止枚举：释放当前 context 避免泄漏
                    CertFreeCertificateContext(ctx);
                    break;
                }
            }
            CertCloseStore(store, 0);
            found
        }
    }
}

#[cfg(target_os = "macos")]
pub mod platform {
    use super::{
        is_fatal_security_error, is_no_interaction_error, manual_install_hint, sha1_hex,
        trust_dump_contains, trust_export_contains, TrustError, CA_SUBJECT_CN,
    };
    use std::path::Path;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 系统钥匙串（admin 域信任设置的目标）
    ///
    /// 注意：`security add-trusted-cert -d` 的默认目标**就是**它，必须**不要**再补
    /// `-k <此路径>` —— 两者同时给出在部分 macOS 版本上会让域判定退化，最终在
    /// `SecTrustSettingsSetTrustSettings` 报 0:290（no user interaction）。本常量
    /// 只用于查询与删除。
    const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

    /// 直接执行 security 命令（不提权），捕获输出便于诊断
    fn security_output(args: &[&str]) -> Result<Output, TrustError> {
        Command::new("security")
            .args(args)
            .output()
            .map_err(|e| TrustError::Trust(format!("security: {e}")))
    }

    /// 当前用户的登录钥匙串路径（新版 `login.keychain-db`，旧版 `login.keychain`）
    ///
    /// 以 `security default-keychain -d user` 为准；读取失败按新版默认路径兜底。
    fn user_keychain() -> String {
        if let Ok(out) = security_output(&["default-keychain", "-d", "user"]) {
            if out.status.success() {
                let p = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .trim_matches('"')
                    .to_string();
                if !p.is_empty() {
                    return p;
                }
            }
        }
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/Library/Keychains/login.keychain-db")
    }

    /// 导出指定信任域的 trust settings（二进制 plist 原样字节）
    ///
    /// 读取失败返回 None，由调用方回退到 `dump-trust-settings` 解析。
    fn export_trust_settings(admin: bool) -> Option<Vec<u8>> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let file = std::env::temp_dir().join(format!(
            "watt-trust-{}-{seq}-{}.plist",
            std::process::id(),
            if admin { "admin" } else { "user" }
        ));
        let file_str = file.to_string_lossy().to_string();
        let mut args: Vec<&str> = vec!["trust-settings-export"];
        if admin {
            args.push("-d");
        }
        args.push(&file_str);
        let ok = security_output(&args)
            .map(|o| o.status.success())
            .unwrap_or(false);
        let data = if ok { std::fs::read(&file).ok() } else { None };
        let _ = std::fs::remove_file(&file);
        data
    }

    /// 安装根证书信任（分级：用户域免提权 → 系统域直试 → 系统域提权）
    ///
    /// ① **用户域**（`add-trusted-cert` 不带 `-d`）：不需要 root，只影响当前用户，
    ///    对加速工具正好够用（本机浏览器/MITM）；GUI 会话下 macOS 会弹一次
    ///    「security 想要修改证书信任设置」由用户确认（输登录密码）。
    /// ② **系统域直试**（`-d`）：进程本身已被提权时免弹窗。
    /// ③ **系统域提权**：osascript 弹一次管理员密码框。
    ///
    /// 三个必须避开的坑：
    /// - 用户域必须显式给 `-k <登录钥匙串>`。macOS 26+ 实测不带 `-k` 时
    ///   `security add-trusted-cert` **静默退出 0 且不写任何东西**（既不导入钥匙串
    ///   也不写 trust settings），上层据退出码判定成功 → 二次校验必然失败。
    /// - `-d` 与 `-k <System.keychain>` 不能同时给。`-d` 的默认目标**就是**
    ///   System.keychain，多给 `-k` 在部分 macOS 版本上会让域判定退化，最终在
    ///   `SecTrustSettingsSetTrustSettings` 报 0:290。故系统域只用 `-d`。
    /// - 用户域若报「no user interaction was possible」，说明 Authorization
    ///   交互通道不可用，第 ③ 步走的是同一套机制、必然失败 —— 此时**不弹框**，
    ///   直接回可复制的手动命令，避免用户白输一次管理员密码。
    ///
    /// 每一级成功后都做一次真实校验：退出码 0 不代表信任已生效。
    pub fn install_root_cert(cert_pem_path: &Path) -> Result<(), TrustError> {
        let path = cert_pem_path.to_string_lossy().to_string();
        let mut notes: Vec<String> = Vec::new();

        // ① 用户域（免提权）
        let keychain = user_keychain();
        let user_args: [&str; 6] = [
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-k",
            &keychain,
            &path,
        ];
        match security_output(&user_args) {
            Ok(out) if out.status.success() => {
                if is_root_cert_installed(cert_pem_path) {
                    tracing::info!("根证书已装入用户信任域（免提权, keychain={keychain}）");
                    return Ok(());
                }
                notes.push("用户域: 命令成功但证书/信任校验未通过".into());
            }
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                if is_fatal_security_error(&err) {
                    return Err(TrustError::Trust(format!(
                        "security add-trusted-cert 失败: {err}"
                    )));
                }
                if is_no_interaction_error(&err) {
                    return Err(TrustError::Trust(manual_install_hint(
                        &path,
                        &format!("用户域安装失败: {err}"),
                    )));
                }
                notes.push(format!("用户域: {err}"));
            }
            Err(e) => notes.push(format!("用户域: {e}")),
        }

        // ② 系统域直试（不带 -k：-d 默认目标即 System.keychain）
        let sys_args: [&str; 5] = ["add-trusted-cert", "-d", "-r", "trustRoot", &path];
        match security_output(&sys_args) {
            Ok(out) if out.status.success() => {
                if is_root_cert_installed(cert_pem_path) {
                    tracing::info!("根证书已装入系统信任域（进程已有权限）");
                    return Ok(());
                }
                notes.push("系统域: 命令成功但证书/信任校验未通过".into());
            }
            Ok(out) => notes.push(format!(
                "系统域: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => notes.push(format!("系统域: {e}")),
        }

        // ③ 系统域提权（osascript 单次弹窗）
        match watt_elevate::run_as_admin_with_prompt(
            "security",
            &sys_args,
            Some(watt_elevate::ElevatePurpose::InstallCert.prompt()),
        ) {
            Ok(_) if is_root_cert_installed(cert_pem_path) => Ok(()),
            Ok(_) => Err(TrustError::Trust(manual_install_hint(
                &path,
                &format!(
                    "提权安装命令已执行，但信任校验仍未通过；{}",
                    notes.join(" / ")
                ),
            ))),
            Err(watt_elevate::ElevateError::Cancelled) => {
                Err(TrustError::Elevation("用户取消了管理员授权".into()))
            }
            Err(e) => {
                let cause = format!("{}；提权重试失败: {e}", notes.join(" / "));
                if is_no_interaction_error(&cause) {
                    Err(TrustError::Trust(manual_install_hint(&path, &cause)))
                } else {
                    Err(TrustError::Elevation(cause))
                }
            }
        }
    }

    /// 卸载根证书（用户域 / 系统域中的全部同名残留）
    ///
    /// 只做 `delete-certificate`：macOS 的 trust settings 是 keychain item 的属性，
    /// 随条目删除一并消失。原实现用 `security remove-trusted-cert "CN=<CN>"` 是错的
    /// —— 该命令的参数是**证书文件路径**，传 CN 字符串必然 `no such file`。
    ///
    /// 用户域直删（免提权）；失败项（通常是系统域）合并为单条脚本提权一次。
    pub fn remove_root_cert() -> Result<(), TrustError> {
        let entries = find_cert_entries();
        if entries.is_empty() {
            return Ok(());
        }

        let mut need_elevation: Vec<(String, String)> = Vec::new();
        for (keychain, sha1) in entries {
            match security_output(&["delete-certificate", "-Z", &sha1, &keychain]) {
                Ok(out) if out.status.success() => {}
                _ => need_elevation.push((keychain, sha1)),
            }
        }
        if need_elevation.is_empty() {
            return Ok(());
        }

        // 单次弹窗删除全部残留（`;` 而非 `&&`：单项失删不应中断其余）
        let script = need_elevation
            .iter()
            .map(|(keychain, sha1)| {
                watt_elevate::build_shell_command(
                    "security",
                    &["delete-certificate", "-Z", sha1, keychain],
                )
            })
            .collect::<Vec<_>>()
            .join(" ; ");
        match watt_elevate::run_as_admin_shell(
            &script,
            Some(watt_elevate::ElevatePurpose::RemoveCert.prompt()),
        ) {
            Ok(_) => Ok(()),
            Err(watt_elevate::ElevateError::Cancelled) => {
                Err(TrustError::Elevation("用户取消了管理员授权".into()))
            }
            Err(e) => Err(TrustError::Elevation(format!("删除根证书失败: {e}"))),
        }
    }

    /// 枚举用户/系统钥匙串中本 CA 的全部 (keychain, sha1)
    fn find_cert_entries() -> Vec<(String, String)> {
        let mut out = Vec::new();
        for keychain in [user_keychain(), SYSTEM_KEYCHAIN.to_string()] {
            let Ok(res) = security_output(&[
                "find-certificate",
                "-a",
                "-c",
                CA_SUBJECT_CN,
                "-Z",
                &keychain,
            ]) else {
                continue;
            };
            if !res.status.success() {
                continue;
            }
            let text = String::from_utf8_lossy(&res.stdout);
            for line in text.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("SHA-1 hash") {
                        let h = v.trim().to_ascii_lowercase();
                        if !h.is_empty() {
                            out.push((keychain.clone(), h));
                        }
                    }
                }
            }
        }
        out
    }

    /// 证书本体是否存在于用户或系统钥匙串（按 SHA-1 精确匹配）
    fn keychain_has_cert(sha1: &str) -> bool {
        for keychain in [user_keychain(), SYSTEM_KEYCHAIN.to_string()] {
            let Ok(out) = security_output(&["find-certificate", "-a", "-Z", &keychain]) else {
                continue;
            };
            if out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .to_ascii_lowercase()
                    .contains(sha1)
            {
                return true;
            }
        }
        false
    }

    /// 信任设置查询三态
    enum TrustLookup {
        /// 命中该指纹
        Found,
        /// 明确判定「没有该证书的信任设置」
        Absent,
        /// 读到了内容但无法据此判定（该 macOS 版本的 dump 不输出指纹等）
        Unknown,
    }

    /// 在用户域 / admin 域中查找该指纹的信任设置
    ///
    /// 优先用 `trust-settings-export`：它把 trustList 按 SHA-1 哈希导出，可精确匹配；
    /// 而 macOS 26+ 的 `dump-trust-settings` 只列证书名（如 `Cert 0: Watt Toolkit`），
    /// 不含指纹，继续依赖它会把校验退化成「同名证书存在即已信任」。
    ///
    /// `dump-trust-settings -d` / `trust-settings-export -d` 在部分版本上对普通用户
    /// 会因权限被拒 —— 那只是这一路读不到，不影响用户域结论。
    ///
    /// 三态而非布尔的理由：输出格式跨版本不一致。只有在完整读到某个域、且确认
    /// 未命中时才敢判 Absent；读不全时只能 Unknown —— 盲目判 Absent 会让安装流程
    /// 陷入死循环（装成功 → 检测判未装 → 再装 → 再弹密码框）。
    fn trust_settings_lookup(sha1: &str) -> TrustLookup {
        let user_export = export_trust_settings(false);
        let admin_export = export_trust_settings(true);
        if user_export
            .as_ref()
            .map_or(false, |d| trust_export_contains(d, sha1))
            || admin_export
                .as_ref()
                .map_or(false, |d| trust_export_contains(d, sha1))
        {
            return TrustLookup::Found;
        }
        // 两个域都完整读到 → 未命中即明确不存在（导出是该域信任设置的完整快照）
        if user_export.is_some() && admin_export.is_some() {
            return TrustLookup::Absent;
        }

        let mut read_any = false;
        let mut saw_entries = false;
        let mut saw_hash_field = false;
        for args in [
            vec!["dump-trust-settings"],
            vec!["dump-trust-settings", "-d"],
        ] {
            let Ok(out) = security_output(&args) else {
                continue;
            };
            if !out.status.success() {
                continue;
            }
            read_any = true;
            let text = String::from_utf8_lossy(&out.stdout);
            if trust_dump_contains(&text, sha1) {
                return TrustLookup::Found;
            }
            let lower = text.to_ascii_lowercase();
            // "No trust settings found." 本身含子串 "trust setting"，须先排除
            if !lower.trim().is_empty() && !lower.contains("no trust settings") {
                saw_entries = true;
            }
            if lower.contains("sha") {
                saw_hash_field = true;
            }
        }
        if read_any && saw_hash_field {
            TrustLookup::Absent
        } else if read_any && !saw_entries {
            TrustLookup::Absent
        } else {
            TrustLookup::Unknown
        }
    }

    /// 检查根证书是否已安装**且处于信任状态**
    ///
    /// 两个条件都满足才算：
    /// 1. 证书本体存在于用户或系统钥匙串；
    /// 2. trust settings 中能找到该 SHA-1。
    ///
    /// 只看 ① 会把「已导入但未信任」误判成已安装：旧版本提权失败时证书其实已写进
    /// System.keychain，只有 trust 设置被拒 —— 误判会让引擎带着不受信任的 CA 启动，
    /// 浏览器侧表现为证书错误（MITM 握手失败）。
    ///
    /// 判定为 Unknown 时取乐观值（视为已安装），避免反复安装的死循环。
    pub fn is_root_cert_installed(cert_pem_path: &Path) -> bool {
        let Ok(content) = std::fs::read_to_string(cert_pem_path) else {
            return false;
        };
        let Ok(Some(der)) = rustls_pemfile::certs(&mut content.as_bytes())
            .next()
            .transpose()
        else {
            return false;
        };
        let sha1 = sha1_hex(&der);

        if !keychain_has_cert(&sha1) {
            return false;
        }
        match trust_settings_lookup(&sha1) {
            TrustLookup::Found => true,
            TrustLookup::Absent => {
                tracing::warn!("证书已在钥匙串但信任设置未命中，判定为未安装");
                false
            }
            TrustLookup::Unknown => {
                tracing::warn!("无法据此判定 trust settings，退化为「证书存在即视为已安装」");
                true
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod platform {
    use super::TrustError;
    use std::path::Path;
    use std::process::Command;

    const CERT_TARGET: &str = "/usr/local/share/ca-certificates/watt-toolkit-ca.crt";

    /// 安装根证书：拷贝到 /usr/local/share/ca-certificates + update-ca-certificates
    /// 需要特权（由 watt-helper 调用）
    pub fn install_root_cert(cert_pem_path: &Path) -> Result<(), TrustError> {
        std::fs::copy(cert_pem_path, CERT_TARGET)?;
        let status = Command::new("update-ca-certificates")
            .status()
            .map_err(|e| TrustError::Trust(format!("update-ca-certificates: {e}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(TrustError::Trust("update-ca-certificates 失败".into()))
        }
    }

    pub fn remove_root_cert() -> Result<(), TrustError> {
        let _ = std::fs::remove_file(CERT_TARGET);
        let status = Command::new("update-ca-certificates")
            .status()
            .map_err(|e| TrustError::Trust(format!("update-ca-certificates: {e}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(TrustError::Trust("update-ca-certificates 失败".into()))
        }
    }

    /// 检查根证书是否已安装（目标文件内容一致）
    pub fn is_root_cert_installed(cert_pem_path: &Path) -> bool {
        let Ok(content) = std::fs::read_to_string(cert_pem_path) else {
            return false;
        };
        match std::fs::read_to_string(CERT_TARGET) {
            Ok(installed) => installed == content,
            Err(_) => false,
        }
    }
}

/// 平台无关接口：安装根证书信任（PEM 路径入参）
pub use platform::install_root_cert;

/// 平台无关接口：移除根证书信任
pub fn remove_root_cert() -> Result<(), TrustError> {
    platform::remove_root_cert()
}

/// 平台无关接口：根证书是否已安装并信任
pub fn is_root_cert_installed(cert_pem_path: &Path) -> bool {
    platform::is_root_cert_installed(cert_pem_path)
}

/// 供上层决定是否走 helper 提权（当前三平台写入系统信任存储均需要特权）
pub fn install_requires_elevation() -> bool {
    cfg!(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // —— macOS security 输出解析：纯逻辑，跨平台可跑（实机 security 行为需 macOS 验证） ——

    #[test]
    fn detects_no_interaction_error() {
        // macOS 实机报错原文（被 osascript 包装成 0:290: execution error）
        assert!(is_no_interaction_error(
            "0:290: execution error: SecTrustSettingsSetTrustSettings:              The authorization was denied since no user interaction was possible. (1)"
        ));
        assert!(is_no_interaction_error(
            "The authorization was denied since NO USER INTERACTION WAS POSSIBLE."
        ));
        // 纯权限错误不是「无法交互授权」：它值得走提权重试
        assert!(!is_no_interaction_error(
            "SecCertificateAddToKeychain: Write permissions error."
        ));
        assert!(!is_no_interaction_error("User canceled. (-128)"));
    }

    #[test]
    fn classifies_fatal_security_error() {
        assert!(is_fatal_security_error("no such file or directory"));
        assert!(is_fatal_security_error("Unable to load certificate"));
        assert!(is_fatal_security_error("invalid certificate format"));
        // 权限/授权问题不是致命错误：应继续尝试其它域
        assert!(!is_fatal_security_error(
            "SecCertificateAddToKeychain: Write permissions error."
        ));
        assert!(!is_fatal_security_error(
            "The authorization was denied since no user interaction was possible."
        ));
    }

    #[test]
    fn normalize_hex_strips_separators_and_lowercases() {
        assert_eq!(normalize_hex("AB:cd-EF 12"), "abcdef12");
        assert_eq!(normalize_hex("zz:GG"), "");
        assert_eq!(normalize_hex(""), "");
    }

    #[test]
    fn trust_dump_matches_sha1_in_both_formats() {
        let sha1 = "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567";
        // find-certificate -Z 风格：连续小写
        assert!(trust_dump_contains(&format!("SHA-1 hash: {sha1}"), sha1));
        // dump-trust-settings 部分版本：大写 + 冒号分隔
        let coloned = "0A:1B:2C:3D:4E:5F:60:71:82:93:A4:B5:C6:D7:E8:F9:01:23:45:67";
        assert!(trust_dump_contains(
            &format!("	SHA-1 hash: {coloned}
	Num trust settings: 1"),
            sha1
        ));
        // 未命中
        assert!(!trust_dump_contains("No trust settings found.", sha1));
        assert!(!trust_dump_contains("", sha1));
    }

    #[test]
    fn trust_dump_ignores_empty_needle() {
        // 空指纹绝不能命中（否则缺失 SHA-1 的实现会被静默判为「已信任」）
        assert!(!trust_dump_contains("No trust settings found.", ""));
    }

    #[test]
    fn trust_export_matches_hash_key() {
        let sha1 = "5ccba6ca76d48ca187d3272e291f098494d014f1";
        // trust-settings-export 的二进制 plist：trustList 以大写 SHA-1 为键
        let plist = format!(
            "bplist00...trustVersiontrustList{}{}...",
            sha1.to_ascii_uppercase(),
            "Watt Toolkit"
        );
        assert!(trust_export_contains(plist.as_bytes(), sha1));
        // 其它指纹不得误命中
        assert!(!trust_export_contains(
            plist.as_bytes(),
            "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567"
        ));
        // 空指纹绝不能命中
        assert!(!trust_export_contains(plist.as_bytes(), ""));
    }

    #[test]
    fn manual_hint_is_actionable() {
        let hint = manual_install_hint("/tmp/watt-ca.pem", "用户域安装失败: boom");
        assert!(hint.contains("用户域安装失败: boom"));
        assert!(hint.contains("/tmp/watt-ca.pem"));
        // 必须给出可直接粘贴的命令与 GUI 路径
        // 用户域命令必须带 -k：不带 -k 在 macOS 26+ 会静默无效
        assert!(hint.contains(
            "security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db"
        ));
        assert!(hint.contains("sudo security add-trusted-cert -d -r trustRoot"));
        assert!(hint.contains("钥匙串访问"));
        assert!(hint.contains("始终信任"));
    }
}
