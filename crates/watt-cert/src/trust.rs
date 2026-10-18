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
            info.nShow = SW_HIDE as i32;

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
            let store = CertOpenSystemStoreA(0, "ROOT\0".as_ptr() as *const u8 as _);
            if store.is_null() {
                return Err(TrustError::Trust("CertOpenSystemStore(ROOT) 失败".into()));
            }
            let encoding = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) as u32;
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
            let store = CertOpenSystemStoreA(0, "ROOT\0".as_ptr() as *const u8 as _);
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
            let store = CertOpenSystemStoreA(0, "ROOT\0".as_ptr() as *const u8 as _);
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
    use super::{sha1_hex, TrustError, CA_SUBJECT_CN};
    use std::path::Path;
    use std::process::{Command, Output};

    const KEYCHAIN: &str = "/Library/Keychains/System.keychain";

    /// 直接执行 security 命令（不提权），捕获输出便于诊断
    fn security_output(args: &[&str]) -> Result<Output, TrustError> {
        Command::new("security")
            .args(args)
            .output()
            .map_err(|e| TrustError::Trust(format!("security: {e}")))
    }

    /// stderr 是否**疑似**权限问题（保守策略：无法明确判定时按权限处理，给提权重试机会）
    ///
    /// 注意与函数名的关系：返回 true 表示「不排除权限问题」，而非「确定是权限问题」。
    /// 仅对明确的非权限错误（文件不存在/证书无法加载/格式无效）返回 false 直接报错，
    /// 避免无谓弹窗；其余一概提权重试。
    fn is_likely_permission_error(stderr: &str) -> bool {
        let s = stderr.to_ascii_lowercase();
        // 明确非权限错误：不弹窗，直接报错（"No matching certificates" = CN 不匹配，绝无提权必要）
        !(s.contains("no such file")
            || s.contains("unable to load")
            || s.contains("invalid")
            || s.contains("no matching certificates"))
    }

    /// 安装根证书到系统钥匙串（对齐 security add-trusted-cert）
    ///
    /// 两段式：先直试（进程恰好有权限时免弹窗）；失败且疑似权限问题时经
    /// `watt-elevate` 提权重试（osascript 弹一次管理员密码框）。
    pub fn install_root_cert(cert_pem_path: &Path) -> Result<(), TrustError> {
        let path = cert_pem_path.to_string_lossy().to_string();
        let direct = security_output(&[
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            KEYCHAIN,
            &path,
        ]);
        if let Ok(out) = &direct {
            if out.status.success() {
                return Ok(());
            }
        }
        // 直试失败：判定是否值得提权重试
        let direct_err = match &direct {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !is_likely_permission_error(&stderr) {
                    return Err(TrustError::Trust(format!(
                        "security add-trusted-cert 失败: {}",
                        stderr.trim()
                    )));
                }
                format!("security add-trusted-cert 失败: {}", stderr.trim())
            }
            Err(e) => e.to_string(),
        };

        match watt_elevate::run_as_admin_with_prompt(
            "security",
            &[
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                KEYCHAIN,
                &path,
            ],
            Some(watt_elevate::ElevatePurpose::InstallCert.prompt()),
        ) {
            Ok(_) => Ok(()),
            Err(watt_elevate::ElevateError::Cancelled) => {
                Err(TrustError::Elevation("用户取消了管理员授权".into()))
            }
            Err(e) => Err(TrustError::Elevation(format!(
                "{direct_err}；提权重试失败: {e}"
            ))),
        }
    }

    /// 卸载根证书：两段式（直试 → 提权重试），且必须补删证书本体。
    ///
    /// `security remove-trusted-cert` 只移除**信任设置**，证书本身可能仍留在
    /// System.keychain，导致 `is_root_cert_installed`（钥匙串 SHA-1 比对）误报
    /// "已安装"。因此提权命令串联删除证书本体（单次弹窗完成）：
    /// `remove-trusted-cert -d CN=<CN> && delete-certificate -Z <sha1> <keychain>`。
    pub fn remove_root_cert() -> Result<(), TrustError> {
        let cn = format!("CN={CA_SUBJECT_CN}");

        // 直试删信任设置（已 root 运行时免弹窗）
        let direct = security_output(&["remove-trusted-cert", "-d", &cn]);
        if let Ok(out) = &direct {
            if out.status.success() {
                // 信任设置删除成功；证书本体是否残留由 find-certificate 判定，
                // 残留时仍需提权补删（见下方 hash 分支）。
                if find_cert_hash().is_none() {
                    return Ok(());
                }
            } else {
                // 直试失败：与 install 对齐——明确非权限错误（如 CN 不匹配）不弹窗，
                // 直接报错，避免无谓弹一次管理员密码框
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !is_likely_permission_error(&stderr) {
                    return Err(TrustError::Trust(format!(
                        "security remove-trusted-cert 失败: {}",
                        stderr.trim()
                    )));
                }
            }
        }

        // 只读查询证书 SHA-1（无需提权），供 delete-certificate -Z 精确定位；
        // 查询失败则退回 -c CN 名称匹配。
        let mut del_args: Vec<String> = vec!["delete-certificate".into(), "-Z".into()];
        match find_cert_hash() {
            Some(hash) => del_args.push(hash),
            None => {
                del_args = vec!["delete-certificate".into(), "-c".into(), CA_SUBJECT_CN.into()];
            }
        }
        del_args.push(KEYCHAIN.into());

        // 单次弹窗完成：删信任设置 + 删证书本体
        let script = format!(
            "{} && {}",
            watt_elevate::build_shell_command("security", &["remove-trusted-cert", "-d", &cn]),
            watt_elevate::build_shell_command("security", &del_args.iter().map(String::as_str).collect::<Vec<_>>()),
        );
        match watt_elevate::run_as_admin_shell(
            &script,
            Some(watt_elevate::ElevatePurpose::RemoveCert.prompt()),
        ) {
            Ok(_) => Ok(()),
            Err(watt_elevate::ElevateError::Cancelled) => {
                Err(TrustError::Elevation("用户取消了管理员授权".into()))
            }
            Err(e) => Err(TrustError::Elevation(format!(
                "security remove-trusted-cert 失败；提权重试失败: {e}"
            ))),
        }
    }

    /// 只读查询钥匙串中本 CA 的 SHA-1（find-certificate -c <CN> -Z <keychain>）
    fn find_cert_hash() -> Option<String> {
        let out = security_output(&["find-certificate", "-c", CA_SUBJECT_CN, "-Z", KEYCHAIN]).ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines().find_map(|l| {
            l.split_once(':').and_then(|(k, v)| {
                k.trim()
                    .eq_ignore_ascii_case("SHA-1 hash")
                    .then(|| v.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
        })
    }

    /// 检查根证书是否已安装（钥匙串中存在同 SHA-1 指纹证书）
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
        match Command::new("security")
            .args(["find-certificate", "-a", "-Z", KEYCHAIN])
            .output()
        {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
                text.contains(&sha1)
            }
            Err(_) => false,
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
