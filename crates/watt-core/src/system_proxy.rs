//! 系统代理设置（对齐 WindowsPlatformServiceImpl.SystemProxy）。
//!
//! Windows：HKCU 注册表写入（无需管理员权限）+ InternetSetOption 通知系统刷新。
//! - 系统代理：ProxyEnable / ProxyServer / ProxyOverride
//! - PAC：AutoConfigURL
//!
//! 其他平台：本阶段不接入（原版 macOS/Linux 各自走 gsettings/networksetup，
//! 返回不支持错误由引擎决定是否阻断）。

/// 排除代理地址（对齐 IPlatformService.GetNoProxyHostName：内网段 + 官方 API）
pub fn no_proxy_host_names() -> Vec<String> {
    let mut names: Vec<String> = [
        "10.*",
        "172.16.*",
        "172.17.*",
        "172.18.*",
        "172.19.*",
        "172.20.*",
        "172.21.*",
        "172.22.*",
        "172.23.*",
        "172.24.*",
        "172.25.*",
        "172.26.*",
        "172.27.*",
        "172.28.*",
        "172.29.*",
        "172.30.*",
        "172.31.*",
        "192.168.*",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // 官方 API 域名（避免加速服务自身请求被代理拦截）
    names.push("api.steampp.net".into());
    names.push("shop-api.steampp.net".into());
    names
}

/// 设置/取消系统代理（Windows：注册表 + 通知）
///
/// `enable=true` 时 `ip:port` 为本地正向代理地址
pub fn set_system_proxy(enable: bool, ip: &str, port: u16) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
            KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
        };

        const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        unsafe {
            let subkey = to_wide(SUBKEY);
            let mut hkey: HKEY = std::ptr::null_mut();
            // 打开（不存在则创建），请求 RW 权限
            let status = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            );
            if status != 0 {
                return Err(format!("打开注册表失败: {status:#x}"));
            }

            macro_rules! set_dword {
                ($name:expr, $value:expr) => {{
                    let name = to_wide($name);
                    let v: u32 = $value;
                    let st = RegSetValueExW(
                        hkey,
                        name.as_ptr(),
                        0,
                        REG_DWORD,
                        &v as *const u32 as *const u8,
                        std::mem::size_of::<u32>() as u32,
                    );
                    if st != 0 {
                        RegCloseKey(hkey);
                        return Err(format!("写入 {} 失败: {st:#x}", $name));
                    }
                }};
            }

            macro_rules! set_string {
                ($name:expr, $value:expr) => {{
                    let name = to_wide($name);
                    let wide = to_wide($value);
                    let st = RegSetValueExW(
                        hkey,
                        name.as_ptr(),
                        0,
                        REG_SZ,
                        wide.as_ptr() as *const u8,
                        (wide.len() * 2) as u32,
                    );
                    if st != 0 {
                        RegCloseKey(hkey);
                        return Err(format!("写入 {} 失败: {st:#x}", $name));
                    }
                }};
            }

            if enable {
                set_dword!("ProxyEnable", 1);
                set_string!("ProxyServer", &format!("{ip}:{port}"));
                set_string!("ProxyOverride", &no_proxy_host_names().join(";"));
            } else {
                // 取消：恢复 ProxyEnable=0（保留用户原有 ProxyServer/Override 以便还原）
                set_dword!("ProxyEnable", 0);
            }

            RegCloseKey(hkey);
        }

        notify_settings_changed();
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (enable, ip, port);
        Err("当前平台暂不支持系统代理模式设置".into())
    }
}

/// 设置/取消 PAC 系统代理（Windows：AutoConfigURL）
pub fn set_system_pac(enable: bool, pac_url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ,
            KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
        };

        const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        unsafe {
            let subkey = to_wide(SUBKEY);
            let mut hkey: HKEY = std::ptr::null_mut();
            let status = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            );
            if status != 0 {
                return Err(format!("打开注册表失败: {status:#x}"));
            }

            let name = to_wide("AutoConfigURL");
            let value = if enable {
                pac_url.to_string()
            } else {
                String::new()
            };
            let wide = to_wide(&value);
            let st = RegSetValueExW(
                hkey,
                name.as_ptr(),
                0,
                REG_SZ,
                wide.as_ptr() as *const u8,
                (wide.len() * 2) as u32,
            );
            RegCloseKey(hkey);
            if st != 0 {
                return Err(format!("写入 AutoConfigURL 失败: {st:#x}"));
            }
        }

        notify_settings_changed();
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (enable, pac_url);
        Err("当前平台暂不支持 PAC 代理模式设置".into())
    }
}

/// 读取当前系统代理状态（供 UI 诊断；Windows）
pub fn get_system_proxy_status() -> (bool, Option<String>, Option<String>) {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_READ, REG_SZ,
        };

        const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        unsafe {
            let subkey = to_wide(SUBKEY);
            let mut hkey: HKEY = std::ptr::null_mut();
            let status = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey);
            if status != 0 {
                return (false, None, None);
            }

            let mut proxy_enable: u32 = 0;
            let mut size = std::mem::size_of::<u32>() as u32;
            RegQueryValueExW(
                hkey,
                to_wide("ProxyEnable").as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut proxy_enable as *mut u32 as *mut u8,
                &mut size,
            );

            let read_string = |name: &str| -> Option<String> {
                let name_w = to_wide(name);
                let mut ty = 0u32;
                let mut len = 0u32;
                let st = RegQueryValueExW(
                    hkey,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    &mut ty,
                    std::ptr::null_mut(),
                    &mut len,
                );
                if st != 0 || ty != REG_SZ || len == 0 || !len.is_multiple_of(2) || len > 2048 {
                    return None;
                }
                let mut buf = vec![0u16; (len / 2) as usize];
                if RegQueryValueExW(
                    hkey,
                    name_w.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    buf.as_mut_ptr() as *mut u8,
                    &mut len,
                ) != 0
                {
                    return None;
                }
                // 截断 NUL
                let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                Some(String::from_utf16_lossy(&buf[..end]))
            };

            let server = read_string("ProxyServer");
            let auto_config = read_string("AutoConfigURL");
            RegCloseKey(hkey);
            (proxy_enable != 0, server, auto_config)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        (false, None, None)
    }
}

/// 通知系统代理设置变更（InternetSetOption：SETTINGS_CHANGED + REFRESH）
#[cfg(target_os = "windows")]
fn notify_settings_changed() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    unsafe {
        let _ = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_proxy_host_names() {
        let names = no_proxy_host_names();
        assert!(names.contains(&"10.*".to_string()));
        assert!(names.contains(&"192.168.*".to_string()));
        assert!(names.contains(&"api.steampp.net".to_string()));
        assert!(names.contains(&"172.31.*".to_string()));
    }
}
