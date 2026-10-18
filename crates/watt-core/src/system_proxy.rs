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
    #[cfg(target_os = "macos")]
    {
        macos::set_system_proxy(enable, ip, port)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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
    #[cfg(target_os = "macos")]
    {
        macos::set_system_pac(enable, pac_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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
    #[cfg(target_os = "macos")]
    {
        macos::get_system_proxy_status()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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


/// macOS networksetup / route 输出解析（纯函数，跨平台单测覆盖）
///
/// 非 macOS 编译时唯一消费者（`macos` 模块）被 cfg 掉，此处静默 dead_code。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod netparse {
    /// 可设置代理的服务：硬件类设备（en* / bridge*），排除 VPN 隧道（utun*）
    pub fn is_proxy_capable(device: &str) -> bool {
        device.starts_with("en") || device.starts_with("bridge")
    }

    /// 解析 `networksetup -listnetworkserviceorder` 输出为 (服务名, Device) 列表。
    ///
    /// 启用中的服务形如：
    /// ```text
    /// (1) Wi-Fi
    /// (Hardware Port: Wi-Fi, Device: en0)
    /// ```
    /// 禁用段（`(*) Disabled Services: ...`）只有名字行、无 Hardware Port 伴随，自然忽略。
    pub fn parse_service_list(text: &str) -> Vec<(String, String)> {
        let mut services = Vec::new();
        let mut pending: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(inner) = line.strip_prefix("(Hardware Port:") {
                let inner = inner.trim_end_matches(')');
                let mut device = String::new();
                for part in inner.split(',') {
                    if let Some(v) = part.trim().strip_prefix("Device:") {
                        device = v.trim().to_string();
                    }
                }
                if let Some(name) = pending.take() {
                    services.push((name, device));
                }
            } else if let Some(rest) = line.strip_prefix('(') {
                if let Some(idx) = rest.find(") ") {
                    pending = Some(rest[idx + 2..].trim().to_string());
                }
            }
        }
        services
    }

    /// 解析 `route -n get default` 输出中的 `interface:` 行
    pub fn parse_route_interface(text: &str) -> Option<String> {
        text.lines()
            .map(|l| l.trim())
            .find_map(|l| l.strip_prefix("interface:").map(|v| v.trim().to_string()))
    }

    /// 从服务列表 + 默认路由设备解析目标服务集合（VPN/多活动服务兜底策略，纯函数）
    pub fn resolve_from(services: &[(String, String)], default_dev: &Option<String>) -> Vec<String> {
        if let Some(dev) = default_dev {
        if let Some((name, _)) = services
            .iter()
            .find(|(_, d)| d == dev && is_proxy_capable(d))
        {
                return vec![name.clone()];
            }
        }
        services
            .iter()
            .filter(|(_, d)| is_proxy_capable(d))
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// 解析 "Key: value" 行（如 `Enabled: Yes` / `Server: 127.0.0.1` / `Port: 26501`）
    pub fn parse_field(text: &str, key: &str) -> Option<String> {
        text.lines().find_map(|l| {
            let l = l.trim();
            l.strip_prefix(key).and_then(|rest| {
                let v = rest.trim().trim_start_matches(':').trim();
                (!v.is_empty()).then(|| v.to_string())
            })
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const LIST_OUTPUT: &str = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) Ethernet\n(Hardware Port: Ethernet, Device: en1)\n\n(3) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n(4) My VPN\n(Hardware Port: L2TP, Device: )\n\n(*) Disabled Services: iPhone USB\n";

        #[test]
        fn parse_service_list_basic() {
            let services = parse_service_list(LIST_OUTPUT);
            assert_eq!(services.len(), 4);
            assert_eq!(services[0], ("Wi-Fi".to_string(), "en0".to_string()));
            assert_eq!(services[1], ("Ethernet".to_string(), "en1".to_string()));
            assert_eq!(services[2], ("Thunderbolt Bridge".to_string(), "bridge0".to_string()));
            assert_eq!(services[3], ("My VPN".to_string(), String::new()));
        }

        #[test]
        fn parse_service_list_localized_name() {
            let out = "(1) 无线局域网\n(Hardware Port: Wi-Fi, Device: en0)\n";
            let services = parse_service_list(out);
            assert_eq!(services[0].0, "无线局域网");
            assert_eq!(services[0].1, "en0");
        }

        #[test]
        fn parse_service_list_ignores_disabled_section() {
            let out = "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(*) Disabled Services: Display Ethernet\n";
            assert_eq!(parse_service_list(out).len(), 1);
        }

        #[test]
        fn proxy_capable_device() {
            assert!(is_proxy_capable("en0"));
            assert!(is_proxy_capable("bridge0"));
            assert!(!is_proxy_capable("utun3"));
            assert!(!is_proxy_capable(""));
        }

        #[test]
        fn parse_route_interface_ok() {
            let out = "   route to: default\n destination: default\n       gateway: 192.168.1.1\n  interface: en0\n";
            assert_eq!(parse_route_interface(out).as_deref(), Some("en0"));
            assert_eq!(parse_route_interface("garbage"), None);
        }

        #[test]
        fn parse_field_ok() {
            let t = "Enabled: Yes\nServer: 127.0.0.1\nPort: 26501\n";
            assert_eq!(parse_field(t, "Enabled").as_deref(), Some("Yes"));
            assert_eq!(parse_field(t, "Port").as_deref(), Some("26501"));
            assert_eq!(parse_field(t, "Missing"), None);
        }

        #[test]
        fn resolve_prefers_default_route_service() {
            let services = parse_service_list(LIST_OUTPUT);
            let resolved = resolve_from(&services, &Some("en0".to_string()));
            assert_eq!(resolved, vec!["Wi-Fi".to_string()]);
        }

        #[test]
        fn resolve_falls_back_to_all_hardware_when_vpn_default() {
            let services = parse_service_list(LIST_OUTPUT);
            let resolved = resolve_from(&services, &Some("utun3".to_string()));
            assert_eq!(
                resolved,
                vec![
                    "Wi-Fi".to_string(),
                    "Ethernet".to_string(),
                    "Thunderbolt Bridge".to_string()
                ]
            );
        }

        #[test]
        fn resolve_falls_back_when_no_route() {
            let services = parse_service_list(LIST_OUTPUT);
            let resolved = resolve_from(&services, &None);
            assert_eq!(resolved.len(), 3);
        }
    }
}

/// macOS 实现：networksetup（普通用户权限即可修改代理设置，无需 sudo）
///
/// 服务名解析策略（对齐 doc/macos-acceleration-plan.md 工作项 1）：
/// 1. `route -n get default` 取默认路由接口；
/// 2. `networksetup -listnetworkserviceorder` 解析 (服务名, Device) 对；
/// 3. 默认路由设备能匹配到可设代理的服务 → 只设该服务；
///    匹配不到（VPN 隧道 utunX 在线、无默认路由、解析失败）→
///    对全部硬件类活动服务（Device 为 en*/bridge*）统一设置；
/// 4. 识别只认 Device 字段，不认本地化服务名（中文系统为"无线局域网"）。
///
/// 解析纯函数在 [`netparse`]（跨平台单测）；本模块只做命令执行。
#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;

    use super::netparse::{parse_field, parse_route_interface, parse_service_list, resolve_from};
    use super::no_proxy_host_names;

    /// 默认路由接口
    fn default_route_interface() -> Option<String> {
        let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        parse_route_interface(&String::from_utf8_lossy(&out.stdout))
    }

    /// 解析本次操作的目标网络服务集合（VPN/多活动服务兜底策略）
    fn resolve_target_services() -> Result<Vec<String>, String> {
        let Ok(out) = Command::new("networksetup")
            .arg("-listnetworkserviceorder")
            .output()
        else {
            return Err("无法获取网络服务列表（networksetup -listnetworkserviceorder 执行失败）".into());
        };
        if !out.status.success() {
            return Err("无法获取网络服务列表（networksetup -listnetworkserviceorder 退出非零）".into());
        }
        let services = parse_service_list(&String::from_utf8_lossy(&out.stdout));
        if services.is_empty() {
            return Err("无法获取网络服务列表（解析结果为空）".into());
        }

        let resolved = resolve_from(&services, &default_route_interface());
        if resolved.is_empty() {
            return Err("无法确定可设置代理的网络服务（默认路由非物理网卡，且无硬件类活动服务）".into());
        }
        Ok(resolved)
    }

    /// 执行 networksetup 命令，失败时带 stderr
    fn run(args: &[&str]) -> Result<(), String> {
        let out = Command::new("networksetup")
            .args(args)
            .output()
            .map_err(|e| format!("networksetup 执行失败: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "networksetup {} 失败: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// 查询 networksetup（只读），成功返回 stdout
    fn query(args: &[&str]) -> Option<String> {
        let out = Command::new("networksetup").args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).to_string())
    }

    pub fn set_system_proxy(enable: bool, ip: &str, port: u16) -> Result<(), String> {
        let services = resolve_target_services()?;
        let bypass = no_proxy_host_names();
        let mut errors: Vec<String> = Vec::new();

        for svc in &services {
            let result = if enable {
                let port_s = port.to_string();
                let mut bypass_args: Vec<&str> = vec!["-setproxybypassdomains", svc];
                bypass_args.extend(bypass.iter().map(String::as_str));
                run(&["-setwebproxy", svc, ip, &port_s])
                    .and_then(|_| run(&["-setsecurewebproxy", svc, ip, &port_s]))
                    .and_then(|_| run(&bypass_args))
            } else {
                run(&["-setwebproxystate", svc, "off"])
                    .and_then(|_| run(&["-setsecurewebproxystate", svc, "off"]))
            };
            if let Err(e) = result {
                errors.push(format!("[{svc}] {e}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn set_system_pac(enable: bool, pac_url: &str) -> Result<(), String> {
        let services = resolve_target_services()?;
        let mut errors: Vec<String> = Vec::new();

        for svc in &services {
            let result = if enable {
                run(&["-setautoproxyurl", svc, pac_url])
                    .and_then(|_| run(&["-setautoproxystate", svc, "on"]))
            } else {
                // 取消：关 autoproxy 状态并清空 URL（对齐 Windows：AutoConfigURL 写空串），
                // 防止引擎停止后用户手动开启系统 PAC 时连到已停的本地代理
                run(&["-setautoproxyurl", svc, ""])
                    .and_then(|_| run(&["-setautoproxystate", svc, "off"]))
            };
            if let Err(e) = result {
                errors.push(format!("[{svc}] {e}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// 查询 PAC 状态（URL + autoproxy 是否启用）；未设置或未启用返回 None
    ///
    /// 独立于 webproxy 查询：PAC 模式下系统可能未配置 webproxy，
    /// 若把本查询嵌在 webproxy 分支内，PAC 模式的状态读取会失效
    /// （`cleanup_orphans` 的残留检测同样依赖此返回值）。
    fn query_pac_status(svc: &str) -> Option<String> {
        let t = query(&["-getautoproxyurl", svc])?;
        let url = parse_field(&t, "Auto Proxy URL").or_else(|| {
            let v = t.trim();
            v.starts_with("http").then(|| v.to_string())
        })?;
        let state_on = query(&["-getautoproxystate", svc])
            .and_then(|s| parse_field(&s, "Enabled"))
            .as_deref()
            == Some("Yes");
        state_on.then_some(url)
    }

    pub fn get_system_proxy_status() -> (bool, Option<String>, Option<String>) {
        let Ok(services) = resolve_target_services() else {
            return (false, None, None);
        };

        for svc in &services {
            // PAC 独立查询（不依赖 webproxy 是否配置）
            let pac = query_pac_status(svc);

            if let Some(text) = query(&["-getwebproxy", svc]) {
                let enabled = parse_field(&text, "Enabled").as_deref() == Some("Yes");
                let server = parse_field(&text, "Server");
                let port = parse_field(&text, "Port");
                if let (Some(server), Some(port)) = (server, port) {
                    return (enabled, Some(format!("{server}:{port}")), pac);
                }
            }

            // 未配置 webproxy 但 PAC 生效：以 PAC 状态返回
            // （消费方 connect_test::system_proxy_addr / cleanup_orphans 均独立判定 pac）
            if pac.is_some() {
                return (false, None, pac);
            }
        }
        (false, None, None)
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
