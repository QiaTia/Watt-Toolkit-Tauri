//! 端口占用诊断（对齐 SocketHelper.GetProcessByTcpPort）。
//!
//! Windows：GetExtendedTcpTable 查 LISTEN 状态占用 PID → 进程名。
//! 其他平台：仅返回 None（端口占用但无法定位进程）。

/// 占用端口的进程信息
#[derive(Debug, Clone, PartialEq)]
pub struct PortOccupant {
    pub pid: u32,
    pub name: String,
}

/// 查询监听指定端口的进程
///
/// Windows：GetExtendedTcpTable；其他平台（macOS/Linux）：lsof。
pub fn find_listener_process(port: u16) -> Option<PortOccupant> {
    #[cfg(target_os = "windows")]
    {
        find_listener_process_windows(port)
    }
    #[cfg(not(target_os = "windows"))]
    {
        find_listener_process_posix(port)
    }
}

/// lsof 查询监听进程（macOS/Linux；lsof 缺失或解析失败返回 None）
#[cfg(not(target_os = "windows"))]
fn find_listener_process_posix(port: u16) -> Option<PortOccupant> {
    let out = std::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-F", "pcn"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_lsof_fields(&String::from_utf8_lossy(&out.stdout))
        .map(|(pid, name)| PortOccupant { pid, name })
}

/// 解析 `lsof -F pcn` 字段输出（p=PID / c=COMMAND / n=NAME），取首个完整记录。
///
/// -F 字段模式无表头、无列对齐问题，进程名含空格也不会被拆列：
/// ```text
/// p1234
/// cGoogle Chrome
/// n*:8080
/// ```
pub fn parse_lsof_fields(text: &str) -> Option<(u32, String)> {
    let mut pid: Option<u32> = None;
    let mut name: Option<String> = None;
    for line in text.lines() {
        let Some(tag) = line.chars().next() else { continue };
        match tag {
            'p' => pid = line[1..].trim().parse().ok(),
            'c' => name = Some(line[1..].to_string()),
            _ => {}
        }
        if pid.is_some() && name.is_some() {
            break;
        }
    }
    pid.zip(name)
}

/// 生成端口占用错误信息（含进程名诊断；对齐 CommunityFix_StartProxyFaild443 文案）
pub fn port_occupied_message(port: u16) -> String {
    match find_listener_process(port) {
        Some(p) => format!(
            "端口 {port} 被进程 {name}({pid}) 占用",
            name = p.name,
            pid = p.pid
        ),
        None => format!("端口 {port} 被其他进程占用"),
    }
}

#[cfg(target_os = "windows")]
fn find_listener_process_windows(port: u16) -> Option<PortOccupant> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCP_STATE_LISTEN,
        TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// 在 TCP 表中查找 LISTEN 状态占用端口的 PID
    unsafe fn find_pid_in_table(af: u32, port: u16) -> Option<u32> {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            af,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            af,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != 0 {
            return None;
        }
        // 布局：dwNumEntries(u32) + N × MIB_TCPROW_OWNER_PID
        let count = *(buf.as_ptr() as *const u32);
        let rows = buf.as_ptr().add(std::mem::size_of::<u32>()) as *const MIB_TCPROW_OWNER_PID;
        for i in 0..count as usize {
            let row = &*rows.add(i);
            // dwLocalPort 网络字节序（高位对齐，低 16 位有效）
            let local_port = ((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF);
            if local_port == port as u32 && row.dwState == MIB_TCP_STATE_LISTEN as u32 {
                return Some(row.dwOwningPid);
            }
        }
        None
    }

    unsafe {
        let pid = find_pid_in_table(AF_INET as u32, port)
            .or_else(|| find_pid_in_table(AF_INET6 as u32, port))?;
        let name = process_name(pid).unwrap_or_else(|| format!("PID {pid}"));
        Some(PortOccupant { pid, name })
    }
}

/// PID → 进程名
#[cfg(target_os = "windows")]
fn process_name(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        // 取文件名
        path.rsplit(['\\', '/'])
            .next()
            .map(|n| n.trim_end_matches(".exe").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsof_fields_ok() {
        let out = "p1234\ncGoogle Chrome\nn*:8080\n";
        assert_eq!(parse_lsof_fields(out), Some((1234, "Google Chrome".to_string())));
    }

    #[test]
    fn parse_lsof_fields_name_with_space_not_split() {
        // c 行整体即进程名，含空格不拆列
        let out = "p42\ncmy server\n";
        assert_eq!(parse_lsof_fields(out), Some((42, "my server".to_string())));
    }

    #[test]
    fn parse_lsof_fields_incomplete_or_empty() {
        assert_eq!(parse_lsof_fields(""), None);
        assert_eq!(parse_lsof_fields("garbage"), None);
        assert_eq!(parse_lsof_fields("p99\n"), None);
    }

    #[test]
    fn test_port_occupied_message_format() {
        // 端口 0 不会有 LISTEN 占用（回退到无进程名文案）
        let msg = port_occupied_message(0);
        assert!(msg.contains("端口 0"));
    }
}
