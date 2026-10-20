fn main() {
    // Windows：注入自定义应用清单（requireAdministrator）。
    // Hosts 模式需要写系统 hosts（启动写入 / 停止摘除），非提升进程会得到 os error 5，
    // 故整个应用以管理员身份运行（与上游 Steam++ 一致）；非 Windows 平台不受影响。
    let mut windows = tauri_build::WindowsAttributes::new();
    windows = windows.app_manifest(include_str!("app.manifest"));

    let attrs = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attrs).expect("failed to run tauri-build");

    println!("cargo:rerun-if-changed=app.manifest");
}
