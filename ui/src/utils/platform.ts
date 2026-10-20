/**
 * 运行平台检测（Tauri webview 的 UA 含宿主 OS 信息；浏览器调试同样可用）。
 * 用于平台专属提示文案（提权弹窗、/etc/hosts 写入说明、管理员运行说明）。
 */
export function isMacOS(): boolean {
  return /Macintosh|Mac OS X/i.test(navigator.userAgent);
}

export function isWindows(): boolean {
  return /Windows/i.test(navigator.userAgent);
}
