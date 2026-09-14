/**
 * Tauri IPC 调用封装：单一入口，命令名与 Rust 侧 fn 名一一对应。
 */
import { invoke } from '@tauri-apps/api/core';
import type {
  AccelerateCatalogDto,
  AppInfo,
  CertificateInfo,
  CertStatusDto,
  ConnectivityTestItem,
  DomainRule,
  EngineStartParams,
  EngineStateDto,
  FlowStatsDto,
  ProxySettings,
} from '@/types/ipc';

/* 应用 */

export function getAppInfo(): Promise<AppInfo> {
  return invoke('get_app_info');
}

/* 引擎 */

export function engineStart(params: EngineStartParams): Promise<EngineStateDto> {
  return invoke('engine_start', { params });
}

export function engineStop(): Promise<EngineStateDto> {
  return invoke('engine_stop');
}

export function engineGetState(): Promise<EngineStateDto> {
  return invoke('engine_get_state');
}

export function engineGetStats(): Promise<FlowStatsDto> {
  return invoke('engine_get_stats');
}

/* 证书 */

export function certGetStatus(): Promise<CertStatusDto> {
  return invoke('cert_get_status');
}

/** 证书详细信息（主题/序列号/有效期/SHA1/SHA256 指纹） */
export function certGetInfo(): Promise<CertificateInfo> {
  return invoke('cert_get_info');
}

/** 安装根证书到系统信任存储（Windows 会触发 UAC） */
export function certInstall(): Promise<boolean> {
  return invoke('cert_install');
}

/** 移除根证书信任（引擎运行中被拒绝） */
export function certUninstall(): Promise<boolean> {
  return invoke('cert_uninstall');
}

export function certExportCa(): Promise<string> {
  return invoke('cert_export_ca');
}

export function certRegenerate(): Promise<CertStatusDto> {
  return invoke('cert_regenerate');
}

/* 设置 */

export function settingsGetProxy(): Promise<ProxySettings> {
  return invoke('settings_get_proxy');
}

export function settingsSaveProxy(settings: ProxySettings): Promise<void> {
  return invoke('settings_save_proxy', { settings });
}

/* 加速项目 */

/** 获取加速项目目录（云端优先，离线降级缓存） */
export function accelerateGetProjects(): Promise<AccelerateCatalogDto> {
  return invoke('accelerate_get_projects');
}

/** 强制刷新（仅云端，成功后更新缓存） */
export function accelerateRefresh(): Promise<AccelerateCatalogDto> {
  return invoke('accelerate_refresh');
}

/** 保存勾选的加速项目 Id 集合 */
export function accelerateSetEnabled(enabledIds: string[]): Promise<void> {
  return invoke('accelerate_set_enabled', { enabledIds });
}

/** 由勾选 Id 集合构建引擎规则 */
export function accelerateGetRules(enabledIds: string[]): Promise<DomainRule[]> {
  return invoke('accelerate_get_rules', { enabledIds });
}

/** 分组连通性测试：并发对每个域名发起完整 HTTPS GET 并计时 */
export function accelerateConnectivityTest(hosts: string[]): Promise<ConnectivityTestItem[]> {
  return invoke('accelerate_connectivity_test', { hosts });
}
