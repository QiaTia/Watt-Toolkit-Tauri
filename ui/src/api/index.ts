/**
 * Tauri IPC 调用封装：单一入口，命令名与 Rust 侧 fn 名一一对应。
 */
import { invoke } from '@tauri-apps/api/core';
import type {
  AccelerateCatalogDto,
  AccessLogFilter,
  AccessLogPage,
  AppInfo,
  BuiltinPoolGroup,
  CertificateInfo,
  CertStatusDto,
  ConnectivityTestItem,
  DohProbeDto,
  DomainPoolOverview,
  DomainRule,
  EngineStartParams,
  EngineStateDto,
  FlowStatsDto,
  IpPoolDomain,
  IpPoolHostResult,
  IpPoolProbeItem,
  ProbeSummaryDto,
  ProxySettings,
  RuntimeLogFilter,
  RuntimeLogPage,
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

export function engineProbeSummary(): Promise<ProbeSummaryDto | null> {
  return invoke('engine_probe_summary');
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

/** 探测 DoH 端点（空 = 默认端点）。失败会抛错，不会静默回退到系统 DNS。 */
export function dnsProbeDoh(endpoint: string | null): Promise<DohProbeDto> {
  return invoke('dns_probe_doh', { endpoint });
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

/* 动态 IP 池 */

/** 从健康 DNS 解析已勾选项目域名 → 本地探测可用 IP → 更新出站 IP 池 */
export function ipPoolRefresh(): Promise<IpPoolHostResult[]> {
  return invoke('ip_pool_refresh');
}

/** 列出池内全部域名条目 */
export function ipPoolList(): Promise<IpPoolDomain[]> {
  return invoke('ip_pool_list');
}

/** 列出版本内置的备用池分组（只读常量） */
export function ipPoolBuiltinList(): Promise<BuiltinPoolGroup[]> {
  return invoke('ip_pool_builtin_list');
}

/** 列出已勾选加速项目的全部域名及其 IP 来源（覆盖 IP / 动态池 / 备用池 / DNS） */
export function ipPoolDomainOverview(): Promise<DomainPoolOverview[]> {
  return invoke('ip_pool_domain_overview');
}

/** 保存某域名的 IP 池（新增或覆盖；ips 支持整段文本，后端逐行解析去重） */
export function ipPoolSaveDomain(host: string, ips: string[]): Promise<IpPoolDomain> {
  return invoke('ip_pool_save_domain', { host, ips });
}

/** 删除某域名的 IP 池 */
export function ipPoolRemoveDomain(host: string): Promise<void> {
  return invoke('ip_pool_remove_domain', { host });
}

/** 清空全部 IP 池 */
export function ipPoolClear(): Promise<void> {
  return invoke('ip_pool_clear');
}

/** 从 DNS 重新解析并探测单个域名，覆盖该域名的池 */
export function ipPoolRefreshHost(host: string): Promise<IpPoolHostResult> {
  return invoke('ip_pool_refresh_host', { host });
}

/** 探测某域名池内全部 IP（只读，返回逐 IP RTT） */
export function ipPoolProbeDomain(host: string): Promise<IpPoolProbeItem[]> {
  return invoke('ip_pool_probe_domain', { host });
}

/* 日志 */

/** 查询代理访问日志（倒序 + 过滤 + 分页） */
export function proxyAccessLogs(
  filter: AccessLogFilter,
  page: number,
  pageSize: number,
): Promise<AccessLogPage> {
  return invoke('proxy_access_logs', { filter, page, pageSize });
}

/** 清空代理访问日志 */
export function proxyAccessLogsClear(): Promise<void> {
  return invoke('proxy_access_logs_clear');
}

/** 查询应用运行日志（tracing 采集，倒序 + 过滤 + 分页） */
export function runtimeLogs(
  filter: RuntimeLogFilter,
  page: number,
  pageSize: number,
): Promise<RuntimeLogPage> {
  return invoke('runtime_logs', { filter, page, pageSize });
}

/** 清空应用运行日志 */
export function runtimeLogsClear(): Promise<void> {
  return invoke('runtime_logs_clear');
}
