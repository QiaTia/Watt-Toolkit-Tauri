/**
 * IPC 类型定义：与 src-tauri 命令层的 serde 序列化严格对齐。
 *
 * 注意：
 * - 命令层 DTO 使用 `#[serde(rename_all = "camelCase")]` → 驼峰；
 * - 领域模型（watt-config / watt-script）未加 rename → 下划线（snake_case）；
 * - ProxyMode 枚举序列化为变体名："Hosts" | "System" | "Pac" | "ProxyOnly"。
 */

/* ========== 应用信息 ========== */

export interface AppInfo {
  name: string;
  version: string;
  platform: string;
  dataDir: string;
}

/* ========== 引擎状态 ========== */

export type EngineStateDto =
  | { type: 'stopped' }
  | { type: 'starting' }
  | { type: 'running'; startedAt: string; mode: string }
  | { type: 'stopping' }
  | { type: 'error'; message: string };

export interface FlowStatsDto {
  upBytes: number;
  downBytes: number;
}

/* ========== 证书 ========== */

export interface CertStatusDto {
  subject: string;
  serial: string;
  notAfter: string;
  daysRemaining: number;
  expired: boolean;
  /** 是否已安装到系统信任存储 */
  installed: boolean;
}

/** 证书详细信息（watt-cert，snake_case） */
export interface CertificateInfo {
  subject: string;
  serial: string;
  not_before: string;
  not_after: string;
  /** SHA-1 指纹（十六进制大写） */
  sha1: string;
  /** SHA-256 指纹（十六进制大写） */
  sha256: string;
}

/* ========== 代理设置（watt-config，snake_case） ========== */

export type ProxyMode = 'Hosts' | 'System' | 'Pac' | 'ProxyOnly';

export type ExternalProxyType = 'Http' | 'Socks4' | 'Socks5';

/** 二级代理（上游代理链）设置 */
export interface TwoLevelAgentSettings {
  enable: boolean;
  /** 类型字符串："HTTP" | "SOCKS4" | "SOCKS5" */
  proxy_type: string | null;
  ip: string | null;
  port: number;
  username: string | null;
  password: string | null;
}

export interface DnsSettings {
  before_dns_check: boolean;
  master_dns: string | null;
  use_doh: boolean;
  custom_doh_address: string | null;
}

export interface ProxySettings {
  proxy_mode: ProxyMode;
  system_proxy_ip: string | null;
  system_proxy_port: number;
  socks5_proxy_enable: boolean;
  socks5_proxy_port: number;
  enable_http_proxy_to_https: boolean;
  two_level_agent: TwoLevelAgentSettings;
  dns: DnsSettings;
  is_proxy_gog: boolean;
  /** 用户勾选的加速项目 Id 集合（空 = 未设置，回退云端默认） */
  enabled_accelerate_ids: string[];
}

/* ========== 域名规则（watt-config，snake_case） ========== */

export interface StaticResponse {
  status_code: number;
  body: string;
  headers: Array<[string, string]>;
}

/** 子规则（正则匹配 URL 递归细化，字段与顶层规则一致） */
export interface SubRule extends DomainRuleFields {
  regex: string;
}

export interface DomainRuleFields {
  ip_address: string | null;
  destination: string | null;
  forward_destination: string | null;
  fake_server_name: string | null;
  response: StaticResponse | null;
  items: SubRule[];
  user_agent: string | null;
  timeout_ms: number | null;
  tls_sni: boolean;
  tls_ignore_name_mismatch: boolean;
  is_server_side_proxy: boolean;
}

export interface DomainRule extends DomainRuleFields {
  match_domain_names: string[];
  listening_domain_names: string[];
  order: number;
}

/* ========== 加速项目（watt-cloud，模型层 camelCase） ========== */

/** 加速项目（可递归包含按 URL 匹配的子项目） */
export interface AccelerateProject {
  id: string;
  name: string;
  order: number;
  /** 监听端口（云端固定 443） */
  port: number;
  /** 云端默认勾选 */
  defaultChecked: boolean;
  /** 服务端加速（ProxyType == 4） */
  serverSide: boolean;
  /** 自身规则（不含子规则，snake_case 嵌套） */
  rule: DomainRule;
  items: AccelerateProject[];
}

/** 加速项目分组 */
export interface AccelerateProjectGroup {
  id: string;
  name: string;
  order: number;
  show: boolean;
  items: AccelerateProject[];
}

/** 加速项目目录 */
export interface AccelerateCatalog {
  groups: AccelerateProjectGroup[];
}

/** 目录响应（source: 'cloud' | 'cache'） */
export interface AccelerateCatalogDto {
  catalog: AccelerateCatalog;
  source: string;
}

/* ========== 连通性测试（对齐原版 NetworkTestService.TestOpenUrlAsync） ========== */

/** 连通性测试单项结果 */
export interface ConnectivityTestItem {
  host: string;
  /** 完整收到 HTTP 响应（任意状态码均算连通） */
  ok: boolean;
  status?: number | null;
  /** 总耗时（连接 + TLS + 请求 + 完整响应体），毫秒 */
  latencyMs: number;
  error?: string | null;
}

/* ========== 引擎启动参数（命令层 camelCase，嵌套领域模型 snake_case） ========== */

export interface EngineStartParams {
  mode: ProxyMode;
  listenIp?: string | null;
  httpsPort?: number | null;
  httpPort?: number | null;
  /** 正向代理端口（System/Pac/ProxyOnly 模式；默认 26501） */
  forwardProxyPort?: number | null;
  socks5Port?: number | null;
  enableHttpToHttps: boolean;
  twoLevelAgent: TwoLevelAgentSettings;
  dns: DnsSettings;
  serverSideProxyToken?: string | null;
  rules: DomainRule[];
}
