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

/** 候选探测摘要（启动预择优；UI 展示） */
export interface ProbeSummaryDto {
  hosts: number;
  candidates: number;
  ok: number;
  fastestMs: number | null;
  finished: boolean;
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

/** DoH 连通性探测结果（含 TLS 握手 + 真实查询） */
export interface DohProbeDto {
  /** 实际使用的端点 */
  endpoint: string;
  /** 探测域名 */
  host: string;
  /** 解析得到的 IP */
  ips: string[];
  /** 端到端耗时（毫秒） */
  elapsedMs: number;
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
  /** 勾选集合是否已初始化（区分首次运行与用户主动清空） */
  enabled_accelerate_ids_initialized: boolean;
  /** 终端（CLI）代理环境变量 + 证书注入（git/curl/npm/pip 等） */
  terminal_proxy_enable: boolean;
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
  /** 启动时注入终端代理环境变量 + CLI 证书（默认 true） */
  terminalProxyEnable?: boolean;
}

/* ========== 动态 IP 池（命令层 camelCase） ========== */

/** IP 池内的一个域名条目（IP 池管理页列表行） */
export interface IpPoolDomain {
  host: string;
  /** 池内 IP（写入顺序 = 上次刷新的 RTT 升序） */
  ips: string[];
  /** 该条目最近一次写入时刻（unix 毫秒） */
  refreshedAtMs: number;
}

/** IP 池管理页：版本内置的备用池分组（编译期常量，只读） */
export interface BuiltinPoolGroup {
  /** 展示用匹配模式（如 `*.github.com`） */
  pattern: string;
  /** IP 段来源 / 选型说明 */
  note: string;
  /** 该组的 IP 列表（已按实测可达性排序） */
  ips: string[];
}

/** IP 池管理页：加速域名 → IP 来源总览 */
export interface DomainPoolOverview {
  /** 规则里的原始匹配模式（可能含 `*.`） */
  pattern: string;
  /** 规范化域名 */
  host: string;
  /** 规则写死的覆盖 IP */
  overrideIps: string[];
  /** 动态池命中的 IP */
  dynamicIps: string[];
  /** 内置备用池命中的 IP */
  builtinIps: string[];
  /** 生效来源（有序）：override / dynamic / builtin / dns */
  sources: Array<'override' | 'dynamic' | 'builtin' | 'dns'>;
}

/** 单个候选 IP 的探测结果 */
export interface IpPoolProbeItem {
  ip: string;
  /** 握手全链路 RTT（毫秒）；null = 未通过 */
  rttMs: number | null;
}

/** 单个域名的 IP 池刷新结果 */
export interface IpPoolHostResult {
  host: string;
  /** DNS 解析到的候选数（去重 + 过滤后） */
  candidates: number;
  /** 探测通过的候选数 */
  ok: number;
  /** 全部候选及探测结果（通过者在前、按 RTT 升序） */
  ips: IpPoolProbeItem[];
  /** 命中的解析来源（如 `DoH https://223.5.5.5/dns-query`） */
  source: string | null;
  /** 失败原因：dns_resolve_empty（无解析结果）/ all_unreachable（全部不可达） */
  error: string | null;
}

/* ========== 日志（访问日志 + 运行日志；命令层 camelCase） ========== */

/** 访问日志处置分类 */
export type Disposition = 'matched' | 'default' | 'unmatched' | 'local';

export interface AccessLogEntry {
  tsMs: number;
  host: string;
  method: string;
  path: string;
  status: number;
  upBytes: number;
  downBytes: number;
  latencyMs: number;
  disposition: Disposition;
}

export interface AccessLogFilter {
  keyword?: string | null;
  method?: string | null;
  statusMin?: number | null;
  statusMax?: number | null;
  disposition?: Disposition | null;
}

export interface AccessLogPage {
  items: AccessLogEntry[];
  total: number;
  page: number;
  pageSize: number;
}

export interface RuntimeLogEntry {
  tsMs: number;
  level: string;
  target: string;
  message: string;
}

export interface RuntimeLogFilter {
  keyword?: string | null;
  minLevel?: string | null;
}

export interface RuntimeLogPage {
  items: RuntimeLogEntry[];
  total: number;
  page: number;
  pageSize: number;
}
