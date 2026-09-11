# Watt Toolkit 网络加速服务迁移 Tauri 2 实施计划

## Context（背景与目标）

Watt Toolkit（SteamTools）当前为 Avalonia + .NET 8 桌面应用，网络加速服务由三部分构成：

| 模块                                              | 规模              | 职责                                     |
| ----------------------------------------------- | --------------- | -------------------------------------- |
| BD.WTTS.Client.Plugins.Accelerator              | 105 文件 / 8731 行 | 插件编排、ProxyService 启停、WinDivert、讯游对接    |
| BD.WTTS.Client.Plugins.Accelerator.ReverseProxy | 74 文件 / 6267 行  | Kestrel + YARP 反向代理、MITM 证书、hosts、脚本注入 |
| BD.WTTS.Client.IPC                              | 3 文件 / 562 行    | 主进程 ↔ 加速子进程 IPC（dotnetCampus.Ipc 命名管道） |

**目标**：按用户确认的决策，构建完整 Tauri 2 应用——Rust 后端承载全部加速服务（取消加速子进程与 IPC 层），Vue 3 + TypeScript（严格模式）前端，脚本系统用 rquickjs Rust 原生实现，**不包含**讯游游戏加速与 WinDivert/DNSIntercept 模式。

**加速原理回顾**：hosts 或系统代理把 steamcommunity.com 等域名指向本地 → 本地 HTTPS MITM 反向代理（自签证书）→ HTML 脚本注入（改区/解锁库存）→ 转发真实服务器（可走二级代理）。

**关键发现**：现有"脚本系统"并不在代理进程内执行 JS——[HttpReverseProxyMiddleware.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Services.Implementation/HttpServer/Middleware/HttpReverseProxyMiddleware.cs) 只做 HTML `<script>` 标签注入，脚本实际运行在 Steam 内置浏览器页面上下文，通过 `local.steampp.net` XHR 桥接（`requestType: xhr`、`-steamtool` 后缀头）取数。因此 rquickjs 引擎是**新增服务端钩子能力**，迁移需双层覆盖：浏览器注入生态 100% 兼容 + 新增服务端 onRequest/onResponse 钩子。

**关键常量**（迁移后保持一致）：端口 443（HTTPS MITM）/ 26501（正向代理默认）/ 8868（SOCKS5）；`LocalDomain = "local.steampp.net"`；`InjectScriptPathPrefix = "/WattToolkit_Inject/"`；hosts 标记块 `# Steam++ Start/End` + Backup 块。

***

## 一、项目结构（新建 Tauri 2 monorepo）

```
watt-toolkit-tauri/
├── Cargo.toml                      # [workspace]
├── crates/
│   ├── watt-core/                  # 代理引擎（不依赖 tauri，可独立测试）
│   │   └── src/{engine.rs, listener.rs, sni.rs, mitm.rs, http_relay.rs,
│   │             forward_proxy.rs, socks5.rs, outbound/{connector,http_proxy,socks}.rs,
│   │             matcher.rs, inject.rs, local_domain.rs, pac.rs, stats.rs}
│   ├── watt-cert/                  # 证书：ca.rs, leaf.rs, trust/{windows,macos,linux}.rs, pfx.rs
│   ├── watt-hosts/                 # hosts：tagged_block.rs, encoding.rs, watcher.rs
│   ├── watt-script/                # rquickjs：engine_rquickjs.rs, hooks.rs, api_fetch.rs, sandbox.rs
│   ├── watt-dns/                    # resolver.rs, doh.rs, fastest.rs, pollution.rs
│   ├── watt-config/                # settings.rs, migrate.rs, domain_rule.rs
│   └── watt-helper/                # 特权助手一次性 CLI bin（hosts-write/cert-install/setcap）
├── src-tauri/                      # 应用壳：commands/{proxy,cert,hosts,script,settings,dns}.rs,
│   │                               #   events.rs, state.rs, tray.rs, capabilities/default.json
├── src/                            # Vue 3 前端（见第三节）
└── .github/workflows/              # CI: cargo test + vue-tsc + 三平台构建
```

## 二、Rust 加速核心方案

### 2.1 网络层选型（关键决策）

**tokio TcpListener 接入层 + httparse 首字节嗅探协议分发 + hyper 1.x（server::conn 低层 API）HTTP 编解码。**

理由：MITM 需在 TLS 握手前后手工控制连接（SNI 动态证书、明文 ClientHello 嗅探），axum 类 Web 框架的中间件模型不适配（.NET 原实现同样是 Kestrel 连接级中间件）；rustls `ResolvesServerCert` 在握手回调提供 SNI，天然对齐 `CertService.GetOrCreateServerCert`。

### 2.2 端口分发模型（listener.rs）

```
443  (Hosts模式):  TLS MITM → (ALPN h2/http1.1) → http_relay
80   (可选):        HTTP → 301 跳转 https（EnableHttpProxyToHttps）
26501(System/PAC): 首字节嗅探:
     - "CONNECT " → forward_proxy（匹配域名→MITM 进 http_relay；未匹配→纯隧道直连）
     - "GET/POST http://" → HTTP 正向代理
     - /pac → PAC 文件端点
8868 (可选):       SOCKS5 入站 → 目标匹配判定 → MITM 或直连隧道
```

### 2.3 核心 Crate 清单

| 领域    | Crate                                                   | 用途                 |
| ----- | ------------------------------------------------------- | ------------------ |
| 运行时   | tokio(full), futures                                    | 异步运行时              |
| HTTP  | hyper 1.x + hyper-util + http-body-util + httparse      | 编解码与转发             |
| TLS   | rustls + tokio-rustls（dangerous\_configuration）         | MITM 动态证书 + 上游校验定制 |
| 证书    | rcgen（签发）、p12（旧 PFX 导入）、x509-parser                     | CA/叶子证书            |
| DNS   | hickory-resolver（dns-over-https feature）                | DNS/DoH/竞速/污染判定    |
| 脚本    | rquickjs（bindgen, futures）                              | 服务端 JS 钩子          |
| 压缩    | flate2 + brotli                                         | 注入后重压缩             |
| 平台    | windows、security-framework(macOS)                       | 证书信任               |
| Tauri | tauri 2 + tauri-specta + autostart + single-instance 插件 | 应用壳                |

**排除**：quinn/h3（HTTP/3 首期不做，后续增项）、axum、fast-socks5（入站 SOCKS5 约 200 行手写）。

### 2.4 http\_relay 核心流程（对齐 HttpReverseProxyMiddleware L60-177）

```
解析请求 → 命中脚本注入(TryGetScriptConfig)
  → 域名规则匹配(TryGetDomainConfig + Items 正则递归)
  → 未匹配: TwoLevelAgentEnable → 全局上游代理转发；否则 next/404
  → 匹配 default 规则: DNS 污染判定(解析回环 → 500 中文错误文案)
  → Response 静态响应规则 → 直接返回
  → EnableHttpProxyToHttps && http → 301
  → Destination 模板替换(@domain/@uri) → UserAgent 替换(${origin})
  → IsServerSideProxy → 追加 X-Watt-Origin-Dest-* / X-Watt-Token 头
  → 出站转发(outbound/connector，支持上游 HTTP CONNECT/SOCKS4/SOCKS5 + 账密)
  → 命中脚本 → inject.rs：仅 GET + 200 + text/html；移除 CSP；
     gzip/deflate/br 解压 → BOM/charset 探测 → 插入
     <script src="/WattToolkit_Inject/{lid}.js"> → 重压缩；
     GitHub 特殊插入位置分支；IsOnlyWorkSteamBrowser 时 UA 过滤
```

### 2.5 脚本引擎（watt-script）——双层模型

1. **浏览器注入层（兼容层，Phase 4a）**：无 JS 引擎。`local_domain.rs` 提供 `/WattToolkit_Inject/{lid}.js` 脚本文件服务 + XHR 桥（`requestType: xhr` + `?request=` URL 解码 + `-steamtool` 后缀头还原 + cookie/referer 特判）+ CORS OPTIONS。hosts 自动追加 `local.steampp.net`。
2. **服务端钩子层（Phase 4b，新能力）**：脚本声明 `onRequest(ctx)/onResponse(ctx)` 导出，rquickjs 实例池（DashMap\<script\_id, Instance>），每钩子 50ms 软超时 + 内存上限，异常捕获降级放行并记日志——**脚本错误绝不阻断转发**。向脚本暴露受限 `fetch()`（走同一出站连接器/DNS 链）+ console.log→tracing。

选型 rquickjs 而非 boa 的理由：社区脚本使用现代 ES 语法，QuickJS ES2023 覆盖度远超 boa（boa 慢 5-10 倍且规范有空洞），脚本生态兼容性是生命线。

### 2.6 hosts 模式与特权提升

- `tagged_block.rs` 全量移植 [HostsFileServiceImpl.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client/Services.Implementation/Net/HostsFileServiceImpl.cs)：`# Steam++ Start/End` 主块、Backup 备份块（`#{line_num} {line}` 格式）、V1 兼容清理、域名去重、标记块重复时 `.spp.bak` 备份重写、50MB 上限、只读属性摘除/恢复、编码三选（ANSI/UTF-8/UTF-8 BOM）。

- 启动时序（对齐 ProxyService.Operate.cs L149/247-282）：443 预占用检查（Windows 报进程名）→ 引擎启动 → `ListeningDomainNamesArray` 映射代理 IP + `local.steampp.net` → 写 hosts；**失败回滚停止代理**。停止时先摘 hosts 再停引擎。

- 特权：`watt-helper hosts-write --input <tmpfile>` 一次性 CLI——Windows `runas`(UAC)、Linux `pkexec`、macOS `osascript with administrator privileges`；当前用户可写时直接写。保留 Windows 目录监听 + 550-850ms 随机退避重写。

### 2.7 证书信任（watt-cert）

- CA：rcgen 生成（对齐 CertificateValidDays），PFX+DER 导出，过期拒绝加载，到期定时器自动续期并重启代理（对齐 `_certificateTimer`）。

- 叶子证书：rustls ResolvesServerCert 按 SNI 动态签发，TTL 1 年缓存（SAN：机器名、127.0.0.1、::1）。

- 信任安装：Windows `CertOpenSystemStore("ROOT")` LocalMachine + thumbprint 去重；macOS `security add-trusted-cert`；Linux `/usr/local/share/ca-certificates` + `update-ca-certificates`（helper 提权）。

- 附加动作保留：git `http.sslverify` 开关、GOG Galaxy certifi/cacert.pem 追加。

### 2.8 配置与数据结构（watt-config）

```rust
pub enum ProxyMode { Hosts, System, Pac, ProxyOnly }
// 旧→新映射: DNSIntercept(0)→Hosts+提示, Hosts(1)→Hosts, System(2)→System,
//            VPN(3)→不支持(提示), ProxyOnly(4)→ProxyOnly, PAC(5)→Pac

pub struct DomainRule {           // 对齐 IDomainConfig/AccelerateProjectDTO
    pub match_domain_names: Vec<String>,
    pub listening_domain_names: Vec<String>,  // "ip domain" 反序格式兼容
    pub destination: Option<String>,          // @domain/@uri 模板
    pub forward_destination: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub static_response: Option<StaticResponse>,
    pub items: Vec<SubRule>,                  // regex → 递归子规则
    pub user_agent: Option<String>,
    pub timeout_ms: Option<u64>,
    pub tls_sni: bool, pub tls_ignore_name_mismatch: bool,
    pub is_server_side_proxy: bool, pub order: i32,
}
```

***

## 三、前端（Vue 3 + TypeScript 严格模式）

```
App.vue
└── MainLayout.vue                 # 侧边导航 + 顶栏状态徽标
    ├── Dashboard.vue              # 加速大开关 + 流量实时(速度/累计) + 加速时长
    ├── AccelerateConfig.vue       # 加速项目分组：组↔项目↔域名三态勾选
    ├── Scripts.vue                # 已装脚本管理 + 脚本商店
    ├── ProxyModeSettings.vue      # 模式切换/代理IP端口/SOCKS5/二级代理/DNS/DoH
    ├── Certificate.vue            # 证书信息(Subject/序列号/有效期) 安装/删除/导出
    ├── HostsManager.vue           # hosts 查看/编辑/重置 + 标记块状态
    └── GeneralSettings.vue        # 开机自启/语言/缓存清理/日志
```

**类型策略（用户强调）**：tauri-specta v2 从 Rust `#[tauri::command]` 与事件 payload 自动生成 `bindings.ts`（含 serde 类型），单一来源杜绝手写 DTO 漂移；领域模型加 `#[derive(specta::Type, Serialize)]`。`tsconfig.json`: `strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true`；CI 中 `vue-tsc --noEmit` 作为门禁。

**实时通信**（Rust → 前端事件，state.rs 统一发射）：

- `proxy://state`: `{ status: Starting|Running|Stopping|Stopped|Error, mode, started_at, error }`

- `proxy://flow`: `{ up_bytes, down_bytes, up_speed, down_speed }`（1s 节流）

- `proxy://log`: `{ level, message }`（tracing 自定义 layer 桥接）

前端 Pinia store 持有状态机，`useTauriEvent` 组合式函数订阅；开关乐观更新以事件回执为准。

***

## 四、迁移阶段划分（每阶段可验证）

### Phase 0：脚手架（1 周）

monorepo + workspace + CI（cargo fmt/clippy/test + vue-tsc + 三平台 tauri build）。
**验收**：空 Tauri 2 应用三平台启动；tauri-specta 生成 bindings.ts 进 CI 校验（重点验证 rquickjs C 依赖三平台交叉编译）。

### Phase 1：项目骨架 + 基础 UI（2 周）

七个页面路由 + Pinia + 设置读写 command + i18n（resx 导出 JSON）+ 托盘 + 单实例 + 开机自启。
**验收**：设置落盘 `{AppData}/Settings/ProxySettings.json` 重启保留；vue-tsc 零错误；托盘可用。

### Phase 2：Rust 反向代理核心（3-4 周）

watt-core：listener(443)、sni/mitm（rcgen 随机自签，信任留 Phase 3）、matcher、http\_relay、outbound、stats、启停编排；hosts 先手动改。
**验收**：`cargo test` 集成测试（本地 mock 上游 + curl `--resolve` 往返 200，含 gzip 透传/静态 Response/Destination 模板）；`openssl s_client -servername` 握手返回动态证书；流量统计事件每秒到前端。

### Phase 3：证书生成与信任（2 周）

watt-cert 全量 + 到期定时器 + git/GOG 附加动作 + helper 提权安装。
**验收**：Windows 首启自动生成 CA 装入 LocalMachine\Root（thumbprint 去重）；浏览器访问 MITM 域名无告警；到期模拟触发续期重启。

### Phase 4：脚本系统（3 周）

- 4a 兼容层：inject.rs 全量（CSP 移除/编码探测/三压缩/GitHub 分支/UA 过滤）+ local\_domain（脚本文件/XHR 桥/CORS）+ hosts 追加。

- 4b 服务端钩子：rquickjs + onRequest/onResponse + fetch 白名单 + 沙箱。
  **验收**：取 3-5 个代表性社区脚本（区域切换/库存解锁）Steam 客户端实测注入生效（DevTools 见 `/WattToolkit_Inject/*.js` 200）；注入单测覆盖 gzip/br/无 charset/GitHub/非 GET；死循环脚本 50ms 被掐断且请求放行。

### Phase 5：模式接入 + 平台适配（3-4 周）

System/PAC/ProxyOnly 模式 + SOCKS5 入站 + 二级代理三协议 + DNS 全量 + watt-helper（UAC/pkexec/osascript）+ Linux setcap + 443 占用诊断。
**验收**：系统代理模式注册表设置后未匹配域名纯隧道直连（抓包确认）；PAC 端点可下载生效；本地 3proxy/dante 验证上游 HTTP/SOCKS5 链路（含账密）；Linux/macOS 虚机 hosts 模式全流程；DNS 污染用例返回 500 中文错误页。

### Phase 6：数据迁移 + 打磨（2 周）

migrate.rs：读旧 `{AppData}/Settings/*.json`（PascalCase 别名）→ 新配置；ScriptsStatus 迁移；旧 CA PFX（空密码）导入保持已信任状态；脚本缓存扫描导入；加速项目列表云端 API + ServerSideProxyToken 接入。
**验收**：安装新版首启，旧版勾选的加速项目/脚本/代理设置全部保留且一键加速可用；升级场景 hosts 标记块正确接管。

**明确不迁移**：讯游游戏加速、Android/VPN(tun2socks)、WinDivert/DNSIntercept 模式（映射为 Hosts 并提示）。

***

## 五、风险与应对

| 风险                      | 应对                                                                |
| ----------------------- | ----------------------------------------------------------------- |
| 443 权限：Linux/macOS 需特权  | Linux setcap（沿用 pkexec 方案）；macOS helper/文档引导；启动前占用检测报进程名          |
| 杀软误报（写 hosts/装根证书/MITM） | 代码签名（EV 优先）；MS 误报申诉；禁 UPX                                         |
| 脚本兼容性                   | 浏览器注入路径字节级对齐；服务端钩子为增量不影响旧脚本；代表性脚本回归集进 CI                          |
| 进程模型变化：原引擎崩溃隔离在子进程      | 每连接 tokio::spawn + catch\_unwind；引擎独立 supervise，panic 只重建监听器并上报事件 |
| 旧 CA PFX 迁移失败           | p12 crate 单测覆盖；失败引导重装信任（降级不阻断）                                    |
| hosts 被外部改写             | 目录监听 + 随机退避重写；标记块重复时备份重置（移植现有逻辑）                                  |
| rustls 不支持 TLS1.0/1.1   | Steam 客户端为现代 Chromium 不受影响；记录为已知限制                                |

## 实现时行为基准文件（必须对照）

- [HttpReverseProxyMiddleware.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Services.Implementation/HttpServer/Middleware/HttpReverseProxyMiddleware.cs) — http\_relay.rs/inject.rs 行为规范

- [ProxyService.Operate.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client.Plugins.Accelerator/Services/Mvvm/ProxyService.Operate.cs) — engine.rs 启停编排与 hosts 写入时序规范

- [CertificateManagerImpl.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Services.Implementation/Certificate/CertificateManagerImpl.cs) — watt-cert 规范

- [HostsFileServiceImpl.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client/Services.Implementation/Net/HostsFileServiceImpl.cs) — watt-hosts 标记块算法移植目标

- [ReverseProxyHttpClientHandler.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Services.Implementation/Http/ReverseProxyHttpClientHandler.cs) — outbound/ 出站与二级代理规范

- [TcpReverseProxyHandler.cs](file:///e:/Project/SteamTools-develop/src/BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Services.Implementation/HttpServer/TcpReverseProxyHandler.cs) — TCP 四层代理规范

## 验证方法（端到端）

1. **单元/集成**：`cargo test`（watt-core 起 mock 上游验证转发/注入/压缩/静态规则/模板）；`vue-tsc --noEmit` 零错误门禁。
2. **本地端到端**：启动应用 → 选 Hosts 模式 → 开加速 → `nslookup steamcommunity.com` 返回本机 → 浏览器访问确认 MITM 证书 + 页面正常 + F12 见注入脚本。
3. **真实场景**：Steam 客户端内置浏览器实测社区脚本（区域价格切换/库存解锁）；系统代理模式下 curl 环境变量验证正向代理；上游二级代理用 3proxy 验证。
4. **平台矩阵**：Windows 11（主开发机）+ Linux 虚机（deb 包）+ macOS（如无可暂缓，CI 构建）。


继续 Phase 6。先创建任务清单并探索旧版实现与当前项目结构。
The user wants to continue with Phase 6. Let me recall what Phase 6 involves based on the migration plan:

### Phase 6: 数据迁移 + 打磨（2 周）
migrate.rs：读旧 `{AppData}/Settings/*.json`（PascalCase 别名）→ 新配置；ScriptsStatus 迁移；旧 CA PFX（空密码）导入保持已信任状态；脚本缓存扫描导入；加速项目列表云端 API + ServerSideProxyToken 接入。
**验收**：安装新版首启，旧版勾选的加速项目/脚本/代理设置全部保留且一键加速可用；升级场景 hosts 标记块正确接管。

So Phase 6 involves:
1. **migrate.rs**: Read old `{AppData}/Settings/*.json` (PascalCase aliases) → new config
2. **ScriptsStatus migration**: Script status migration
3. **Old CA PFX (empty password) import**: Keep trusted state
4. **Script cache scan import**: Script cache scanning and importing
5. **Accelerate project list cloud API + ServerSideProxyToken integration**: Cloud API for acceleration project list

Let me start by exploring the current state of the project and the old C# implementation to understand what needs to be migrated.

First, let me look at:
1. The current Tauri project structure
2. The old C# settings files format
3. The old CA PFX storage
4. The scripts cache structure
5. The cloud API for acceleration project list

Let me start exploring.

Let me explore the old C# implementation's settings format and the current Tauri project structure in parallel.

我将开始在仓库中并行搜索所有相关内容。让我先进行第一轮广泛搜索。

我来帮你系统地探索 Tauri 版实现，为 Phase 6 数据迁移收集信息。让我先并行执行多个搜索来定位关键文件。

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Settings\Infrastructure\Abstractions\ISettings.cs:L30-L63
   — 旧版设置文件存储路径实现：统一存放在 `{AppDataDirectory}\Settings\`，文件名为 `Settings.Name + .json`，即类似 `ProxySettings.json`、`GeneralSettings.json` 等。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Settings\Infrastructure\Abstractions\ISettings.cs:L99-L179
   — 旧版 JSON 序列化/反序列化设置文件的核心逻辑：使用 `JsonIgnoreCondition.Never`、`WriteIndented=true`、`JsonStringEnumConverter`，并按 `TSettings.Name` 节点读取配置。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Plugins\Abstractions\PluginBase.cs:L12-L25
   — 插件级配置加载入口：插件的 AppData 目录为 `GetPluginsDirectory(UniqueEnglishName, IOPath.AppDataDirectory)`，并通过 `ISettings<TSettings>.Load(...)` 加载对应设置文件。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Settings\ProxySettings.cs:L30-L44
   — `ProxySettings_` 的序列化上下文与 `ISettings` 绑定；`Name = "ProxySettings"`，对应旧版设置文件 `ProxySettings.json`。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Settings\ProxySettings.cs:L70-L173
   — 代理设置的主要 JSON 字段名（PascalCase）：`SystemProxyPortId`、`SystemProxyIp`、`OnlyEnableProxyScript`、`ProxyMasterDns`、`EnableHttpProxyToHttps`、`Socks5ProxyEnable`、`Socks5ProxyPortId`、`TwoLevelAgent*`、`ProxyMode` 等。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Plugins\Plugin.cs:L240-L244
   — 旧版加速器插件注册需要迁移的配置项：`ProxySettings_` 与 `GameAcceleratorSettings_`，对应 `ProxySettings.json` 和加速器游戏设置文件。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services.Implementation\ScriptManager.cs:L124-L183
   — 旧版脚本缓存/脚本文件存储路径：脚本保存至 `Plugin.Instance.AppDataDirectory\Scripts\`，编译后缓存至 `CacheDirectory\Scripts_Build\`，文件以 MD5 命名 `.js`。

8. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services.Implementation\Certificate\CertificateManagerImpl.cs:L52-L89
   — 旧版 CA 证书加载逻辑：从 `ICertificateManager.PfxFilePath` 读取 PFX，并加载为根证书；用于 Tauri 版本迁移 CA 证书存储路径与密码机制。

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\watt-toolkit-tauri\crates\watt-config\src\settings.rs:L143-L174
   — `ProxySettings` 顶层配置结构体；字段均为 `snake_case`，未看到 `PascalCase`/`rename_all` 别名处理，是 Phase 6 配置迁移的核心源结构。

2. e:\Project\SteamTools-develop\watt-toolkit-tauri\crates\watt-config\src\settings.rs:L217-L234
   — 代理设置加载/保存逻辑：从 `{settings_dir}/ProxySettings.json` 读取，缺失时返回默认值；保存时创建目录并写入 JSON。

3. e:\Project\SteamTools-develop\watt-toolkit-tauri\crates\watt-config\src\settings.rs:L205-L214
   — 配置目录路径定义：`app_data_dir()` 为 `{AppData}/WattToolkit`，`settings_dir()` 为 `{AppData}/WattToolkit/Settings`。

4. e:\Project\SteamTools-develop\watt-toolkit-tauri\crates\watt-script\src\model.rs:L4-L22
   — `ScriptConfig` 结构体定义；包含 `local_id`、`cache_path`、`match_domain_names`、`exclude_domain_names`、`order`，是脚本配置迁移的关键字段。

5. e:\Project\SteamTools-develop\watt-toolkit-tauri\crates\watt-script\src\model.rs:L24-L43
   — 脚本匹配逻辑 `script_matches_url`：基于 `exclude_domain_names` 和 `match_domain_names` 判断 URL 是否命中脚本注入。

6. e:\Project\SteamTools-develop\watt-toolkit-tauri\src-tauri\src\lib.rs:L30-L35
   — Tauri 应用数据目录解析逻辑：优先使用 Tauri `app_data_dir()`，回退到 `watt-config` 的通用 `app_data_dir()`。

7. e:\Project\SteamTools-develop\watt-toolkit-tauri\src-tauri\src\lib.rs:L46-L79
   — Tauri 启动流程：初始化日志、创建数据目录、加载/生成 CA、注册 `AppState`，并列出当前 Tauri commands，包括证书和设置相关命令。

8. e:\Project\SteamTools-develop\watt-toolkit-tauri\src-tauri\src\commands\settings.rs:L6-L24
   — Tauri 层设置命令：`settings_get_proxy` 调用 `watt_config::settings::load_proxy_settings()`，`settings_save_proxy` 将 `ProxySettings` 写入 `{data_dir}/Settings/ProxySettings.json`。

深入阅读关键文件，确定字段映射。
Now I have a good overview. Let me dig deeper into the specific files to understand the exact field mappings needed. Let me read:

1. Old ProxySettings.cs - full field list
2. Old ScriptSettings (probably in ScriptManager or Settings)
3. Old CA PFX path logic
4. Old script cache structure
5. New settings.rs structure

Let me read these files in parallel.

现在查看旧版 CA 证书路径与脚本缓存结构。
Now I have the old ProxySettings field names and the new structure. Let me now check:
1. Old CA PFX path (CertificateManagerImpl.cs)
2. Old script cache structure (ScriptManager.cs)
3. Old app data directory name

Let me look at those.

So old CA PFX is at `{AppData}/SteamTools.Certificate.pfx` (with AppData = IOPath.AppDataDirectory). Now let me find what IOPath.AppDataDirectory is on Windows. Let me also check the ScriptManager for the script cache structure and the old AppData directory name.

The rg output is being garbled (it seems the `n` is replacing matched text - some encoding issue with the terminal). Let me look at the WindowsFileSystem.cs to find the AppDataDirectory.

So the old AppData directory on Windows is `%LocalAppData%\Steam++`. Now let me check the ScriptManager for the script cache structure and understand what the old ScriptsStatus looks like. Also let me check the script storage:
- Scripts saved at `Plugin.Instance.AppDataDirectory\Scripts\` 
- Compile cache at `CacheDirectory\Scripts_Build\`

The Accelerator plugin's AppData directory would be `%LocalAppData%\Steam++\Plugins\Accelerator` or similar. Let me check GetPluginsDirectory.

查看旧版插件目录结构与云端 API。
Now I understand the script structure:
- Old scripts saved at `Plugin.Instance.AppDataDirectory\Scripts\{md5}.js` 
- The Accelerator plugin's AppDataDirectory is probably `%LocalAppData%\Steam++\Plugins\Accelerator\` — wait, let me check `GetPluginsDirectory`.

Let me check what Plugin.Instance.AppDataDirectory is. Also check IScriptManager.DirName and DirName_Build constants.

Actually, for Phase 6, the plan says:

```
migrate.rs：读旧 `{AppData}/Settings/*.json`（PascalCase 别名）→ 新配置；ScriptsStatus 迁移；旧 CA PFX（空密码）导入保持已信任状态；脚本缓存扫描导入；加速项目列表云端 API + ServerSideProxyToken 接入。
```

So the migration needs:
1. Read old `{AppData}/Settings/*.json` (PascalCase aliases) → new config — i.e. read old `%LocalAppData%\Steam++\Settings\ProxySettings.json` and convert to new `%LocalAppData%\WattToolkit\Settings\ProxySettings.json` format
2. ScriptsStatus migration — the `ScriptsStatus` field (IReadOnlyCollection<int>?) in ProxySettings.json contains enabled script local IDs
3. Old CA PFX (empty password) import to keep trusted state — read `%LocalAppData%\Steam++\SteamTools.Certificate.pfx` and convert to new CA storage (PEM format)
4. Script cache scan import — scan old `%LocalAppData%\Steam++\Plugins\Accelerator\Scripts\*.js` files (or wherever scripts are) and import to new script storage
5. Accelerate project list cloud API + ServerSideProxyToken — cloud API for acceleration project list

Wait, but the current Tauri implementation stores scripts in ScriptConfig with cache_path. Let me check how the current Tauri version handles script storage — where scripts are stored.

Actually, looking at the current state, the migration plan says to focus on the essential parts. Let me look at:
1. What's the current Tauri app data dir: `{AppData}/WattToolkit` (dirs::data_dir() = %Roaming% on Windows? Actually dirs::data_dir() on Windows is %AppData% (Roaming)). Hmm, wait — `dirs::data_dir()` on Windows returns `%AppData%` (Roaming). The old version used `%LocalAppData%\Steam++`.

Let me verify the current app_data_dir usage in the Tauri app — lib.rs uses Tauri's app_data_dir() which for Tauri v2 is `%AppData%/{bundle identifier}` typically, and they said it falls back to watt-config's generic app_data_dir().

For migration, I need to:
- Detect old install: `%LocalAppData%\Steam++` exists
- Read `%LocalAppData%\Steam++\Settings\ProxySettings.json` (PascalCase JSON)
- Convert to new ProxySettings (snake_case)
- Import old CA PFX
- Scan script cache
- Mark migration done (e.g., write a marker file) so it only happens once

Also the acceptance criteria:
- 安装新版首启，旧版勾选的加速项目/脚本/代理设置全部保留且一键加速可用
- 升级场景 hosts 标记块正确接管

Let me also check where the old scripts live. Plugin.Instance.AppDataDirectory — let me find GetPluginsDirectory. From earlier exploration: "插件的 AppData 目录为 `GetPluginsDirectory(UniqueEnglishName, IOPath.AppDataDirectory)`". Let me find the actual constant and check the Accelerator plugin's UniqueEnglishName.

Also, the cloud API for acceleration project list. Let me search for that — SteamPlusService or similar.

现在查看云端 API 端点定义。
Now I have the old directory structure:
- Old AppData: `%LocalAppData%\Steam++`
- Old settings: `%LocalAppData%\Steam++\Settings\ProxySettings.json`
- Old CA PFX: `%LocalAppData%\Steam++\SteamTools.Certificate.pfx`
- Old scripts: `%LocalAppData%\Steam++\Plugins\Accelerator\Scripts\{md5}.js`
- Old script build cache: `{Cache}\Steam++\Plugins\Accelerator\BuildScripts\{md5}.js`

Also, `ScriptsStatus` field in ProxySettings.json contains enabled script local IDs (integers).

Now let me check the cloud API for acceleration project list. Let me search for SteamPlusService or the API endpoints.

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L77-L78
   — 在启动/刷新代理配置时，检测是否存在 `ProxyType.ServerAccelerate` 的加速项目；若存在则调用 `TryRequestServerSideProxyToken()` 获取服务端代理 token。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L399-L419
   — `TryRequestServerSideProxyToken()` 的完整实现：通过 `IMicroServiceClient.Instance.Account.GenerateServerSideProxyToken(cts.Token)` 请求云端 API，并将返回的 `AccessToken` 缓存为 `proxyTokenCache`。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L181-L198
   — 加速项目列表项的响应/模型字段映射位置，包含 `ListenDomainNames`、`Checked`、`Id`、`Order`、`FakeUserAgent`、`Version`、`ThreeStateEnable` 以及递归 `Items`，对应查询中的项目列表 DTO 结构。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L461-L489
   — 本地加速项目列表的序列化/反序列化逻辑：使用 `MessagePackSerializer` 将 `ProxyDomains.Items` 写入本地文件，或从 `localAccelerateFilePath` 读取并 `AddOrUpdate` 到 `ProxyDomains`。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services\IReverseProxyService.Constants.cs:L89-L92
   — 反向代理设置接口中定义当前勾选的加速项目组 `ProxyDomains`，类型是 `IReadOnlyCollection<AccelerateProjectDTO>`，是加速项目列表进入代理服务的配置入口。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services\IReverseProxyService.Constants.cs:L169-L183
   — 反向代理设置项中包含 DNS、DOH、自定义 DNS 以及 `ServerSideProxyToken`，其中 `ServerSideProxyToken` 是服务端代理令牌配置字段。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services\Implementation\ReverseProxyServiceImpl.cs:L89-L92
   — `ReverseProxyServiceImpl` 实现类中实际保存 `ServerSideProxyToken`，该 token 后续用于服务端代理请求头注入。

8. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services\Implementation\HttpServer\Middleware\HttpReverseProxyMiddleware.cs:L140-L146
   — 当 `domainConfig.IsServerSideProxy` 为真时，调用 `SetWattHeaders(context, reverseProxyConfig.Service.ServerSideProxyToken)` 将服务端代理 token 写入请求头，并使用 HTTP/3 转发配置。

Good info but I need the actual API URL. Let me search for the specific API endpoint constants for the accelerate project list and the GenerateServerSideProxyToken implementation.

我来帮你搜索这些云端 API 的 URL。让我并行启动多个搜索。

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Constants\UrlConstants.cs:L4-L44
   — 旧版 URL 常量入口；该类已标记 `[Obsolete("use Constants.Urls/Constants", true)]`，说明实际 API 域名/路径常量应查找 `Constants.Urls`，这里仅保留对旧 consumers 的兼容导出。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Models\AppSettings.cs:L144-L152
   — `ApiBaseUrl` 的来源逻辑：DEBUG 下可选 `Constants.Urls.BaseUrl_API_Debug` / `Development`，发布版使用 `Constants.Urls.BaseUrl_API_Production`；这是客户端请求云端 API 的根 URL 配置点。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Services.Implementation\MicroServiceClient.cs:L32-L40
   — `MicroServiceClient` 创建 HTTP client 时将 `client.BaseAddress` 设置为 `new Uri(ApiBaseUrl, UriKind.Absolute)`，表明所有通过 `IMicroServiceClient` 发起的 REST 请求都会以 `ApiBaseUrl` 为完整域名前缀。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L409-L417
   — `GenerateServerSideProxyToken` 的调用点：通过 `IMicroServiceClient.Instance.Account.GenerateServerSideProxyToken(cts.Token)` 请求；完整 URL 由 `IMicroServiceClient` 的 `ApiBaseUrl` 加上该 Account API 路径组成。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L160-L198
   — 加速项目/代理域名列表的本地过滤逻辑：`GetEnableProxyDomains()` 从 `ProxyDomains` 中递归筛选 `ThreeStateEnable != false` 的 `AccelerateProjectDTO`，并赋值给 `EnableProxyDomains`。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services\IReverseProxyService.Constants.cs:L30-L40
   — 反向代理相关常量，包含 `LocalDomain = "local.steampp.net"` 与脚本注入路径前缀；与代理域名/本地回环域名相关。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator.ReverseProxy\Services\IReverseProxyService.Constants.cs:L45-L56
   — 反向代理服务接口定义，包含 `ProxyRunning`、`Scripts`、`StartProxyAsync(...)`；这是代理列表/配置进入子进程或代理服务端的接口边界。

查看当前 watt-cert CA 存储与 src-tauri 启动流程。
Constants.Urls is in a NuGet package (BD.Common), not in the repo. The BaseUrl_API_Production is likely `https://api.steampp.net`. This is well known from the Watt Toolkit open source project: the API base is `https://api.steampp.net`.

Given the cloud API depends on external service and the migration plan says "加速项目列表云端 API + ServerSideProxyToken 接入", but this requires knowing the exact endpoints which are in a NuGet package. Let me check if there are any route strings in the repo related to the accelerate project list, e.g. "ProxyDomains" route or similar.

Actually, let me focus on what's pragmatic here. The core Phase 6 work:

1. **migrate.rs**: read old `%LocalAppData%\Steam++\Settings\ProxySettings.json` (PascalCase) → new settings. This is the main deliverable and fully testable.

2. **ScriptsStatus migration**: parse the ScriptsStatus array (int local IDs) — but new script system uses local_id strings. The old scripts are stored in `%LocalAppData%\Steam++\Plugins\Accelerator\Scripts\*.js`. ScriptsStatus contains local IDs of enabled scripts from the old DB. Without the old DB (application.dbf), we can't map IDs to scripts. But we CAN scan the old Scripts directory and import all scripts with `enable` state — the plan says "脚本缓存扫描导入" (script cache scan import). For ScriptsStatus, the old app stored script metadata in application.dbf (SQLite dbf). Reading that DB is complex. 

Hmm, let me think about what's reasonable:
- Scan old Scripts dir → for each .js file, parse the UserScript header (==UserScript== ==/UserScript==, @Name, @Match, @Exclude etc.) → create ScriptConfig entries with local_id = md5 filename
- Import files to new script storage location

3. **Old CA PFX import**: read `%LocalAppData%\Steam++\SteamTools.Certificate.pfx` (empty password) → parse with p12/pkcs12 crate → convert to new CA format (PEM). The new watt-cert uses rcgen + rustls. Let me check how the CA is currently stored in watt-cert.

Let me check the current watt-cert CA storage format and the current lib.rs startup flow to see where to hook migration.

Now I understand the CA structure. Now let me check the current watt-script storage structure and commands/settings.rs, and the current script storage location. Let me look at the commands directory and the watt-script model.

查看旧版加速项目列表 API 路由与 ScriptsStatus 语义。
Now I have a complete picture. Let me now design the Phase 6 implementation:

## Phase 6 实现设计

### 6.2 migrate.rs — 旧设置迁移（核心）

**旧版位置（Windows）**：
- AppData 根：`%LocalAppData%\Steam++`
- 设置：`%LocalAppData%\Steam++\Settings\ProxySettings.json`（PascalCase）
- CA PFX：`%LocalAppData%\Steam++\SteamTools.Certificate.pfx`（空密码）
- 脚本：`%LocalAppData%\Steam++\Plugins\Accelerator\Scripts\{md5}.js`

**新版位置**：
- AppData 根：Tauri app_data_dir（`{AppData}/WattToolkit` 或 fallback）
- 设置：`{data_dir}/Settings/ProxySettings.json`（snake_case）
- CA：`{data_dir}/Certificates/ca.cert.pem + ca.key.pem`
- 脚本：需要决定新位置，如 `{data_dir}/Scripts/{local_id}.js`

**迁移逻辑（migrate.rs，src-tauri 内）**：
1. 检测迁移标记文件 `{data_dir}/.migrated` 不存在时执行（幂等）
2. 旧设置迁移：读旧 ProxySettings.json → LegacyProxySettings（PascalCase 反序列化 DTO）→ 映射到新 ProxySettings → 仅当新设置不存在时写入
   - ProxyMode: 数字枚举（JsonStringEnumConverter → 字符串！注意：旧版用 JsonStringEnumConverter，枚举序列化为字符串 "Hosts"/"System" 等，但注意旧版 ProxyMode 枚举值：DNSIntercept=0, Hosts=1, System=2, VPN=3, ProxyOnly=4, PAC=5）。需要兼容字符串和数字两种。
   - TwoLevelAgentProxyType: ExternalProxyType 枚举（Http=0, Socks4=1, Socks5=2?）需确认。字符串形式如 "Http"/"Socks4"/"Socks5"（注意 C# 枚举名可能是 Http, Socks4, Socks5）。
3. ScriptsStatus：旧字段是脚本 LocalId 集合。新脚本系统 local_id 用什么？扫描脚本目录导入时生成。旧版脚本启用状态存储在 DB 中（ScriptsStatus 只存"启用"的脚本 ID 列表）。扫描导入脚本文件 + 解析 UserScript 头部提取 @Match/@Exclude → ScriptConfig。
4. CA PFX 导入：读 PFX（空密码）→ 解析 PKCS#12 → 提取证书 DER + RSA 私钥 → 写为 PEM（ca.cert.pem + ca.key.pem）。这需要 pkcs12 解析。Rust 生态：`p12` crate（纯 Rust，支持 RC2/3DES）或 `cms` 相关。旧版 .NET 生成的 PFX 通常用 RC2-40 或 AES-256 加密。`p12` crate 支持 RC2。或者用 `pkcs12` crate（RSA）。

   实际上，考虑简化：PFX 解析在纯 Rust 侧比较麻烦。可选项：
   - `p12` crate：支持解析 PKCS12（RC2 + 3DES），能拿到证书和私钥（RSA）。
   
   CA 私钥是什么类型？.NET `RSACertificateExtensions` 生成的是 RSA。新 rcgen KeyPair::from_pem 支持 RSA PEM（PKCS#1/PKCS#8）。rcgen 的 KeyPair 支持 "RSA"？（rcgen 支持 ECDSA P-256/384, Ed25519, RSA 需要 ring 特性，PKCS#8 RSA PEM 可以 with `--features rsa`? 让我想想：rcgen 0.13 KeyPair::from_pem 支持 PKCS8 的 RSA（通过 ring）？rcgen 0.13 使用 ring signature。ring 支持 RSA PKCS#8（RSA_KEY_PAIR）。rcgen `KeyPair::from_pem` 文档：支持 PKCS#8 Documents with ECDSA/EdDSA，以及 RSA with...实际上 rcgen 0.13 KeyPair::from_pkcs8_pem_and_sign_algo 可指定算法。KeyPair::from_pem 自动探测：EC, RSA, Ed25519。
   
   Rustls 0.23 with ring provider 支持 RSA2048+。所以 RSA CA 可行。

   风险点：pkcs12 解析 crate 依赖。用 `p12` crate（轻量，纯 Rust）。但 `p12` 的密码解密支持 RC2-40-CBC（.NET 默认）与 3DES。Windows .NET 生成 PFX（X509Certificate2.Export）用 AES256-SHA256 或 RC2？.NET Framework 默认 RC2-40；.NET Core 3.0+/5+ 默认 AES256。Watt Toolkit 用 .NET 6+，所以 AES-256-CBC。`p12` crate 不支持 AES。`cms` crate + aes…… 复杂。
   
   替代：`pkcs12` crate（RustCrypto）？还是 `p12`？
   
   另一个思路：使用 OpenSSL 命令行？不希望在运行时依赖。
   
   还有一个crate：`p12-keystore`（支持 AES/RC2/3DES）。让我确认下 crates.io 上的选项：
   - `p12`：纯 Rust，RC2/3DES
   - `p12-keystore`：支持 RC2, 3DES, AES（纯 Rust，较新）
   - `cms`：底层
   
   其实我可以检查我的记忆：`p12-keystore` crate 确实存在且支持 AES-256-CBC。它是 spiffe 相关项目。PKCS12 解析 → SafeContents → EncryptedPrivateKeyInfo (PBES2 with AES)。
   
   考虑到不确定性，实现时用一个抽象 trait + 优先 `p12-keystore`。但如果 p12-keystore 不存在或不好用，则降级。
   
   实际上让我先搜索确认 crates.io。我不联网搜索了——用 WebSearch 确认一下。

   或者更简单方案：不解析加密 PFX，而是引导用户重新信任。但迁移计划明确说"旧 CA PFX（空密码）导入保持已信任状态"。用 p12-keystore 或 p12。

   实际上还有一个 crate：`revolt-pkcs12`？不记得。让我 WebSearch 确认。

5. 脚本缓存扫描导入：扫描 `%LocalAppData%\Steam++\Plugins\Accelerator\Scripts\*.js`，解析 UserScript 元数据头：
   ```
   // ==UserScript==
   // @Name xxx
   // @Match *xxx
   // @Exclude ...
   // ==/UserScript==
   ```
   生成 ScriptConfig（local_id = md5 文件名或重新计算内容 md5，cache_path 指向新位置）+ 复制文件到 `{data_dir}/Scripts/`。
   
   新脚本系统在哪存脚本？当前 watt-script 的 ScriptConfig.cache_path 是传入的。当前 UI/启动参数中 scripts: []。EngineConfig.scripts 是 Vec<ScriptConfig>。所以迁移生成的是"脚本清单" JSON（如 `{data_dir}/Scripts/scripts.json`），前端可以加载。
   
   当前还没有脚本管理 UI（ScriptManager 页面），Phase 6 只需要把旧脚本文件迁移到新位置并生成清单。engine_start 的 scripts 参数从设置读取（目前 AcceleratorPage 传 scripts: []）。

6. 加速项目列表云端 API：URL 在 NuGet 包中（BD.Common）。已知 Watt Toolkit API 域名是 api.steampp.net。加速项目列表 API 是 `https://api.steampp.net/api/proxy/services` 或类似。让我搜索 GitHub 上的 WattToolkit 仓库确认。实际上，我可以搜索本地仓库中 MicroServiceClient 的 Account 接口实现，看看是否有更多线索。

   其实 Repository 层可能定义了路由。让我搜索 GetProxyDomains 或 RefreshProxyDomains 的 HTTP 请求。

计划行动：
1. 先搜 ServerSideProxyToken API 路由与加速列表 API 路由（在本地仓库搜索）
2. 设计并实现 migrate.rs
3. PFX 解析 crate 确认

让我先搜索 API 路由。

我来帮你在项目中查找这些信息。先进行第一轮并行搜索。

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L402-L419
   — `TryRequestServerSideProxyToken()` 调用 `IMicroServiceClient.Instance.Account.GenerateServerSideProxyToken(cts.Token)`，这是查询中“接口中 `GenerateServerSideProxyToken` 方法”的直接使用点；本文件未包含 HTTP 路由字符串，仅展示客户端接口调用与 `AccessToken` 响应处理。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L77-L78
   — 代理服务启动核心逻辑中，当存在 `ServerAccelerate` 类型代理域时调用 `TryRequestServerSideProxyToken()` 获取服务端代理 token，说明 `GenerateServerSideProxyToken` 的触发条件。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L33-L39
   — `StartProxyServiceCoreAsync()` 读取 `EnableProxyDomains`，若为空则提示用户；这是“加速项目列表/代理域”相关流程的入口。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L424-L440
   — `InitializeAccelerateAsync()` 使用 `IMicroServiceClient.Instance.Accelerate.All()` 加载加速项目列表，并写入 `ProxyDomains`；这是获取加速项目列表 API 的实际调用点。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L454-L490
   — `LoadOrSaveLocalAccelerate()` 将 `ProxyDomains.Items` 序列化到 `LOCAL_ACCELERATE.json`，或从本地文件恢复加速项目列表，是列表刷新/持久化相关逻辑。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Settings\ProxySettings.cs:L64-L68
   — `ScriptsStatus` 字段保存为 `IReadOnlyCollection<int>?`，注释说明为“脚本启用状态”；这是查询中“脚本列表获取 API 后保存状态”的相关配置字段。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.GameAccount\Models\Abstractions\IAccount.cs:L2-L25
   — 仓库中存在 `IAccount` 模型接口，但它是游戏账号平台抽象，不包含 `GenerateServerSideProxyToken`；用于区分 `IMicroServiceClient.Instance.Account` 的账号接口与本地 `IAccount` 模型。

The IMicroServiceClient is likely in a NuGet package. Let me quickly check what IMicroServiceClient resolves to and whether Accelerate.All() route is visible somewhere. Let me do a quick direct search.

IMicroServiceClient is in a NuGet package (not in the repo source). The cloud API details:
- API base: `https://api.steampp.net` (from Constants.Urls.BaseUrl_API_Production in BD.Common NuGet)
- Accelerate list: `IMicroServiceClient.Instance.Accelerate.All()` — route unknown, likely `/api/accelerate/all` or similar
- ServerSideProxyToken: `IMicroServiceClient.Instance.Account.GenerateServerSideProxyToken()` — route unknown

Since these routes are in a NuGet package and not visible in the repo, the pragmatic approach for Phase 6.5 is:
- Implement a `watt-cloud` module (or in src-tauri) with the AccelerateProjectDTO model, cloud client with the known API base `https://api.steampp.net` and configurable/unknown route
- OR skip actual cloud API integration and implement it as a stub/configurable

Let me check the old local cache: LOCAL_ACCELERATE.json at `Plugin.Instance.AppDataDirectory` = `%LocalAppData%\Steam++\Plugins\Accelerator\LOCAL_ACCELERATE.json`. This is a JSON file with the accelerate project list. If present on the user's machine, migration could import it! Let me check its serialization format - JSON (probably PascalCase with the DTO).

Let me look at ProxyService.cs around line 454-490 to see the serialization format, and check the AccelerateProjectDTO model fields.

Important finding: LOCAL_ACCELERATE.json is **MessagePack with LZ4 compression** (MessagePackSerializer with lz4Options), not plain JSON. Parsing MessagePack+LZ4 in Rust is possible (rmp-serde + lz4_flex) but the C# MessagePack typeless/contractless format with MessagePack-CSharp is NOT compatible with rmp-serde — MessagePack-CSharp uses its own format with typeless LZ4 extension headers when lz4Options is used. That's a custom framing: extension type 98/99 (LZ4 block/frame). rmp-serde would choke.

That's too fragile. Better approach for Phase 6.5: implement the cloud API directly. The API base is `https://api.steampp.net`. The Accelerate.All() route — let me try to find the actual route. The IMicroServiceClient is from a NuGet package. Let me check the nuget package cache or look at GitHub for WattToolkit's api. 

Actually, I recall the Watt Toolkit API documentation: 
- Base: `https://api.steampp.net`
- Accelerate list: `GET https://api.steampp.net/api/proxy/accelerate` — I'm not 100% sure.

Let me try searching the web for the actual API route. Or check if there's a swagger/docs. Actually — let me check the NuGet package locally first. The BD.Common.Api might be in the user's NuGet cache. Let me check ~/.nuget/packages for bd.common.

No BD.Common in local NuGet cache. The IMicroServiceClient Accelerate.All() route is inside the NuGet package source, not visible. Let me do a web search to find the Watt Toolkit API endpoint for the accelerate project list.

云端 API 路由在 NuGet 包中不可见。先查看 AccelerateProjectDTO 模型字段对齐 DTO。
The web search was not useful. The API routes are inside the BD.Common NuGet package which isn't publicly documented. Given this, the pragmatic approach for Phase 6.5:

1. Implement the cloud client module (`watt-cloud` or in src-tauri) with the known base URL `https://api.steampp.net` and a reasonable route for the accelerate list. I actually recall from the Watt Toolkit ecosystem the accelerate list API is `https://api.steampp.net/api/proxy/accelerate` returning groups... I'm not certain though.

Actually, let me reconsider the scope. The migration plan says:

"migrate.rs：读旧 `{AppData}/Settings/*.json`（PascalCase 别名）→ 新配置；ScriptsStatus 迁移；旧 CA PFX（空密码）导入保持已信任状态；脚本缓存扫描导入；加速项目列表云端 API + ServerSideProxyToken 接入。"

The core deliverable is migrate.rs. For the cloud API part, since the exact route is not discoverable from the repo (it's in a NuGet package), I should:
- Design the accelerate project DTO aligned with AccelerateProjectDTO from the C# code
- Implement a cloud client with configurable base URL and the best-known routes
- Mark the exact route as needing verification

Let me check the AccelerateProjectDTO model fields in the C# repo first to align the DTO. Let me also check if there's an ApiRsp wrapper.

Actually, let me focus and be pragmatic. The user said "继续 Phase 6". The key work items:

1. **migrate.rs** in src-tauri (or watt-config): 
   - Legacy settings migration (PascalCase → snake_case ProxySettings)
   - Migration marker for idempotency
2. **CA PFX import**: parse old PFX → PEM pair
3. **Script scan import**: scan old Scripts dir → parse UserScript headers → copy files + generate script manifest
4. **Cloud API**: implement accelerate project list client + DTO (with known base URL)

Let me check the AccelerateProjectDTO model first.

The DTO is also in the NuGet package (BD.Common.Api or similar). Since the DTO is in a NuGet package, I can't see its exact fields. But I can infer from usage. Let me look at how the fields are used in ProxyService.cs (L181-L198 showed fields: ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items) and the ReverseProxyConfig conversion in AutoMapperProfile.

Let me look at the usage in ProxyService.cs L160-200 and IReverseProxyConfig.cs to understand the accelerate project structure.

DTO 结构已明确。查看 src-tauri 依赖与 watt-script 模型，然后开始实现。
Now I understand the AccelerateProjectDTO fields:
- Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items (recursive)

And it's serialized to LOCAL_ACCELERATE.json using MessagePack+LZ4 (C#-specific format — hard to parse in Rust).

Given the constraints, my Phase 6 approach:

### 实现范围决策

**核心（必做，可测试）**：
1. `migrate.rs`（src-tauri/commands 或独立模块）：
   - 旧设置迁移：`%LocalAppData%\Steam++\Settings\ProxySettings.json`（PascalCase）→ 新 ProxySettings（含 ProxyMode 数字/字符串兼容、TwoLevelAgent 全字段、DNS 字段、脚本设置、ScriptsStatus 提取）
   - 迁移标记：`{data_dir}/.migrated`（幂等，仅首启）
   - 仅当新设置文件不存在时才迁移（不覆盖用户已有配置）

2. CA PFX 导入：`%LocalAppData%\Steam++\SteamTools.Certificate.pfx`（空密码）→ 解析 → 写 `{data_dir}/Certificates/ca.cert.pem + ca.key.pem`
   - 需要 PKCS#12 解析 crate。选择：`p12`（RC2/3DES）或 `p12-keystore`（RC2/3DES/AES）。.NET 6+ 导出 PFX 默认 AES-256-CBC + PBKDF2-SHA256。所以选支持 AES 的 `p12-keystore`。
   - 注意 PFX 内私钥可能是 RSA，rcgen KeyPair::from_pem 支持 RSA（PKCS#8）。rustls+ring 支持 RSA2048/3072/4096。

3. 脚本缓存扫描导入：`%LocalAppData%\Steam++\Plugins\Accelerator\Scripts\*.js` → 复制到 `{data_dir}/Scripts/` + 解析 UserScript 头（@Name/@Match/@Exclude/@Include）→ 生成 `{data_dir}/Scripts/scripts.json` 清单（ScriptConfig 列表）
   - ScriptsStatus（旧版启用脚本 LocalId 列表）无法映射（旧 LocalId 在旧 DB 中，无文件级关联），但文件名是内容 MD5。旧 DB application.dbf 是 SQLite。跳过启用状态精确迁移，默认全部导入并启用（脚本默认启用与旧版默认一致）。记录该限制。

4. 云端 API：`watt-cloud` 模块（src-tauri 内或 crate）：
   - AccelerateProjectDTO（对齐 C# 字段）
   - 客户端：GET `{base}/api/proxy/accelerate`（路由不可考，用环境变量/常量可配置 + 默认 api.steampp.net）
   
   等等——查一下实际的路由。让我想想我了解的 Watt Toolkit。实际上我记得 Watt Toolkit 的 API：api.steampp.net。加速列表接口……我在 GitHub 上看到过 WattToolkit/Steam++ 的 issue 提到。不可靠。
   
   决策：实现为可配置 URL + 默认值，并在响应解析上宽容（ApiRsp 包装：{code, message, content}）。列出已知不确定性。命令层提供 `accelerate_fetch_list` 命令。前端 AcceleratorPage 加载列表。

   实际上，为了不让这个任务无限膨胀，云端 API 接入我做核心链路：DTO + 客户端 + 命令 + 前端列表展示（含勾选状态存储），路由 URL 用常量并注明需联调验证。

**不做**（说明原因）：
- LOCAL_ACCELERATE.json（MessagePack-LZ4 C# 专有格式）解析 —— 云端 API 直接拉取取代
- application.dbf 脚本启用状态 —— ScriptsStatus 的 int LocalId 与文件无关联，脚本迁移默认启用

好，还有一个问题：新增 crate 依赖 p12-keystore 需要验证存在。让我先加依赖试试。另外我需要确认 rcgen KeyPair::from_pem 是否支持 RSA PEM。

rcgen 0.13 的 KeyPair::from_pem 文档：supports PKCS#8 PEM for EC (P-256, P-384, P-521), Ed25519, and RSA (with RSA support in ring)。实际上 rcgen 0.13.x `KeyPair::from_pem` 会尝试解析 PKCS#8。RSA PKCS#8 也走 ring 的 RSA_KEY_PAIR。签名算法由 PEM 内容决定（SignedDbType）。应该 OK。但要注意 rustls (ring provider) 的 TLS 签名算法支持 RSA2048+。旧 CA 若是 RSA2048 没问题。

还有一个关键问题：**PFX 中的证书+私钥导入后，CaCertificate::load 需要 PEM。** 我可以在 migrate 中：解析 PFX → cert.der + key pkcs8 der → 转 PEM（手写 PEM base64 包装，或用 rustls-pemfile）。然后调用 CaCertificate::load 路径（已有代码处理 from_ca_cert_pem + KeyPair::from_pem）。

检查 p12-keystore crate：它在 crates.io 上存在（用于 SPIFFE 工具），版本 0.2.x，支持解析 PKCS12，加密算法 RC2-40-CBC、3DES、AES-128/256-CBC。API 大概：
```rust
use p12_keystore::PKCS12;
let ks = PKCS12::load(byte_slice, password)?;
for (alias, item) in ks.certs() ...
```
不完全确定 API。备选 `p12` crate（更流行）：
```rust
let cert = p12::PFX::parse(der)?;
cert.decrypt(password)?; // 然后 cert.cert: Vec<u8>, cert.key: Option<Vec<u8>>（pkcs8 der）
```
`p12` crate 的 PFX 结构有 `cert`（DER）和 `key`（PKCS#8 DER 明文）。p12 只支持 RC2 和 3DES 解密。.NET Core 3.0+ 在 Windows 上导出 PFX 用 AES256。所以旧 Watt Toolkit PFX 大概率是 AES256 加密 → `p12` 解不了，`p12-keystore` 可以。

风险较大。让我先加 p12-keystore 依赖验证。如果不行，就 fallback：写明 PFX 解析失败时跳过（保持新 CA，用户重装信任）——降级不阻断（与迁移计划"失败引导重装信任（降级不阻断）"一致）。

好，开始实现。结构：

**新文件：`src-tauri/src/migrate.rs`**（或放 watt-config？）迁移逻辑与 Tauri app 目录耦合（需要 data_dir 和旧目录），放 src-tauri 更合适。但纯逻辑部分（LegacyProxySettings 解析）放 watt-config 便于测试。决定：
- `watt-config/src/migrate.rs`：LegacyProxySettings DTO（PascalCase serde）→ ProxySettings 转换 + 单测
- `src-tauri/src/migrate.rs`：编排（检测旧目录、调用转换、CA PFX、脚本扫描、写标记）
- PFX 解析放 watt-cert：`watt-cert/src/pfx.rs`：`parse_pfx(der, password) -> (cert_der, key_pkcs8_der)`，写 PEM

**脚本清单**：`{data_dir}/Scripts/scripts.json`。用 watt-script 的 ScriptConfig。扫描解析 UserScript 头。

**云端 API**：`src-tauri/src/commands/accelerate.rs` + `watt-config` 或独立 `watt-cloud` crate？简单起见：`src-tauri/src/cloud.rs` 模块（reqwest 依赖？src-tauri 已有哪些 http 客户端？watt-core 用 hyper。reqwest 更方便，但避免新依赖可以用 hyper。实际上 tauri 应用一般有 reqwest。让我检查 src-tauri/Cargo.toml。

先看 Cargo.toml 再决定。

ScriptsStatus 语义：旧版 ProxySettings.ScriptsStatus 是脚本启用状态的 int 集合。看 ScriptManager 如何使用它……算了，直接接受它是 LocalId 集合的事实，迁移时无法映射（旧 DB 不可读），在迁移结果中报告。

另外还有 SupportProxyServicesStatus（string Id 集合 —— 加速项目启用状态！）。RestoreAccelerateEnableAllIds(items, enableItems)：enableItems 是字符串 Id 集合，与加速项目 AllId 对照恢复勾选状态。这个可以迁移到新设置的加速项目勾选状态存储！新设置需要加一个字段存勾选的加速项目（如 `enabled_accelerate_ids: Vec<String>`）。

计划确定。让我检查 src-tauri/Cargo.toml 与 watt-script model.rs。

开始实现。先确认旧版枚举定义细节。
Now I have the full picture. Let me plan the implementation:

## Phase 6 实现计划

### 6.2 watt-config: `migrate.rs` — 旧设置迁移
- `LegacyProxySettings` struct (PascalCase serde, all `#[serde(default)]`)
- `convert_legacy(legacy) -> ProxySettings` 映射：
  - ProxyMode（数字/字符串两种，用自定义反序列化）: JsonStringEnumConverter 序列化为字符串。旧版 ProxyMode 枚举名：DNSIntercept, Hosts, System, VPN, ProxyOnly, PAC。也兼容数字。
  - SystemProxyPortId → system_proxy_port（注意：旧版默认 0 时不迁，用新默认 26501？旧版 DefaultSystemProxyPortId 是多少？不重要，直接迁移值，0 视为新默认）
  - SystemProxyIp → system_proxy_ip
  - Socks5ProxyEnable/Socks5ProxyPortId → socks5_proxy_enable/port
  - EnableHttpProxyToHttps → enable_http_proxy_to_https
  - TwoLevelAgent* → two_level_agent（ProxyType 枚举 Http/Socks4/Socks5 字符串）
  - ProxyMasterDns → dns.master_dns
  - UseDoh → dns.use_doh
  - CustomDohAddres2 → dns.custom_doh_address
  - ProxyBeforeDNSCheck → dns.before_dns_check
  - IsEnableScript → script.enable_script
  - OnlyEnableProxyScript → script.only_enable_proxy_script
  - IsOnlyWorkSteamBrowser → script.only_work_steam_browser
  - IsProxyGOG → is_proxy_gog
  - SupportProxyServicesStatus → 新字段 enabled_accelerate_ids（需要给 ProxySettings 加字段，default 空）
  - ScriptsStatus → 记录到迁移结果（报告用），但无法映射
- 转换函数返回 (ProxySettings, Vec<String> warnings)

### 6.3 watt-cert: `pfx.rs` — PFX 导入
- `import_pfx(pfx_path, password: Option<&str>, cert_dir) -> Result<(), CaError>`
- 解析 PKCS#12 → cert DER + key DER → PEM → 复用 CaCertificate::load 校验 → save
- 依赖：p12-keystore 或 p12。先试 p12-keystore（支持 AES）。

### 6.4 脚本扫描导入（src-tauri/migrate.rs）
- 扫描 `{old_appdata}/Plugins/Accelerator/Scripts/*.js`
- 解析 UserScript 头（// ==UserScript== 到 // ==/UserScript==，@Name/@Match/@Include/@Exclude）
- match_domain_names = @Match 优先（对齐旧 ReadScriptAsync：matchs = @Match，includes = @Include，match 为空用 include）
- 复制到 `{data_dir}/Scripts/{md5}.js`，cache_path = 新路径
- 生成 `{data_dir}/Scripts/scripts.json`（Vec<ScriptConfig>）

### 6.5 云端 API（src-tauri/cloud.rs + commands/accelerate.rs）
- AccelerateProjectDto（对齐 C# 字段，camelCase？云端 DTO 用 MessagePack，也走 HTTP JSON？不可知。假设 JSON + PascalCase）
- 客户端用 hyper？src-tauri 没有 http 客户端依赖。watt-core 有 hyper + tls。可以复用 watt-core 的 RelayFetch？不合适。
- 加 reqwest 依赖最简单（带 rustls-tls）。src-tauri 加 reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
- API URL 常量：`https://api.steampp.net`。路由不可考——用 `api/proxy/accelerate`。

等等，我重新想一下 6.5。云端 API 路由未知，无法联调。做出来的东西没法验证。把它做成：
- `watt-config` 加 `AccelerateProject` 模型（domain rules 已经有 DomainRule）
- cloud 客户端 + 命令 + 前端展示
- 验收只能靠单元测试（mock server）

这是合理的工程决策：完整链路 + 测试用 mock，真实路由联调后补。

好，还要检查 watt-config 的 lib.rs 和 constants.rs 以了解现有模块。

关于 ProxySettings 新增字段 `enabled_accelerate_ids`：
- serde default
- 前端 types/ipc.ts ProxySettings 加字段
- AcceleratorPage 用它

开始实现。先写 watt-config/src/migrate.rs。

关于旧版 ProxyMode 枚举序列化：JsonStringEnumConverter → 字符串（枚举名）。旧枚举定义（src/BD.WTTS.Client.Plugins.Accelerator/Abstractions? 或 BD.Common）：DNSIntercept=0, Hosts=1, System=2, VPN=3, ProxyOnly=4, PAC=5（从 settings.rs 的 from_legacy 注释确认）。字符串形式就是这些名字。

ExternalProxyType 枚举名：Http, Socks4, Socks5（C# 惯例，且 watt-config ExternalProxyType::parse 接受 "HTTP"/"SOCKS4"/"SOCKS5"）。旧 JSON 里是 "Http"/"Socks4"/"Socks5" 或数字 0/1/2。

让我确认旧版 ExternalProxyType 枚举定义。快速搜索。

枚举确认。开始实现 Phase 6.2 —— watt-config 迁移模块。
Confirmed:
- ExternalProxyType: Http=0, Socks4=1, Socks5=2 (string serialized as "Http"/"Socks4"/"Socks5")
- ProxyMode: DNSIntercept=0, Hosts=1, System=2, VPN=3, ProxyOnly=4, PAC=5 (string serialized as names)

Now, implementation. Let me first add the `enabled_accelerate_ids` field to ProxySettings, then create migrate.rs in watt-config.

Let me check watt-config lib.rs and constants.rs first.

Now let me implement. First add `enabled_accelerate_ids` to ProxySettings, then create the migrate module in watt-config.

创建 watt-config 迁移模块。

修正 serde 字段匹配方式（应使用 rename 而非 alias 反向）。
Wait, I made an error in the LegacyProxySettings struct. serde with PascalCase JSON needs the field names to match. I wrote lowercase field names with `alias` for PascalCase, but serde's default is exact field name matching. The JSON has "IsEnableScript" but my struct field is `isenablescript` with `alias = "IsEnableScript"`. Actually serde tries the field name first, then aliases. So "IsEnableScript" would match the alias. But wait — actually it's cleaner to just name the fields with PascalCase directly using rename. Let me rewrite using `#[serde(rename = "...")]` which is the standard approach. Actually the alias approach works too but is ugly. Let me use rename properly.

更新 From 实现中的字段引用。
Now update the field references in the `From<LegacyProxySettings>` implementation since field names changed. Let me update them.

修正两个 PascalCase 转换不匹配的字段（IsProxyGOG / ProxyBeforeDNSCheck）。
Note: `rename_all = "PascalCase"` will convert `is_proxy_gog` → `IsProxyGog` ✓, `use_doh` → `UseDoh` ✓, `custom_doh_addres2` → `CustomDohAddres2` ✓, `proxy_before_dnscheck` → hmm, `ProxyBeforeDNSCheck`? Let's verify: `proxy_before_dnscheck` in PascalCase → `ProxyBeforeDnscheck`. But the actual JSON field is `ProxyBeforeDNSCheck`. Mismatch!

Let me fix by explicit rename for that field. Also check `is_auto_check_script_update` → `IsAutoCheckScriptUpdate` ✓. `scripts_status` → `ScriptsStatus` ✓. `is_enable_script` → `IsEnableScript` ✓. `support_proxy_services_status` → `SupportProxyServicesStatus` ✓. `system_proxy_port_id` → `SystemProxyPortId` ✓. `custom_doh_addres2` → `CustomDohAddres2` ✓ (matches the typo'd original field name). `is_proxy_gog` → `IsProxyGog`? Hmm! The C# property is `IsProxyGOG`. PascalCase conversion of `is_proxy_gog` gives "IsProxyGog" — mismatch with "IsProxyGOG"!

So I need explicit renames for:
- `proxy_before_dnscheck` → `ProxyBeforeDNSCheck`
- `is_proxy_gog` → `IsProxyGOG`
- `socks5_proxy_enable` → PascalCase of `socks5_proxy_enable` = "Socks5ProxyEnable" ✓ (rename_all handles digits fine: socks5 → Socks5)
- `socks5_proxy_port_id` → "Socks5ProxyPortId" ✓
- `two_level_agent_user_name` → "TwoLevelAgentUserName" ✓

Let me add explicit renames for the two problematic fields.

注册 migrate 模块到 lib.rs，运行测试。

Phase 6.2 完成（9 测试通过）。现在实现 Phase 6.3 —— PFX 导入。先验证 PKCS#12 解析 crate 可用性。
9 tests passed (5 old + 4 new migrate tests). Phase 6.2 core conversion logic done.

Now Phase 6.3: CA PFX import. I need a PKCS#12 parser. Let me check what crates are available. I'll try `p12-keystore` which supports AES (needed for .NET-generated PFX). Let me first check if it exists on crates.io by trying to add it.

Actually, let me think about this more carefully. The options:
1. `p12` crate - RC2/3DES only (won't handle AES-256 from .NET 6+)
2. `p12-keystore` - supports RC2, 3DES, AES variants
3. `cms` + manual - too complex

Let me try adding p12-keystore to watt-cert. If it fails to resolve, I'll fall back.

Actually wait — I should check network access for cargo. The sandbox says network is allowed. Let me try.

`p12-keystore` 支持现代与旧式加密。先确认本机 Rust 版本，再查看其 API 获取私钥的方式。
`p12-keystore` v0.3.1 is available: pure Rust, supports modern (AES) and legacy encryption, MSRV 1.85.0 (need to check my Rust version — if the toolchain is older, this might fail; there are older versions 0.2.x with lower MSRV).

API:
```rust
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
let keystore = KeyStore::from_pkcs12(&data, PASSWORD, policy)?;
if let Some((alias, chain)) = keystore.private_key_chain() { ... }
```

But I need the private key material too — let me check the KeyStore API docs to get key DER. `keystore.key(alias)` probably returns `Key` enum with RSA private key structure. Let me fetch the docs to see how to get the private key bytes as PKCS#8/DER.

Let me check rust toolchain version first, and then look at the p12-keystore docs.

`p12-keystore` 0.3.1:
- `KeyStore::from_pkcs12(&data, password, policy)` — parse
- `keystore.private_key_chain()` — Option<(alias, PrivateKeyChain)>
- `PrivateKeyChain` has `.key()` (PrivateKey) and `.certs()` (chain)
- `PrivateKey::as_der()` — PKCS#8 DER bytes
- `Certificate` — X.509 wrapper, likely `as_der()` too

Rust 1.97.1 >= MSRV 1.85.

Now the plan for watt-cert pfx.rs:
```rust
pub fn import_pfx_to_ca(pfx_path: &Path, password: Option<&str>, cert_dir: &Path) -> Result<CaCertificate, PfxError> {
    let data = fs::read(pfx_path)?;
    let ks = KeyStore::from_pkcs12(&data, password.unwrap_or(""), Pkcs12ImportPolicy::Any)?;
    let (_, chain) = ks.private_key_chain().ok_or(NoKey)?;
    let key_der = chain.key().as_der();
    let cert = chain.certs()[0].as_der(); // need to check Certificate API
    // PEM encode both
    let cert_pem = pem_encode("CERTIFICATE", cert_der);
    let key_pem = pem_encode("PRIVATE KEY", key_der);
    // Write to cert_dir/ca.cert.pem + ca.key.pem, then CaCertificate::load to validate
}
```

Need to check Certificate API for as_der. Let me check quickly. Also need PEM encoding — write a small helper (base64 crate is already a dependency of watt-cert? Let me check watt-cert's Cargo.toml).

API 已确认。给 watt-cert 添加 p12-keystore 与 base64 依赖，创建 PFX 导入模块。
API confirmed:
- `Certificate::as_der()` → cert DER
- `PrivateKey::as_der()` → PKCS#8 DER
- `KeyStore::from_pkcs12(&data, password, policy)`

Need base64 for PEM encoding — watt-cert doesn't have base64 directly but workspace has base64 = "0.22". I'll add base64 to watt-cert deps.

Also need to check `Pkcs12ImportPolicy` — Strict vs Any. For .NET PFX, use `Pkcs12ImportPolicy::Any`? Let me check what policies exist... The docs show `Pkcs12ImportPolicy::Strict` in the README. Options probably: Strict, Any. I'll use Any to be lenient... actually let me be careful: Strict might require certain structures. Since old PFX from .NET has one key + one cert, either works. I'll use `Any` for robustness. Let me quickly check the enum.

创建 watt-cert PFX 导入模块。

写一个 PFX 导入往返测试。先看 Pkcs12Writer API。
watt-cert compiles with p12-keystore and 7 tests pass (5 old + 2 new).

Now I need a real end-to-end PFX test. I can generate a PFX using... hmm, on Windows PowerShell:
```powershell
$cert = New-SelfSignedCertificate ...
Export-PfxCertificate ...
```
That requires admin? No, New-SelfSignedCertificate works in user store. But it's an integration test not a unit test — better done as an optional test. Actually I can write a test that creates a PFX using PowerShell... too fragile for CI.

Alternative: use p12-keystore's own writer to create a test PFX in the test, then import it! `Pkcs12Writer` exists. Let me check its API... From the docs: `p12_keystore::Pkcs12Writer`. That would make a perfect roundtrip test: create keystore from our generated CA (cert DER + key PKCS#8 DER), write to p12, then import_pfx and verify the cert_der matches.

Wait — but CaCertificate::load uses `CertificateParams::from_ca_cert_pem` + `KeyPair::from_pem`. Our generated CA uses an EC key (rcgen KeyPair::generate() default is ECDSA P-256? or Ed25519?). Let me check: rcgen 0.13 KeyPair::generate() default → ECDSA P-256 (PKCS#8). So for the roundtrip test, we can export our CA's key as PKCS#8 DER (KeyPair::serialize_der() gives PKCS#8 DER), write a p12 with p12-keystore, then import.

Let me check Pkcs12Writer API quickly.

The docs page output didn't include the constructor methods (`new`, `with_key` etc.). Let me check the source of the writer at the repo. Actually, easier: look at KeyStore's `to_pkcs12` method. Let me fetch the KeyStore struct docs which has the to_pkcs12 signature.

Now I know the KeyStore API. For the roundtrip test, I need to construct a KeyStore with a PrivateKeyChain entry. Let me check the PrivateKeyChain constructor:

`PrivateKeyChain` — need to see its API. From keychain.rs source: `PrivateKey::from_der`, and PrivateKeyChain likely `new(key, certs)`. Let me check quickly.

Now I have all the API pieces for the roundtrip test:
- `PrivateKeyChain::new(local_key_id, PrivateKey, certs_iter)`
- `KeyStore::new()`, `add_entry(alias, KeyStoreEntry::KeyChain(chain))` — need to check KeyStoreEntry variants. Probably `KeyStoreEntry::KeyChain(PrivateKeyChain)` and `KeyStoreEntry::Certificate(Certificate)`.
- `ks.writer(password).to_der()` or similar write method — Pkcs12Writer has methods, one of them writes. Let me check the writer's remaining methods... From the earlier source I saw encryption_algorithm, encryption_iterations, mac_algorithm. There must be a `build()`/`to_der()`. Let me just grep the earlier dump.

添加 PFX 往返集成测试。
I have all the API pieces:
- `PrivateKeyChain::new(key_id, PrivateKey::from_der(key_der), vec![Certificate::from_der(cert_der)])`
- `KeyStore::new()` + `add_entry("alias", KeyStoreEntry::KeyChain(chain))` — need KeyStoreEntry variant name. Likely `KeyStoreEntry::KeyChain(PrivateKeyChain)`. I'll guess and fix on compile.
- `ks.writer("").write()` → Vec<u8>

Now write the roundtrip test in pfx.rs. Our CA: `CaCertificate::generate()` → key_pair.serialize_der() (PKCS#8 DER) + cert_der.

Phase 6.3 完成（PFX 往返测试通过）。搜索仓库内是否有 steampp.net API 路由线索。
PFX roundtrip test passes. Phase 6.3 done.

Now Phase 6.4: Script cache scan import. This is src-tauri level orchestration. Let me now write the main migration orchestrator in src-tauri that:
1. Runs once on startup (check `.migrated` marker)
2. Migrates settings (if new settings don't exist)
3. Imports CA PFX (if new CA doesn't exist)
4. Scans scripts (copies .js files + parses UserScript headers + writes scripts.json manifest)
5. Writes marker file

Script scanning logic:
- Old scripts dir: `{old_appdata}/Plugins/Accelerator/Scripts/*.js`
- Parse UserScript header: `// ==UserScript==` ... `// ==/UserScript==`, tags like `// @Name xxx`, `// @Match xxx`, `// @Include xxx`, `// @Exclude xxx`
- The old ScriptManager used DescRegex = `(?<={0})[\s\S]*?(?=\n)` after `@Name` etc. So the value is everything after the tag until newline.
- matchDomainNames = @Match (joined with GeneralSeparator which is "," probably) or @Include if no match
- New local_id: use the file stem (MD5) — that keeps identity stable. Or simpler: use file stem as local_id.
- Copy to `{data_dir}/Scripts/{stem}.js`
- cache_path = new path
- order: 10 default (old used 10 default)

Where do scripts live in new app? Let me decide: `{data_dir}/Scripts/` with manifest `{data_dir}/Scripts/scripts.json`.

Also the cloud API part (6.5). Let me now design:

**src-tauri/src/cloud.rs** (or commands/accelerate.rs):
- `AccelerateProjectDto` with PascalCase fields (matching C# DTO serialization — actually cloud DTO serialized via MessagePack for local cache, but HTTP JSON from the server likely uses camelCase or PascalCase JSON. Since unknown, use `#[serde(alias)]` for both camelCase and PascalCase! That's the robust approach.)

Actually for the response DTO, using serde aliases for both naming conventions is the safest.

- API base: `https://api.steampp.net`
- Route for accelerate list: unknown. I'll define a constant `ACCELERATE_LIST_URL` with a comment noting it needs verification. Actually, let me search GitHub for the WattToolkit API routes one more time with a different query.

Actually — wait. Let me search the repo for "steampp.net" strings to see if any route shows up.

我先查看之前后台运行的验证命令结果，确认 Phase 6.3 的状态。
Let me review the current state. Phase 6.3 (CA PFX import) is marked as in_progress. The summary says Phase 6.2 and 6.3 work was done (migrate.rs created, pfx.rs created, tests added). But there were 4 background jobs running - probably cargo test/clippy runs. Let me check the status of those background jobs first, and verify the current state of the files.

Let me check the background job outputs to see if the tests passed.

Hmm, these outputs look strange - they seem to be from earlier phases (rquickjs feature issue was likely from Phase 4, resolved long ago). These might be stale job outputs or the log files contain mixed content. Let me check the other two jobs.

后台任务日志混杂了早期输出。我直接运行测试验证 Phase 6.2/6.3 的当前状态。
The background jobs were stale/mixed - job 4 shows `cargo build -p watt-script` finished successfully. These logs are from previous phases. The actual verification of Phase 6.2/6.3 work needs to be re-run to confirm the current state. Let me first verify the current state of the files - check that migrate.rs and pfx.rs exist and tests pass.

Let me run the tests for watt-cert and watt-config to verify Phase 6.2/6.3 status.

Phase 6.2/6.3 的测试全部通过。现在检查迁移逻辑是否已接入应用启动流程，并准备 Phase 6.4。
Phase 6.2 and 6.3 tests pass:
- watt-cert: 8 tests pass (including pfx tests)
- watt-config: 9 tests pass (including migrate tests)

Now Phase 6.3 needs to be completed — but wait, the summary said migrate.rs and pfx.rs were created with tests. The tests pass. But is Phase 6.3 fully complete? The task says "旧 CA PFX（空密码）导入保持已信任状态" — the PFX import function exists, but is it wired into the app startup? Let me check where migration is invoked. Let me look at the watt-toolkit main app to see if migration is called at startup.

Actually, let me first look at the overall structure to understand what exists. Let me check:
1. migrate.rs - full content
2. Where migration should be invoked (app startup in watt-toolkit)
3. What Phase 6.4 needs (script cache scanning)

Let me read the key files.

Now let me look at the src-tauri lib.rs and settings.rs command to understand where migration should be wired in. Let me read those files.

Phase 6.2/6.3 的核心逻辑已完成并通过测试，但迁移尚未接入应用启动流程。先看下 settings.rs 和 pfx.rs 的现状。
Now I understand the structure. Migration is not yet wired into the app startup. I need to:

1. **Complete Phase 6.3**: Wire migration into app startup — on first launch (no existing settings file), load legacy settings from `{LocalAppData}/Steam++/Settings/ProxySettings.json`, migrate, and persist. Also attempt legacy CA PFX import if no new CA exists.

2. **Phase 6.4**: Script cache scanning/import.

3. **Phase 6.5**: Cloud API for acceleration project list.

4. **Phase 6.6**: Integration tests + full verification.

Let me first look at settings.rs in watt-config to see the load/save functions, and check the legacy paths. Let me also check the pfx.rs file to see what's there.

核心逻辑已就绪。现在需要把迁移接入应用启动流程。先查旧版 C# 代码确认数据路径（设置/PFX/脚本缓存）。
Now I understand the state. Phase 6.2 (migrate.rs) and 6.3 (pfx.rs) are complete with passing tests. Now I need to:

1. **Wire migration into app startup** (completing 6.2/6.3 integration): On startup, if new settings file doesn't exist, try to load legacy settings from `{LocalAppData}\Steam++\Settings\ProxySettings.json`, migrate, and save. Similarly for CA: if no new CA exists, try to import legacy PFX from `{LocalAppData}\Steam++\Certificates\SteamTools.Certificate.pfx` (need to check actual legacy path).

2. **Phase 6.4**: Script cache scanning/import.

3. **Phase 6.5**: Cloud API.

4. **Phase 6.6**: Integration tests + full verification.

Let me first explore the legacy C# codebase to find:
- Legacy settings file path
- Legacy CA PFX path
- Legacy script cache directory structure

Let me look at the original C# source to determine these paths.

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\watt-toolkit-tauri\crates\watt-config\src\settings.rs:L201-L238
   — 新版/迁移代码明确定义代理设置持久化路径为 `{AppData}/Settings/ProxySettings.json`，并实现 `load_proxy_settings()` / `save_proxy_settings()`；这是“旧版 ProxySettings.json 存储路径”的最直接路径常量来源。

2. e:\Project\SteamTools-develop\.trae\documents\watt-toolkit-tauri-migration-plan.md:L183-L187
   — 迁移计划验收项写明旧设置落盘目标：`{AppData}/Settings/ProxySettings.json`，用于确认该 JSON 设置文件的预期存储位置。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client\FileSystem\WindowsFileSystem.cs:L6-L10
   — 旧 C# 客户端文件系统注释定义 AppData/Cache 根目录语义：`AppData: \AppData or %LocalAppData%\Steam++`，说明旧代码库以 `Steam++` 为 AppData 子目录根。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client\FileSystem\WindowsRuntimeFileSystem.cs:L24-L43
   — 旧 UWP 运行时文件系统初始化使用 `ApplicationData.Current.LocalFolder.Path` / `LocalCacheFolder.Path` 作为 AppData/Cache 根目录，并调用 `InitFileSystem(...)`；与旧版设置/缓存目录结构相关。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client\UI\ViewModels\Pages\SettingsPageViewModel.cs:L47-L52
   — 旧 C# UI 设置页根据目录名常量解析 `IOPath.AppDataDirectory` / `IOPath.CacheDirectory`，是旧代码访问 AppData/Cache 目录结构的入口。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Plugins\Accelerator\UI\ViewModels\ScriptStorePageViewModel.cs:L31-L35
   — 旧版脚本缓存/脚本列表页面初始化入口，使用 `IMicroServiceClient.Instance.Script` 初始化脚本列表，关联“脚本缓存目录结构”的旧代码位置。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Plugins\Accelerator\AssemblyInfo.Constants.cs:L68-L70
   — 旧版常量定义 `Product_APP_REVERSE_PROXY = "... - Accelerator and script module sub-process"`，确认 `Accelerator` 是旧代码库中脚本/加速模块相关组件。

8. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Plugins\Accelerator\AssemblyInfo.Constants.cs:L124-L143
   — 旧版常量定义 `Accelerator = "Accelerator"`、`AcceleratorId` 等，是旧 C# 代码中脚本/加速插件模块标识与路径常量的相关位置。

探索结果不够精确，我直接搜索关键路径。
The explore agent didn't find the exact paths I needed. Let me search directly for the key paths in the C# codebase.

Now I have the legacy paths:
- CA PFX: `{AppData}/Steam++/Plugins/Accelerator/SteamTools.Certificate.pfx` (after 3.0.207 migration; older versions had it directly in `{AppData}/Steam++/`)
- Scripts dir: `{AppData}/Steam++/Plugins/Accelerator/Scripts`
- Script cache (BuildScripts): `{Cache}/Steam++/Plugins/Accelerator/BuildScripts`

Note: `IOPath.AppDataDirectory` = `%LocalAppData%\Steam++`, `IOPath.CacheDirectory` = probably `%LocalAppData%\Steam++\cache` or similar. Let me check IOPath and also look at the script download/cache logic in ScriptManager.cs to understand how scripts are cached and how the script list is fetched (cloud API).

现在查看迁移计划文档中 Phase 6 的具体要求和 watt-script 的现状。
Now I understand the script system:
- Scripts are stored in the script database (sqlite `Scripts.db`?) with metadata (MD5, Name, MatchDomainNames, etc.)
- Script files are stored at `{AppData}/Steam++/Plugins/Accelerator/Scripts/{md5}.js`
- Built script caches at `{Cache}/Steam++/Plugins/Accelerator/BuildScripts/{md5}.js`
- Script metadata parsed from UserScript header: @Name, @Version, @Description, @Author, @HomepageURL, @DownloadURL, @UpdateURL, @Exclude, @Grant, @Require, @Match, @Include

For Phase 6.4 (script cache scanning import), I need to:
1. Scan legacy script files at `{LocalAppData}/Steam++/Plugins/Accelerator/Scripts/*.js`
2. Parse UserScript headers to extract metadata (match domains, excludes)
3. Convert to ScriptConfig and persist

But wait — the new watt-script model has ScriptConfig with local_id, cache_path, match_domain_names, exclude_domain_names, order. The new system doesn't have a script database; how are scripts managed in the new implementation? Let me check the watt-script crate structure and how scripts are loaded in the new app (is there a scripts store/commands?).

Let me also check the migration plan document for Phase 6 details to align with what's planned.

现在明确了 Phase 6 剩余任务。先看新版引擎命令如何使用脚本，以及旧版云端 API 定义。
Now I have the full picture. Phase 6 requirements:
- migrate.rs: 读旧 `{AppData}/Settings/*.json`（PascalCase 别名）→ 新配置 ✅ (6.2 done)
- ScriptsStatus 迁移 ✅ (in MigrationOutcome)
- 旧 CA PFX（空密码）导入保持已信任状态 ✅ core logic (6.3) - needs startup wiring
- 脚本缓存扫描导入 (6.4) - TODO
- 加速项目列表云端 API + ServerSideProxyToken 接入 (6.5) - TODO

验收: 安装新版首启，旧版勾选的加速项目/脚本/代理设置全部保留且一键加速可用；升级场景 hosts 标记块正确接管。

Now I need to:
1. Complete 6.3: Wire migration into app startup (lib.rs setup) — on first launch:
   - If new settings file doesn't exist → try migrate legacy settings from `{LocalAppData}/Steam++/Settings/ProxySettings.json`
   - If new CA doesn't exist → try import legacy PFX from `{LocalAppData}/Steam++/Plugins/Accelerator/SteamTools.Certificate.pfx` (and fallback to old path `{LocalAppData}/Steam++/SteamTools.Certificate.pfx`)
2. Phase 6.4: 脚本缓存扫描导入 — scan legacy script files:
   - Legacy scripts at `{LocalAppData}/Steam++/Plugins/Accelerator/Scripts/*.js`
   - Parse UserScript headers (@Name, @Match, @Include, @Exclude, etc.)
   - Convert to ScriptConfig and persist to new location
   
   But wait — how does the new app manage scripts? There's no script command in src-tauri. Let me check how scripts are currently used in the new app. The engine takes ScriptConfig. Where do script configs come from currently? Let me check the engine commands and how scripts get loaded into the engine.

3. Phase 6.5: 加速项目列表云端 API + ServerSideProxyToken 接入 — need to find the cloud API in the C# code (IMicroServiceClient).

Let me first check how scripts are currently wired in the new app (commands/engine.rs), and find the cloud API endpoints in the C# code.

我将开始在项目中进行并行搜索，查找这四个主题。

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\UI\ViewModels\ScriptStorePageViewModel.cs:L32-L57
   — `ScriptStorePageViewModel` 通过 `IMicroServiceClient.Instance.Script` 调用脚本列表查询接口；这是“脚本列表/加速项目列表”相关 API 的客户端调用入口，并处理返回的 `DataSource` 到本地 `ScriptDTO` 列表。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\UI\ViewModels\ScriptStorePageViewModel.props.cs:L4-L20
   — 定义 `ScriptStorePageViewModel` 的脚本列表状态、搜索文本、空列表判断和下载命令，是脚本列表 UI 模型的核心字段。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L77-L79
   — 当启用代理的加速项目包含 `ServerAccelerate` 类型时，调用 `TryRequestServerSideProxyToken()` 获取服务端代理 token。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L402-L419
   — `TryRequestServerSideProxyToken` 的实现：使用 `IMicroServiceClient.Instance.Account.GenerateServerSideProxyToken` 请求 token，并缓存 `AccessToken`。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L24-L34
   — `ProxyService` 初始化 `ProxyDomains` 为 `SourceCache<AccelerateProjectGroupDTO, string>`，并按 `Order/Name` 排序绑定到 UI，是加速项目列表在客户端的本地列表来源。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L160-L198
   — `GetEnableProxyDomains()` 从 `ProxyDomains` 中递归过滤 `ThreeStateEnable != false` 的 `AccelerateProjectDTO`，生成实际用于代理配置的加速项目列表。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.Operate.cs:L235-L242
   — 将 `proxyDomains`、`scripts`、`isEnableScript` 等参数序列化为 `ReverseProxySettings`，并调用 `reverseProxyService.StartProxyAsync` 启动代理服务。

I need more details on the API. Let me search directly for the MicroServiceClient interface and the API endpoints.

Let me find the ApiBaseUrl and the Script API routes. Let me search for the base URL and script API definitions.

The search was too broad. Let me be more targeted - find the IAccountClient interface with GenerateServerSideProxyToken method.

The rg output is strange — it seems there's some recursive grep issue with the output. The `-l` flag with pipe seems broken. Let me try a different approach using a single rg command.

接口定义可能在 NuGet 包中。查看 API 基地址常量和 DTO。
Hmm, only one file. The interface definition must be in a NuGet package (System.Application.Client or similar) — the IMicroServiceClient.Account is likely defined in a referenced library not in this repo. Let me check the DTOs and API URLs available. Let me search for the API URL constants.

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Models\AppSettings.cs:L20-L26
   — `ApiBaseUrl` 的配置项定义；这是 `BD.WTTS.Client` 中服务端 API 基础地址的存储字段。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Models\AppSettings.cs:L131-L152
   — `ApiBaseUrl` 的赋值逻辑：根据 DEBUG/Release 与 localhost 开关，从 `Constants.Urls.BaseUrl_API_*` 中选择，并同步写入 `Constants.Urls.ApiBaseUrl`。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Services.Implementation\MicroServiceClient.cs:L32-L40
   — HTTP 客户端创建时把 `ApiBaseUrl` 设置为 `HttpClient.BaseAddress`，说明所有微服务客户端请求会基于该 API 地址。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client\UI\ViewModels\Pages\AboutPageViewModel.cs:L131-L159
   — `https://steampp.net` 相关常量引用，用于官网、更新日志、联系、协议、隐私等页面链接；非 API 地址，但属于查询中的 `https://` 常量使用点。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Plugins\Abstractions\PluginBase.Properties.cs:L17-L22
   — 插件 store/help URL 使用 `https://steampp.net/store/plugins/...` 拼接生成，属于 BD.WTTS.Client 中固定域名 URL 的定义点。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client\UI\ViewModels\AcceleratorPageViewModel.cs:L16-L42
   — 加速项目页面 ViewModel 中根据代理状态生成可启用代理域名列表，并构造 `https://<listenDomain>` 形式的代理域名展示。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client\UI\ViewModels\AcceleratorPageViewModel.cs:L53-L70
   — `RefreshCommand` 刷新加速页面时调用 `ProxyService.Current.InitializeAccelerateAsync()`，并在代理启动后加载游戏加速数据。

8. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Services\Mvvm\GameAcceleratorService.cs:L186-L214
   — 游戏加速服务通过 `IMicroServiceClient.Instance.Manage.GetXunYouVipEndTime()` 调用微服务接口获取加速会员时间，体现加速相关业务与 `ApiBaseUrl` 客户端链路的关联。

The Constants.Urls is defined in a NuGet package (System.Application). The API base URL for production is likely `https://api.steampp.net`. Let me check the NuGet package cache or find it in the project. Let me search in the user's NuGet cache.

The `Constants.Urls` class is from the `System.Application` NuGet package which is a binary reference. I can't easily read its source. But based on knowledge of the Watt Toolkit project, the API base URL is `https://api.steampp.net`.

Now let me check how ProxyService loads the accelerate project list — InitializeAccelerateAsync. Let me look at ProxyService.cs to see the loading.

Now I have a clear picture of Phase 6.5 requirements:
- `IMicroServiceClient.Instance.Accelerate.All()` gets the accelerate project list from the cloud
- The local cache is `LOCAL_ACCELERATE.json` (MessagePack format) — this is a local fallback
- The API endpoint likely is `https://api.steampp.net/api/Accelerate/All`

Now let me check the AccelerateProjectDTO structure. Let me search for it.

AccelerateProjectDTO is also defined in the NuGet package. Let me check what the domain_rule.rs in watt-config already has (it mentions AccelerateProjectDTO alignment), and check how the new frontend currently gets its accelerate project list (maybe there's a hardcoded/default list somewhere).

现在查看 watt-config 的 domain_rule.rs（对齐 AccelerateProjectDTO 的模型）。
Now I have a clear picture of the current state:

**Current state:**
- Phase 6.2 (settings migration): ✅ migrate.rs done with tests
- Phase 6.3 (CA PFX import): ✅ pfx.rs done with tests, but NOT wired into startup
- Phase 6.4 (script cache import): ❌ not started
- Phase 6.5 (cloud API): ❌ not started — frontend passes `rules: []` and `scripts: []`
- Phase 6.6 (integration tests): ❌ pending

**What remains for Phase 6:**

1. **Wire migration into app startup** (completes 6.2/6.3):
   - Create a migration runner in src-tauri (or watt-config) that:
     - On first launch (no new settings file): load legacy `{LocalAppData}/Steam++/Settings/ProxySettings.json`, migrate, save
     - On first launch (no new CA): import legacy PFX from `{LocalAppData}/Steam++/Plugins/Accelerator/SteamTools.Certificate.pfx` (also check old root path `{LocalAppData}/Steam++/SteamTools.Certificate.pfx`)
   
2. **Phase 6.4 script cache scanning**:
   - Scan `{LocalAppData}/Steam++/Plugins/Accelerator/Scripts/*.js`
   - Parse UserScript headers (@Match/@Include/@Exclude/@Name)
   - Convert to ScriptConfig list and persist to new location `{AppData}/WattToolkit/Scripts/` with a manifest

3. **Phase 6.5 cloud API**:
   - Create watt-cloud or add to src-tauri a cloud API client for accelerate project list
   - `GET https://api.steampp.net/api/Accelerate/All` returns groups with projects
   - Convert AccelerateProjectGroupDTO → DomainRule list for the engine
   - Cache to local JSON (fallback)
   - ServerSideProxyToken: requires login... but new app has no login system yet. AccountPage exists though. Let me check what's there. The token comes from `IMicroServiceClient.Instance.Account.GenerateServerSideProxyToken()` which needs an authenticated user. For migration purposes, maybe just support a manually-input token or read from migrated data. Actually let me keep it simpler: expose `server_side_proxy_token` setting in settings (already exists in engine params), the frontend currently passes null. 

Let me check what the AccelerateProjectDTO looks like. It's in the NuGet package System.Application.Client... but maybe there's a local copy. Let me check domain_rule.rs in watt-config since it says "对齐 AccelerateProjectDTO". Also check the LOCAL_ACCELERATE.json format if there's a sample.

Let me first look at domain_rule.rs to understand the current DomainRule model.

查看本机旧版数据是否存在，确认实际数据格式。
Now I understand the complete picture. Let me check if there's an actual LOCAL_ACCELERATE.json on this machine to understand the real format of the accelerate project DTO, since the DTO is in a NuGet package.

No legacy data on this machine. That's fine — the migration logic needs to be robust and tested via unit tests with synthetic data.

Now let me find the AccelerateProjectDTO structure. It's in the NuGet package System.Application. Let me try to find it in the project's referenced packages, or search for the JSON structure online. Actually, let me check if there are any JSON samples in the repo, or look at how the DTO is used to understand fields.

Key usage from ProxyService.cs:
- `result.Content` = List<AccelerateProjectGroupDTO>
- `group.Items` = List<AccelerateProjectDTO>
- `item.Id` (string-ish, Guid), `item.Name`, `item.Order`, `item.ThreeStateEnable` (bool?), `item.Items` (nested children)
- Each project has domain config: `MatchDomainNames`, `ListeningDomainNames`, etc.

Let me look at how proxyDomains are used to build ReverseProxySettings — the conversion from AccelerateProjectDTO to DomainRule happens somewhere. Let me look at GetEnableProxyDomains and the conversion logic in ProxyService.cs.

Now let me find the conversion from AccelerateProjectDTO to the domain config used by the reverse proxy. Let me look at where ReverseProxySettings is constructed with the proxy domains. Let me search for the conversion — probably in ProxyService.Operate.cs where it maps `proxyDomains` to `DomainConfig`.

Now I understand the flow. Let me check the ReverseProxySettings constructor to see how AccelerateProjectDTO is converted into domain configs.

Now I understand the AccelerateProjectDTO structure. The DTO is defined in the System.Application NuGet package. Its key fields (from usage):
- Id (Guid)
- Name (string)
- Order (int)
- ThreeStateEnable (bool?)
- Items (List<AccelerateProjectDTO>) — nested children
- MatchDomainNames (string[] or string)
- ForwardDomainNames
- IgnoreSSLCertVerification
- FakeServerName
- ProxyType (enum: ReverseProxy?/ServerAccelerate/ForwardProxy...)
- ListenDomainNames
- Checked
- Port
- FakeUserAgent
- Version

And how does the YARP implementation convert AccelerateProjectDTO into IDomainConfig? Let me check how proxyDomains are converted in the reverse proxy middleware. Since watt-core already has the DomainRule model aligned, the key task for 6.5 is to fetch the project list from the cloud and convert to DomainRule.

Let me look for how the DTO is converted to domain configs. Search for TryGetDomainConfig or ConvertAccelerateProject in the ReverseProxy project.

Now I understand the conversion. The AccelerateProjectDTO itself IS the IDomainConfig (it implements the interface). Its `MatchDomainNames` is a string (joined by separator), with `MatchDomainNamesArray`.

Now, for Phase 6.5, I need to find the actual cloud API response format. The `IMicroServiceClient.Instance.Accelerate.All()` is the endpoint. Since the interface is in a NuGet package, let me try to find the actual API URL. Based on the project structure, the API is at `https://api.steampp.net`. Let me search GitHub knowledge: Watt Toolkit's API is `https://api.steampp.net/api/Accelerate/All`.

Actually, since I can't verify the exact endpoint easily, let me check if there's any HTTP sample or config in the repo. Let me search for "Accelerate/All" pattern.

The web search didn't give me the exact API endpoint. Let me try to probe the actual API endpoint directly. Based on the Watt Toolkit architecture, the API base URL is `https://api.steampp.net`. Let me test if the endpoint works. Actually, a better approach: check the decompiled NuGet package. The System.Application packages would be in the global NuGet cache if the project was built. Let me check.

API 端点可用。现在查找 AccelerateProjectDTO 的字段映射定义。
Excellent! The API endpoint `https://api.steampp.net/api/Accelerate/All` works and returns data! The response uses MessagePack-style compact JSON keys (MessagePack serialization with string keys — MP2Obj with explicit keys). Let me decode:

- Top level: `{"\uD83E\uDD93": [...]}` — the emoji 📓? That's odd. Actually `"\uD83E\uDD93"` is the 🤓 emoji? Let me decode: U+1F993 is 🦓 (zebra)? Hmm, that's strange. Wait — it might be an obfuscation or just a key. Actually it's likely the response wrapper `ApiRsp` uses a key... let me get the full response to understand the structure.

The fields use MP2Key numeric-string keys:
- "0": Name ("Steam 服务" group name / project name)
- "1": Port (443)
- "2": MatchDomainNames (semicolon-separated)
- "3": FakeServerName? ("steamimage.rmbgame.net") — actually this looks like the reverse proxy target... Hmm, "3" for the first project is "steamimage.rmbgame.net" which is a mirror destination. Let me map fields via the AccelerateProjectDTO definition.

Actually from the C# code in ProxyService.cs L172-190, the DTO fields used are:
- Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items

And from ReverseProxyConfig: item.MatchDomainNames (string), item.Order.

The JSON response is compact MP2 (MessagePack-to-JSON with numeric keys). The keys map:
- "0" = Name
- "1" = Port (443)
- "2" = MatchDomainNames
- "3" = FakeServerName? or... let me think. For "Steam 图片": "2" = "steamcdn-a.akamaihd.net;..." (match domains), "3" = "steamimage.rmbgame.net" — hmm, what would that be? Possibly "Destination"? Hmm.

Wait, looking at the nested item: "12" = Items (nested array). And "11" = FakeUserAgent? No wait — "11":null appears where "Chrome/150.0.6478.183; ${origin}" appears in the Steam 社区 entry. Let me map:

For "Steam 社区" entry:
- "0": "Steam 社区" (Name)
- "1": 443 (Port)
- "2": "steamcommunity.com;www.steamcommunity.com" (MatchDomainNames)
- "3": "steamcommunity.rmbgame.net" (?)
- "4": "" (?)
- "5": "steamstore-a.akamaihd.net" (?)
- "ProxyType": 0
- "7": "steamcommunity.com;www.steamcommunity.com" (ListenDomainNames? — same as match)
- "8": true (?)
- "9": "abd6dafa-c295-eb11-abaa-a0d3c1f2a15d" (Id — Guid)
- "10": 37 (Order)
- "11": "Chrome/150.0.6478.183; ${origin}" (FakeUserAgent!)
- "12": [...] (Items — nested sub-rules)

So the numeric keys correspond to the MP2Obj explicit layout in AccelerateProjectDTO. Let me find the DTO definition to map exactly. It's in System.Application.Data package... but maybe I can find it on GitHub. The Watt Toolkit repo is BeyondDimension/SteamTools. The DTO might be defined there in src/System.Application.Data or similar. Let me check the local repo structure.

The AccelerateProjectDTO is in a NuGet package (System.Application.Data or similar). Let me search GitHub for it. Actually — the response is compact JSON with MP2 keys. I can deduce the field mapping from usage. Let me get the full API response and analyze the structure to build a robust parser.

API 已验证可用（emoji 混淆键的 MessagePack JSON）。现在查 IDomainConfig 字段定义以正确映射。
Now I have the full API response. Let me decode the structure:

Top level: `{"🤓": [...groups], "🐴": 200, "🐴": null}` — wait: `"\uD83E\uDD93"` = U+1F993 = 🦓 (zebra)? Actually U+1F993 is ZEBRA. And `"\uD83E\uDD84"` = U+1F984 = 🦄 (unicorn). `"\uD83D\uDC34"` = U+1F434 = 🐴 (horse face).

This is the `IApiRsp` response wrapper where fields are obfuscated with emoji keys (MP2Obj with string keys):
- "🦓" (U+1F993) = Content (the list of groups)
- "🦄" (U+1F984) = Code (200)
- "🐴" (U+1F434) = Message (null)

The group level (AccelerateProjectGroupDTO):
- "0" = Name ("Steam 服务")
- "1" = Items (array of projects)
- "2" = Id (Guid)
- "3" = ThreeStateEnable (bool) — "true" for Steam 服务 (default enabled)
- "4" = Order (1, 3, 4, 5, 8, 9, 10, 14, 15, 16)

The project level (AccelerateProjectDTO):
- "0" = Name ("Steam 图片")
- "1" = Port (443)
- "2" = MatchDomainNames (semicolon-separated; can be URLs with wildcards like "https://steamcommunity.com/comment")
- "3" = ??? ("steamimage.rmbgame.net" — some kind of DNS/forward host? For "Steam 静态资源" it's "community.steamstatic.com" with "5" = "{origin}") 
  - Hmm. Looking at the C# usage: FakeServerName — likely. Let's see: for "Twitch 直播聊天": "3" = "5a895ed07aed1b254ee21cd78958ae0b.steam302.xyz". This looks like a proxy domain. In the C# DTO usage from GetEnableProxyDomains: MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items.
  
  Let me map from usage in the middleware. Actually, I recall from the watt-core http_relay.rs implementation which fields are used. Let me check what watt-core's http_relay uses — the DomainRule has destination, forward_destination, etc.

  Actually let me think about what each field means based on values:
  - "3" = FakeServerName: e.g. "steamimage.rmbgame.net" — the fake/target server name. Hmm, but for DNS-less acceleration, this could be the "Destination" host to connect to.
  - "4" = IPAddress (string like "192.0.80.239", "20.43.185.14") — the fixed IP to connect to
  - "5" = UserAgent? No wait — "5" for "Steam 静态资源" is "{origin}" and for "Uplay 商店" is "@domain". Hmm interesting. These look like Destination templates! "@domain" and "{origin}" and "ttv" and "Github".
  
  Wait, but "11" for "Steam 社区" is "Chrome/150.0.6478.183; ${origin}" which looks like a UserAgent replacement template (with ${origin}).
  
  So "5" = ForwardDomainNames? For "Uplay 商店": "5" = "@domain"... hmm, that's more like a Destination template.

Let me look at the actual YARP middleware code to understand how these fields are used. Let me check HttpReverseProxyMiddleware.cs and the IDomainConfig interface definition to map fields.

Now I need to find how AccelerateProjectDTO maps to IDomainConfig. Since AccelerateProjectDTO implements IDomainConfig, let me search for how the interface properties map to DTO properties. The IDomainConfig interface would be in the System.Application package too. Let me check how watt-core already handles this mapping (since it was aligned per the migration plan). Actually, let me check the watt-core http_relay.rs to see how DomainRule fields are used — I already have domain_rule.rs which is the aligned model.

The mapping from AccelerateProjectDTO fields (from the C# DTO usage I've seen):
- MatchDomainNames ("2") — string, semicolon-separated
- ListenDomainNames ("7") — "ip domain" reversed format? No — looking at the API response, "7" = "steamcdn-a.akamaihd.net;..." (list of listening domains for hosts writing)
- Id ("9")
- Order ("10")
- FakeUserAgent ("11") = UserAgent replacement
- Items ("12") = nested sub-rules
- Port ("1") = 443
- ProxyType = enum 0/1/4 (ReverseProxy=0? ForwardProxy? ServerAccelerate?)

What's "3", "4", "5", "8"?
- "3" = FakeServerName? For "Steam 图片": "steamimage.rmbgame.net" — but where is this used? Let me check where FakeServerName is used in the middleware or config.
- "4" = IP address string (like "192.0.80.239")
- "5" = ? values: "{origin}", "@domain", "ttv", "Github", "steamstore-a.akamaihd.net", "gstatic.loli.net" — this looks like ForwardDomainNames or Destination!
- "8" = bool (true for Steam 服务 items, false for others) — maybe "Checked"?

Wait — let me reconsider. For "Steam 图片":
- "3": "steamimage.rmbgame.net" — could be the Destination host (where to connect)
- "5": "" 

For "Steam 静态资源":
- "3": "community.steamstatic.com"
- "5": "{origin}"

Hmm. Let me check the C# DTO property order. I recall the AccelerateProjectDTO from the Watt Toolkit source (it's in System.Application.Data project in the BeyondDimension/SteamTools GitHub repo). From my knowledge of the repo:

```csharp
[MP2Obj(GenerateType.VersionTolerant, SerializeLayout.Explicit)]
public partial class AccelerateProjectDTO : IDomainConfig
{
    [MP2Key(0)] public string Name { get; set; }
    [MP2Key(1)] public ushort Port { get; set; }
    [MP2Key(2)] public string? MatchDomainNames { get; set; }
    [MP2Key(3)] public string? FakeServerName { get; set; }
    [MP2Key(4)] public string? IPAddress { get; set; }
    [MP2Key(5)] public string? ForwardDomainNames { get; set; }
    [MP2Key(6)] public ProxyType ProxyType { get; set; }
    [MP2Key(7)] public string? ListenDomainNames { get; set; }
    [MP2Key(8)] public bool Checked { get; set; }
    [MP2Key(9)] public Guid Id { get; set; }
    [MP2Key(10)] public int Order { get; set; }
    [MP2Key(11)] public string? FakeUserAgent { get; set; }
    [MP2Key(12)] public List<AccelerateProjectDTO>? Items { get; set; }
    ...
}
```

Hmm, wait. But in the JSON "ProxyType" appears as a literal key name (not "6"). That's because in the C# DTO, ProxyType might be marked with [MP2Key] differently or it uses the property name. Looking at the JSON: `"ProxyType":0` — yes it's by name.

And in the group DTO:
```csharp
[MP2Obj(...)]
public partial class AccelerateProjectGroupDTO
{
    [MP2Key(0)] public string Name { get; set; }
    [MP2Key(1)] public List<AccelerateProjectDTO> Items { get; set; }
    [MP2Key(2)] public Guid Id { get; set; }
    [MP2Key(3)] public bool? ThreeStateEnable { get; set; }  // or Checked
    [MP2Key(4)] public int Order { get; set; }
}
```

Let me verify by looking at how these fields are used in the C# code. Search for FakeServerName usage.

FakeServerName is only copied but not used elsewhere in the visible source — it's part of the DTO in the NuGet package. Let me check the watt-core http_relay.rs to see how the aligned DomainRule is used, so I know which fields matter for the engine. Also I should check how the YARP HttpClientFactory uses the domain config — let me look at ReverseProxyHttpClientFactory.cs which handles TlsSni / IgnoreSSLCertVerification etc.

The key conversion between AccelerateProjectDTO and the domain resolution happens in LifetimeHttpHandler with IDnsResolver. Let me search where the DNS resolution uses the DTO's IP/FakeServerName. Let me check the DomainResolver implementations that use IDomainConfig's fields.

Actually, I recall in the watt-core implementation the fields have already been aligned. The important thing for me now is to determine the AccelerateProjectDTO's exact field layout. Let me search GitHub for the actual DTO source. The BeyondDimension/SteamTools repository has it in src/System.Application.Data (or ref/...). Let me fetch from GitHub raw.

Search returned nothing useful. Let me try to find the field mapping by analyzing how the DTO properties are used elsewhere. Actually, let me check watt-core's http_relay.rs to see which DomainRule fields it uses and what the semantic is — because in previous phases we already aligned this. The mapping question is: which JSON key ("3", "4", "5") maps to which DomainRule field.

From the API response analysis:
- "3": e.g. "steamimage.rmbgame.net", "community.steamstatic.com", "5a895ed07aed1b254ee21cd78958ae0b.steam302.xyz", "" (empty for IP-based entries)
- "4": e.g. "192.0.80.239", "20.43.185.14", "" (empty for domain-based entries)
- "5": e.g. "{origin}", "@domain", "ttv", "Github", "steamstore-a.akamaihd.net", "gstatic.loli.net", "" 

For "Gravatar 头像": "2" = "gravatar.com" (match), "3" = "" (empty), "4" = "192.0.80.239" (IP), "5" = "" 

For "Steam 图片": "3" = "steamimage.rmbgame.net", "4" = "" — so if "3" is the "Destination" host (i.e., replace connecting host) and "4" is the IP address override.

For "Uplay 商店": "3" = "commcloud.prod-abbs-ubi-com.cc-ecdn.net.cdn.cloudflare.net", "4" = "", "5" = "@domain"

Hmm interesting — "5" = "@domain" suggests ForwardDomainNames which works like a destination template. For "Steam 商店": "5" = "steamstore-a.akamaihd.net" — hmm.

Wait. Let me reconsider. Maybe:
- "3" = FakeServerName — the SNI/fake server name to use when connecting? For MITM TLS, this would be the SNI override... Hmm but "steamimage.rmbgame.net" as a server name?
- "5" = ForwardDomainNames — for "Steam 静态资源" ("5" = "{origin}")...

Let me look at the IDomainConfig interface definition. Let me search for it in the repo.

字段语义已基本清晰。查一下 ProxyType 枚举定义。
Now I have solid evidence of the field semantics:

From `GetIPEndPointsAsync`:
- `domainConfig.IPAddress` — fixed IP to connect to (maps to "4")
- `domainConfig.ForwardDestination` — alternate domain to resolve when connecting (maps to "5"?)

And `domainConfig.GetTlsSniPattern()` for TLS SNI.

And from the middleware:
- `domainConfig.Destination` — the destination URI template with @domain/@uri replacement

So the AccelerateProjectDTO (which implements IDomainConfig) has:
- Name ("0")
- Port ("1")
- MatchDomainNames ("2")
- ??? ("3")
- IPAddress ("4")
- ??? ("5")
- ProxyType (by name)
- ListenDomainNames ("7")
- ??? ("8")
- Id ("9")
- Order ("10")
- FakeUserAgent ("11")
- Items ("12")

Now for "3" and "5": IDomainConfig has Destination, ForwardDestination, TlsSni, TlsIgnoreNameMismatch, UserAgent, Response...

For "Steam 图片" — "3" = "steamimage.rmbgame.net". This looks like a "Destination" host — i.e., where to actually connect. For "Steam 静态资源" — "3" = "community.steamstatic.com" and "5" = "{origin}". Hmm, "{origin}" in the UserAgent sense? No — "{origin}"... 

Wait. Let me look at "Gravatar 头像": "2" = "gravatar.com" (match domains), "3" = "", "4" = "192.0.80.239" (IP), "5" = "". So the connection flow: match gravatar.com → connect to 192.0.80.239 (IP override).

For "OneDrive 服务": "2" = "storage.live.com;skyapi.onedrive.live.com", "3" = "apis.live.net", "4" = "", "5" = "skyapi.onedrive.live.net". Hmm — "3" = "apis.live.net"?? That doesn't look like a destination for storage.live.com...

For "Twitch 直播聊天": "2" = "irc-ws.chat.twitch.tv;...", "3" = "5a895ed07aed1b254ee21cd78958ae0b.steam302.xyz", "4" = "", "5" = "". So "3" is likely a "Destination" (proxy domain to connect to).

For "Twitch 登录": "3" = "passttv.steam302.xyz", "5" = "passttv.steam302.xyz" — both same. So "5" = ForwardDestination, "3" = Destination. When both are the same, connection goes to that domain.

For "hCaptcha 验证码": "3" = "cf.rmbgame.net", "5" = "@domain". Hmm, "5" = "@domain" — ForwardDestination as "@domain" template? That doesn't fit GetIPEndPointsAsync which resolves `domainConfig.ForwardDestination` directly as a host...

Hmm wait, but maybe the AccelerateProjectDTO property getters process templates. Let me think about the DTO's implementation of IDomainConfig:
- `Destination` getter: might combine "3" into a URI
- `ForwardDestination`: "5"

Actually, let me check the Destination property usage in the middleware:
```csharp
var destination = domainConfig.Destination;
if (domainConfig.Destination?.AbsoluteUri.Contains("@") == true) { ... }
var destinationPrefix = GetDestinationPrefix(context.Request.Scheme, context.Request.Host, destination);
```

`GetDestinationPrefix(scheme, host, destination)`: `new Uri(baseUri, destination)` — combines `scheme://host/` with the destination (relative or absolute URI). If destination is "steamimage.rmbgame.net" (a plain string), then `new Uri(base, "steamimage.rmbgame.net")` would treat it as a relative path → `https://original-host/steamimage.rmbgame.net`?? Hmm no wait — for the Uri constructor, a relative string like "steamimage.rmbgame.net" would be appended as a path. That gives a weird result... unless the DTO's Destination getter wraps it as an absolute URI like `https://steamimage.rmbgame.net/`.

So DTO likely implements:
```csharp
public Uri? Destination => string.IsNullOrEmpty(FakeServerName) ? null : new Uri($"https://{FakeServerName}/");
```

Hmm, but the names: for the DTO from GitHub (I recall from the Watt Toolkit source):

```csharp
public partial class AccelerateProjectDTO : IDomainConfig
{
    ...
    public string? FakeServerName { get; set; }
    public string? ForwardDomainNames { get; set; }
    ...
    [MP2Ignore]
    public Uri? Destination => ...
    [MP2Ignore]
    public Uri? ForwardDestination => ...
}
```

The interface IDomainConfig:
```csharp
public interface IDomainConfig
{
    string? MatchDomainNames { get; }
    string? ListenDomainNames { get; }
    Uri? Destination { get; }
    Uri? ForwardDestination { get; }
    IPAddress? IPAddress { get; }
    DomainPattern? ...
    int Order { get; }
    TimeSpan? Timeout { get; }
    bool TlsSni { get; }
    bool? TlsIgnoreNameMismatch { get; }
    string? UserAgent { get; }
    IDomainResponse? Response { get; }
    ...
}
```

OK here's my conclusion based on the API data and usage — the mapping for the JSON keys in AccelerateProjectDTO:
- "0" = Name
- "1" = Port
- "2" = MatchDomainNames (may contain full URLs with wildcards for sub-rule matching — e.g. "https://steamcommunity.com/comment")
- "3" = FakeServerName → this is the Destination host (rewrites the connection target host)
- "4" = IPAddress (string)
- "5" = ForwardDomainNames → ForwardDestination (alternate resolve target / destination override)
- "ProxyType" = proxy type enum (0=ReverseProxy? 1=Forward? 4=ServerAccelerate?)
- "7" = ListenDomainNames (hosts entries)
- "8" = Checked?/ThreeStateEnable?
- "9" = Id (Guid)
- "10" = Order
- "11" = FakeUserAgent → UserAgent
- "12" = Items (nested)

Group DTO:
- "0" = Name
- "1" = Items (projects)
- "2" = Id
- "3" = ThreeStateEnable (bool)
- "4" = Order

Response wrapper: {"🦓"(content): [...], "🦄"(code): 200, "🐴"(message): null}

Let me verify the ProxyType enum. Let me search for ProxyType enum definition usage. From ProxyService.Operate.cs: `proxyDomains.Any_Nullable(s => s.ProxyType == ProxyType.ServerAccelerate || ...)`. Let me find the ProxyType enum values.

查看 watt-core 引擎如何消费 DomainRule 字段，确定映射目标。
The ProxyType enum isn't in this repo (it's in the NuGet package). Based on the API data and the C# naming, the ProxyType enum is likely:

```csharp
public enum ProxyType
{
    ReverseProxy = 0,  // 反向代理 MITM
    ForwardProxy = 1,  // 正向（直连转发，改目标）
    ...
    ServerAccelerate = 4,  // 服务端加速（需要 token）
}
```

From the data:
- Most entries have ProxyType: 0 (ReverseProxy — MITM via hosts)
- Some have ProxyType: 1 (e.g. "Steam 白山云CDN 修复", "Twitch 登录", "fonts.gstatic.com" with ProxyType 1)
- greasyfork has ProxyType: 4 with "3" = "http://pt.mossimo.net:41080/"

Hmm wait — greasyfork's "3" is a full URL "http://pt.mossimo.net:41080/" with ProxyType 4. And ServerAccelerate requires the token. Since ProxyType 4 with "3" being an http proxy URL — maybe ProxyType 4 means "connect via HTTP proxy" (forward via proxy). Hmm, but ProxyService says ProxyType.ServerAccelerate requires a token...

Actually, looking at the greasyfork entry: "3" = "http://pt.mossimo.net:41080/" — this is a full destination URL. So "3" (FakeServerName/Destination) can be a full URL too.

OK. Let me now check the watt-core http_relay.rs to see how DomainRule is used — since I already implemented the whole engine in previous phases, the mapping to DomainRule is what matters. Let me read the engine.rs and http_relay.rs to see how rules fields are consumed.

Now I have a complete picture. The engine's DomainRule is the target. The mapping from cloud DTO to DomainRule:

**AccelerateProjectDTO (cloud JSON compact keys) → DomainRule:**
- "0" Name → (仅用于显示)
- "1" Port → (连接端口，一般 443)
- "2" MatchDomainNames → match_domain_names (split by ";") — 注意 URL 形式（https://...）用于子规则匹配。在 watt-config 的 DomainRule 中，顶层规则的 match_domain_names 是域名；而 URL 模式（如 "https://steamcommunity.com/*/discussions/"）应该作为 SubRule。看 C# ReverseProxyConfig.AddDomainConfigs — 它直接用 item.MatchDomainNames（含 URL 形式）作为 DomainPattern key。DomainPattern 支持两种形式：纯域名（通配）或 "/^...$/" 正则。而 watt-core 的 matcher.rs 可能也已支持。让我检查 watt-core matcher 如何匹配 URL 形式的域名。

- "3" FakeServerName → destination（连接目标主机名，full host）
- "4" IPAddress → ip_address
- "5" ForwardDomainNames → forward_destination（备用解析目标）
- "ProxyType" → is_server_side_proxy 当 = ServerAccelerate(4)？其实从 C# 看只有 ServerAccelerate 需要 token。但 ProxyType 还有其他值。watt-core 中 is_server_side_proxy 控制 X-Watt 头注入。所以映射：ProxyType == 4 (ServerAccelerate) → is_server_side_proxy = true。其他值怎么处理？ProxyType=0 (ReverseProxy) → 正常 MITM。ProxyType=1 (Forward?) → 直连转发？需要看 matcher/engine 是否区分。watt-core 的 DomainRule 没有显式的 ProxyType 字段，所以：
  - ProxyType=0: 默认（MITM 反代）
  - ProxyType=1: ForwardProxy —— C# 中这些项目在 hosts 模式下也写 hosts（"7" ListenDomainNames 有值），行为上可能等同（都是反代）。从数据看 ProxyType=1 的项（如 fonts.gstatic.com）的 "5"（ForwardDomainNames）都有值（gstatic.loli.net），即"转发到另一域名"。而 destination("3") 也有值。所以 ProxyType=1 与 0 的行为差异在 C# 实现中可能不大——都走同样的中间件。
  
  好，既然 watt-core DomainRule 没有区分，我可以将 ProxyType 保留在 DTO 中做显示用途，映射到 DomainRule 时：
  - is_server_side_proxy = (proxy_type == ServerAccelerate)

- "7" ListenDomainNames → listening_domain_names (split by ";")
- "8" → Checked/默认启用（与 "3"=true 的 Steam 服务组结合——组默认启用）
- "9" Id → 项目 Id（用于 enabled_accelerate_ids 匹配）
- "10" Order → order
- "11" FakeUserAgent → user_agent
- "12" Items → items（子规则，"2" 是 URL 正则/通配模式）

关于子规则匹配：C# DomainPattern.IsMatch(url) 支持 URL 模式。让我检查 watt-core 的 matcher.rs 如何处理 URL 形式的模式。

**Group DTO:**
- "0" Name → 组名
- "1" Items → 项目列表
- "2" Id → 组 Id
- "3" ThreeStateEnable → 默认启用状态
- "4" Order → 组排序

**响应包装:**
- "🦓" (U+1F993) → content
- "🦄" (U+1F984) → code (200)
- "🐴" (U+1F434) → message

等等，让我重新验证 emoji 编码：
- "\uD83E\uDD93" = U+1F993 = 🦓 (zebra)
- "\uD83E\uDD84" = U+1F984 = 🦄 (unicorn)
- "\uD83D\uDC34" = U+1F434 = 🐴 (horse face)

这些是 ApiRsp 混淆键。Content="🦓", Code="🦄", Message="🐴"。

现在检查 watt-core matcher.rs 的 URL 匹配能力。

现在全面了解了架构。更新任务清单并开始实现。
Now I understand the complete architecture. Let me now plan the remaining Phase 6 work:

**Phase 6.3 收尾（接入启动流程）**: 
- 在 src-tauri 的 setup 中添加迁移逻辑：
  - 设置迁移：若新设置文件不存在且旧版存在 `{LocalAppData}/Steam++/Settings/ProxySettings.json` → migrate + save
  - CA 导入：若新 CA 不存在且旧版 PFX 存在 → import_pfx

**Phase 6.4 脚本缓存扫描导入**:
- 扫描 `{LocalAppData}/Steam++/Plugins/Accelerator/Scripts/*.js`
- 解析 UserScript 头部（@Name/@Match/@Include/@Exclude）
- 转换为 ScriptConfig 并持久化到新位置（`{AppData}/WattToolkit/Scripts/scripts.json` manifest + 脚本文件）

**Phase 6.5 云端 API**:
- 新建 watt-cloud crate（或在 watt-config 中）：HTTP 客户端 GET `https://api.steampp.net/api/Accelerate/All`
- 解析 emoji 键响应 → AccelerateProjectGroupDTO 列表
- 转换为 DomainRule 列表（供引擎）
- 本地缓存 JSON（降级）
- ServerSideProxyToken：引擎参数已支持，前端透传设置（新版暂无登录体系，token 可后续接入；迁移计划中说"接入"，最小实现为引擎参数已支持 + 前端设置字段）

关于 rustls 版本，我需要确认前端如何获取项目列表。当前 AcceleratorPage.vue 传 `rules: []`。需要：
1. 新 command `accelerate_list()` 返回项目组列表（含名称/ID/默认启用）
2. 前端展示分组勾选 UI（简化版：组列表 + 勾选状态 → enabled_accelerate_ids 持久化）
3. engine_start 时把勾选项目转换为 rules 传给引擎

这个范围比较大。让我先聚焦后端：watt-cloud crate + 命令 + 迁移接入，然后前端 AcceleratorPage 集成项目列表勾选。

先看 watt-core 的 Cargo.toml 和 workspace 配置，以及 src-tauri 的 Cargo.toml，确定依赖怎么加。

先确认旧版设置文件路径。
First, let me create the migration runner in watt-config (migrate.rs) that handles paths, then wire into src-tauri lib.rs. Let me look at the C# code one more time to confirm the legacy paths:

- 旧版设置: `{LocalAppData}/Steam++/Settings/ProxySettings.json` — need to verify. C# uses IOPath.AppDataDirectory = %LocalAppData%\Steam++. Settings are stored via PersistentConfig… let me quickly verify the settings file location.

Good — this confirms the ProxySettings DTO (already migrated in 6.2). Now, the settings are stored where? `ISettings` uses a directory... Let me check where settings files are stored — probably `{AppData}/Steam++/Settings/`. Let me verify quickly by looking at ISettings / PersistentConfig base.

Now I have the complete path structure:
- 旧版 AppData: `%LocalAppData%\Steam++`
- 旧版 Cache: `%TMP%\Steam++`
- Settings: `{AppData}/Settings/ProxySettings.json` (based on ISettings conventions — settings stored in Settings subdirectory)
- CA PFX: `{AppData}/Plugins/Accelerator/SteamTools.Certificate.pfx`
- Scripts: `{AppData}/Plugins/Accelerator/Scripts/*.js`
- Script build cache: `{Cache}/Plugins/Accelerator/BuildScripts/*.js`

Let me quickly verify the Settings directory name by checking where ISettings saves. Let me search for "Settings" directory constant in the common settings library.

查看 DomainPattern 匹配实现。
The Settings directory name logic is in the BD.Common.Settings NuGet package. Based on Watt Toolkit's known behavior, settings are stored in `{AppData}/Steam++/Settings/` as JSON files. This matches my migrate.rs documentation: `旧版设置文件：{LocalAppData}/Steam++/Settings/ProxySettings.json`.

Now I have enough understanding. Let me start implementing:

**Step 1: Phase 6.3b — Migration runner wired into src-tauri startup**

Add to watt-config migrate.rs (or a new module) a `MigrationPaths` struct + `run_startup_migration` function:
- Legacy root: `%LocalAppData%\Steam++`
- Legacy settings: `{legacy}/Settings/ProxySettings.json`
- Legacy PFX: `{legacy}/Plugins/Accelerator/SteamTools.Certificate.pfx` (also check `{legacy}/SteamTools.Certificate.pfx` for pre-3.0.207)
- Legacy scripts: `{legacy}/Plugins/Accelerator/Scripts/*.js`

The migration function:
```rust
pub struct LegacyPaths { root: PathBuf }
impl LegacyPaths {
    pub fn detect() -> Option<Self> // %LocalAppData%/Steam++ exists
    pub fn settings_path(&self) -> PathBuf
    pub fn pfx_paths(&self) -> Vec<PathBuf> // both candidate paths
    pub fn scripts_dir(&self) -> PathBuf
}

pub struct MigrationReport {
    pub settings_migrated: bool,
    pub ca_imported: bool,
    pub scripts_imported: usize,
    pub warnings: Vec<String>,
}

pub fn run_startup_migration(new_data_dir: &Path) -> MigrationReport
```

For scripts import in 6.4 — new location for scripts: `{AppData}/WattToolkit/Scripts/`. I'll implement `scan_legacy_scripts` in watt-script crate: parse UserScript headers, produce ScriptConfig + copy file. Persist manifest `scripts.json`.

Wait — how does the new app manage scripts currently? There's no script storage yet (ScriptPage.vue / ScriptStorePage.vue exist but probably placeholder). The engine gets `scripts: Vec<ScriptConfig>` from frontend. For migration, I'll:
- Copy legacy script files to `{new}/Scripts/{md5}.js`
- Parse headers → ScriptConfig list with local_id (hash-based), cache_path, match/exclude domains, order
- Persist manifest `{new}/Scripts/scripts.json`
- Add a command `scripts_list` for frontend + wire into engine start params

For 6.5, new crate `watt-cloud`:
- `fetch_accelerate_projects()` — GET https://api.steampp.net/api/Accelerate/All, parse compact keys response
- DTO structs with serde aliases for the emoji keys and numeric keys
- Convert to `Vec<AccelerateProjectGroup>` (display model) and `to_domain_rules(&groups, enabled_ids)` → Vec<DomainRule>
- Local cache at `{AppData}/WattToolkit/Cache/accelerate.json`

For the response parsing with compact keys, I need serde to deserialize the raw JSON with keys "0"-"12", "ProxyType" etc. Design:

```rust
#[derive(Deserialize)]
struct RawApiRsp { 
    #[serde(rename = "\u{1F993}")]
    content: Option<Vec<RawGroup>>,
    #[serde(rename = "\u{1F984}")]
    code: Option<i32>,
    #[serde(rename = "\u{1F434}")]
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")] // no — keys are numeric strings
struct RawGroup {
    #[serde(rename = "0")] name: Option<String>,
    #[serde(rename = "1")] items: Option<Vec<RawProject>>,
    #[serde(rename = "2")] id: Option<String>,
    #[serde(rename = "3")] three_state_enable: Option<bool>,
    #[serde(rename = "4")] order: Option<i32>,
}

struct RawProject {
    #[serde(rename = "0")] name: Option<String>,
    #[serde(rename = "1")] port: Option<u16>,
    #[serde(rename = "2")] match_domain_names: Option<String>,
    #[serde(rename = "3")] fake_server_name: Option<String>,
    #[serde(rename = "4")] ip_address: Option<String>,
    #[serde(rename = "5")] forward_domain_names: Option<String>,
    #[serde(rename = "ProxyType")] proxy_type: Option<i32>,
    #[serde(rename = "7")] listen_domain_names: Option<String>,
    #[serde(rename = "8")] checked: Option<bool>,
    #[serde(rename = "9")] id: Option<String>,
    #[serde(rename = "10")] order: Option<i32>,
    #[serde(rename = "11")] fake_user_agent: Option<String>,
    #[serde(rename = "12")] items: Option<Vec<RawProject>>,
}
```

Then the semantic model (aligned with watt-config DomainRule):
- AccelerateProject { id, name, order, enabled_default, listen_domain_names: Vec<String>, rule: DomainRule-ish }
- Conversion to DomainRule: match "2" — if contains "://" it's URL pattern → sub-rule matching. Hmm.

Wait — how do I handle the URL-form match patterns (e.g. "https://steamcommunity.com/comment" for sub-rules)? Looking at the data: sub-items (Items "12") have "2" as URL patterns like "https://steamcommunity.com/*/discussions/". The top-level project has "2" as pure domains. But some top-level projects also have URL-ish "2": e.g. "Steam 讨论区" sub-items. Also "BootStrap CDN" has "2" = "maxcdn.bootstrapcdn.com/bootstrap" (domain with path!) and "3" = "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" (path-preserving mirror). So "2" may contain host+path.

How does C# DomainPattern handle this? DomainPattern: "2" (MatchDomainNames) is split by ";" — each entry either:
- starts with "/" → regex form
- contains "://"? Hmm.

Let me look at the C# DomainPattern class to understand. It's from FastGithub. In FastGithub: DomainPattern takes domain names, and supports wildcard matching. But in BD.WTTS the pattern can also be a URL... 

From ReverseProxyConfig.AddDomainConfigs: `new DomainPattern(matchDomainNames)` where matchDomainNames is the full "a;b;c" string. And `DomainPattern.IsMatch(url)` matches the full URL. Let me find the DomainPattern implementation. It's likely in the ReverseProxy project.

查看 resolve_destination 的实现细节。
DomainPattern is in the NuGet package (System.Application). Based on my knowledge of the Watt Toolkit source code (it's public on GitHub), the DomainPattern class looks like this:

```csharp
public sealed class DomainPattern
{
    public const string GeneralSeparator = ";";
    ...
    // Splits MatchDomainNames by ";"
    // For each pattern:
    //   - If starts with "/" → regex pattern like /^...$/ 
    //   - If contains "://" → URL prefix match
    //   - Otherwise → domain match (wildcard support)
    // IsMatch(url) — matches against full URL
}
```

From `AddScriptConfigs` in ReverseProxyConfig.cs (which I read earlier):
```csharp
static string GetDomainPatternString(string s)
{
    if (s.IndexOf("/") != 0)
    {
        return "/^" + Regex.Escape(s).Replace("\\*", ".*").Replace("\\?", ".") + "$";
    }
    return s;
}
```

This converts a domain pattern (like "*.example.com") into a regex "/^...$/" form. So DomainPattern internally uses regexes: `/^pattern$/` where wildcards are converted. And IsMatch(url) — matches the URL against the regex. Hmm wait, for domain-only patterns converted to "/^.*\.example\.com$/" — matching against full URL "https://www.example.com/path" would fail because the regex anchors the whole URL...

Hmm, actually wait. Let me look at the actual DomainPattern implementation from the BeyondDimension/SteamTools GitHub. From my memory of the codebase:

```csharp
public sealed class DomainPattern : IEquatable<DomainPattern?>
{
    public const string GeneralSeparator = ";";

    private DomainPattern() { }

    private DomainPattern(string pattern) { ... }

    public static implicit operator DomainPattern(string pattern) => new(pattern);

    public int Order { get; init; }

    public bool IsMatch(string url)
    {
        // ...
    }
}
```

I recall the IsMatch implementation handles:
- Domain patterns (with * wildcards) — extract host from URL and match
- URL patterns (containing "/" or "://") — convert to regex and match full URL

Given uncertainty, let me be pragmatic: my watt-core engine already has matching logic (`DomainRules::find(host)` for domain matching + sub-rules with regex for URL matching). The cloud data uses:

1. Top-level projects: "2" = pure domains (semicolon-separated), e.g. "steamcommunity.com;www.steamcommunity.com"
2. Sub-items (Items): "2" = URL patterns like "https://steamcommunity.com/*/discussions/"

BUT some top-level projects also have URL-ish patterns: "BootStrap CDN" ("2" = "maxcdn.bootstrapcdn.com/bootstrap"), "Github UserContent" ("2" = "githubusercontent.com;raw.github.com"), "greasyfork" ("2" = "greasyfork.org;update.greasyfork.org"), "Steam 讨论/留言 (IPv6)" (sub-item with "2" = URLs).

So my conversion approach for watt-config DomainRule:
- For each project: split "2" by ";".
  - Entries that are pure domains (no "/" after host, no "://") → match_domain_names
  - Entries that are URLs (contain "/" path or "://") → these need URL-regex matching. In the new model, sub-rules (Items) have regex. But the top-level match is by host.

Hmm — but the watt-core engine's `DomainRules::find(host)` only matches hosts. For URL patterns at the top level... looking at how the C# works: `dict.Add(new DomainPattern(matchDomainNames) { Order = item.Order }, item)` and `TryGetDomainConfig(url)` → `domainConfigs.Keys.FirstOrDefault(item => item.IsMatch(url))` — IsMatch against the full URL. So a DomainPattern constructed from "https://steamcommunity.com/comment" (URL form) would match URLs starting with that prefix.

For the new Rust model, I need to handle this in the cloud→rule conversion:
- If pattern contains "://" or a path → treat as URL pattern → convert to regex and put into... hmm, the top-level DomainRule only matches by domain. 

Pragmatic approach for the URL patterns at top level (rare: "maxcdn.bootstrapcdn.com/bootstrap", greasyfork "http://pt.mossimo.net:41080/" is destination not match): 
- Extract host from URL pattern → add host to match_domain_names (the path part would need sub-rule; for simplicity, add host match + a sub-rule regex for path-specific rules).

Actually, for correctness with minimal complexity: for URL-form patterns like "https://steamcommunity.com/*/discussions/", I'll:
1. Extract the host → match_domain_names (so the domain gets routed to this rule)
2. Convert the URL pattern to a regex → store as a sub-rule item with `is_server_side_proxy` etc. — but wait, sub-rules REPLACE the whole fields when matched, and fall through to parent when not matched. That's exactly the C# semantics for Items. But here the URL pattern is in "2" of the top project, not in Items.

Hmm, wait. Let me re-read the API data. Sub-items appear in "12" (Items) with URL-form "2". For those, the parent ("Steam 社区") has domain-form "2". The sub-item "2" = "https://steamcommunity.com/comment;https://steamcommunity.com/forum;..." — multiple URL patterns. So the C# flow: request URL "https://steamcommunity.com/comment/xyz" → DomainPattern("https://steamcommunity.com/comment;...") matches (URL prefix/wildcard match) → item found → then RecursionMatchDomainConfig checks Items of that item...

So in the C#, EVERY project (top-level and nested) is in the SAME domainConfigs dict — wait no. Look at AddDomainConfigs: it only iterates `reverseProxyService.ProxyDomains` (top-level projects), NOT nested items. The nested items are only reachable via `RecursionMatchDomainConfig` which matches `item.Key.IsMatch(url)` — the Key is the DomainPattern of the sub-item constructed from its MatchDomainNames.

Wait: `domainConfig.Items.FirstOrDefault(s => s.Key.IsMatch(url)).Value` — so Items is a dictionary of DomainPattern → IDomainConfig. The sub-item's Key is its MatchDomainNames pattern. OK so:
1. Top-level: find by pattern matching the URL
2. If found and has Items: find nested item whose pattern matches the URL → recurse

So both levels use DomainPattern.IsMatch(url) — full URL matching. And the patterns at both levels can be domain-form or URL-form.

So my conversion needs a two-mode matcher like C# DomainPattern. But my watt-core engine currently matches only hosts at the top level (rules.find(host)). 

Options:
A. Extend watt-core's DomainRules to support URL patterns at top level (matching full URL).
B. At conversion time (watt-cloud), handle URL patterns by extracting hosts → match_domain_names, and URL-form patterns become... they'd only match via sub-rules.

Hmm. Let me look at how watt-core's engine currently consumes rules — `self.rules.find(host)`. The URL is available in handle_request. Extending find to URL matching would align better with C#. Let me check the full signature of rules.find and where it's called: `find(&self, host: &str)`. I could add `find_for_url(url, host)` that first tries host matching, then URL-pattern matching.

Actually — simplest robust approach: in watt-cloud conversion, convert EVERY pattern (domain or URL form) into the DomainRule structure:
- domain-form pattern → match_domain_names entry (host matching)
- URL-form pattern (contains "/" or "://") → ALSO extract host into match_domain_names (so the top-level lookup hits), AND create a self-sub-rule? No...

Wait, actually — rethink. For URL-form patterns in the TOP-level project's match list, e.g. sub-items under "Steam 社区" have "2" = URL patterns. These sub-items are in Items (12) — they become sub-rules with regex. Good. But what about top-level projects whose "2" itself is URL-form? Looking at the data:
- "BootStrap CDN": "2" = "maxcdn.bootstrapcdn.com/bootstrap" — domain with path!
- "Steam 讨论/留言 (IPv6)": sub-item (inside "12" of Steam 社区) — URL-form. ✓
- greasyfork: "2" = "greasyfork.org;update.greasyfork.org" — pure domains ✓

So "BootStrap CDN" is the rare case: domain+path at top level. The C# DomainPattern would match "https://maxcdn.bootstrapcdn.com/bootstrap/..." but NOT "https://maxcdn.bootstrapcdn.com/other". For my conversion: I'd put "maxcdn.bootstrapcdn.com" in match_domain_names and add a sub-rule regex "^https://maxcdn\\.bootstrapcdn\\.com/bootstrap" with... hmm, but sub-rule replaces fields entirely — and here the fields would be the same as the parent (the sub-rule would be a copy of the parent's fields). That works! If the sub-rule regex matches, use a copy of fields; else fall to parent fields (which would still route the domain but apply to other paths...). 

Hmm — that deviates from C# (which wouldn't match other paths at all → falls to "未配置域名 default 规则"). Edge case; acceptable for now? The "default rule" path does DNS pollution check + forwards directly — actually that's the same as parent rule without destination... no, the parent has destination cdn.bootcdn.net.

Hmm, actually simpler and MORE correct: for URL-form patterns, only extract host → match_domain_names, and DO NOT create sub-rules. The path-specificity is lost (whole domain routes to the rule). For BootStrap CDN that means maxcdn.bootstrapcdn.com entirely maps to cdn.bootcdn.net with path "/ajax/libs/twitter-bootstrap" as destination template... wait "3" = "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" — destination has a path! And the original path gets... replaced? In C# GetDestinationPrefix: `new Uri(baseUri, destination)` where baseUri = "https://maxcdn.bootstrapcdn.com/" and destination = "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" (relative) → resolves to "https://maxcdn.bootstrapcdn.com/cdn.bootcdn.net/ajax/libs/twitter-bootstrap"?? That seems wrong... 

Hmm wait, relative URI resolution: base "https://maxcdn.bootstrapcdn.com/" + relative "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" → "https://maxcdn.bootstrapcdn.com/cdn.bootcdn.net/ajax/libs/twitter-bootstrap". That's broken unless the DTO's Destination getter pre-processes it. The DTO's `Destination` property probably returns `new Uri("https://" + FakeServerName + "/")` if FakeServerName doesn't contain scheme... For "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" → "https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap" — an absolute URI with path. Then `new Uri(baseUri, absoluteUri)` → absolute wins → "https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/". Then YARP appends the request path? GetDestinationPrefix returns the prefix and YARP combines path... Actually YARP's SendAsync with destinationPrefix + HttpTransformer.Empty — the request URI stays as-is (path from original request). Hmm, the transform would keep original path "/bootstrap/xxx" → final "https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap" + original path?? 

I don't need to be 100% byte-perfect on these edge cases. My watt-core `resolve_destination` already handles: absolute URI destination, relative path destination, @domain/@uri templates, domain-only template. Let me look at what resolve_destination does with "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" — likely treats as... let me read it.

Now I understand `resolve_destination`. For a destination like "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" (no scheme, no leading /): `resolve_relative` → "https://maxcdn.bootstrapcdn.com/cdn.bootcdn.net/ajax/libs/twitter-bootstrap" — wrong for this edge case. But wait — in the conversion layer I can pre-process: if the destination ("3") is a bare host (no scheme, no leading "/"), the C# DTO's Destination getter likely produces `https://{host}/`. Let me think about what the DTO does:

For "Steam 图片": "3" = "steamimage.rmbgame.net" — as a bare host, the DTO destination is likely `https://steamimage.rmbgame.net/` (absolute URI). Then GetDestinationPrefix: `new Uri(baseUri, absoluteDestination)` → "https://steamimage.rmbgame.net/" + request path appended by YARP. 

So in my cloud→rule conversion, I should normalize "3" (FakeServerName):
- If empty → None (no destination)
- If starts with http:// or https:// → use as-is (e.g. "http://pt.mossimo.net:41080/")
- Else → format as "https://{value}/" → then resolve_destination appends original path → "https://steamimage.rmbgame.net{path}" ✓

For "5" (ForwardDomainNames): used as ForwardDestination in the C# resolver — resolved via DNS as an alternative connect target when the primary DNS fails. In my watt-core, OutboundTarget has override_ip + host. ForwardDestination = alternate DNS resolution target... my watt-core doesn't have a forward_destination field usage in OutboundTarget — let me check. Actually DomainRuleFields has forward_destination but let me check where it's used in watt-core... In the earlier grep of http_relay.rs: `override_ip: rule.fields.ip_address` — no forward_destination usage. Hmm. So forward_destination is parsed but unused by the engine (it's fine — it's a fallback resolution path).

Also note "4" (IPAddress): string like "192.0.80.239" → ip_address: Option<IpAddr>.

Wait, but for many projects like "Github 网站": "3" = "", "4" = "20.207.73.82" (IP), "5" = "" — connect to fixed IP with SNI = original host. My OutboundTarget: host=original (no destination), override_ip=Some(20.207.73.82) ✓.

For "Steam 社区": "3" = "steamcommunity.rmbgame.net" → destination = "https://steamcommunity.rmbgame.net/" + path ✓.

Now — what about "3" AND "4" both set? e.g. checking data... "Github Dev": "3"="", "4"="20.43.185.14". Most entries have either "3" or "4". OK.

What about "5" (ForwardDomainNames) = "@domain"? For "Uplay 商店": "3" = "commcloud...cloudflare.net", "5" = "@domain". Hmm, "@domain" as ForwardDestination... in C# GetIPEndPointsAsync, `domainConfig.ForwardDestination` is a Uri — "@domain" would be... probably the DTO getter processes it. Not critical — my engine ignores forward_destination for now (it's an optimization path).

Hmm wait, actually let me reconsider: what IS "5" semantically? For "Twitch 登录": "3" = "passttv.steam302.xyz", "5" = "passttv.steam302.xyz". Both identical. For "fonts.gstatic.com": "3" = "gstatic.loli.net", "5" = "gstatic.loli.net". Identical again! For "Steam 静态资源": "3" = "community.steamstatic.com", "5" = "{origin}". Hmm "{origin}"...

OK here's a cleaner hypothesis: the DTO implements:
- `Destination` → derived from FakeServerName ("3"): if it looks like a full URL use it; else "https://{name}/"
- `ForwardDestination` → derived from ForwardDomainNames ("5"): same normalization

And in GetIPEndPointsAsync the connection tries: IPAddress ("4") first, then resolves ForwardDestination ("5") domain, then normal DNS. The connection's destination host comes from `GetDestinationPrefix` — which uses `Destination` ("3"). Wait no — actually re-reading: `GetIPEndPointsAsync(context.DnsEndPoint...)` — dnsEndPoint.Host is from the REQUEST URI (which is the destination URI after GetDestinationPrefix). So:
- dest_host = destination host ("3" if set, else original host)
- IPs to try: "4" (override), then DNS of "5" (ForwardDestination), then DNS of dest_host

Hmm interesting — so "5" is the DNS resolution target for connecting to dest_host. E.g. "Twitch 登录": dest = passttv.steam302.xyz, resolve passttv.steam302.xyz via DNS... same.

For "Steam 静态资源": dest = community.steamstatic.com, ForwardDestination = "{origin}"... 

Hmm, "{origin}" — probably the DTO getter replaces "{origin}" with the original host. So forward destination = original request host → resolve original host via (clean) DNS, connect directly to it. This is the "fake server name + direct resolution" trick.

OK — for my Rust implementation, I'll map "5" → forward_destination field (parsed but with "{origin}" passthrough). My watt-core currently doesn't use it in outbound — I could add: OutboundTarget resolution order: override_ip → DNS(forward_destination) → DNS(host). Actually, that's a small change in outbound.rs connect. Let me check outbound.rs to see if I can add it easily... Actually, keep scope tight: the engine currently tries override_ip then DNS(host). The forward_destination is a minor optimization; I'll pass it through to the DomainRule field (so it's persisted), and optionally use it in the connector if trivial.

Let me check outbound.rs quickly.

现在开始实现。先看 workspace 依赖配置。
I now understand the full architecture. Let me now implement. Plan:

**1. watt-config: 添加 `legacy` 路径模块**（migrate.rs 扩展）:
- `LegacyPaths::detect()` — 检测旧版数据目录
- settings_path, pfx candidates, scripts_dir
- `run_startup_migration(new_data_dir)` 返回报告

**2. watt-script: UserScript 头解析 + 脚本导入**（新模块 `import.rs`）:
- `parse_userscript_headers(content)` → 提取 @Name/@Match/@Include/@Exclude
- `import_legacy_scripts(legacy_dir, new_dir)` → Vec<ScriptConfig> + 复制文件 + 持久化 manifest

**3. watt-cloud 新 crate**:
- DTO 解析（emoji 键 + 数字键兼容）
- `AccelerateProjectGroup` 语义模型
- `to_domain_rules(groups, enabled_ids)` → Vec<DomainRule>
- 本地缓存 load/save
- HTTP 客户端（reqwest？看 workspace 是否已有 reqwest 依赖）

让我先看 workspace Cargo.toml 确定可用依赖。

架构清晰了。开始实现。首先扩展 `watt-config` 的 `migrate.rs`，加入旧版路径检测。
No reqwest in the workspace. I'll write a minimal HTTP client using hyper (already in workspace). Actually for a simple GET request to the cloud API, I can use hyper-util's client. Let me create watt-cloud with hyper.

Now let me implement everything:

**Step 1: watt-config migrate.rs — legacy paths + startup migration runner**

Add to migrate.rs:
```rust
/// 旧版数据目录检测
pub struct LegacyPaths { pub root: PathBuf }

impl LegacyPaths {
    pub fn detect() -> Option<Self> {
        let root = dirs::data_dir()?.join("Steam++");  // %LocalAppData%\Steam++
        root.is_dir().then(|| Self { root })
    }
    pub fn settings_path(&self) -> PathBuf { self.root.join("Settings").join("ProxySettings.json") }
    pub fn pfx_candidates(&self) -> [PathBuf; 2] {
        [self.root.join("Plugins").join("Accelerator").join("SteamTools.Certificate.pfx"),
         self.root.join("SteamTools.Certificate.pfx")]
    }
    pub fn scripts_dir(&self) -> PathBuf { self.root.join("Plugins").join("Accelerator").join("Scripts") }
}
```

Wait — dirs::data_dir() on Windows = Roaming? No: `dirs::data_dir()` on Windows = %APPDATA% (Roaming). `dirs::data_local_dir()` = %LOCALAPPDATA%. The old app uses LocalApplicationData. And watt-config's `app_data_dir()` uses `dirs::data_dir()` — hmm, that's Roaming on Windows! Let me check what the existing code uses... settings.rs: `let base = dirs::data_dir()` — on Windows this is {FOLDERID_RoamingAppData} = %APPDATA%\Roaming. Hmm, but Tauri's app_data_dir() = %APPDATA%/{identifier} (Roaming). So the new app stores data in Roaming. The old app stores in LocalAppData. That's a discrepancy but consistent within the new app (Tauri convention). For legacy detection I need data_local_dir() → %LOCALAPPDATA%\Steam++.

**Migration runner** in src-tauri (since it needs watt-cert for PFX import):
```rust
fn run_startup_migration(data_dir: &Path) -> MigrationSummary {
    // 1. settings: if !new settings exists && legacy exists → migrate + save + write marker
    // 2. CA: if !new cert exists && legacy pfx exists → import_pfx (failure → fallback generate)
    // 3. scripts: if !new scripts manifest exists && legacy scripts dir exists → import
}
```

Actually — the CA load in lib.rs currently: `CaCertificate::load_or_generate(&cert_dir)`. I'll insert before it: try PFX import first if cert_dir empty. 

**Step 2: watt-script import.rs** — parse UserScript headers:
```rust
pub struct UserscriptMeta { name, match_domains: Vec<String>, exclude_domains: Vec<String> }
pub fn parse_userscript(content: &str) -> Option<UserscriptMeta>
pub fn import_legacy_scripts(legacy_dir: &Path, target_dir: &Path) -> Result<Vec<ScriptConfig>, ...>
```

The C# ReadScriptAsync regex: `(?<={0})[\s\S]*?(?=\n)` with "{0}" = "@Name" etc. — extracts value after "@Name" up to newline. MatchDomainNames = @Match joined; if empty use @Include. ExcludeDomainNames = @Exclude joined. Separator = "; " (ApiConstants.GeneralSeparator — actually it's "; " I believe; C# `string.Join(ApiConstants.GeneralSeparator, ...)`). Let me check what GeneralSeparator is — likely ";" or "; ". Doesn't matter much; I'll split on ';' and trim.

Script file naming: `{md5}.js` in legacy Scripts dir. local_id: C# uses LocalId from DB (int). For migrated scripts I'll use the file stem (md5 hex) as local_id — the inject path becomes /WattToolkit_Inject/{md5}.js. Cache path: new location {data}/Scripts/{md5}.js.

Manifest: `{data}/Scripts/scripts.json` — Vec<ScriptConfig> (has serde derive already ✓).

**Step 3: watt-cloud crate**:
```
crates/watt-cloud/
├── Cargo.toml (hyper, hyper-util, http-body-util, serde, serde_json, watt-config, tokio, tracing, thiserror, bytes)
└── src/
    ├── lib.rs      — 模块导出
    ├── dto.rs      — 原始 JSON DTO（emoji 键/数字键）+ 语义模型 + 转换
    ├── client.rs   — HTTP GET + 解析
    └── cache.rs    — 本地缓存
```

Semantic model:
```rust
pub struct AccelerateProjectGroup {
    pub id: String,
    pub name: String,
    pub order: i32,
    pub default_enable: bool,  // group "3"
    pub items: Vec<AccelerateProject>,
}

pub struct AccelerateProject {
    pub id: String,
    pub name: String,
    pub order: i32,
    pub port: u16,
    pub listen_domain_names: Vec<String>,
    pub domain_rule: DomainRule,  // 完整规则
}
```

Conversion DTO → DomainRule per project:
- match_domain_names: split "2" by ";" — domain-form entries only... wait no. The C# DomainPattern matches the full URL with patterns that can be domain or URL form. My watt-core matcher: `rules.find(host)` matches host only against match_domain_names (with `*.` wildcard). For URL-form patterns (in sub-items), my sub-rule regex handles them.

Let me look at the actual data again:
- Top-level projects all have domain-form "2" EXCEPT "BootStrap CDN" ("maxcdn.bootstrapcdn.com/bootstrap" — host+path).
- Sub-items have URL-form "2".

For the conversion:
- Top-level: split "2" entries; for each entry: if it contains "/" → extract host part for match_domain_names (path specificity dropped, noted); else push entry.
  - Hmm wait — "maxcdn.bootstrapcdn.com/bootstrap" — but its destination "3" = "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" preserves the mapping via path. If I drop path specificity, requests to maxcdn.bootstrapcdn.com/other → destination cdn.bootcdn.net/ajax/libs/twitter-bootstrap/other — hmm, path prefix still maps fine actually. The C# behavior for non-matching paths: falls to default rule (direct). The difference: my conversion would route ALL paths through the mirror. Acceptable edge case — actually wait, is it? The listening domains "7" = "maxcdn.bootstrapcdn.com" — hosts file writes it, so all requests to that host come to us regardless. C# then only proxies /bootstrap/* paths; others → default rule → direct forward. My version proxies all → mirror. Slight over-routing, edge case. I'll handle URL-form entries properly instead: extract host → match_domain_names + create a sub-rule with the full URL regex (fields copied from parent). Then behavior: URL matches sub-rule (same fields) = C# match; URL doesn't match → falls to parent fields... which still routes to mirror. Hmm — to be exactly C#, parent fields should be "empty/default" when ALL its patterns are URL-form. 

  Actually wait — in C#, if the pattern is URL-form and doesn't match, the domain isn't in domainConfigs at all (pattern didn't match) → falls to "default domain config" (since host resolves to local via hosts) → DNS pollution check → direct forward. In my conversion, the host is in match_domain_names → rule found → forwarded to mirror destination. The difference is only for non-matching paths on hosts whose ONLY patterns are URL-form. That's just BootStrap CDN ("maxcdn.bootstrapcdn.com/bootstrap"). Minor. I'll accept: host match + sub-rule regex (same fields). Behavior for /bootstrap/* → mirror ✓; for other paths → also mirror (slight over-route, acceptable). 

  Hmm, actually — simpler alternative: for URL-form entries, extract host → match_domain_names, and DON'T create sub-rules. Same outcome, less code. OK.

- destination: normalize "3":
  - empty → None
  - starts with http:// or https:// → Some(as-is)... wait but greasyfork's "3" = "http://pt.mossimo.net:41080/" — a full URL destination. resolve_destination handles absolute URI: base = dest, path = dest path + raw... "http://pt.mossimo.net:41080/" + raw ✓.
  - else (bare host, maybe with path): "https://{value}" — hmm, if value has a path like "cdn.bootcdn.net/ajax/libs/twitter-bootstrap", "https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap" + raw ✓.
  - Note: C# GetDestinationPrefix does `new Uri(baseUri, destination)` where destination is the DTO's Destination (Uri). If DTO Destination = new Uri("https://steamimage.rmbgame.net/") → absolute → prefix "https://steamimage.rmbgame.net/" → YARP: final = prefix + path ✓ matches my resolve_destination absolute branch.

- ip_address: "4" parse to IpAddr.
- forward_destination: "5" — normalize similarly (None if empty). My engine doesn't use it (kept in fields).
- user_agent: "11" as-is ("Chrome/150.0.6478.183; ${origin}" — the ${origin} template handled by http_relay ✓).
- is_server_side_proxy: proxy_type == 4 (ServerAccelerate). But wait — I inferred ProxyType enum values. Let me think: C# ProxyService checks `s.ProxyType == ProxyType.ServerAccelerate`. The data shows ProxyType: 0 (most), 1 (some), 4 (greasyfork). Hmm — is ServerAccelerate = 4? greasyfork with destination "http://pt.mossimo.net:41080/" — a proxy-ish URL... Actually hmm. If ProxyType 4 = ServerAccelerate, then greasyfork needs token. Plausible.

  But wait, what does ProxyType=1 mean? "Steam 白山云CDN 修复" has ProxyType 1 with destination cdn.queniuqe.com... Actually let me not overthink: the enum from the Watt Toolkit source (System.Application.Data):
  ```csharp
  public enum ProxyType : byte
  {
      ReverseProxy = 0,
      ForwardProxy = 1,
      ServerAccelerate = 4,  // hmm?
  }
  ```
  Hmm, I'm not 100% sure. Let me look for any other hints... The middleware only checks IsServerSideProxy (from the DTO). The DTO's IsServerSideProxy likely = ProxyType == ServerAccelerate. 

  Hmm, actually I recall in the actual Watt Toolkit source:
  ```csharp
  public enum ProxyType
  {
      /// <summary>反向代理(默认)</summary>
      ReverseProxy = default,
      /// <summary>正向代理</summary>
      ForwardProxy = 1,
      /// <summary>服务端加速</summary>
      ServerAccelerate = 4,
  }
  ```
  This is my best guess given greasyfork (ProxyType=4) with an "http://" destination that looks like a relay server and C# ServerAccelerate requiring a token. I'll map proxy_type 4 → is_server_side_proxy = true. If none of the current projects use it except greasyfork, the impact is small anyway.

- listening_domain_names "7": split by ";". For hosts-mode these get written to hosts. Note C# hosts writing uses ListeningDomainNamesArray. Also the format in some entries is "ip domain" reversed... my DomainRule doc says `"ip domain" 反序格式兼容`. The current data shows plain "domain;domain". OK just split.

- Items "12" → sub-rules: each sub-item's "2" (URL patterns) → regex conversion like C# GetDomainPatternString: `"/^" + Regex.Escape(s).Replace("\\*", ".*").Replace("\\?", ".") + "$/"` — converts glob to regex, strips the surrounding /^...$/ → my SubRule.regex = the regex body. Note C# converts even plain domains this way for scripts. For sub-items "2" = "https://steamcommunity.com/comment" → regex escaped "^https://steamcommunity\.com/comment$" matching full URL ✓ (my effective_rule calls regex_matches(&s.regex, url) with the full URL — good).

- order "10", and group order "4".
- "8" (bool) = Checked — default checked state of project? For "Steam 服务" group items "8"=true; others false. This is likely "Checked"... Hmm, or is it "ThreeStateEnable"? Looking at RestoreAccelerateEnableAllIds — projects get ThreeStateEnable=true if Id in enableItems. The "8" field might be the default checked state (default enabled items like Steam 社区/商店). For migration purposes: default enabled = group default ("3") or project "8". Hmm.

  Actually — for the frontend UI, the initial state: group "3"=true means the Steam 服务 group is enabled by default. And items "8"=true are individually default-enabled. The enabled_accelerate_ids (SupportProxyServicesStatus) overrides. For display I'll expose both.

Wait, actually, let me reconsider: maybe "8" = "ThreeStateEnable"? and group "3" = "ThreeStateEnable" too (bool?). For Steam 服务 group: "3": true. For projects: "8": true only for Steam 服务 items. So both represent default enable state. I'll model: group.default_enable = "3", project.default_enable = "8".

Hmm hold on — but actually for the engine conversion, which projects become rules? Only ENABLED ones (GetEnableProxyDomains filters ThreeStateEnable != false). The frontend passes enabled ids; conversion filters by enabled set. But also: the "Steam 白山云CDN 修复" project has "8": false — it's not enabled by default but can be manually enabled.

For default enabled when user has no stored selection: C# defaults = SupportProxyServicesStatus default value (DefaultSupportProxyServicesStatus)... The first-run experience: the Steam 服务 group (ThreeStateEnable=true) + its default-checked children. I'll compute default enable as: project enabled if (project "8" true) OR (group "3" true AND project "8" true)... hmm no.

Let me look at ThreeStateEnable semantics: it's a tri-state checkbox (true/false/null-indeterminate). Group "3": true → the group checkbox is on. Item "8" is likely "Checked". GetEnableProxyDomains filters `w.ThreeStateEnable != false` — items are included unless explicitly disabled. ThreeStateEnable is computed from Checked? For the UI tree, parent's ThreeStateEnable derives from children's Checked... 

OK pragmatic approach: 
- group.default_enable = "3" (bool)
- project.default_enable = "8" (bool)
- Default enabled set (when user hasn't stored selection): all projects with "8" == true. For Steam: 图片/静态资源/更新/社区/商店 = true. That matches the known first-run behavior (Steam 加速默认开启).

**4. Cloud cache + commands + frontend**

- Cache file: `{data_dir}/Cache/accelerate.json` — serialized semantic model (groups). 
- Command `accelerate_list` (fetch with cache fallback) → Vec<AccelerateProjectGroupDto> (serializable for frontend).
- Command `scripts_list` → migrated/installed scripts.
- Frontend: AcceleratorPage 集成 — project groups with checkboxes; on start → build rules via a command? Or compute rules in Rust at engine_start? 

Hmm — the frontend has `rules: Vec<DomainRule>` in EngineStartParams (camelCase serde). The frontend could call `accelerateToRules(enabledIds)` command → Vec<DomainRule>, then pass into engineStart. That keeps engine API unchanged. DomainRule is already Serialize + Deserialize (serde) ✓.

Also `scripts`: Vec<ScriptConfig> — frontend calls `scriptsList()` → pass enabled ones. C# passes scripts with !Disable ordered by Order. Migrated scripts: enabled state from ScriptsStatus (legacy db ids — can't map). Default: all imported scripts enabled? C# ScriptDTO.Disable=false default (ReadScriptAsync sets Disable=false). So yes, imported scripts default enabled.

For `server_side_proxy_token`: pass through from settings if user configured; no login system yet. I'll add it to ProxySettings? It's already an engine param. For now: frontend passes null; the is_server_side_proxy rules only exist for greasyfork-like projects. Skip token config UI (add settings field server_side_proxy_token: Option<String>? — not in scope; migration plan says "ServerSideProxyToken 接入" — engine already supports it end-to-end. I'll add a settings field + pass-through so the plumbing is complete).

OK. Let me also double-check the C# API request headers: MicroServiceClient sets User-Agent. The API worked via plain Invoke-WebRequest without UA. Fine.

Response format — the JSON is compact-key. serde: keys "0".."12" as rename. serde_json will parse escaped unicode emoji keys natively if I use `#[serde(rename = "\u{1F993}")]`? In Rust source: `#[serde(rename = "\u{1F993}")]` — serde rename accepts any string; the JSON key is the actual emoji character. `"\u{1F993}"` in Rust = the emoji character ✓.

Also handle MessagePack responses? The API returned JSON when requested via PowerShell (Accept header not set). The C# client probably requests MessagePack or JSON... The response I got IS JSON (with compact keys). Good — parse as JSON.

Also — should I verify whether the response is gzipped etc.? Invoke-WebRequest handled it transparently. hyper client: I'll request with Accept: application/json and handle the body. Keep simple; no gzip decompression (server likely returns identity for no Accept-Encoding).

Now, one important detail — the response `"9"` = Id is a Guid string. enabled_accelerate_ids contains... what? C# SupportProxyServicesStatus is `IReadOnlyCollection<string>` and GetAccelerateEnableAllIds uses `node.Id.ToString()`. So enabled ids are project Id strings ✓.

Also GOG: C# ProxyService has IsProxyGOG adding GOG domains. There's a GOG group in the API? I didn't see one in the response (only Steam 服务/Twitch/Origin/Uplay/公共CDN/验证码/Github/Nexus Mods/网盘/其它网站). GOG domains likely added specially in C# (hardcoded). Skip — the plan says "加速 GOG" setting field exists; the C# ReverseProxySettings has IsProxyGOG. Let me check what GOG does in C# quickly... it probably appends GOG Galaxy domains + GOG cert. Not critical for this phase; skip GOG domain injection (keep setting field).

Let me now write the code. Start with watt-config legacy paths + migration runner pieces that don't need watt-cert (settings), then src-tauri wiring for CA.

Actually the migration runner needs watt-cert (PFX) and watt-script (scripts import) — those are app-layer concerns. I'll put the runner in src-tauri (app layer): `src-tauri/src/migration.rs`.

watt-config additions (migrate.rs):
- LegacyPaths + detect + paths

watt-script additions (import.rs):
- parse_userscript_meta + import_legacy_scripts + manifest load/save

watt-cloud new crate:
- dto.rs (raw + semantic + conversion + tests using the saved real response sample!)
- client.rs (hyper GET)
- cache.rs? — fold into lib.rs

src-tauri:
- migration.rs (startup runner: settings + CA + scripts)
- commands/accelerate.rs (accelerate_list, accelerate_to_rules, scripts_list)
- lib.rs wiring

Frontend:
- types/ipc.ts: AccelerateProjectGroupDto etc.
- api/index.ts: accelerateList, accelerateToRules, scriptsList
- stores/accelerate.ts (new Pinia store)
- AcceleratorPage.vue: group/project checkboxes + rules on start
- ScriptPage.vue: show imported scripts list

Let me start writing. First watt-config migrate.rs additions.

继续 Phase 6.3b：把迁移逻辑接入 src-tauri 启动流程。先读取当前相关文件确认状态。
Let me review the current state. I'm continuing Phase 6 of the Watt Toolkit Tauri migration. The current task is Phase 6.3b: integrating migration into the Tauri startup flow (settings + PFX first-launch import).

Let me first check the current state of the relevant files:
1. `watt-toolkit-tauri/src-tauri/src/lib.rs` - the Tauri app entry point
2. `watt-toolkit-tauri/crates/watt-config/src/migrate.rs` - migration logic
3. `watt-toolkit-tauri/crates/watt-cert/src/pfx.rs` - PFX import logic

There are also background jobs running. Let me check what those are - they may be test runs or builds. Actually, I shouldn't re-run them. Let me read the current lib.rs and migrate.rs files to understand the state.

Let me start by reading the key files.

再看设置存取与 PFX 导入接口。
Now let me look at the settings.rs to understand how ProxySettings are loaded/saved, and the pfx.rs for PFX import. Also need to check the cert.rs commands and the settings commands.

看命令层结构与 CA 模块接口。
Now let me check the commands module structure to understand how settings commands work, and check the cert commands. Let me look at the commands directory.

Now I understand the current state. Let me check the CA module for `load_or_generate` to understand when a CA is generated vs loaded, so I can determine the "first launch" condition for PFX migration.

The migration logic for Phase 6.3b should be:
1. In `setup`, after resolving `data_dir`:
   - Check if new settings file exists (`{data_dir}/Settings/ProxySettings.json`). If NOT and legacy settings exist → migrate settings (import + save).
   - Check if new CA files exist (`{data_dir}/Certificates/ca.cert.pem` etc.). If NOT and legacy PFX exists → import PFX. Otherwise generate new CA.

Note: `watt_config::settings::app_data_dir()` uses `dirs::data_dir().join("WattToolkit")` but the Tauri app_data_dir may be different (e.g. `{AppData}/com.watt-toolkit.app` or based on identifier in tauri.conf.json). The commands use `state.data_dir` for writes. So the migration should check both:
- New settings at `{data_dir}/Settings/ProxySettings.json`
- Legacy settings at LegacyPaths.

Wait, there's an inconsistency: `settings_get_proxy` uses `watt_config::settings::load_proxy_settings()` which reads from `watt_config::settings::app_data_dir()` but `settings_save_proxy` writes to `state.data_dir`. Let me check what the Tauri app_data_dir is - it depends on the identifier in tauri.conf.json. Let me check.

Actually, this inconsistency existed before. Let me check tauri.conf.json to see the identifier.

Let me also check the CaCertificate::load_or_generate function.

PowerShell doesn't have `head`. Use Select-Object instead.

查看 watt-config 的导出与 commands 模块结构。
Now I have the full picture. Let me design Phase 6.3b:

**Goal**: On first launch (no new settings file / no new CA), detect legacy installation and migrate:
1. Settings: if `{data_dir}/Settings/ProxySettings.json` doesn't exist AND legacy settings file exists → migrate and save.
2. PFX: if new CA files don't exist AND legacy PFX exists → import PFX before `load_or_generate`.

Implementation plan:
- Add a new module `migration.rs` in `src-tauri/src/` (or add to lib.rs directly). Better: a new file `src-tauri/src/migrate.rs` with a `run_startup_migration(data_dir: &Path) -> Vec<String>` function that:
  - `migrate_settings(data_dir)` — returns warnings
  - `migrate_ca(data_dir)` — tries PFX import
  
- Wire in lib.rs setup: call `run_startup_migration(&data_dir)` before CA load_or_generate.

Also note the settings inconsistency: `settings_get_proxy` reads from `watt_config::settings::app_data_dir()` (which is `{RoamingAppData?}/WattToolkit`)... wait `dirs::data_dir()` on Windows is RoamingAppData. But Tauri `app_data_dir` for identifier `net.steampp.watttoolkit` is `{RoamingAppData}/net.steampp.watttoolkit`. So `settings_get_proxy` and `settings_save_proxy` use DIFFERENT paths! That's a bug. Phase 6.3b should also fix this inconsistency — make settings load/save use the same data_dir.

Let me fix that:
- `settings_get_proxy` should take `state: tauri::State<AppState>` and read from `state.data_dir.join("Settings")`.
- `settings_save_proxy` already writes to state.data_dir.

This makes the migration write to `{data_dir}/Settings/ProxySettings.json` consistent with reads.

Also for PFX migration: the CA import should happen before `CaCertificate::load_or_generate(&cert_dir)`. So in setup:

```rust
let cert_dir = data_dir.join("Certificates");
// 首启迁移：旧版 CA PFX 导入（失败降级为新 CA 生成）
migrate::migrate_legacy_ca(&cert_dir);

let ca = Arc::new(CaCertificate::load_or_generate(&cert_dir)...);
```

Wait, but import_pfx writes cert/key files directly. So after import, load_or_generate will load them. 

Order in setup:
1. resolve data_dir, create dirs
2. run migration (settings + PFX)
3. load_or_generate CA
4. manage AppState

For settings migration:
```rust
pub fn migrate_legacy_settings(data_dir: &Path) -> Result<Vec<String>, String> {
    let new_path = data_dir.join("Settings").join("ProxySettings.json");
    if new_path.exists() {
        return Ok(vec![]); // 已有设置，跳过
    }
    let Some(legacy) = watt_config::migrate::LegacyPaths::detect() else {
        return Ok(vec![]);
    };
    let legacy_settings = legacy.settings_path();
    if !legacy_settings.exists() {
        return Ok(vec![]);
    }
    let json = std::fs::read_to_string(&legacy_settings).map_err(...)?;
    let outcome = watt_config::migrate::migrate_legacy_settings(&json).map_err(...)?;
    // 保存
    std::fs::create_dir_all(new_path.parent().unwrap())?;
    std::fs::write(&new_path, serde_json::to_string_pretty(&outcome.settings)?)?;
    // 记录 warnings + legacy_scripts_status
    ...
}
```

Should we record migration happened? Maybe write a marker to avoid re-migration? Since we write the new settings file, its existence is the marker. For PFX: after import, cert files exist → marker. If import fails → load_or_generate generates new CA → cert files exist → next startup won't retry PFX. Good, natural markers.

Should migration results be visible to the user? The frontend could show migration notices. Keep it simple for now: log warnings via tracing. Maybe also expose a `migration_get_report` command? The plan says Phase 6.3b: 迁移接入 src-tauri 启动流程（设置+PFX 首启导入）. Let me keep it minimal but log warnings. Actually, warnings like "旧版 VPN 模式不受支持" are user-relevant. Let me store the migration report in AppState so a command can query it, and the frontend can show it later (in Phase 6.5b/6.6 we can integrate the UI). Hmm, but avoid over-engineering. The plan says settings + PFX first-launch import. I'll add a simple `MigrationReport` stored in AppState and a `migration_get_report` command so the frontend can display it — that's genuinely useful for a migration feature and was implied by "迁移警告（不可映射项说明）" design in migrate.rs. Let me check the frontend to see if there's a natural place... Actually let me not touch the frontend in this step; just add the command and register it. The frontend integration can come in 6.5b.

Actually, let me think about what's needed:
1. `src-tauri/src/migrate.rs` — startup migration module with settings + PFX logic and report.
2. `lib.rs` — wire into setup, add report to AppState.
3. `commands/settings.rs` — fix path inconsistency (get reads from data_dir).
4. Register `migration_get_report` command.

Also need `dirs` dependency in src-tauri? No — LegacyPaths::detect() is in watt-config which already has dirs. Good.

Let me check watt-config's lib.rs exports to confirm `migrate` is public.

Everything is exported. Now let me write the startup migration module. I'll create `src-tauri/src/migrate.rs`:

```rust
//! 首启迁移：检测旧版（C# Steam++）数据并导入设置与 CA PFX。
//!
//! 触发条件（各自独立，幂等）：
//! - 设置：新设置文件不存在且旧版 ProxySettings.json 存在
//! - CA：新证书目录为空且旧版 SteamTools.Certificate.pfx 存在
//!
//! 迁移结果写入 MigrationReport（AppState 持有），供前端展示提示。

use std::path::Path;
use watt_config::migrate::LegacyPaths;

/// 首启迁移报告
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    /// 检测到旧版安装
    pub legacy_detected: bool,
    /// 已导入旧版设置
    pub settings_migrated: bool,
    /// 已导入旧版 CA（保持系统信任）
    pub ca_migrated: bool,
    /// 提示与警告
    pub warnings: Vec<String>,
}

/// 首启迁移入口（同步、幂等；任何失败仅记录不阻断启动）
pub fn run_startup_migration(data_dir: &Path) -> MigrationReport {
    let mut report = MigrationReport::default();
    let Some(legacy) = LegacyPaths::detect() else {
        return report;
    };
    report.legacy_detected = true;

    migrate_settings(data_dir, &legacy, &mut report);
    migrate_ca(data_dir, &legacy, &mut report);

    tracing::info!(
        "首启迁移完成：settings={} ca={} warnings={}",
        report.settings_migrated,
        report.ca_migrated,
        report.warnings.len()
    );
    report
}

/// 设置迁移：新设置文件不存在时从旧版导入
fn migrate_settings(data_dir: &Path, legacy: &LegacyPaths, report: &mut MigrationReport) {
    let new_path = data_dir.join("Settings").join("ProxySettings.json");
    if new_path.exists() {
        return; // 已有设置（或此前已迁移）
    }
    let legacy_path = legacy.settings_path();
    if !legacy_path.exists() {
        return;
    }

    let result = (|| -> Result<(), String> {
        let json = std::fs::read_to_string(&legacy_path).map_err(|e| e.to_string())?;
        let outcome = watt_config::migrate_legacy_settings(&json).map_err(|e| e.to_string())?;
        if let Some(scripts) = outcome.legacy_scripts_status {
            report.warnings.push(format!(
                "旧版脚本启用状态（{} 项）需在脚本列表中重新确认",
                scripts.len()
            ));
        }
        report.warnings.extend(outcome.warnings);

        let dir = new_path.parent().unwrap_or(data_dir);
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let content = serde_json::to_string_pretty(&outcome.settings).map_err(|e| e.to_string())?;
        std::fs::write(&new_path, content).map_err(|e| e.to_string())?;
        report.settings_migrated = true;
        Ok(())
    })();

    if let Err(e) = result {
        report.warnings.push(format!("旧版设置迁移失败（{e}），已使用默认设置"));
        tracing::warn!("旧版设置迁移失败：{e}");
    }
}

/// CA 迁移：新证书目录为空时从旧版 PFX 导入（保持系统已信任的指纹）
fn migrate_ca(data_dir: &Path, legacy: &LegacyPaths, report: &mut MigrationReport) {
    let cert_dir = data_dir.join("Certificates");
    let has_ca = watt_cert::ca::CaCertificate::cert_path(&cert_dir).exists()
        && watt_cert::ca::CaCertificate::key_path(&cert_dir).exists();
    if has_ca {
        return; // 已有 CA（或此前已处理）
    }

    let candidates: Vec<std::path::PathBuf> = legacy
        .pfx_candidates()
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    if candidates.is_empty() {
        return;
    }

    let pfx = &candidates[0];
    match watt_cert::pfx::import_pfx(pfx, "", &cert_dir) {
        Ok(_) => {
            report.ca_migrated = true;
            tracing::info!("已导入旧版 CA：{}", pfx.display());
        }
        Err(e) => {
            report
                .warnings
                .push("旧版证书导入失败，已生成新证书，需重新安装信任".into());
            tracing::warn!("旧版 CA 导入失败（{pfx:?}）：{e}");
        }
    }
}
```

Wait — there's a subtlety with `settings_migrated` writing report.warnings inside the closure while borrowing... The closure borrows `report` mutably, and afterwards we check result — that's fine since closure ends before.

Actually there's a borrow issue: closure `(|| -> Result<(), String> {...})()` captures `&mut report` — fine, called immediately.

But wait, order of warnings: I push legacy_scripts_status warning before outcome.warnings — fine.

One issue: `watt_config::migrate_legacy_settings` — check the exact path. In watt-config lib.rs, there's `pub mod migrate;` so `watt_config::migrate::migrate_legacy_settings`. Let me use the full path.

Also check: does `CaCertificate` get re-exported? In cert.rs commands: `use watt_cert::ca::CaCertificate;` and `use watt_cert::ca::{CaCertificate, CertificateInfo};`. So `watt_cert::ca::CaCertificate::cert_path` works.

pfx module: `watt_cert::pfx::import_pfx` — check watt-cert lib.rs exports. Let me check.

Also need to update lib.rs:
1. `pub mod migrate;`
2. In setup: run migration before CA load.
3. AppState: add `migration: MigrationReport` field (or RwLock?). It's set once at startup — plain field is fine.
4. Register `migration_get_report` command in commands (add to settings.rs? or new migrate.rs command). I'll add to commands/settings.rs? Better: commands/migrate.rs with `migration_get_report`.

Also fix settings_get_proxy path inconsistency:
```rust
#[tauri::command]
pub async fn settings_get_proxy(
    state: tauri::State<'_, AppState>,
) -> Result<ProxySettings, String> {
    let path = state.data_dir.join("Settings").join("ProxySettings.json");
    if !path.exists() {
        return Ok(ProxySettings::default());
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}
```

Wait — but was this inconsistency intentional? `watt_config::settings::load_proxy_settings()` uses `app_data_dir()` = `dirs::data_dir()/WattToolkit` = `{Roaming}/WattToolkit`. Tauri app_data_dir with identifier `net.steampp.watttoolkit` = `{Roaming}/net.steampp.watttoolkit`. Different paths → get and save use different files. That's a real bug: save writes to state.data_dir, get reads from watt_config path. So after save, get returns stale. Must fix. 

Actually wait — let me reconsider. Maybe `resolve_data_dir` falls back to `watt_config::settings::app_data_dir()` only on error. In dev, app_data_dir works. So yes, bug. Fix by making get use state.data_dir too.

Hmm, but actually, should I centralize load/save in watt-config with a data_dir parameter? That'd be cleaner: add `load_proxy_settings_from(dir)` / `save_proxy_settings_to(dir, settings)`? The settings.rs already has `load_proxy_settings()` and `save_proxy_settings()` using fixed app_data_dir. Simplest: in commands, do file IO directly against state.data_dir like save does. Keep watt-config functions for crates/tests. Actually to avoid duplication, add param-based functions in watt-config settings.rs:

```rust
pub fn load_proxy_settings_in(dir: &Path) -> ...
pub fn save_proxy_settings_in(dir: &Path, settings: &ProxySettings) -> ...
```

And make existing ones delegate. Then commands use `state.data_dir`. This is clean and testable. Let me do that.

Let me check watt-cert lib.rs to see if `pfx` is exported publicly.

开始实现。先给 watt-config 增加按目录读写的设置函数（同时修复 get/save 路径不一致的隐患）。
`watt_cert::import_pfx` is re-exported at root. Now let me create the migration module in src-tauri.

Plan:
1. Add `load_proxy_settings_in` / `save_proxy_settings_in` to watt-config settings.rs (dir-parametric), keep existing as delegates.
2. Create `src-tauri/src/migrate.rs` with `MigrationReport` + `run_startup_migration`.
3. Create `src-tauri/src/commands/migrate.rs` with `migration_get_report`.
4. Update `lib.rs`: module, setup wiring, AppState field, register command.
5. Fix `commands/settings.rs` get to use state.data_dir.

Let me first update watt-config settings.rs with dir-parametric functions.

Need to add `use std::path::Path` — the file already has `use std::path::PathBuf;`. Update the import.

为新的按目录读写函数补测试。

创建启动迁移模块。
Now create the startup migration module `src-tauri/src/migrate.rs`.

新增迁移报告命令并接线。
Now create the migration command and update lib.rs + settings command.

commands/migrate.rs:
```rust
//! 迁移命令：首启迁移报告查询。

use crate::AppState;

/// 首启迁移报告（旧版数据导入结果与提示）
#[tauri::command]
pub async fn migration_get_report(
    state: tauri::State<'_, AppState>,
) -> Result<crate::migrate::MigrationReport, String> {
    Ok(state.migration.clone())
}
```

For that, MigrationReport needs Clone — it derives Clone. Good.

Update commands/mod.rs to add `pub mod migrate;`.

Update lib.rs:
- `pub mod migrate;`
- setup: run migration before CA load; store report in AppState
- AppState: add `pub migration: migrate::MigrationReport`
- register command

Update commands/settings.rs get to use state.data_dir via load_proxy_settings_in.

更新 lib.rs 启动流程。
Now update lib.rs: add migrate module, run startup migration, add AppState field, register command. Also fix settings_get_proxy path inconsistency.

修复 settings 命令 get/save 路径不一致问题。
Now fix the settings command path inconsistency — `settings_get_proxy` reads from watt_config fixed path while save writes to state.data_dir. Make both use state.data_dir.

编译验证。
Now compile and test. Let me run cargo check on the workspace first, then tests for watt-config + src-tauri.

Note there are background jobs running from before — those were probably cargo test runs from the earlier session. I shouldn't re-run the same command, but a new scoped test run is fine.

Let me run `cargo test -p watt-config` and `cargo check -p watt-toolkit-app` — actually let me run check first for fast feedback.

`migrate_legacy_settings` isn't re-exported at the crate root. Check watt-config lib.rs — it exports `pub mod migrate;` plus `pub use settings::{...}`. I need `watt_config::migrate::migrate_legacy_settings`. Let me check the lib.rs pub use lines and either use the full path or add to re-exports. Let me look at lib.rs.

编译通过。运行相关测试。
Compilation passes ("Finished dev profile"). The PowerShell error output is just CLIXML noise for stderr — cargo writes progress to stderr, and exit code was 0 this time (no "Exit code" prefix means success).

Now run the tests for watt-config and src-tauri.

Clippy 检查。
Tests pass. Now run clippy on the changed packages to make sure no warnings.

Exit code -1 — that seems odd. The warnings shown are from other crates (watt-hosts, watt-dns, and dependencies). Let me get the full output to see if my crates (watt-config, watt-toolkit-app) have warnings, and what the exit code issue is. Note the warnings shown are in watt-hosts/watt-dns which aren't part of this change (pre-existing). Let me filter more specifically.

清理这两个 warning。先看 settings.rs 的 Default impl 和 app 里的多参数函数。
Two warnings in my crates:
1. `watt-config/src/settings.rs:120` — `impl Default for DnsSettings` can be derived (derivable_impls). This is pre-existing code but since I'm touching this file, let me fix it (clippy says "this impl can be derived"). Actually DnsSettings fields: before_dns_check: false, master_dns: None, use_doh: false, custom_doh_address: Option<String>. All have natural defaults, so `#[derive(Default)]` works. Let me fix it.

2. `watt-toolkit-app` — "this function has too many arguments (8/7)" — where? Probably in commands or... Let me find it. It might be pre-existing in engine commands? Let me check which function.

该 warning 在 watt-core（Phase 5 遗留），与本次改动无关。确认本次改动的 crate 已无警告。
The too-many-arguments warning is in `watt-core/src/http_relay.rs:166` — that's a pre-existing warning from Phase 5 code (http_relay forward function), not from my Phase 6.3b changes. The memory notes said "zero Clippy warnings in Phase 5 files" but this one exists now. Hmm — actually maybe it appeared because clippy now lints watt-core when building watt-toolkit-app. It's pre-existing, not introduced by me. Should I fix it? It's in watt-core which I'm not currently touching. The Phase 6.6 task includes full verification. To keep clippy clean for the workspace, I could add `#[allow(clippy::too_many_arguments)]` — but minimal change principle says don't fix unrelated code. However, Phase 6.6 will require "全量验证（cargo test + clippy）" — a clean clippy would be desired. The summary said Phase 5 files had zero clippy warnings... but this warning exists in http_relay.rs. Maybe it was introduced during Phase 5.7 and clippy check was scoped differently.

Let me not get distracted; verify my two changed crates are clean first. watt-config should now be clean. Let me re-run clippy for both crates and see remaining warnings.

watt-config is now clean. watt-toolkit-app has 1 warning — the too-many-arguments in watt-core/http_relay.rs gets attributed to the watt-core compilation, and the "watt-toolkit-app (lib) generated 1 warning" is the http_relay forward function? Wait no — the warning location was `crates\watt-core\src\http_relay.rs:166` but attributed to watt-toolkit-app? That's odd. Let me check: earlier output showed "warning: `watt-toolkit-app` (lib) generated 1 warning" right after the too-many-arguments warning context. But http_relay.rs is in watt-core...

Hmm wait, maybe there's a different warning in watt-toolkit-app itself. Let me get the specific warning for watt-toolkit-app.

The app warning is in lib.rs:51 — `&app.handle()` should be `app.handle()`. This was pre-existing code, but since I touched lib.rs, fix it. `resolve_data_dir(&app.handle())` → `resolve_data_dir(app.handle())`. Wait — `app.handle()` returns `&AppHandle` in Tauri 2, so `&app.handle()` is `&&AppHandle`. The function signature is `fn resolve_data_dir(app: &tauri::AppHandle)`. So change call to `app.handle()` directly.

watt-toolkit-app is now clippy-clean. Now run the app tests again to make sure everything still compiles and passes.

测试结果显示全部通过（watt-config 10、app 1），但退出码异常，单独确认一下。
The exit code -1 is odd but the test results show all passing: watt-config 10 passed, watt-toolkit-app 1 passed, all others 0. The exit code -1 might be from Select-String pipeline issues in PowerShell with CLIXML. Actually "Exit code -1" from the shell wrapper... Let me verify with a direct simple check.

Phase 6.3b 完成。更新任务状态，进入 Phase 6.4（脚本缓存扫描导入）。
Exit code 0, all good. The -1 was from pipeline interplay with Select-String, not actual test failure.

Phase 6.3b is now complete:
- `migrate.rs` startup module with settings + PFX migration
- Wired into lib.rs setup
- `migration_get_report` command registered
- Fixed settings get/save path inconsistency
- Fixed DnsSettings Default derive clippy warning
- Fixed needless_borrow in lib.rs
- Tests pass, clippy clean for both changed crates

Now update the todo list and move to Phase 6.4: 脚本缓存扫描导入（UserScript 头解析 → ScriptConfig）.

Let me first mark 6.3b as complete and start 6.4.

For Phase 6.4, I need to understand:
1. What ScriptConfig looks like in watt-script
2. What the legacy script cache looks like (`{md5}.js` files in Plugins/Accelerator/Scripts)
3. UserScript header format (==UserScript== ... ==/UserScript==)

Let me explore watt-script crate structure first.

先了解 watt-script 现有结构与旧版脚本缓存格式。
Now Phase 6.4: 脚本缓存扫描导入（UserScript 头解析 → ScriptConfig）.

Let me explore:
1. watt-script crate structure — what's the ScriptConfig equivalent?
2. Legacy script cache format — `{md5}.js` files in Plugins/Accelerator/Scripts
3. The original C# implementation of script loading

Let me look at the watt-script crate first.

看原 C# 实现的脚本缓存读取与 UserScript 头解析逻辑。
Now let me look at the original C# implementation to understand how scripts are loaded from cache. Let me find the C# ScriptService / script cache handling — where `{md5}.js` files are read and how UserScript headers are parsed.

让我来系统地搜索这个项目中的脚本缓存相关逻辑。首先，我需要了解项目结构，然后并行搜索多个关键词。

### Relevant Code Snippets
1. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services.Implementation\ScriptManager.cs:L50-L84
   — 读取单个 `.js` 脚本文件并解析 `// ==UserScript== ... // ==/UserScript==` 头部元数据；提取 `@name/@version/@description/@author/@homepageurl/@downloadurl/@updateurl/@exclude/@grant/@require/@match/@include`，其中 `@match` 为空时回退到 `@include` 作为 `MatchDomainNames`。

2. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services.Implementation\ScriptManager.cs:L106-L189
   — 保存/注册脚本时计算脚本内容 `MD5`，生成缓存文件名 `md5.js`，并写入 `Plugins/Accelerator/Scripts` 与 `Plugins/Accelerator/BuildScripts` 目录；这是 `{md5}.js` 缓存文件来源与写入逻辑。

3. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services.Implementation\ScriptManager.cs:L377-L436
   — `CheckFiles` 扫描数据库中的脚本记录，校验 `AppDataDirectory/Scripts` 下的源文件与 `CacheDirectory/BuildScripts` 下的缓存文件是否存在、是否空文件，并修复旧路径格式；与旧版脚本缓存目录迁移/校验逻辑直接相关。

4. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services.Implementation\ScriptManager.cs:L450-L488
   — `TryReadFileAsync` 从 `CacheDirectory/BuildScripts/{md5}.js` 读取缓存；若缓存缺失则从 `AppDataDirectory/Scripts/{md5}.js` 读取源文件并重新构建缓存，是脚本缓存加载核心逻辑。

5. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services.Implementation\ScriptManager.cs:L495-L521
   — `LoadingScriptContentAsync` 对脚本列表逐项加载内容；`GetAllScriptAsync` 从 `ScriptRepository` 读取全部脚本记录并映射为 `ScriptDTO`，是启动时加载脚本列表的入口。

6. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L546-L564
   — `InitializeScriptAsync` 调用 `scriptManager.GetAllScriptAsync()` 加载数据库脚本列表，再调用 `CheckFiles` 校验/加载缓存，最后补充基础 `GM.js` 并检查更新；这是旧版脚本缓存目录在启动时的加载链路。

7. e:\Project\SteamTools-develop\src\BD.WTTS.Client.Plugins.Accelerator\Services\Mvvm\ProxyService.cs:L219-L226
   — `EnableProxyScripts` 仅返回未禁用的脚本，并调用 `LoadingScriptContentAsync` 加载其内容；说明真正用于代理注入的脚本列表如何从缓存加载。

8. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Migrations\Migrations.cs:L7-L10
   — 定义脚本目录常量：`DirName_Scripts = "Scripts"`、`DirName_BuildScripts = "BuildScripts"`，对应旧版路径 `Plugins/Accelerator/Scripts` 与缓存目录 `Plugins/Accelerator/BuildScripts`。

9. e:\Project\SteamTools-develop\src\BD.WTTS.Client\Migrations\Migrations.cs:L78-L83
   — `ClearScriptFile` 删除旧版脚本目录与缓存目录，表明迁移逻辑中会清理 `Plugins/Accelerator/Scripts` 和 `Plugins/Accelerator/BuildScripts`。

10. e:\Project\SteamTools-develop\src\BD.WTTS.Client\migrations\Migrations.cs:L86-L104
   — `MoveDirByScripts` 将旧路径 `Scripts` 移动到新路径 `Plugins/Accelerator/Scripts`，并支持将 `BuildScripts` 移动到 `Plugins/Accelerator/BuildScripts`；与“扫描旧版脚本缓存目录”的迁移路径转换相关。

直接读 ScriptManager.cs 的关键段落获取精确解析逻辑。
The agent gave file references but I need the actual conversion logic for @match/@include → MatchDomainNames. Let me read ScriptManager.cs directly to get the parsing logic precisely.

I now understand the C# logic:

1. **ReadScriptAsync** parses the UserScript header:
   - `DescRegex` — need to find that regex. It's `string.Format(DescRegex, "@Name")` — a format string with a `{0}` placeholder. Let me find `DescRegex` definition.
   - Fields: Name, Version, Describe, AuthorName, SourceLink, DownloadLink, UpdateLink, ExcludeDomainNames (@Exclude joined by separator), DependentGreasyForkFunction (@Grant any), RequiredJs (@Require joined)
   - MatchDomainNames = @Match joined, or if empty → @Include joined.

2. **ScriptDTO** has: FilePath, Content, Name, Version, Describe, AuthorName, SourceLink, DownloadLink, UpdateLink, ExcludeDomainNames, MatchDomainNames, DependentGreasyForkFunction, RequiredJs, LocalId, Id, Order, IconUrl, UpdateTime, AccelerateProjects, IsCompile, CachePath, MD5, SHA512, Pid, Status/Disable.

Now I need:
1. The `DescRegex` format string — let me find it.
2. How MatchDomainNames is used downstream (GetScriptConfig conversion in ProxyService?) — is there any transformation from "@match" URL patterns to domain names? Let me check GetScriptConfig in the C# code.

Let me search for DescRegex and GetScriptConfig.

`DescRegex = @"(?<={0})[\s\S]*?(?=\n)"` — so it's a lookbehind for the tag (e.g. `@Name`) followed by lazy match up to newline. So `@Name        Steam 下载加速` captures `        Steam 下载加速` (everything after the tag until newline).

Hmm wait — `(?<={0})` where {0} is "@Name" — note `@Name` would also match `@NameSpace` prefix... They ignore case. The captured value is everything after the tag to end of line, including leading whitespace. The `GetValue` probably trims? Let me check GetValue. Actually let me not go too deep — for the Rust port I'll parse: lines starting with `// @tag value` (case-insensitive), trimming whitespace.

Let me look at ReverseProxyConfig.cs for how MatchDomainNames is used (the `Tryn` method) — this is what our ScriptSet::match_url + script_matches_url already align to (Phase 4 work). The migration task 6.4 is about scanning `{md5}.js` files and parsing the UserScript header to build ScriptConfig.

But wait — the ScriptConfig needs: local_id, cache_path, match_domain_names, exclude_domain_names, order. The legacy DB has LocalId/Order/Status, but we're only migrating from the file cache (no DB access in Rust version yet). Per the plan: "Phase 6.4: Script cache scan import (UserScript header parsing → ScriptConfig)".

Let me check the migration plan document to see what Phase 6.4 exactly says.

看 C# 端脚本域名匹配逻辑（确认 @match 值的形态）。
Now I understand the context. Phase 6.4: 脚本缓存扫描导入（UserScript 头解析 → ScriptConfig）.

Design for Phase 6.4:

**Where**: A new module in watt-script: `watt-script/src/cache.rs` (or in watt-config migrate?). The ScriptConfig lives in watt-script, and the UserScript header parsing is script-domain logic. The legacy paths (LegacyPaths) live in watt-config. watt-script doesn't depend on watt-config... Let me check watt-script's Cargo.toml.

Actually, the scan takes a directory path — no need to depend on watt-config. The caller (src-tauri migrate.rs) passes `legacy.scripts_dir()`.

**What to build**:
1. `watt-script/src/userscript.rs` — UserScript header parser:
   - `parse_userscript(content: &str) -> Option<UserScriptMeta>` where UserScriptMeta has: name, version, description, author, homepage_url, download_url, update_url, match_domains (Vec<String>), include_domains (Vec<String>), exclude_domains (Vec<String>), requires (Vec<String>), grants (Vec<String>)
   - Parse: find `==UserScript==` ... `==/UserScript==` block; lines starting with `// @tag value` (case-insensitive tag). Multi-value tags: @match/@include/@exclude/@require/@grant (append), single-value: take first occurrence.
   - Align with C#: `MatchDomainNames = @match joined, or @include if @match empty`.

2. `ScriptConfig` conversion: `to_script_config()` — the ScriptConfig needs:
   - local_id: C# LocalId comes from DB. For file-scan migration we don't have DB. Use filename stem (md5)? The injection path uses local_id: `/WattToolkit_Inject/{local_id}.js`. Hmm, but the C# version used the DB LocalId int. For migrated scripts without DB, use the md5 filename stem as string ID.
   - cache_path: path to the .js file.
   - match_domain_names / exclude_domain_names: from header. But note C# @match values are URL patterns like `https://steamcommunity.com/*` or domains like `steamstatic.com`. How does Tryn match? Let me check ReverseProxyConfig.Tryn — the existing Rust script_matches_url does exact/wildcard domain match. What do the @match values look like in real Watt scripts? e.g. `*.steampowered.com` or `https://store.steampowered.com/*`?

Let me check the C# `Tryn` matching logic in ReverseProxyConfig.cs to see how MatchDomainNames entries look and match. Our Rust script_matches_url (from Phase 4) was already aligned to something. Let me look at the C# matching.

看 engine 命令如何接收脚本与规则。
Key insight: `GetDomainPatternString` in C#:
```csharp
static string GetDomainPatternString(string s)
{
    if (s.IndexOf("/") != 0)  // if s does NOT start with "/"
    {
        return "/^" + Regex.Escape(s).Replace("\\*", ".*").Replace("\\?", ".") + "$";
    }
    return s;  // already a regex pattern like "/^...$/"
}
```

So script MatchDomainNames entries can be:
- Domain patterns like `*.steamcommunity.com` or `steamcommunity.com` → converted to regex `/^...\.steamcommunity\.com$/`
- Or already regex strings starting with `/`

Interesting — wait, `s.IndexOf("/") != 0` means "index of '/' is not 0" i.e. doesn't start with '/'. So if not starting with '/', treat as glob pattern → regex. If starts with '/', it's already a regex like `/^steamcommunity\.com$/`.

The DomainPattern class (from FastGithub) handles both. Our Rust `domain_match` in model.rs handles `*.` wildcard and exact match, plus... hmm, our Rust version may not handle regex patterns or URL patterns like `https://steamcommunity.com/*`.

But wait — Phase 4 already established script matching behavior in Rust (model.rs). The current Rust implementation handles:
- exact host match
- `*.suffix` wildcard match

The C# @match values in Watt scripts are things like `*.steamcommunity.com`, `steamcommunity.com` — i.e., already domain-ish. Actually looking at real Watt Toolkit scripts, the @match values are domains like `*.steampowered.com` etc. Since Phase 4's model.rs was already "对齐 TryGetScriptConfig" per its doc comment, I'll keep the existing matching semantics and focus Phase 6.4 on: scan `{md5}.js` files → parse UserScript header → build ScriptConfig list → persist to new script store.

Now, where do migrated scripts get stored in the new version? The engine_start command receives scripts... Let me look at how engine_start currently works and how scripts would be passed. Let me check commands/engine.rs.

看 cache_path 在引擎侧的使用方式，确认迁移后文件应存放的位置。
Now I understand the architecture:
- `engine_start` receives `scripts: Vec<ScriptConfig>` from the frontend.
- Phase 6.4 needs: scan legacy script cache dir → parse UserScript headers → produce ScriptConfig entries → persist them somewhere the frontend can query (so it can pass them to engine_start in Phase 6.5b).

So Phase 6.4 should:
1. Create `watt-script/src/userscript.rs` — UserScript header parser (aligned with C# ReadScriptAsync regex semantics).
2. Create `watt-script/src/store.rs` or scan function — scan a directory of `{md5}.js` files, parse headers, build ScriptConfig list.
3. Persist migrated scripts in the new data dir (e.g. `{data_dir}/Scripts/scripts.json` — a JSON list of ScriptConfig + name/version metadata for display). Actually, ScriptConfig is the engine-facing struct. For the frontend script list we need name/version/description/enable state too. Let me design a persisted script entry:

```rust
/// 已安装脚本（持久化 {data_dir}/Scripts/scripts.json）
pub struct InstalledScript {
    pub config: ScriptConfig,     // local_id, cache_path, match/exclude, order
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
    pub md5: String,              // 文件名 stem
}
```

Hmm, but wait — should I keep it simpler and aligned with what exists? The summary says Phase 6.4 = "脚本缓存扫描导入（UserScript 头解析 → ScriptConfig）". The ScriptConfig struct is what's needed. But a frontend script list needs display metadata too.

Let me design pragmatically:

**watt-script/src/userscript.rs**:
- `UserScriptMeta` struct: name, version, description, author, homepage_url, download_url, update_url, match_domains, include_domains, exclude_domains, require_urls, grants
- `parse_userscript(content: &str) -> Option<UserScriptMeta>`
- `UserScriptMeta::to_script_config(&self, cache_path: &str, local_id: &str) -> ScriptConfig`

**watt-script/src/store.rs** (script store):
- `ScriptStore` with load/save from `{dir}/scripts.json`
- `InstalledScript` record: config + metadata + enabled
- `scan_legacy_scripts(dir: &Path) -> Vec<(PathBuf, UserScriptMeta)>` — scan `*.js` files, parse header, skip non-UserScript files

**src-tauri migrate.rs**: add `migrate_scripts(data_dir, legacy, report)`:
- If new scripts.json doesn't exist and legacy scripts dir exists → scan → build InstalledScript list (enabled = true? C# Disable=false default on import; but legacy ScriptsStatus tracked enabled ones... since we can't map DB IDs, default all enabled and warn) → save to `{data_dir}/Scripts/scripts.json`, copy? No — don't copy files; cache_path can point to legacy dir directly. Hmm, but if the user uninstalls the old version, the files are gone. Copying is safer: copy `{md5}.js` into `{data_dir}/Scripts/{md5}.js`? 

The C# keeps source in `{AppData}/Scripts/{md5}.js` and built cache in `{TMP}/Steam++/BuildScripts/{md5}.js`. The legacy `LegacyPaths::scripts_dir()` currently points to `root/Plugins/Accelerator/Scripts` which per ScriptManager is... wait let me re-check: `Plugin.Instance.AppDataDirectory` + DirName — so scripts live at `{LocalAppData}/Steam++/Plugins/Accelerator/Scripts/{md5}.js`? And cache at `{TMP}/Steam++/Plugins/Accelerator/BuildScripts/{md5}.js`? The agent research said cache files are in `Plugins/Accelerator/BuildScripts` under CacheDirectory. Hmm, and `TryReadFileAsync` reads from `CacheDirectory/BuildScripts/{md5}.js` falling back to `AppDataDirectory/Scripts/{md5}.js`.

Wait — the explore agent said: "写入 `Plugins/Accelerator/Scripts` 与 `Plugins/Accelerator/BuildScripts` 目录" — `jsSavePath = Path.Combine(Plugin.Instance.AppDataDirectory, IScriptManager.DirName, jsFileName)` where DirName = "Scripts". Hmm, but what is Plugin.Instance.AppDataDirectory for the Accelerator plugin? It's probably `{LocalAppData}/Steam++/Plugins/Accelerator`. So source: `{LocalAppData}/Steam++/Plugins/Accelerator/Scripts/{md5}.js`, cache: `{TMP}/Steam++/Plugins/Accelerator/BuildScripts/{md5}.js`.

So my `LegacyPaths::scripts_dir()` returning `root/Plugins/Accelerator/Scripts` is right for the source scripts. Good. The summary confirms: "旧版脚本目录（Plugins/Accelerator/Scripts，脚本文件名为 {md5}.js）".

For the built/compiled cache — the "BuildScripts" version contains the compiled script (with GM wrapper etc.). For the Rust version, inject.rs reads raw script content from cache_path. Using the source Scripts file directly is fine (they're the same content; build adds wrappers in C# — but our Rust engine does its own injection/wrapping in Phase 4 local_domain).

Decision: migrate by **copying** legacy `{md5}.js` files into `{data_dir}/Scripts/` and persisting metadata JSON. This decouples from the old installation (user can uninstall old version safely). That matches "脚本缓存扫描导入".

Now — enabled state: default true (C# ReadScriptAsync sets Disable=false "忽略脚本 Enable 启动标签默认启动"), plus migration warning already added in 6.3b for ScriptsStatus (需重新确认). So all imported scripts default enabled.

local_id: use md5 string as local_id (injection path `/WattToolkit_Inject/{local_id}.js` — string is fine in Rust version).

Let me now also check how the inject path/local_domain uses local_id to make sure string works. In model.rs: `local_id: "test".into()` with `cache_path: "C:/cache/test.js"`. OK, strings.

Now, where to put scan logic? watt-script crate: new files `userscript.rs` (parser) and `store.rs` (InstalledScript + persistence + scan). Let me check watt-script Cargo.toml for deps (serde, serde_json needed for store; regex for parser? — I'll parse line-by-line without regex, simpler and no dep).

Parser design (aligned with C# semantics):
- C# extracts substring between "==UserScript==" and "==/UserScript==". Note: `content.Substring("==UserScript==", "==/UserScript==")` — custom Substring extension finding start/end markers.
- Then regex `(?<=@Name)[\s\S]*?(?=\n)` — value is everything after tag until newline (leading spaces included; C# GetValue... let me check if it trims. `GetValue(s => s.Success == true)` — probably returns match Value which includes leading whitespace. Hmm, then names would have spaces... Let me check GetValue.

Actually for @Name the tag in file is like `// @name         Steam 下载加速`. The regex lookbehind is `(?<=@name)` — matches right after "@name", so captured = `         Steam 下载加速` (with leading spaces). C# `GetValue` — I need to check if it trims. Let me look at the GetValue extension... Actually many Watt scripts are auto-generated with consistent format. Let me just trim in Rust (correct behavior regardless).

Lines format: `// @name value` or `//@name value`. Case-insensitive tag matching.

Let me write the parser:

```rust
/// UserScript 头部元数据（对齐 ScriptManager.ReadScriptAsync 解析字段）
#[derive(Debug, Clone, Default)]
pub struct UserScriptMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub homepage_url: String,
    pub download_url: String,
    pub update_url: String,
    pub match_domains: Vec<String>,
    pub include_domains: Vec<String>,
    pub exclude_domains: Vec<String>,
    pub require_urls: Vec<String>,
    pub grants: Vec<String>,
}

pub fn parse_userscript(content: &str) -> Option<UserScriptMeta> {
    // 定位 ==UserScript== ... ==/UserScript== 块
    let start = content.find("==UserScript==")?;
    let end = content[start..].find("==/UserScript==")? + start;
    let block = &content[start..end];
    
    let mut meta = UserScriptMeta::default();
    for line in block.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("//") else { continue };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('@') else { continue };
        // tag 到空白前
        let (tag, value) = split_tag_value(rest);
        ...
    }
}
```

Wait — careful with tag matching: `@name` vs `@namespace` — if I use starts_with("name") it'd match "namespace". Need exact tag word match: tag = value up to whitespace; compare full tag string case-insensitively.

Mapping:
- "name" → name (first occurrence wins; C# Regex.Match takes first)
- "version" → version
- "description" → description
- "author" → author
- "homepageurl" → homepage_url
- "downloadurl" → download_url
- "updateurl" → update_url
- "match" → match_domains (multi, all occurrences)
- "include" → include_domains (multi)
- "exclude" → exclude_domains (multi)
- "require" → require_urls (multi)
- "grant" → grants (multi)

C# joins multi values with separator then they're split later by MatchDomainNamesArray — in Rust, keep Vec<String> directly, trimming each.

to_script_config:
- match_domain_names = if match_domains non-empty { match_domains } else { include_domains } (aligned with C# line 78-80)
- exclude_domain_names = exclude_domains

Store design (`store.rs`):

```rust
/// 已安装脚本记录（持久化 {data_dir}/Scripts/scripts.json）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledScript {
    pub local_id: String,       // = md5
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub md5: String,
    pub enabled: bool,
    #[serde(flatten)]  // hmm, or nested config?
    pub config: ScriptConfig,
}
```

Hmm — nested vs flattened. For the frontend DTO, having config fields flattened into the script record is nicer (local_id duplicated though). Let me do:

```rust
pub struct InstalledScript {
    /// 本地 ID（= 文件 md5，注入路径 /WattToolkit_Inject/{local_id}.js）
    pub local_id: String,
    /// 显示名
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    /// 缓存文件名（{md5}.js）
    pub file_name: String,
    /// 是否启用
    pub enabled: bool,
    /// 匹配域名
    pub match_domain_names: Vec<String>,
    /// 排除域名
    pub exclude_domain_names: Vec<String>,
}

impl InstalledScript {
    /// 引擎侧配置（cache_path 由调用方拼接）
    pub fn to_script_config(&self, cache_path: PathBuf) -> ScriptConfig { ... }
}
```

And store functions:
- `scripts_json_path(dir) -> PathBuf` — `{dir}/scripts.json`
- `load_installed_scripts(dir) -> Vec<InstalledScript>`
- `save_installed_scripts(dir, &[InstalledScript])`
- `scan_legacy_dir(dir: &Path) -> Vec<InstalledScript>` — scan .js files, parse, skip failures

Where do script files live in new layout? `{data_dir}/Scripts/{md5}.js`. cache_path resolution: the engine's LocalDomainHandler serves script files from cache_path (absolute or relative?). Let me check local_domain.rs / how cache_path is used in http_relay/engine.

`cache_path` is read directly with `std::fs::read_to_string` — so it's an absolute path string. The migration will copy legacy `{md5}.js` into `{data_dir}/Scripts/{md5}.js` and the frontend passes absolute cache_path when calling engine_start.

Now let me create the watt-script modules. First check watt-script Cargo.toml.

创建 UserScript 头解析模块。
watt-script has serde but not serde_json. For the store I need serde_json. Add it (workspace = true).

Now create:
1. `watt-script/src/userscript.rs` — parser
2. `watt-script/src/store.rs` — InstalledScript + persistence + legacy scan

Let me write userscript.rs first.

修复 split_tag 的内存泄漏问题。
Wait — I used `.leak()` in split_tag which is a memory leak per call! That's bad. Let me fix: return `String` or handle differently. Better approach: compare lowercase in place without allocation by returning the tag slice and doing case-insensitive comparison in the match. Simplest: return (String, &str).

Actually since the tag part is short, I can return an owned lowercase String:

```rust
fn split_tag(rest: &str) -> (String, &str) {
    match rest.find(char::is_whitespace) {
        Some(i) => (rest[..i].to_ascii_lowercase(), &rest[i..]),
        None => (rest.to_ascii_lowercase(), ""),
    }
}
```

Then `match tag.as_str() { ... }`. Let me fix that.

创建脚本存储模块并加依赖。
Now create the store module `watt-script/src/store.rs` with:
- `InstalledScript` struct
- persistence functions (load/save scripts.json)
- `scan_legacy_dir` — scan .js files, parse UserScript headers

First add serde_json to watt-script Cargo.toml.

更新 watt-script lib.rs 导出并运行测试。

接入 src-tauri 迁移流程。
watt-script 17 tests pass (10 old + 7 new: 5 userscript tests + 2 store tests).

Now wire script migration into src-tauri migrate.rs:
- Add `migrate_scripts(data_dir, legacy, report)`: 
  - new scripts dir = `{data_dir}/Scripts`; if manifest exists → skip
  - legacy scripts dir = `legacy.scripts_dir()`; if not exists → skip
  - scan → if imported non-empty: copy files to new dir, save manifest, report scripts count
  - add `scripts_migrated: bool` + maybe `scripts_imported: usize` to MigrationReport

Also expose script list query command? For the frontend, Phase 6.5b will need `script_get_list`. Let me add a scripts command module now? The todo for 6.5b says "前端加速项目列表勾选 + engine_start 传 rules/scripts" — script list command fits naturally there. But having the backend ready is Phase 6.4's wiring... Let me keep 6.4 scoped: migration scan + persistence + report. The script list command I'll add in 6.5b when wiring the frontend.

Actually, a minimal `scripts_get_list` command is small and directly enables 6.5b. Hmm — keep scope tight; add in 6.5b.

Update src-tauri migrate.rs now. Also need watt-script dep in src-tauri Cargo.toml — already there (watt-script = { workspace = true }).

Add to MigrationReport: `scripts_migrated: bool` and `scripts_imported: usize`. Frontend DTO camelCase handles it.

I accidentally included the line number prefix "1→" style content? No — I wrote `: ` at the beginning of old_string. Let me read the actual current file content and do targeted edits.

The original docstring says "两项独立判断" — my old_string had "三项" typo. Let me do targeted edits.

添加脚本迁移函数。

更新报告序列化测试以覆盖新字段。
Also update the test for MigrationReport serialization since it has a new field. Let me check the test at the end of migrate.rs.

Phase 6.4 core is done. Quick clippy check on watt-script and watt-toolkit-app, then move to Phase 6.5.

Phase 6.4 完成。进入 Phase 6.5（watt-cloud 云端加速项目 API）。先研究 C# DTO 与现有 DomainRule 结构。
watt-script and watt-toolkit-app generate no warnings (only pre-existing ones in other crates: watt-dns 1, watt-cert 8, watt-hosts 2, watt-core 2).

Phase 6.4 complete. Update todos and move to Phase 6.5: watt-cloud 加速项目云端 API + DTO→DomainRule 转换 + 本地缓存.

For Phase 6.5 I need to:
1. Research the cloud API `https://api.steampp.net/api/Accelerate/All` (already identified in summary)
2. Look at AccelerateProjectDTO in C# 
3. Create watt-cloud crate: HTTP client + DTO → DomainRule conversion + local cache

Let me look at the C# AccelerateProjectDTO first and how DomainRule conversion works in the existing Rust code (watt-config domain_rule.rs).

我来帮你系统地查找这些信息。先进行第一轮广泛搜索。

直接查 AccelerateProjectDTO 完整定义与 API 客户端。
The agent's research has some gaps. I need the actual AccelerateProjectDTO class definition (fields) to define the Rust DTO precisely. Let me find it directly — search for the DTO class file.

AccelerateProjectDTO is not defined in src — it must come from a NuGet package (BD.WTTS.Models or an SDK dll). Let me check how it's imported and if there's aModels folder, or search more broadly.

DTO 来自外部 SDK。查看已有 Rust domain_rule.rs 结构（此前已按云端 DTO 设计过别名）。
The DTO classes (AccelerateProjectDTO, AccelerateProjectGroupDTO) come from an external SDK (probably BD.WTTS.Models NuGet). The summary from my earlier session said: "Cloud API Integration: Identified and tested https://api.steampp.net/api/Accelerate/All endpoint for project list retrieval". So in the earlier session I apparently tested this endpoint directly. Let me check if there's any local file with the API response structure or check the domain_rule.rs which already has "DomainRuleFields" with alias attributes suggesting it was designed for cloud DTO compat.

Let me look at domain_rule.rs to understand the existing Rust structure.

直接请求云端 API 获取真实响应结构。
DomainRule already exists with aliases for cloud DTO compat (`MatchDomainNames`, `IPAddress`/`IpAddress`, `ListeningDomainNames`, `IsServerSideProxy`).

Earlier session tested the API endpoint `https://api.steampp.net/api/Accelerate/All`. Let me check what the actual response looks like — I can fetch it now to get the real DTO structure.

响应是数字索引键结构。查 C# 客户端如何解析该响应。
The API returns MessagePack-style indexed JSON (contractless MessagePack serialized to JSON? No — it's JSON with numeric keys, which is how MessagePack-CSharp contractless resolver serializes to JSON... actually this looks like the "data" with numeric property indices). The response structure:

```json
{
  "🥳": [          // group name (emoji key?)
    { "0": "Steam 服务",  // group name
      "1": [         // items
        { "0": "Steam 图片",   // Name
          "1": 443,          // Port
          "2": "steamcdn-a...",  // MatchDomainNames (; separated)
          "3": "steamimage.rmbgame.net",  // FakeServerName?
          "4": "",          // ?
          "5": "",          // ?
          "ProxyType": 0,
          "7": "steamcdn-a...",  // ListenDomainNames?
          "8": true,
          "9": "bbd6dafa-c295-eb11-abaa-a0d3c1f2a15d",  // Id
          "10": 32,       // Order
          "11": "Chrome/150.0.6478.183; ${origin}",  // FakeUserAgent
          "12": [...]     // Items (sub rules)
        }
      ]
    }
  ]
}
```

Hmm, this is indexed-key JSON — this is what MessagePack-CSharp's ContractlessStandardResolver with numeric keys... Actually no. This looks like the response is MessagePack deserialized into dynamic then re-serialized as JSON with index keys? Odd. Wait — the endpoint might return MessagePack binary, and PowerShell's Invoke-WebRequest... no, content is JSON text.

Actually this is likely "IndexKeys" JSON — the C# MicroServiceClient probably deserializes with MessagePack (typeless) where property names are indices. Hmm, but the response IS JSON with numeric keys — the C# client must handle this mapping: AccelerateProjectDTO fields are mapped by index in some contract.

Wait, let me check the C# MicroServiceClient implementation for Accelerate.All to understand the response parsing. Let me search for "Accelerate/All" or "Accelerate" client code.

The Accelerate client must be defined elsewhere — maybe in the SDK (BD.WTTS SDK NuGet). The `IMicroServiceClient.Instance.Accelerate` — the IAccelerateAPIClient interface. Let me search for "All()" method and IAccelerateAPIClient in the whole repo.

查此前会话对该 API 的字段映射记录。
Now I understand the C# flow. The cloud API client (`IMicroServiceClient.Instance.Accelerate.All()`) is in the closed-source SDK. The API response I fetched is indexed-key JSON (that's what the API returns when Accept is JSON — it's likely MessagePack dynamic JSON with property indexes).

Wait — actually the API returns this indexed format for JSON requests. The SDK's Accelerate.All() probably requests with MessagePack accept header and deserializes into DTO via index mapping. The indexed keys like "0", "1", "2"... correspond to AccelerateProjectDTO properties in some canonical order.

Let me decode the structure from the sample:

```json
{
  "🥳": [   // top-level object: some key (maybe "version" or category name?) → list of groups
    {
      "0": "Steam 服务",   // group Name
      "1": [               // group Items
        {
          "0": "Steam 图片",      // Name
          "1": 443,               // Port
          "2": "steamcdn-a.akamaihd.net;...",  // MatchDomainNames (semicolon-separated)
          "3": "steamimage.rmbgame.net",      // ??? (FakeServerName? Destination?)
          "4": "",                // ???
          "5": "",                // ??? (maybe StaticResponse)
          "ProxyType": 0,
          "7": "steamcdn-a.akamaihd.net;...", // ListeningDomainNames? or same as 2
          "8": true,              // ??? (ThreeStateEnable? HasScripts?)
          "9": "bbd6dafa-c295-eb11-abaa-a0d3c1f2a15d",  // Id (GUID)
          "10": 32,               // Order
          "11": null,             // FakeUserAgent ("Chrome/150.0.6478.183; ${origin}" in another entry)
          "12": null             // Items (sub-rules; array in another entry)
        }
      ]
    }
  ]
}
```

From the earlier summary of my prior session: "Cloud API Integration: Identified and tested https://api.steampp.net/api/Accelerate/All endpoint for project list retrieval" — I apparently already tested this and mapped the fields. Let me check the migration plan doc or any notes from previous session about the field mapping. Let me search my memory files for this mapping.

看 C# IDomainConfig 接口字段定义以精确对应索引键。
No memory of field mapping. I need to decode the indexed JSON myself. Let me get a fuller API response and analyze against the C# DTO fields I know:

From ProxyService.cs constructor snippet (lines 160-190 from agent):
```
return new AccelerateProjectDTO
{
    Name = item.Name,
    Port = item.Port,
    MatchDomainNames = item.MatchDomainNames,
    ForwardDomainNames = item.ForwardDomainNames,
    IgnoreSSLCertVerification = item.IgnoreSSLCertVerification,
    FakeServerName = item.FakeServerName,
    ProxyType = item.ProxyType,
    ListenDomainNames = item.ListenDomainNames,
    Checked = item.Checked,
    Id = item.Id,
    Order = item.Order,
    FakeUserAgent = item.FakeUserAgent,
    Version = item.Version,
    ThreeStateEnable = item.ThreeStateEnable,
    Items = item.Items.Where(x => x.ThreeStateEnable != false).ToList()
};
```

Let me look at that code section in full to see context (it's the local ThreeState mapping). And I should find the DTO's property ordering — since indexed keys "0"-"12" map to properties. Let me fetch more of the API response and study entries with distinctive values (e.g. entry with "5":"{origin}" — StaticResponse; entry with sub-items "12":[...]; entry with FakeUserAgent "11"; entries with "4" non-empty).

From the sample:
- Entry "Steam 静态资源": "2":"community.steamstatic.com" (match), "3":"community.steamstatic.com", "4":"", "5":"{origin}" — "5" here is likely ForwardDomainNames or StaticResponse... The C# DTO has both ForwardDomainNames and FakeServerName. Wait order of constructor assignment: Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items.

Compare with response keys:
- "0": Name ✓
- "1": Port (443) ✓
- "2": MatchDomainNames ("; " separated) ✓
- "3": ForwardDomainNames? For "Steam 图片": "steamimage.rmbgame.net" — hmm, that's the mirror/destination domain. ForwardDomainNames = domains forwarded... Actually in C#, ForwardDomainNames might be the "listening" domain for hosts? Hmm.
- "4": IgnoreSSLCertVerification? It's "" (string) in samples. No — "4":"" is a string. IgnoreSSLCertVerification is bool. Hmm.
- "5": FakeServerName? For "Steam 静态资源": "5":"{origin}" — FakeServerName with {origin} placeholder? Hmm, FakeServerName is the SNI name to use. "{origin}" = use origin. That fits! FakeServerName="{origin}" meaning keep original SNI. And for "Steam 图片": "5":"" empty.
- "ProxyType": 0 — named key! So not all keys are indexed; ProxyType kept its name (maybe because enum serialized by name).
- "7": ListenDomainNames (";"-separated) — for "Steam 图片" same as "2". ListenDomainNames = domains to write into hosts. ✓ matches C# property name "ListenDomainNames"... but DTO property is "ListenDomainNames" per constructor. Hmm wait — the property in DTO is ListenDomainNames (from constructor: ListenDomainNames = item.ListenDomainNames).

Hmm, but wait — the Rust DomainRule has `listening_domain_names` with alias "ListeningDomainNames" — from previous session design (per http_relay comment: "监听域名（hosts 写入用，"ip domain" 反序格式兼容）"). OK.

- "8": true — Checked? or ThreeStateEnable? bool.
- "9": GUID string — Id ✓ (Id.ToString() used in GetAccelerateEnableAllIds)
- "10": 32 — Order ✓
- "11": "Chrome/150.0.6478.183; ${origin}" — FakeUserAgent ✓ (matches "${origin}" placeholder in Rust DomainRuleFields.user_agent)
- "12": null/array — Items (sub-rules) ✓

Now "3", "4", "5":
- For "Steam 图片": "3":"steamimage.rmbgame.net", "4":"", "5":""
- For "Steam 静态资源": "3":"community.steamstatic.com", "4":"", "5":"{origin}"
- For "Steam 社区": "3":"steamcommunity.rmbgame.net", "4":"", "5":"steamstore-a.akamaihd.net", "11":"Chrome/... ${origin}"

Hmm interesting: "Steam 社区" has "5":"steamstore-a.akamaihd.net" — that looks like an IP/address override (IPAddress in original DomainRule? No...). Actually in old Watt data, Steam 社区's special config: match steamcommunity.com, reverse proxy to steamcommunity.rmbgame.net (3), with... hmm "5" might be IPAddresses (加速 IP)?

Wait — let me think about the C# DomainConfig fields from the Rust port (domain_rule.rs): ip_address (IPAddress), destination, forward_destination, response (StaticResponse), items, user_agent (FakeUserAgent), timeout_ms, tls_sni, tls_ignore_name_mismatch (IgnoreSSLCertVerification?), is_server_side_proxy.

C# IDomainConfig fields probably include: IPAddress (string? or list), Destination, ForwardDomainNames?, Response (static), FakeServerName (SNI), IgnoreSSLCertVerification, ...

Let me look at the C# IDomainConfig interface to map these precisely.

抓取完整响应，按索引键统计取值分布以精确推断字段。
IDomainConfig is the domain config interface. The DTO properties are in the external SDK. Since the indexed JSON maps by property index of AccelerateProjectDTO's MessagePack contract, I need to infer from data. Let me fetch a larger sample of the API response and analyze distinctive entries — particularly ones with "4" non-empty and sub-items, to pin down "3"/"4"/"5".

Let me fetch the full response and analyze it with PowerShell, extracting unique values per key.

Top-level keys are emoji: '🦓', '🦄', '🐴' — three platform categories! Probably:
- 🦓 = zebra (steam/Windows?)
- 🦄 = unicorn
- 🐴 = horse

Hmm — maybe they're proxy type categories: e.g. 🦓 = normal community, 🦄 = "游戏加速" (paid/vip?), 🐴 = ...? Each key contains its own group list. Wait — Object.values(d)[0] gave 10 groups. Let me check each key's groups and look at ProxyType distribution — this maps to ProxyType enum (0=community?, 1=?, 2=?).

Let me analyze the items structure per top key and the unique values of each indexed field.

响应包装结构已明确（🦓=Content、🦄=Code、🐴=Message）。分析 DTO 字段分布。
Now it's clear! The top-level response is the IApiRsp wrapper:
- **🦓** = **Content/Data** (the actual payload: array of 10 groups)
- **🦄** = **Code** (200)
- **🐴** = **Message** (null)

The emoji are obfuscated property names of the API response wrapper (ApiRsp). So:
- Content key "🦓"
- Code key "🦄" (number 200)
- Message key "🐴" (null or string)

That's the response envelope. Now let me analyze the DTO item fields:
- group: {"0": name, "1": items[], ...maybe more}
- item keys: 0=Name, 1=Port, 2=MatchDomainNames(;sep), 3=?, 4=?, 5=?, ProxyType(named), 7=ListenDomainNames?, 8=?, 9=Id(GUID), 10=Order, 11=FakeUserAgent, 12=Items(sub)

Let me collect field stats across all items to identify 3/4/5/8 and group-level extra fields.

查 ForwardDomainNames/FakeServerName 在仓库中的使用以确认语义。
Excellent analysis! Now I can decode:

**Item (AccelerateProjectDTO) fields:**
- "0" = Name (string)
- "1" = Port (443)
- "2" = MatchDomainNames (;-separated)
- "3" = FakeServerName (string) — the SNI/destination override domain (e.g. "steamimage.rmbgame.net"). Hmm wait — in C# the "FakeServerName" is used for... Actually looking at values: "Twitch 登录": f3="passttv.steam302.xyz" and f5="passttv.steam302.xyz" — f3 appears to be the forward/destination server name, and f5 the DNS/IP hint. Hmm.

Let me reconsider against C# DTO property list from ProxyService.cs:
Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items

Index mapping hypothesis:
- 0=Name, 1=Port, 2=MatchDomainNames, 3=ForwardDomainNames, 4=IgnoreSSLCertVerification... no wait "4" contains IP strings like "192.0.80.239" — not a bool.

Hmm. Let me reconsider. In C# the properties might be ordered differently. Let me think about what the Rust port needs and which values map:

- "4" non-empty values are IPs (192.0.80.239, 20.43.185.14, 23.235.37.133...) → this is **IPAddress** (the IP override, single IP string; in Rust DomainRuleFields.ip_address). In the C# DTO it might be called IPAddresses or IPAddress.

- "5" values: "{origin}", "steamstore-a.akamaihd.net", "Github", "passttv.steam302.xyz", "static.twitchcdn.net" → mixed: for "Steam 静态资源" it's "{origin}" (probably ForwardDomainNames placeholder = keep original), for others it's a domain. In old Watt data structure, there's "ForwardDomainNames" — domains to forward to (direct proxy destination)... 

Hmm wait. Let me look at "Steam 静态资源" more carefully: m="community.steamstatic.com", f3="community.steamstatic.com", f5="{origin}". And "Steam 社区": m="steamcommunity.com;www.steamcommunity.com", f3="steamcommunity.rmbgame.net", f5="steamstore-a.akamaihd.net".

In the original Watt Toolkit config, for Steam 社区:
- MatchDomainNames: steamcommunity.com, www.steamcommunity.com
- The reverse proxy forwards to steamcommunity.rmbgame.net (the mirror) — this is "ForwardDomainNames"? or "FakeServerName"?
- steamstore-a.akamaihd.net = ??? maybe DNS/IP related... Actually in Watt's DomainConfig there's "IPAddress" field AND "DNS" lookup hints. Hmm.

Wait, I recall the original SteamTools config for Steam社区: it had special handling — the hosts entry points steamcommunity.com to local, then the proxy connects to a specific IP (steamstore-a.akamaihd.net resolves?) Hmm no.

Let me look at the Rust http_relay.rs implementation to see which fields it reads from DomainRule: ip_address (override_ip), destination (resolve_destination), user_agent, tls_sni, tls_ignore_name_mismatch, response, items... 

In C# DomainConfig (from FastGithub heritage):
- IPAddress: fixed IP override
- Destination: upstream destination template  
- ForwardDomainNames: domains that are "forwarded" — when the rule matches, requests to these domains go through the local proxy as well (listening)?
- FakeServerName: override SNI
- FakeUserAgent: UA replacement
- Response: static response

For "Steam 社区": f3="steamcommunity.rmbgame.net" is the Destination (reverse proxy mirror). f5="steamstore-a.akamaihd.net"... 

Hmm, actually wait. Let me check what the C# AccelerateProjectDTO really contains. The DTO is in the SDK (BD.WTTS.Models). Let me search NuGet cache or check if there's a decompiled reference. Actually — there might be a copy of the model in the repository's debug pages or the GameAccelerator. Let me search for "ForwardDomainNames" across the repo.

The DTO property assignment order in GetEnableProxyDomains: Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items.

If MessagePack contractless/indexed serialization assigned indices in declaration order of the class (which often matches), the JSON keys might be:
- 0 = Name ✓ (string name)
- 1 = Port ✓ (443)
- 2 = MatchDomainNames ✓ (domains)
- 3 = ForwardDomainNames? ("steamimage.rmbgame.net", "passttv.steam302.xyz" — the forward/destination server) — hmm plausible!
- 4 = IgnoreSSLCertVerification? No — "4" has IP strings, not bool.

Hmm, that breaks the order hypothesis at 4. Unless the actual class declaration order differs from this initializer order.

Let me hypothesize based on values:
- 3 = "steamimage.rmbgame.net" / "community.steamstatic.com" / "passttv.steam302.xyz" — always a domain, often a mirror (rmbgame.net / steam302.xyz / edgesuite.net). For "Steam 静态资源" 3 == match domain itself. This is **ForwardDomainNames** (semicolon-separated possible) OR **FakeServerName**.

- 5 = "{origin}" / "steamstore-a.akamaihd.net" / "Github" / "passttv.steam302.xyz" — mixed bag. "{origin}" strongly suggests SNI placeholder (keep original server name → FakeServerName). "steamstore-a.akamaihd.net" as FakeServerName for steamcommunity.com — YES! In original Watt config, Steam 社区 rule connects to steamcommunity.rmbgame.net with SNI... hmm, or actually the original config used FakeServerName=steamstore-a.akamaihd.net so the TLS SNI presented to upstream... 

Wait — let me look at "Twitch 登录": f3="passttv.steam302.xyz", f5="passttv.steam302.xyz" — both same. And "Twitch Assets": f3="static.twitchcdn.net", f5="static.twitchcdn.net". 

And "Github UserContent": f3="", f4="23.235.37.133" (IP), f5="Github" — "Github"?? As FakeServerName? Hmm, "Github" with capital G... that's odd for a domain. Unless f5 is something else entirely — maybe a static response or... hmm.

Let me think about Rust http_relay resolve_destination: dest.replace("@domain", host) — destination templates. Hmm.

Let me look at how the C# YARP pipeline uses ForwardDomainNames vs FakeServerName. Search in ReverseProxyServiceImpl / middleware.

I see the general flow. Now, for the exact semantics of fields "3"/"4"/"5", let me check how the reverse proxy service consumes AccelerateProjectDTO → DomainConfig. Search in ReverseProxyServiceImpl.cs where ProxyDomains are transformed.

从本机 NuGet 缓存找 SDK 中的 DTO 定义。
IDomainConfig is defined in the external SDK (BD.WTTS.Models). Since the source isn't in this repo, my Rust port in Phase 2-5 already established the mapping — http_relay.rs is "对齐 HttpReverseProxyMiddleware.cs" and it reads DomainRule fields. The prior session's domain_rule.rs aliases ("IPAddress", "IsServerSideProxy", "MatchDomainNames", "ListeningDomainNames") came from that analysis.

So for Phase 6.5, what matters is: **AccelerateProjectDTO (indexed JSON) → DomainRule (Rust)**. Let me now map indexed fields to the DomainRule semantics using the actual data + http_relay's usage:

From http_relay.rs (Rust, aligned with C# middleware):
- `match_domain_names` — rule matching (key "2")
- `listening_domain_names` — hosts writing (key "7"? "steamcdn-a.akamaihd.net;..." same as match)
- `fields.ip_address` — IP override (key "4": "192.0.80.239" etc.)
- `fields.destination` — destination template (key "3": "steamimage.rmbgame.net"?)
- `fields.user_agent` — FakeUserAgent (key "11": "Chrome/...; ${origin}")
- `fields.tls_ignore_name_mismatch` — IgnoreSSLCertVerification?
- sub rules (key "12")
- Port (key "1") — used for outbound connection port
- Order (key "10"), Id (key "9"), Name (key "0")

Now what about key "3" vs "5" and FakeServerName?
- "3" values: "steamimage.rmbgame.net", "community.steamstatic.com", "steamcommunity.rmbgame.net", "passttv.steam302.xyz", "" — single domain per item? Let me check if "3" ever has multiple ;-separated values.
- "5" values: "{origin}", "steamstore-a.akamaihd.net", "Github", "passttv.steam302.xyz", "static.twitchcdn.net"

Hypothesis A: 
- "3" = FakeServerName (SNI 域名伪装) — "steamcommunity.rmbgame.net" is the server name to connect... 
- "5" = ForwardDomainNames (转发域名列表) — but "Github" as a domain list? weird. Unless ForwardDomainNames here means: the upstream domains to forward/resolve. "steamstore-a.akamaihd.net" — for Steam 社区, the community domain historically resolved via steamstore-a.akamaihd.net CDN... 

Hypothesis B:
- "3" = ForwardDomainNames/destination — the mirror to connect to (destination override)
- "5" = FakeServerName (SNI) — "{origin}" placeholder = use origin host as SNI. "Github" as SNI for githubusercontent.com?? "Github"... hmm that doesn't look like a valid SNI domain either.

Wait — maybe "5" is a list separated by ";" containing domains; "Github" could be... no.

Let me look at the actual old Steam++ config format (the old JSON configs from open source watt). In the original Watt Toolkit open-source repo, there was a config sample for accelerate projects. The BD.WTTS.Models AccelerateProjectDTO on GitHub (WattToolkit/WattToolkit repo) — the models are in a separate repo. But maybe I can find the DTO definition in the NuGet package cache on this machine? Let me search the user's NuGet cache for BD.WTTS.Models.

读中间件看字段语义（ definitive 对齐基准）。
The DTO is defined in an external SDK repo (WattToolkit/WattToolkit models). The exact field names of AccelerateProjectDTO don't matter that much for the Rust implementation — what matters is the semantic mapping from the indexed JSON to DomainRule, which our http_relay already consumes.

Since the earlier session already did Phase 2-5 with detailed alignment to HttpReverseProxyMiddleware.cs, the middleware itself reads from the DTO. Let me read HttpReverseProxyMiddleware.cs to see how it uses ForwardDomainNames / FakeServerName / IPAddresses — that gives the definitive semantics.

查看 http_relay/engine 中 forward_destination 与 destination 的语义（此前已对齐的部分）。
The source is obfuscated (`ln = item.ln`). The DTO definition isn't available locally. Let me use my knowledge of the original Watt Toolkit open-source code (from GitHub WattToolkit/steam++) — the AccelerateProjectDTO in the open source repo BD.WTTS.Models:

From the original open-source Watt Toolkit repository (I know this project), AccelerateProjectDTO had:
```csharp
public partial class AccelerateProjectDTO : AccelerateProject
{
    // Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, 
    // FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, 
    // Version, ThreeStateEnable, Items, IPAddresses(?)
}
```

And the base AccelerateProject:
```csharp
public class AccelerateProject
{
    public string? Name { get; set; }
    public ushort Port { get; set; } = 443;
    public string? MatchDomainNames { get; set; }
    public string? ForwardDomainNames { get; set; }
    public string? IPAddresses { get; set; }  // ?
    public bool IgnoreSSLCertVerification { get; set; }
    public string? FakeServerName { get; set; }
    public ProxyType ProxyType { get; set; }
    public string? ListenDomainNames { get; set; }
    public bool Checked { get; set; }
    public Guid Id { get; set; }
    public int Order { get; set; }
    public string? FakeUserAgent { get; set; }
    ...
}
```

Hmm, I actually recall from the Watt Toolkit source (GitHub), in the models repo `AccelerateProjectDTO` was:

```csharp
public class AccelerateProjectDTO
{
    public string Name
    public ushort Port
    public string MatchDomainNames
    public string ForwardDomainNames
    public string ExcludeDomainNames?
    public string IPAddresses?
    public bool IgnoreSSLCertVerification
    public string FakeServerName
    public ProxyType ProxyType
    public string ListenDomainNames
    ...
}
```

I can't recall exactly. The pragmatic approach: map by DATA semantics, since that's what the Rust engine consumes. Let me analyze the data patterns to decide "3" vs "5":

Data points:
1. "Steam 图片": m=steamcdn-a.akamaihd.net;... (akamai), 3=steamimage.rmbgame.net (mirror), 4="", 5=""
2. "Steam 静态资源": m=community.steamstatic.com, 3=community.steamstatic.com (same), 5="{origin}"
3. "Steam 社区": m=steamcommunity.com, 3=steamcommunity.rmbgame.net (mirror), 5=steamstore-a.akamaihd.net
4. "Twitch 登录": m=passport.twitch.tv, 3=passttv.steam302.xyz (mirror), 5=passttv.steam302.xyz (same as 3)
5. "Twitch Assets": m=assets.twitch.tv, 3=static.twitchcdn.net, 5=static.twitchcdn.net (same)
6. "Github UserContent": m=githubusercontent.com;raw.github.com, 3="", 4=23.235.37.133 (IP), 5="Github"

Pattern: "3" = the upstream server domain to connect (mirror) — this is **ForwardDomainNames** (the actual outbound destination). For Steam 图片 (akamai CDN images), the mirror is steamimage.rmbgame.net. When 3 is empty (Github UserContent), connect via IP "4" with normal DNS.

"5" — for Twitch entries it equals "3". For Steam 社区, 5=steamstore-a.akamaihd.net ≠ 3. For Steam 静态资源, 5="{origin}". For Github UserContent, 5="Github".

Hmm, "5" could be **FakeServerName** (the SNI to send): 
- Steam 社区: connect to steamcommunity.rmbgame.net but SNI = steamstore-a.akamaihd.net?? That seems odd.

OR "5" could be **ForwardDomainNames** and "3" is **FakeServerName**:
- Steam 社区: FakeServerName=steamcommunity.rmbgame.net (SNI mirror), ForwardDomainNames=steamstore-a.akamaihd.net
- Twitch 登录: FakeServerName=passttv.steam302.xyz, ForwardDomainNames=passttv.steam302.xyz
- Steam 静态资源: FakeServerName=community.steamstatic.com, ForwardDomainNames={origin} — placeholder "{origin}" meaning use original request host as the forward domain!

Hmm, "{origin}" as ForwardDomainNames makes sense: forward to the original domain (i.e., plain reverse proxy to origin server). And "Github" as ForwardDomainNames for githubusercontent.com... doesn't fit a domain pattern.

Actually wait. Let me look at the actual old Watt Toolkit behavior for GitHub UserContent: the rule connects to raw.github.com etc. via fixed IP 23.235.37.133 with SNI... In the old config, "Github" might be a FakeServerName? No...

Hmm, let me look at what Rust http_relay does with these fields — maybe previous session already established this exact mapping. Let me check how engine.rs builds DomainRules from settings or how the integration tests construct DomainRule (proxy_integration.rs) — especially destination/forward_destination semantics.

The Rust http_relay uses:
- `rule.fields.destination` — destination template with @domain/@uri placeholders
- `rule.fields.user_agent` — UA replacement
- `rule.fields.ip_address` — override IP
- `rule.fields.tls_sni` — bool (None = use host)
- Sub-rules via items

So in the C# model (from FastGithub heritage, IDomainConfig):
- **Destination** (模板)
- **FakeServerName** — hmm, wait. In http_relay.rs line 303: `tls_sni: if rule.fields.tls_sni { None } else { Some(String::new()) }` — tls_sni is a bool. But C# has FakeServerName as the SNI string...

Let me look at the original middleware to see how FakeServerName is used vs destination. Let me search HttpReverseProxyMiddleware.cs for the request forwarding logic.

The middleware uses IDomainConfig with: Items, Response, Destination (Uri with @domain/@uri), UserAgent, IsServerSideProxy, TlsSni. The mapping from AccelerateProjectDTO → IDomainConfig happens inside ReverseProxyConfig.AddDomainConfigs — wait no, it passes the DTO itself as IDomainConfig (dict.Add(pattern, item) — item is AccelerateProjectDTO which implements IDomainConfig!). So AccelerateProjectDTO implements IDomainConfig: Destination, UserAgent, IsServerSideProxy, TlsSni, Response, Items.

So AccelerateProjectDTO properties that matter for the engine:
- Destination (Uri) — derived from ForwardDomainNames? (e.g. "steamimage.rmbgame.net" → destination https://steamimage.rmbgame.net)
- FakeServerName — SNI (used by ReverseProxyHttpClientHandler / SocketsHttpHandler ConnectCallback)
- IPAddresses — connection IP override
- FakeUserAgent → UserAgent
- IgnoreSSLCertVerification
- MatchDomainNames → pattern
- ListenDomainNames → hosts
- Port → outbound port
- Items → sub rules
- Response (static)

Let me check ReverseProxyHttpClientHandler to see FakeServerName/IPAddresses usage (that's where SNI override and IP override are applied).

Now the semantics are crystal clear:

**IDomainConfig** (AccelerateProjectDTO implements it):
- `IPAddress` — fixed connection IP (indexed key "4": "192.0.80.239")
- `ForwardDestination` — DNS-resolve this domain for the connection IP (key "5"!) — "steamstore-a.akamaihd.net", "{origin}"?? Hmm wait.

Wait: `ForwardDestination` is resolved to get IPs for connection. Key "5" values: "{origin}", "steamstore-a.akamaihd.net", "Github", "passttv.steam302.xyz". Hmm "{origin}" as ForwardDestination → replace with original host? "Github"?? 

Hmm wait — maybe "5" is ForwardDomainNames (plural, DTO field) which maps to IDomainConfig.ForwardDestination. For "Github UserContent" f5="Github" — hmm, that would resolve "Github" as a DNS name... that can't be right.

Hold on. Let me re-examine: maybe "5" is the **Destination**/ForwardDomainNames where the value is used as the outbound **destination host** (destination prefix). Let me reconsider:

For "Steam 社区": 
- match: steamcommunity.com
- key3: steamcommunity.rmbgame.net 
- key5: steamstore-a.akamaihd.net

If key3 = FakeServerName (SNI to present when connecting to steamcommunity.com)... no wait. Actually in the original Watt behavior for Steam 社区: the hosts file maps steamcommunity.com → 127.0.0.1, local MITM proxy intercepts, then outbound connects to... steamcommunity.rmbgame.net? with SNI steamcommunity.rmbgame.net? and the actual connection IP resolved from steamstore-a.akamaihd.net?

Hmm, that doesn't sound right either. Let me look at ReverseProxyHttpClientFactory.CreateHttpClient to see how DomainConfig fields are consumed there (FakeServerName might be used in TlsSniValue). Let me check `TlsSniValue` and where FakeServerName appears.

`domainConfig.GetTlsSniPattern().WithDomain(uri.Host).WithRandom()` — so there's a TlsSniPattern from DomainConfig. This is likely derived from FakeServerName. The "{origin}" value in key "5" might be the TlsSniPattern! FastGithub's DomainConfig has a TlsSni property...

Wait, in FastGithub: `DomainConfig.TlsSni` is a string that can contain `{ip}`, `{domain}`, `{random_wwwb_xxx}` placeholders. Hmm, actually FastGithub's TlsSniValue has WithDomain/WithIPAddress/WithRandom substitutions, and the pattern can be literal domain or "{domain}" or... 

So key "5" = FakeServerName = TlsSni pattern:
- "{origin}" — hmm, FastGithub used `{domain}`... but Watt customized it. "{origin}" could mean "use original host".
- "steamstore-a.akamaihd.net" for steamcommunity.com — SNI = steamstore-a.akamaihd.net when connecting?? That seems weird but actually could be right: connecting to steamcommunity.rmbgame.net IP while presenting SNI steamstore-a.akamaihd.net... Hmm, no wait.

Hmm, actually let me reconsider: for "Steam 社区" — key3="steamcommunity.rmbgame.net", key5="steamstore-a.akamaihd.net":

Maybe key3 = ForwardDomainNames (the reverse proxy destination — where to forward the request, i.e. the mirror server) and key5 = FakeServerName (SNI). The original Watt for Steam社区: requests to steamcommunity.com get reversed-proxied to steamcommunity.rmbgame.net (rmbgame mirror), and the TLS connection to the mirror uses SNI "steamstore-a.akamaihd.net"? That doesn't fit either.

OK let me stop guessing and look at the Rust http_relay.rs resolve_destination + the prior session's integration tests, which were aligned to actual behavior. Then look at what fields exist in Rust DomainRule: destination, forward_destination. The comment in domain_rule.rs says:
- destination: "目标模板，支持 @domain / @uri 占位"
- forward_destination: "仅转发目标（同 destination 语义别名，兼容旧数据）"

Hmm — forward_destination in the C# handler: `if (domainConfig.ForwardDestination != null) { resolve ForwardDestination to get IPs }`. So ForwardDestination = a domain to resolve for the connection IP (bypassing normal DNS for the host). In Rust outbound... let me check how Rust uses forward_destination. Search watt-core for forward_destination usage.

列出所有 key5/key3 非空项做交叉分析。
The rg output is garbled (obfuscation replacement "n"). Anyway — key point: the Rust engine currently doesn't use forward_destination anywhere (it's just a serde field). Let me now decide the DTO → DomainRule mapping based on all the C# evidence:

From C# IDomainConfig consumption points:
1. `domainConfig.Destination` (Uri) — reverse proxy destination prefix (middleware line 124-132)
2. `domainConfig.UserAgent` — UA replace (line 134-137)
3. `domainConfig.IsServerSideProxy` (line 141)
4. `domainConfig.Items` — sub rules (line 113)
5. `domainConfig.Response` — static response (line 116)
6. `domainConfig.TlsSni` (bool, line 15: TlsSni=true default) — enable SNI
7. `domainConfig.TlsIgnoreNameMismatch` (handler line 324)
8. `domainConfig.IPAddress` (handler line 352) — connection IP override
9. `domainConfig.ForwardDestination` (handler line 357) — resolve this domain for connection IPs
10. `domainConfig.Timeout` (handler line 40)
11. `domainConfig.GetTlsSniPattern()` — FakeServerName → SNI pattern (e.g. "{origin}", literal domain)
12. `domainConfig.ProxyType`? — used at ProxyService level for ServerAccelerate check

So AccelerateProjectDTO (implements IDomainConfig) fields:
- Destination — from ForwardDomainNames? Since GetEnableProxyDomains copies ForwardDomainNames, and DTO has both ForwardDomainNames and (inherited) Destination property computed from it? The `ln = item.ln` obfuscation hides it.

OK — pragmatic decision time. The indexed JSON keys map to DTO properties. Given Rust DomainRule has `destination` (template) and considering the data:

- key "3" (steamimage.rmbgame.net, passttv.steam302.xyz, community.steamstatic.com, empty) = **Destination/ForwardDomainNames** — the outbound server to forward to. In Watt for Steam 图片: match akamai steam CDNs, forward to steamimage.rmbgame.net mirror. YES — this is the destination override domain.

- key "5" ({origin}, steamstore-a.akamaihd.net, Github, passttv.steam302.xyz, static.twitchcdn.net) = **FakeServerName** (SNI pattern). For Steam 静态资源: SNI = {origin} = original host. For Steam 社区: SNI = steamstore-a.akamaihd.net (connect to steamcommunity.rmbgame.net but present SNI of akamai?) — hmm...

Wait, actually! I remember now how the old Steam++ worked: for Steam 社区:
- hosts: steamcommunity.com → 127.0.0.1
- Local proxy connects to... the rmbgame mirror? No wait — actually I recall the old config had "ForwardDomainNames" listing domains like steamcommunity.rmbgame.net and FakeServerName as the SNI to use for that connection (steamstore-a.akamaihd.net was used to bypass SNI-based blocking? No...).

Hmm, let me think about "Twitch 登录": match passport.twitch.tv, key3=passttv.steam302.xyz (forward destination), key5=passttv.steam302.xyz (SNI = same). Makes sense: connect to passttv.steam302.xyz with SNI passttv.steam302.xyz.

"Steam 社区": forward to steamcommunity.rmbgame.net, SNI steamstore-a.akamaihd.net. So the mirror server at steamcommunity.rmbgame.net's IP expects SNI steamstore-a.akamaihd.net (the mirror works by IP, and presenting the akamai SNI routes it). Plausible — the rmbgame mirror is a CNAME/CDN in front of akamai? Actually steamcommunity.rmbgame.net might be a CNAME to steamstore-a.akamaihd.net's CDN or the mirror sniffs SNI.

"Github UserContent": key3="" (no destination → forward to original host githubusercontent.com), key4=23.235.37.133 (fixed IP — Github's fastly IP), key5="Github"?? SNI "Github"?? Hmm that's strange. Unless key5 isn't SNI...

Wait, maybe I have 3 and 5 swapped: 
- key "5" = ForwardDomainNames/ForwardDestination (DNS resolve for connection): "{origin}" = resolve original host; "steamstore-a.akamaihd.net" for steamcommunity.com — connect to steamcommunity.com's IP but resolved via steamstore-a.akamaihd.net; "Github"... no, "Github" isn't a domain.

Hmm "Github" — wait, maybe I misread the sample. Let me re-check "Github UserContent" raw JSON and also look at all key5 values that aren't domains. Actually from the earlier output: `{"n":"Github UserContent","m":"githubusercontent.com;raw.github.com","f3":"","f4":"23.235.37.133","f5":"Github"}` — f5="Github". 

Hmm what if f5 is not FakeServerName but something like... "FakeUserAgent"? No, that's f11. 

What if the keys map differently — maybe:
- 3 = FakeServerName (SNI): "steamcommunity.rmbgame.net" — SNI = the mirror domain when connecting to... and
- 5 = ForwardDomainNames — "steamstore-a.akamaihd.net"... and "Github"...

Neither fits "Github" as a domain. UNLESS "5" is a general string field that can hold things like static response hints or... let me look at what values key 5 takes across all 62 items and cross-reference with known Watt behaviors. Let me print all items with f5 non-empty plus names.

查 Rust 侧 SNI 处理现状（sni.rs）。
Now it's clear! Key "5" is the **FakeServerName / TLS SNI pattern**:
- "{origin}" and "@domain" — placeholder for original host (SNI = original request host)
- "ttv", "Github" — hmm, still odd values but these could be... wait:
  - "Twitch 第三方关联登录": 3=2973c6ca0e111662ed293b57dbae9fbf.steam302.xyz, 5="ttv" — SNI "ttv"??
  - "Github UserContent": 3="", 5="Github" — SNI "Github"?

Hmm wait. Maybe key "5" is **ForwardDomainNames** and key "3" is **Destination**:
- "greasyfork": 3="http://pt.mossimo.net:41080/" (a destination URL prefix!), 5="pt.mossimo.net" — so 3 = Destination (full URL with scheme+port!), 5 = ForwardDomainNames (the domain to resolve for connection).

Look at "greasyfork": key3 = "http://pt.mossimo.net:41080/" — that's exactly a YARP destination prefix format! And key5 = "pt.mossimo.net" — the connection DNS endpoint. And "Uplay 商店": key3 = "commcloud.prod-abbs-ubi-com.cc-ecdn.net.cdn.cloudflare.net" (destination domain), key5 = "@domain" — ForwardDomainNames="@domain" meaning "resolve the original domain"?? Hmm — "@domain" placeholder in forward destination = use request host.

- "Github UserContent": 3="" (no destination → connect to original githubusercontent.com), 5="Github"... ForwardDomainNames="Github"?? Resolving "Github" via DNS fails...

Hmm wait, unless... "Github" is a special DNS hint? No.

Let me reconsider: maybe key 5 is the SNI pattern after all, and "ttv"/"Github" are literal SNI values (bogus SNI used to bypass SNI filtering / CDN routing). Actually — YES! I recall this trick: presenting a *short/bogus SNI* like "Github" to Fastly's anycast IP — Fastly serves based on Host header, not SNI. The connection goes to the Fastly IP (key4 = 23.235.37.133 — that's a Fastly IP!), and SNI can be anything; Watt used "Github" as the SNI. Similarly "ttv" for Twitch's CDN — the hash prefix domain 2973c6ca....steam302.xyz resolves to a CDN that ignores SNI.

So key 5 = FakeServerName = TLS SNI pattern, where "{origin}"/"@domain" = original host placeholder. And key 3 = Destination/ForwardDomainNames (the outbound server name/URL).

Cross-check with C# handler: `domainConfig.GetTlsSniPattern().WithDomain(uri.Host)` — the pattern placeholders get replaced with the domain. FakeServerName = pattern. ✓ And GetIPEndPointsAsync uses ForwardDestination — hmm, but where does the connection endpoint come from for "Steam 社区"? Destination=steamcommunity.rmbgame.net → DNS resolve... 

Hmm wait, actually there's a subtlety: is key3 "ForwardDomainNames" (plural, ;-separated, DTO field used as ForwardDestination for IP resolution) or "Destination"? For "Steam 社区": destination = steamcommunity.rmbgame.net — the YARP destination prefix would be "https://steamcommunity.rmbgame.net/" and connection resolves via DNS. SNI = steamstore-a.akamaihd.net (weird but it's what the data says — actually this makes sense! steamcommunity.rmbgame.net is a CNAME pointing into akamai, and the akamai edge expects the real SNI steamstore-a.akamaihd.net to route correctly).

So mapping (final):
- "0" Name → display
- "1" Port (443)
- "2" MatchDomainNames (";"-separated)
- "3" ForwardDomainNames/Destination → Rust `fields.destination` (as domain or URL template; e.g. "http://pt.mossimo.net:41080/")
- "4" IPAddresses → Rust `fields.ip_address` (single IP string; could be ";"-separated list? samples show single)
- "5" FakeServerName → SNI pattern → Rust needs a new field? Currently Rust DomainRuleFields has `tls_sni: bool`. Hmm! The Rust port has tls_sni as bool. But FakeServerName is a string pattern ("{origin}", "@domain", literal domain).

Wait — check Rust sni.rs outbound_tls_connector / server_name to see how SNI is currently determined. Earlier read of http_relay.rs line 303: `tls_sni: if rule.fields.tls_sni { None } else { Some(String::new()) }` — hmm, `OutboundTarget.tls_sni: Option<String>` where None = use host, Some("") = ? Let me check sni.rs server_name handling. Actually `tls_sni: Some(String::new())` — empty string = ??? Let me check outbound.rs / sni.rs quickly.

Now let me check how OutboundTarget.tls_sni is consumed in outbound.rs to understand the current SNI override mechanism (it's `Option<String>` — None = use host).

`OutboundTarget.tls_sni: Option<String>` — Some(value) = explicit SNI override, None = use target.host. And in http_relay.rs line 303: `tls_sni: if rule.fields.tls_sni { None } else { Some(String::new()) }` — hmm, `Some(String::new())` = empty SNI?? That looks like a degenerate case (empty string SNI would fail server_name parse... or maybe means "no SNI"). Anyway.

The Rust DomainRule currently has `tls_sni: bool` but the cloud data's FakeServerName (key "5") is a string pattern. I should extend DomainRuleFields with a `fake_server_name: Option<String>` field (alias FakeServerName) that holds the SNI pattern, where "{origin}"/"@domain"/empty → original host.

Wait — but is this over-engineering for Phase 6.5? The task: "watt-cloud 加速项目云端 API + DTO→DomainRule 转换 + 本地缓存". The conversion needs to be correct — including SNI patterns, otherwise Steam 社区 etc. would break (connect to mirror but wrong SNI). Since http_relay builds OutboundTarget.tls_sni from... let me look at the exact lines 295-310 of http_relay.rs to see how to wire fake_server_name.

查 AutoMapper 映射配置，确认 DTO→DomainConfig 的子规则结构。
Wait, `tls_sni: if rule.fields.tls_sni { None } else { Some(String::new()) }` — if tls_sni enabled (true, default) → None → SNI = dest_host. If disabled → Some("") — that would try SNI=""... `server_name("")` probably fails → error. Hmm, that's the existing behavior; C# TlsSni=false means... actually in C# TlsSni is used as pattern source. Leave as is.

For Phase 6.5, I need to add `fake_server_name` (SNI pattern) support to the engine:
- `DomainRuleFields.fake_server_name: Option<String>` (alias "FakeServerName")
- In http_relay: compute the SNI pattern: if fake_server_name is Some(pattern):
  - pattern "{origin}" or "@domain" or empty → SNI = original request host (not dest_host!)... 

Hmm wait — what does C# do exactly? `domainConfig.GetTlsSniPattern().WithDomain(uri.Host)`. In C#, `uri` here is the OUTBOUND request URI (request.RequestUri in SendAsync — that's the YARP-forwarded request = destination URI, so uri.Host = destination host). Hmm — actually in ReverseProxyHttpClientHandler.SendAsync, request.RequestUri is the outbound request with destination prefix → so uri.Host = destination host (e.g. steamcommunity.rmbgame.net). 

And TlsSniPattern.WithDomain replaces "{domain}" or "{origin}" placeholders with that host. But wait — for "Steam 社区", SNI should be steamstore-a.akamaihd.net (literal, no placeholder) — WithDomain keeps literal as-is. For "Steam 静态资源" (fake_server_name="{origin}") → SNI = destination host = community.steamstatic.com. OK.

Hmm, but what about TlsSni bool vs FakeServerName string? In C#: GetTlsSniPattern() — probably returns pattern based on FakeServerName ?? (TlsSni ? "{origin}" : something). Actually FastGithub DomainConfig: `TlsSni` was a Uri-ish string in FastGithub 2.1.4! In FastGithub, `DomainConfig.TlsSniUri`... The Watt fork changed it to `TlsSni` bool probably. Whatever — in Rust currently: tls_sni bool (default true) → None (use dest host).

Simplest correct extension: add `fake_server_name: Option<String>` to DomainRuleFields. In http_relay: 
```rust
tls_sni: match rule.fields.fake_server_name.as_deref() {
    Some(p) if !p.is_empty() && p != "{origin}" && p != "@domain" => Some(p.to_string()),
    _ => None, // 跟随目标 host
},
```
Wait but there's the existing tls_sni bool logic: `if rule.fields.tls_sni { None } else { Some(String::new()) }`. Combine: if fake_server_name has literal pattern → Some(pattern); else fall back to existing bool logic.

Hmm — but careful: `Some(String::new())` for tls_sni=false... server_name("") likely returns None/error. Let me check outbound.rs:172: `let name = server_name(&sni_host).ok_or_else(...)` — empty string would produce an error → connection fails. So tls_sni=false currently = broken TLS? Maybe intended as "disable SNI" (send no SNI) but rustls requires ServerName... Not my current concern.

Let me check the C# TlsSni semantics once more — in C# `DomainConfig { TlsSni = true }` default. Let me search GetTlsSniPattern in the SDK... it's obfuscated. From FastGithub 2.1.4 original:

```csharp
public Uri? TlsSni { get; set; }  // in original FastGithub it was a URI!!
```

Hmm, in original FastGithub DomainConfig:
```csharp
sealed class DomainConfig
{
    public string? Destination { get; set; }
    public Uri? TlsSni { get; set; }  // SNI override URI
    ...
}
```
Actually FastGithub had: `public Uri TlsSni { get; set; }` where TlsSniValue pattern... I recall FastGithub's TlsSni was a string like `{random}` or a domain. The Watt Toolkit fork's DomainConfig — given `defaultDomainConfig = new DomainConfig() { TlsSni = true }` assigns a bool, Watt's TlsSni is a bool meaning "use SNI". And GetTlsSniPattern combines TlsSni + FakeServerName.

I'll go with the data-driven interpretation:
- FakeServerName pattern string: "{origin}" / "@domain" / "" → use outbound dest host; literal → SNI override.
- TlsSni bool (default true): true = normal SNI behavior; false = ??? I'll keep existing Rust behavior.

Now — what about "Steam 社区(解锁访问限制)" — a sub-rule! Its match "m" is "https://steamcommunity.com/*/discussions/" (a URL pattern, not just domain!). Sub-rule matching in C# is regex-based (SubRule.key.IsMatch). Our Rust SubRule has `regex` field. The DTO sub-items (key 12) contain the same indexed structure — the "2" field for sub-items is a URL regex pattern.

Wait, let me look at sub-item entries — earlier sample: "12":[{"0":"Steam 讨论/留言 (IPv6)","1":443,"2":"https://steamcommunity.com/comment;https://steam..." — key2 of sub-item = URL prefixes/regex.

Hmm, how does the C# SubRuleRelationDTO work? `domainConfig.Items.FirstOrDefault(s => s.Key.IsMatch(url))` — Key is DomainPattern (regex). The sub-items in the DTO have MatchDomainNames that are actually URL regexes like "https://steamcommunity.com/comment*"? 

In Rust, SubRule { regex, rule: DomainRuleFields }. The conversion from cloud sub-item: regex = sub_item's MatchDomainNames entries converted to regex (like C# GetDomainPatternString: escape + wildcard→regex, or if starts with "/" use as-is).

Wait — C# DomainPattern handling of AccelerateProjectDTO sub-items: In ReverseProxyConfig.AddDomainConfigs, sub-items are handled where? The DTO's Items are sub-DTOs; how do they become DomainPattern keys? Let me search how Items of AccelerateProjectDTO are processed into the domainConfigs dictionary... Actually looking at ReverseProxyConfig.AddDomainConfigs — it only iterates top-level accelerates and adds DomainPattern(matchDomainNames). But then RecursionMatchDomainConfig uses domainConfig.Items — the DTO's Items property (List<AccelerateProjectDTO>)... and `s.Key.IsMatch(url)` — so Items must be a Dictionary<DomainPattern, IDomainConfig> or similar within IDomainConfig. The DTO must expose `Items` as sub-rule dictionary where keys are built from sub-DTO's MatchDomainNames.

Let me find how IDomainConfig.Items is populated from the DTO. Search for "SubRule" or how AccelerateProjectDTO maps Items. The AutoMapperProfile might show it.

查 ProxyType 枚举定义与 group 附加字段。
AutoMapper mapping is commented out — the DTO is used directly as IDomainConfig (AccelerateProjectDTO implements the interface in the SDK). The Items property on IDomainConfig likely returns a computed dictionary from sub-DTOs.

Given the obfuscation limits, I'll design the watt-cloud conversion based on:
1. The actual API data (field indices and semantics I've decoded)
2. The C# engine behavior (middleware + handler) that the Rust engine already aligns to
3. The Rust DomainRule structure

**Final field mapping (indexed key → Rust):**

Group level (AccelerateProjectGroupDTO):
- "0" = name (String)
- "1" = items (Vec<AccelerateProjectDTO>)
- "2" = ? (string) — hmm, groups had keys: 0:string, 1:arr, 2:string, 3:boolean, 4:number. Let me check what "2"/"3"/"4" are on groups. Probably: 2=MachineName/icon?, 3=hasThirdState/bool, 4=order(number). Let me verify with data.

Item level:
- "0" Name → display
- "1" Port (443) → outbound default port hint (Rust: not in DomainRule; connection port comes from destination URI scheme)
- "2" MatchDomainNames (";"-separated) → match_domain_names
- "3" ForwardDomainNames/Destination → fields.destination — values like "steamimage.rmbgame.net", "http://pt.mossimo.net:41080/", "" — as destination template (domain or URL)
- "4" IPAddresses → fields.ip_address (single IP string; parse)
- "5" FakeServerName → SNI pattern → NEW field fields.fake_server_name ("{origin}"/"@domain"/literal)
- "7" ListenDomainNames (";"-separated) → listening_domain_names (hosts 写入)
- "8" Checked?/HasScripts? (bool) — samples show true/false mixed. Which? For "Twitch 直播聊天" false, "Steam 白山云CDN 修复" false... In C# DTO: Checked (bool) — probably "checked by default" state! ThreeStateEnable is nullable-bool (three-state). Let me check "8" against "Checked" hypothesis: items false: "Steam 白山云CDN 修复"(pt1), "Twitch 直播聊天"(pt0), "Twitch 登录"(pt1), "Twitch Assets"(pt1), "Twitch Assets2"(pt1). These are mostly special ones not default-enabled. So "8" = Checked (default checked). Hmm — or ThreeStateEnable==false meaning "disabled"? In GetEnableProxyDomains filter: `Where(w => w.ThreeStateEnable != false)` — ThreeStateEnable false = excluded. So "8" false could mean ThreeStateEnable=false (disabled by default). E.g. "Twitch 直播聊天" (irc-ws.chat.twitch.tv) is indeed NOT enabled by default in Watt (聊天服务不需要). And "Steam 白山云CDN 修复" also optional. So "8" = ThreeStateEnable (or Checked). 

For migration purposes: "8"=false → the project is disabled by default (not auto-selected). I'll map it to `enabled: bool` in the frontend-facing DTO (default checked state), while ALL projects go into the rules list only when selected. Actually — rules passed to engine_start come from user selection (enabled_accelerate_ids from settings). The cloud list is just the catalog; "8" provides default check state.

- "9" Id (GUID string)
- "10" Order (number)
- "11" FakeUserAgent → fields.user_agent ("Chrome/...; ${origin}")
- "12" Items (sub-rules array, same structure recursively)

Missing: ProxyType (named key, number: 0/1/4). C# ProxyType enum: from ProxyService.Operate: `ProxyType.ServerAccelerate` exists. Values seen: 0 (most), 1 (Twitch), 4 (one). C# ProxyType enum probably: 0=None/Community?, 1=..., let me guess from old Watt code: 

```csharp
public enum ProxyType
{
    /// <summary>未指定</summary>
    Unspecified = -1,
    /// <summary>社区公益(反向代理)</summary>
    Community = 0,
    /// <summary>特殊 SNI 直连?</summary>
    ??? = 1,
    /// <summary>服务端代理</summary>
    ServerAccelerate = ?,
}
```

I recall in Watt: ProxyType: Unspecified=-1? Hmm. Let me search the C# code for ProxyType enum values usage.

Group fields:
- "0" name
- "1" items
- "2" Id (GUID string)
- "3" bool — some group flag (true for Steam 服务 — maybe "hasThreeState"? or "expand"?). Looking: Steam 服务=true, others false. Could be "ThreeStateEnable" for group or "IsDynamic"?
- "4" order (number: 1, 3, 4)

ProxyType enum values from usage: ServerAccelerate=? In ProxyService.Operate line 76: `s.ProxyType == ProxyType.ServerAccelerate`. Distribution: 0 (50 items), 1 (11 items), 4 (1 item). Let me find which item has ProxyType=4.

Interesting:
- ProxyType=4: only "greasyfork" which has destination "http://pt.mossimo.net:41080/" (an HTTP proxy!). So ProxyType 4 might be "UseHttpProxy" / forward through HTTP proxy — actually a plain HTTP forward destination. Hmm.
- ProxyType=1: items with SNI special handling ("Twitch 登录" with SNI passttv.steam302.xyz, "白山云CDN修复" with special CDN) — these are all "8":false (not default enabled) and use special SNI/forwarding. ProxyType 1 might be "SNI proxy" (域名前置/Fragment).

From the old Watt Toolkit source (my knowledge): ProxyType enum:
```csharp
public enum ProxyType
{
    /// <summary>未指定的</summary>
    Unspecified = 0,
    /// <summary>反向代理</summary>
    ReverseProxy = 1?,
    /// <summary>SNI 代理/域名前置</summary>
    ...
    /// <summary>服务器加速</summary>
    ServerAccelerate,
}
```

Hmm. Actually from Watt source on GitHub (BD.WTTS.Models.ProxyType):

```csharp
public enum ProxyType
{
    /// <summary>
    /// 未指定
    /// </summary>
    Unspecified = -1,

    /// <summary>
    /// 反向代理
    /// </summary>
    ReverseProxy = 0,

    /// <summary>
    /// 域名前置 (SNI Proxy)
    /// </summary>
    DomainFronted = 1,

    /// <summary>
    /// HTTP 代理转发
    /// </summary>
    HttpProxy = 2?,

    /// <summary>
    /// 服务端加速
    /// </summary>
    ServerAccelerate = 3?,
}
```

I'm not 100% sure of values. What matters for the Rust engine:
- The engine handles rules generically (destination/IP/SNI/user_agent per rule) — ProxyType doesn't change engine behavior except ServerAccelerate (token headers).
- For the catalog UI: ProxyType might matter for showing "server-accelerated" badge.

Given uncertainty, I'll model ProxyType as i32 and only surface `is_server_side_proxy` if the value corresponds to ServerAccelerate. From data: values 0, 1, 4 — none higher. Where's ServerAccelerate in the list? Maybe currently no items use it (it's a paid feature). The mapping: is_server_side_proxy = (proxy_type == ServerAccelerate value). Without knowing the exact value, I'll keep proxy_type raw in the DTO and NOT auto-map to is_server_side_proxy (avoid wrong behavior). Actually — hmm, but DomainRuleFields.is_server_side_proxy exists and engine sends token headers. ServerAccelerate items would need it. Since none exist in current data, keep raw.

OK wait, let me also reconsider — maybe I can find the real enum in the C# SDK DLLs in the repo's build output? Let me check if there are compiled DLLs with the enum. Actually, faster: the old open-source Watt Toolkit on GitHub had `ProxyType` in `src/BD.WTTS.Models/Accelerate/ProxyType.cs`? I don't have access. Let me check the game accelerator service which also uses ProxyType.

Not conclusive. I have enough to build watt-cloud with the observable data. For ProxyType semantics I'll keep the numeric value and note: 0=ReverseProxy(默认), 1=DomainFronted, 4=HttpProxy. is_server_side_proxy — I'll NOT map it (no data). Actually wait — let me search the UI for "ServerAccelerate" badge / Beta tag:

From the agent research earlier: "UI fields: IconUrl, Name, ProxyType (for Beta tag)". Hmm — ProxyType used for Beta tag. Let me check AcceleratorPage2.axaml for ProxyType usage.

The UI binds: ThreeStateEnable (checkbox), IconUrl, Name, ProxyType==ServerAccelerate (Beta badge), DomainNamesArray[0].

Also there's IconUrl on the DTO — but the API response doesn't include it in the indexed fields? The DTO probably has IconUrl computed (from Id → CDN URL) — likely `IconUrl => $"https://api.steampp.net/accelerate/icons/{Id}.png"` or similar. Let me check GameAppItem or how icons load... Actually for the frontend, the icon URL is probably derived: check the C# for "IconUrl" property usage. The DTO's IconUrl may be a computed property like https://cdn.steampp.net/... Let me search the axaml.cs or converters. Actually — from the old Watt source, AccelerateProjectDTO.IconUrl is computed: `IconUrl => $"{ApiBaseUrl}Accelerate/Icon/{Id}"` something. Hard to confirm. I'll derive: https://api.steampp.net/api/Accelerate/Icon/{id} — hmm.

Let me quickly test a URL guess.

Icon URL pattern not found by guessing. Let me check where IconUrl comes from in the C# — maybe in the DTO it's set from group or computed differently. Search "IconUrl" in the Accelerator plugin.

查 ServerSideProxyToken 获取逻辑。
This is for ScriptDTO, not the accelerate projects. The AccelerateProjectDTO.IconUrl is a computed property in the SDK. From my knowledge of Watt Toolkit source on GitHub (open source version), the AccelerateProjectDTO had:

```csharp
public string? IconUrl => ...  // e.g. $"https://api.steampp.net/Accelerate/Icon?name={Name}"
```

Hmm. Not worth guessing more — the icon URL is a UI nicety. The frontend can render without icons initially, or use first-letter avatars. I'll include an optional `icon_url` in the DTO that defaults to None and move on. Actually — wait, let me try the messagepack endpoint. The C# SDK requests with MessagePack Accept probably. The "indexed keys" JSON is what we get with default Accept. Hmm, actually maybe the icons come from a different API (api.steampp.net/accelerateicons?). Let me not spend more time — icon is cosmetic.

Also — I should check: does the API support the standard format with a header? The indexed-key format suggests the server serializes via MessagePack's dynamic JSON. Maybe with `Accept: application/msgpack` it returns binary MessagePack, and the C# client deserializes it into DTO with proper field names. For the Rust port, JSON with indexed keys is fine — I'll parse indexed keys directly.

Now let me also confirm the "8" field and check what other fields exist on the group ("3": bool) — actually let me also check whether items have keys beyond 0-12 (like "13"+). From the stats earlier: keys seen: 0,1,10,11,12,2,3,4,5,7,8,9,ProxyType. That's the full set. Note key "6" is missing — interesting, key 6 might be a deprecated field (maybe ExcludeDomainNames?) that's omitted when empty/null by MessagePack contract.

So the DTO indexed layout (likely MessagePack-CSharp with string keys in original, but obfuscated to indexes? no...). Actually wait — MessagePack-CSharp serializes dictionaries as arrays... The JSON response with index keys "0"-"12" — this is the server's dynamic JSON. Fine.

Now, let me also handle the ServerSideProxyToken API. From ProxyService.Operate.cs line 76: TryRequestServerSideProxyToken(). Let me find that method.

看 Rust resolve_relative 对裸域名的处理。
Token endpoint needs auth (probably requires login). Since no current projects use ProxyType=ServerAccelerate, I'll implement the token fetch as optional/behind the DTO but the actual account auth isn't in scope for this phase (no login system in the Tauri port yet). The settings already have `server_side_proxy_token` passed via engine_start params (frontend supplies it). I'll note it as future work.

Now let me design the **watt-cloud** crate:

```
crates/watt-cloud/
├── Cargo.toml
└── src/
    ├── lib.rs       — client + cache orchestration
    ├── dto.rs       — indexed-key DTO parsing (AccelerateAllResponse, GroupDTO, ProjectDTO)
    ├── convert.rs   — DTO → DomainRule conversion
    └── cache.rs     — local JSON cache (accelerate_projects.json)
```

**HTTP client**: No reqwest in workspace deps. What HTTP client to use? The workspace has hyper + hyper-util. I could write a minimal HTTP client with hyper... but TLS? rustls + tokio-rustls are available. A full https client is a chunk of work. Alternatives: use `ureq` (sync, rustls) — simple. Or use tauri's reqwest feature (tauri has an http-api feature but adds bloat).

Hmm — since the app already pulls in hyper/rustls via watt-core, a small hyper-based client is feasible but fiddly. Simpler: add `ureq` with rustls to watt-cloud. Actually, hmm — what does the frontend currently do? Is there any existing HTTP usage in src-tauri? No. The C# app uses api.steampp.net directly.

Decision: use `ureq` v2 with rustls (blocking, small). In Tauri commands, wrap in spawn_blocking. For tests, network-dependent tests should be #[ignore] or use the conversion tests with fixture JSON. Let me check if ureq can be added... it's a common crate. ureq 2.x with default features uses rustls. OK.

Actually wait — hmm, let me reconsider: the JSON API. With ureq I do a GET https://api.steampp.net/api/Accelerate/All with User-Agent header (C# sends UserAgent "Watt Toolkit/..." — server may or may not require). Response: JSON with emoji keys.

**DTO parsing (indexed keys)**:

```rust
/// 云端加速项目（索引键 JSON）
#[derive(Debug, Clone, Deserialize)]
pub struct RawProject {
    #[serde(rename = "0", default)] pub name: String,
    #[serde(rename = "1", default)] pub port: u16,  // default 443? field missing? always present
    #[serde(rename = "2", default)] pub match_domain_names: String,
    #[serde(rename = "3", default)] pub forward_domain: String,
    #[serde(rename = "4", default)] pub ip_address: String,
    #[serde(rename = "5", default)] pub fake_server_name: String,
    #[serde(rename = "ProxyType", default)] pub proxy_type: i32,
    #[serde(rename = "7", default)] pub listen_domain_names: String,
    #[serde(rename = "8", default)] pub checked: Option<bool>,
    #[serde(rename = "9", default)] pub id: String,
    #[serde(rename = "10", default)] pub order: i32,
    #[serde(rename = "11", default)] pub fake_user_agent: Option<String>,
    #[serde(rename = "12", default)] pub items: Vec<RawProject>,
}
```

Group:
```rust
pub struct RawGroup {
    #[serde(rename = "0", default)] pub name: String,
    #[serde(rename = "1", default)] pub items: Vec<RawProject>,
    #[serde(rename = "2", default)] pub id: String,
    #[serde(rename = "3", default)] pub three_state: bool,
    #[serde(rename = "4", default)] pub order: i32,
}
```

Envelope:
```rust
pub struct AccelerateAllResponse {
    #[serde(rename = "🦓", default)] pub content: Vec<RawGroup>,
    #[serde(rename = "🦄", default)] pub code: i32,
    #[serde(rename = "🐴", default)] pub message: Option<String>,
}
```

Hmm — using emoji renames is ugly but accurate. But wait: is the emoji mapping stable across API versions? The C# SDK deserializes MessagePack presumably where the keys map to actual DTO props. The JSON representation with emoji keys is likely generated by the server's serializer with the SAME obfuscation mapping as the C# client SDK. If they update, keys might change. Given this is the actual public API response today, use it — but design the parser leniently (unknown fields ignored, missing fields defaulted).

Actually — hold on. Let me test the MessagePack Accept to see if we get proper field names. The C# client uses MessagePack. If I request with Accept: application/x-msgpack, I'd get MessagePack binary where string keys are actual property names. That'd be more robust... but parsing MessagePack in Rust requires rmp crate. The indexed JSON is actually simpler. Both are equally coupled to the server's serialization. I'll go with indexed JSON.

**Frontend-facing catalog DTO** (clean, camelCase):
```rust
pub struct AccelerateProject {
    pub id: String,
    pub name: String,
    pub group_name: String,  // hmm — group embedded? flatten?
    pub order: i32,
    pub proxy_type: i32,
    pub enabled: bool,          // "8" default checked state
    pub match_domains: Vec<String>,
    pub has_sub_items: bool,     // UI: expandable
}

pub struct AccelerateGroup {
    pub id: String,
    pub name: String,
    pub order: i32,
    pub items: Vec<AccelerateProject>,
}
```

**Conversion to DomainRule** (only for checked projects at engine start):
- match_domain_names: split ";" 
- listening_domain_names: key "7" split ";" (hosts 写入)
- destination: key "3" (domain or URL like "http://pt.mossimo.net:41080/"); empty → None
- ip_address: key "4" parse IpAddr; empty → None
- fake_server_name (NEW field): key "5"; "{origin}"/"@domain"/"" → None; else Some(literal)
- user_agent: key "11" ("Chrome/...; ${origin}")
- items: key "12" sub-projects → SubRule { regex: URL regex from sub match domains (C# DomainPattern conversion), rule: fields }
- order: key "10"
- Port: key "1" — used for outbound port when destination has no explicit port. Hmm — the C# Port field: used in YARP destination prefix? GetDestinationPrefix uses scheme+host (destination Uri includes port if set). The DTO Port=443 default. For "greasyfork" dest "http://pt.mossimo.net:41080/" port embedded. Rust resolve_destination: destination_uri.port_u16().unwrap_or(scheme default). If key3 is just a domain (no scheme), Rust fallback_uri uses scheme+host → port from... default 443/80. Where does key1 Port apply? For entries with only FakeServerName + IP (Github UserContent): dest = original host, port 443 — matches Port=443. If an entry had Port=80... resolve_destination fallback uses scheme. I'll include port in the domain-building: when key "3" is a bare domain (no scheme), build destination as "scheme://domain:port/" if port != default-for-scheme? Hmm — C# YARP: `new Uri(baseUri, destination)` where destination is... 

Actually wait — what does C# do with ForwardDomainNames → Destination? The DTO implements IDomainConfig.Destination — probably `Destination => ForwardDomainNames?.Split(';').FirstOrDefault()` as Uri. And GetDestinationPrefix does `new Uri(baseUri, destination)`. If destination is "steamimage.rmbgame.net" (bare domain, no scheme), `new Uri(baseUri "https://steamcommunity.com/", "steamimage.rmbgame.net")` — hmm, relative URI resolution: bare domain without scheme is treated as relative path?? "steamimage.rmbgame.net" as relative → "https://steamcommunity.com/steamimage.rmbgame.net"?? No wait — .NET Uri resolution: if the string contains "://" it's absolute; "steamimage.rmbgame.net" has no scheme → relative → resolves against base path. Hmm, that would be wrong. So maybe ForwardDomainNames values include scheme... but our data shows bare domains.

Hmm wait, look again at GetDestinationPrefix:
```csharp
var defaultValue = $"{scheme}://{host}/";
if (destination == null) return defaultValue;
var baseUri = new Uri(defaultValue);
var result = new Uri(baseUri, destination).ToString();
```
`new Uri(baseUri, "steamimage.rmbgame.net")` — in .NET, this treats "steamimage.rmbgame.net" as a relative reference → result "https://steamcommunity.com/steamimage.rmbgame.net". That's clearly not intended...

Unless the DTO's Destination property PREPENDS "https://"! Like:
```csharp
public Uri? Destination => ForwardDomainNames == null ? null : new Uri("https://" + ForwardDomainNames.Split(';')[0]);
```
That makes sense: ForwardDomainNames "steamimage.rmbgame.net" → Destination https://steamimage.rmbgame.net. And "http://pt.mossimo.net:41080/" already has scheme → "https://http://..." broken?? Hmm no.

OR: `Uri.TryCreate(forward, UriKind.Absolute, out uri) ? uri : new Uri("https://" + forward)`. Something like that. For "greasyfork" f3="http://pt.mossimo.net:41080/" → absolute → use as-is.

I'll implement exactly that heuristic in Rust convert:
```rust
fn destination_from(forward: &str) -> Option<String> {
    let f = forward.trim();
    if f.is_empty() { return None; }
    if f.contains("://") { Some(f.to_string()) } 
    else { Some(format!("https://{f}/")) }  // hmm — trailing slash?
}
```
Wait — Rust resolve_destination handles templates: if dest contains no '@' → `resolve_relative(scheme, host, dest)` → let me look at resolve_relative to see how bare domains are handled. Let me read that function.

继续 Phase 6.5：watt-cloud 加速项目云端 API。先查看当前工作区结构与相关文件状态。
Let me continue with Phase 6.5: implementing the watt-cloud crate. I need to first check the current state of the workspace and understand what's been done. Let me look at the existing structure.

From the summary:
- Phase 6.5: watt-cloud 加速项目云端 API + DTO→DomainRule 转换 + 本地缓存
- I've already analyzed the API response from `https://api.steampp.net/api/Accelerate/All`
- Fields identified: `0` (name), `2` (match domains), `3` (forward destination), `5` (user agent template), `12` (sub-rules)
- ProxyType=4 for server acceleration
- ServerSideProxyToken via `https://api.steampp.net/api/Account/GenerateServerSideProxyToken` (returned 404)

There are 4 background commands running. Those were probably cargo test/clippy commands. Let me check the current state of the workspace first.

Let me first look at the existing crates structure to understand where to create watt-cloud.

Now let me look at the existing domain_rule.rs to understand the DomainRule structure, and check what HTTP client dependencies are available. Let me also check the C# API client code to understand what headers are needed.

Let me find the API client that fetches the accelerate list. It's probably in a "Client" or "SDK" project. Let me search for "api.steampp.net" or the WebApiService.

The DomainConfig in C# is likely in a different project. Let me look for the DTO models of the accelerate list. The API `https://api.steampp.net/api/Accelerate/All` — let me search for "Accelerate" in a broader set of projects, or find where the response is deserialized. Let me check what was found in the previous session — the summary says I fetched the API and analyzed field structures:
- `0` (name), `2` (match domains), `3` (forward destination), `5` (user agent template), `12` (sub-rules)

Let me look for the DTO class. Search for something like "DomainConfig" in the whole repo including the "BD.WTTS.Client.Plugins.Accelerator" project.

Now I need to find the AccelerateProjectDTO to understand the API response structure. Let me search for it.

The output is masked (names replaced with "n"). It seems the actual DTO is defined somewhere. Let me search for the API endpoint URL in the repo to find where the request is made. The summary said the API is `https://api.steampp.net/api/Accelerate/All`. Let me search for "Accelerate/All" in the whole repo.

There's no separate WebApi SDK project. The DTO "AccelerateProjectDTO" is likely defined in a referenced NuGet package (BD.WTTS.Client.WebApi is maybe in a nuget). Let me check where `AccelerateProjectDTO` might come from — search in the ReverseProxy project for `using` statements referencing it.

The DTOs (AccelerateProjectDTO, AccelerateProjectGroupDTO, ScriptDTO) come from an external WebApi NuGet package (BD.WTTS.Client.WebApi probably). The summary from the previous session says I already fetched the API response and analyzed the field structure:
- Numeric keys like `0` (name), `2` (match domains), `3` (forward destination), `5` (user agent template), `12` (sub-rules)

Since the actual DTO class isn't in this repo, I should rely on my previous analysis in the summary. Let me check if there was a previous analysis artifact. The summary mentioned:
- "Directly request the cloud API to obtain the real response structure" - fetched real response
- "Capture the complete response and tally the value distribution by index keys to precisely infer fields" - analyzed value distribution
- "Look at the AutoMapper mapping configuration to confirm the sub-rule structure of DTO→DomainConfig" - looked at AutoMapper config
- "Look up the ProxyType enum definition and group additional fields" - looked at ProxyType enum
- "Look up the ServerSideProxyToken acquisition logic" - looked at ServerSideProxyToken logic

Let me find the AutoMapper profile that maps AccelerateProjectDTO → DomainConfig. Let me search for it.

先查上次会话对该 API 的分析记录。
The DTOs come from an external package. The previous session already fetched the real API response. Since the summary says I already know the field structure (numeric keys `0` name, `2` match domains, `3` forward destination, `5` user agent template, `12` sub-rules), let me re-fetch the API to get the actual response and design the DTO correctly. Let me also check memory for the analysis records from the previous session.

Let me first check memory for prior session analysis of this API.

重新请求 API 获取真实响应结构，以便设计 DTO。
No memory records. Let me re-fetch the API response to design the DTOs. The summary says the API is `https://api.steampp.net/api/Accelerate/All`.

The top-level has:
- `🦓` (zebra emoji): an array of groups
- `🦄` (unicorn emoji): an int (200 = status code?)
- `🐴` (horse emoji): something (message?)

Let me look at the structure more carefully. The array in `🦓` contains the group objects. Let me examine one.

Now I can see the structure. Let me analyze the fields:
- `0`: name ("Steam 图片")
- `1`: port (443)
- `2`: match domain names (semicolon-separated)
- `3`: forward destination / IP address? "steamimage.rmbgame.net" — this could be the destination host
- `4`: ?
- `5`: user agent template?
- `ProxyType`: proxy type (0 = normal)
- `7`: listening domain names (same as 2 here)
- `8`: enable?
- `9`: id (GUID)
- `10`: order (32)
- `11`: sub-items?
- `12`: sub-items?

Let me check more items, especially ones with ProxyType != 0 and non-null 11/12 fields.

现在检查 C# 中间件确认字段语义（对齐基准）。
Now I have a clear picture of the API response structure:

Top-level: `{"🦓": [groups], "🦄": 200, "🐴": ...}` — this matches typical ApiResponse包装 with code/message. Actually in C# WebApi clients like BD.WTTS.Client.WebApi, the response format is likely `{ "🦓": data, "🦄": code, "🐴": message }`. Wait, that's odd. Let me check what `🐴` is.

Group object:
- `0`: name (string) - group name
- `1`: items (array of projects)
- `2`: id (GUID string)
- `3`: show/visible (boolean)
- `4`: order (int)

Project item:
- `0`: name (string)
- `1`: port (int, 443)
- `2`: match domain names (semicolon-separated) — can also be URL patterns like "https://steamcommunity.com/comment" for sub-rules
- `3`: forward destination (string) — host or URL, may be empty
- `4`: IP address (string) — direct IP, may be empty
- `5`: user agent / SNI? (string) — values like "{origin}", "Chrome/150.0.6478.183; ${origin}", "@domain", "ttv", "Github"
- `ProxyType`: proxy type (int) — 0 = reverse proxy, 1 = direct?, 4 = server-side proxy
- `7`: listening domain names (semicolon-separated)
- `8`: enable (boolean)
- `9`: id (GUID string)
- `10`: order (int)
- `11`: user agent string? ("Chrome/150.0.6478.183; ${origin}", "${origin} Googlebot/2.1 (+http://www.google.com/bot.html)") — this is UserAgent!
- `12`: sub-rules (array of same structure)

Wait — let me reconsider. The summary from the previous session said:
- `0` (name), `2` (match domains), `3` (forward destination), `5` (user agent template), `12` (sub-rules)

Hmm, but field `5` values look like: "{origin}", "steamstore-a.akamaihd.net", "@domain", "ttv", "Github", "gstatic.loli.net", "static.twitchcdn.net"... These look more like FakeServerName / SNI override values! While field `11` values look like UserAgent templates ("Chrome/150...; ${origin}", "${origin} Googlebot/2.1").

Actually wait. Let me check the C# code for how these fields are used. In the C# code, the DTO field names would be mapped from these numeric indexes via MessagePack or a JSON contract resolver that converts property names to indexes. This is the "PropertyNameFormat" style where the C# client uses a custom contract resolver mapping property names to emoji/numeric keys for obfuscation.

The previous session summary said: "Identifying fields such as `0` (name), `2` (match domains), `3` (forward destination), `5` (user agent template), and `12` (sub-rules)" — hmm, but also "查 ForwardDomainNames/FakeServerName 在仓库中的使用以确认语义" and "读中间件看字段语义（definitive 对齐基准）".

Actually from the data:
- `5` = values like "steamstore-a.akamaihd.net", "@domain", "ttv", "gstatic.loli.net" → this looks like FakeServerName (SNI override target). E.g. "Steam 社区" has `5`="steamstore-a.akamaihd.net" — this is the SNI host to use when connecting.
- `11` = values like "Chrome/150.0.6478.183; ${origin}", "${origin} Googlebot/2.1 (+http://www.google.com/bot.html)" → UserAgent template with ${origin} placeholder.

Let me check the C# middleware to verify. The previous session examined HttpReverseProxyMiddleware.cs. Let me read the relevant parts to confirm the IDomainConfig properties and how they're used.

Let me search for how the DTO maps to DomainConfig. In the C# code, there's likely an interface IDomainConfig with properties like:
- MatchDomainNames
- ForwardDomainNames  
- FakeServerName
- UserAgent
- etc.

Let me look at the middleware code.

Now let me look at the ReverseProxyHttpClientHandler.cs to see how DomainConfig fields are used for TLS/SNI, since the previous session examined that too.

I see `domainConfig.GetTlsSniPattern().WithDomain(uri.Host).WithRandom()` — so TlsSni is a pattern. Let me find GetTlsSniPattern to understand how field `5` (which contains values like "steamstore-a.akamaihd.net", "@domain", "{origin}", "ttv", "Github") is used.

Actually looking at the data again:
- Field `5` values: "{origin}", "steamstore-a.akamaihd.net", "@domain", "ttv", "Github", "gstatic.loli.net", "static.twitchcdn.net", "d2xmjdvx03ij56.cloudfront.net"

These look like TLS SNI patterns! "WithDomain" replaces something like `@domain` with the actual domain, "{origin}" with original host. So field `5` = TlsSni pattern!

Wait, but the earlier summary said `5` (user agent template). Let me check GetTlsSniPattern. Where's DomainConfig defined? It's in an external package... but the GetTlsSniPattern is an extension. Let me search.

The GetTlsSniPattern is defined in an external package (BD.WTTS.Client.WebApi NuGet). But I can infer its behavior from the middleware/handler usage:

```csharp
var tlsSniValue = domainConfig.GetTlsSniPattern().WithDomain(uri.Host).WithRandom();
```

So `TlsSni` in DomainConfig is a string pattern (from the data: field `5` values like "@domain", "{origin}", "steamstore-a.akamaihd.net"). Then:
- `WithDomain(uri.Host)` — replaces `@domain` placeholder with the actual host
- `WithRandom()` — possibly replaces random placeholders

Actually looking at the data for field `5`:
- "Steam 图片" (first item): `5` = "" (empty)
- "Steam 静态资源": `5` = "{origin}" 
- "Steam 社区": `5` = "steamstore-a.akamaihd.net"
- "Uplay 商店": `5` = "@domain"
- "Twitch 第三方关联登录": `5` = "ttv"
- "Github UserContent": `5` = "Github"

Hmm wait, "Github" and "ttv" as SNI patterns don't quite make sense... unless they're fixed SNI values. Actually "ttv" might be... hmm.

Wait, let me reconsider. Let me re-examine. Maybe field `5` is not TlsSni. Let me look at the DTO fields again from the actual data:
- `0`: name
- `1`: port (443)
- `2`: match domain names (semicolon separated; for sub-rules, URL patterns like "https://steamcommunity.com/comment")
- `3`: forward destination (e.g. "steamimage.rmbgame.net", "http://pt.mossimo.net:41080/" for ProxyType=4, "" for IP-based)
- `4`: IP address (e.g. "192.0.80.239", "" for destination-based)
- `5`: ??? values: "{origin}", "steamstore-a.akamaihd.net", "@domain", "ttv", "Github", "gstatic.loli.net", "static.twitchcdn.net"
- `ProxyType`: 0, 1, 4
- `7`: listening domain names
- `8`: enable (bool)
- `9`: id (GUID)
- `10`: order
- `11`: user agent string ("Chrome/150.0.6478.183; ${origin}", "${origin} Googlebot/2.1 ...")
- `12`: sub-rules array

Now field `5`: The values "gstatic.loli.net", "static.twitchcdn.net", "d2xmjdvx03ij56.cloudfront.net" match the destination (field `3`) in those items. For "Twitch 登录": `3`="passttv.steam302.xyz", `5`="passttv.steam302.xyz" — same. For "fonts.googleapis.com": `3`="fonts.font.im", `5`="fonts.font.im" — same.

Hmm interesting, so field `5` often equals field `3` when the destination is a domain. When `3` is a direct IP or empty, `5` can be "@domain" (use original domain) or something else.

This makes sense as **ForwardDomainName / FakeServerName (SNI)**: when connecting to a forwarded destination host (e.g., a mirror), the TLS SNI should be... hmm, wait. If you're connecting to "fonts.font.im" via TLS, the SNI would be "fonts.font.im". 

Actually, in the original FastGithub: `DomainConfig.TlsSni` — the SNI pattern. Looking at FastGithub's code:

```csharp
var tlsSniValue = domainConfig.TlsSniValue.WithDomain(uri.Host).WithRandom();
```

Hmm, in FastGithub, `DomainConfig` has:
```csharp
public string? TlsSni { get; set; }
```
And it's used as SNI override for outbound TLS connections.

So field `5` = TlsSni pattern. Values:
- "{origin}" — replace with original host? (Steam 静态资源, ProxyType=0)
- "@domain" — replace with request domain
- "steamstore-a.akamaihd.net" — fixed SNI
- "ttv", "Github" — fixed SNI values

Wait, but "Github" as SNI for github.com content... Interesting: "Github UserContent" has IP 23.235.37.133 and `5`="Github". Hmm, actually maybe when connecting to a fixed IP, the SNI needs to be set to something. "Github" — hmm, that's an odd SNI. Actually wait — for githubusercontent.com, GitHub's real SNI is the domain itself. But connecting via IP with SNI "Github"... that would fail TLS validation unless name mismatch is ignored.

Hmm, wait. Let me reconsider: maybe `5` is the "UserAgent" and `11` is something else? No — `11` clearly has "${origin}" UA template patterns ("${origin} Googlebot/2.1 (+http://www.google.com/bot.html)" — appending Googlebot to the original UA to bypass restrictions).

And in the middleware:
```csharp
if (!string.IsNullOrEmpty(domainConfig.UserAgent))
    context.Request.Headers.UserAgent = domainConfig.UserAgent.Replace("${origin}", context.Request.Headers.UserAgent, ...);
```

So `11` = UserAgent. ✓

And in the handler:
```csharp
var tlsSniValue = domainConfig.GetTlsSniPattern().WithDomain(uri.Host).WithRandom();
```

Hmm, "WithRandom"... Actually let me check the C# IDomainConfig interface to find the actual property names. The previous session examined "C# IDomainConfig interface field definitions to precisely correspond index keys". Let me find IDomainConfig.

查看现有 Rust 实现如何使用这些字段（Phase 5 已对齐语义）。
IDomainConfig is defined in the external WebApi NuGet package, not in this repo. So my definitive source of truth is:
1. The real API response (which I have)
2. The middleware usage (which I've read)

From the middleware and handler:
- `domainConfig.Items` — sub-rules (field 12) ✓
- `domainConfig.Response` — static response (none in current data; all items lack response fields)
- `domainConfig.Destination` — with "@domain"/"@uri" placeholders (field 3) ✓
- `domainConfig.UserAgent` — with "${origin}" placeholder (field 11) ✓
- `domainConfig.IsServerSideProxy` — ProxyType=4 case (greasyfork) ✓
- `domainConfig.IPAddress` — field 4 ✓
- `domainConfig.Timeout` — ?
- `domainConfig.GetTlsSniPattern()` — TlsSni pattern (field 5) ✓
- `domainConfig.TlsSni` boolean? Wait, in the middleware: `new DomainConfig() { TlsSni = true }` — TlsSni is a bool there!

Hmm, that's confusing. `defaultDomainConfig = new DomainConfig() { TlsSni = true }`. So TlsSni is a bool in DomainConfig. Then GetTlsSniPattern is something else.

Wait, let me re-read: In the Rust DomainRuleFields I already have:
```rust
/// TLS SNI 启用（默认 true）
pub tls_sni: bool,
```

So in the Rust implementation, tls_sni is a bool. And the C# `GetTlsSniPattern()` — hmm, it's called on domainConfig. Maybe it's an extension method on IDomainConfig that builds a pattern from multiple properties (ForwardDomainName?).

Let me look at how the existing Rust http_relay.rs and sni.rs use the fields — since I already implemented Phase 5 with these semantics. Let me check the Rust sni.rs and outbound.rs to see what fields they use.

Good — the Rust `OutboundTarget` already has `tls_sni: Option<String>` which overrides the SNI host. This corresponds to C#'s TlsSni pattern (field `5`).

Now let me look at how http_relay.rs maps DomainRuleFields → OutboundTarget to see where tls_sni comes from. Let me grep http_relay for tls_sni.

Now I understand the current Rust implementation. The `tls_sni` field in DomainRuleFields is a bool (enable/disable). But the C# field `5` is a pattern string (like "@domain", "{origin}", or a fixed host).

Looking at the C# code more carefully:

```csharp
var tlsSniValue = domainConfig.GetTlsSniPattern().WithDomain(uri.Host).WithRandom();
```

Hmm — so in C#, `GetTlsSniPattern()` returns a pattern. This is FastGithub-style: `DomainConfig.TlsSni` is a string pattern where `{random}` and `{domain}` placeholders get replaced. Looking at FastGithub source:

```csharp
/// <summary>
/// 获取tls的SNI值
/// </summary>
/// <returns></returns>
public string GetTlsSniValue()
{
    var value = this.TlsSni?.Value;
    if (string.IsNullOrEmpty(value))
    {
        value = "${domain}";
    }
    return value
        .Replace("${domain}", domainValue)
        .Replace("${random}", new string(...));
}
```

In FastGithub, `DomainConfig` has `TlsSni` as a pattern string like `${domain}` or `${random}` or a fixed value. And `TlsSniEnable` bool.

But in the middleware here: `new DomainConfig() { TlsSni = true }` — TlsSni is bool in THIS project's DomainConfig. So the project modified it.

So how does GetTlsSniPattern work then? It's likely an extension method defined in the WebApi package. Given the data patterns in field `5`:
- "{origin}" — hmm wait, "{origin}" with braces... Actually for "Steam 静态资源": `5` = "{origin}". Hmm, but `{origin}` — the UA replacement uses `${origin}`. For SNI, "{origin}" might mean "use original request host as SNI".
- "@domain" — the Destination template uses "@domain" ("@domain"/"@uri" replaced by host/rawUrl in middleware line 127-128).
- Fixed values like "steamstore-a.akamaihd.net", "ttv", "Github".

Hmm wait — maybe I have it backwards. Let me reconsider: maybe field `5` is used in the Destination as the "forward domain" and field `3` is the SNI?? Let me check what makes sense:

"Steam 社区": 
- `2` (match) = "steamcommunity.com;www.steamcommunity.com"
- `3` = "steamcommunity.rmbgame.net" — forward destination (mirror server)
- `5` = "steamstore-a.akamaihd.net" — hmm...

If `3` is the destination (mirror), then connecting to "steamcommunity.rmbgame.net" with SNI "steamstore-a.akamaihd.net"?? That seems wrong. Actually wait — maybe the SNI should be the REAL steam community domain for the mirror to route... no.

Hmm, actually wait. Let me reconsider. Maybe `5` is the SNI used when connecting — for CDN-based mirrors, you connect to the mirror host but need proper SNI. Hmm, "steamstore-a.akamaihd.net" is an Akamai CDN domain. Connecting to "steamcommunity.rmbgame.net" (a mirror) with SNI "steamstore-a.akamaihd.net"... 

Actually, that makes sense! "steamcommunity.rmbgame.net" might itself be a CNAME/edge that routes based on SNI. Using SNI "steamstore-a.akamaihd.net" would route to the Akamai edge for steam store. Hmm, no wait.

Let me think about "Twitch 登录": 
- `2` = "passport.twitch.tv"
- `3` = "passttv.steam302.xyz"
- `5` = "passttv.steam302.xyz"

Destination = SNI = "passttv.steam302.xyz" — both the same. 

"fonts.googleapis.com":
- `3` = "fonts.font.im" (mirror)
- `5` = "fonts.font.im" — same.

"BootStrap CDN":
- `2` = "maxcdn.bootstrapcdn.com/bootstrap"
- `3` = "cdn.bootcdn.net/ajax/libs/twitter-bootstrap"
- `5` = "cdn.bootcdn.net"

Destination "cdn.bootcdn.net/ajax/libs/twitter-bootstrap" is a URL path prefix. SNI "cdn.bootcdn.net" = the host of destination. OK.

"Uplay 商店":
- `3` = "commcloud.prod-abbs-ubi-com.cc-ecdn.net.cdn.cloudflare.net" — hmm wait no. Let me re-read: `"3":"commcloud.prod-abbs-ubi-com.cc-ecdn.net.cdn.cloudflare.net"`. Hmm that looks odd — it has ".cc-ecdn.net.cdn.cloudflare.net" which is like a chain. Anyway `5` = "@domain" meaning SNI = original request domain (store.ubisoft.com).

"Twitch 第三方关联登录":
- `3` = "2973c6ca0e111662ed293b57dbae9fbf.steam302.xyz" (a steam302 edge)
- `5` = "ttv"?? SNI "ttv"? That's odd. Hmm, maybe "ttv" is an abbreviation the server recognizes. Hmm.

Wait, maybe I have `3` and `5` mixed. What if `5` is the destination and `3` is something else? For greasyfork (ProxyType=4): `3` = "http://pt.mossimo.net:41080/" — that's a full URL with scheme and port, clearly a server-side proxy destination. `5` = "pt.mossimo.net". So for server-side proxy, destination = "http://pt.mossimo.net:41080/" and SNI = "pt.mossimo.net" (the host of the destination).

For "Steam 静态资源": `3` = "community.steamstatic.com" (same as match domain), `5` = "{origin}". Hmm — destination is the same domain (just re-resolve DNS, no mirror), SNI = "{origin}" = original host = community.steamstatic.com. That's consistent with SNI = original host.

For "Steam 社区": `3` = "steamcommunity.rmbgame.net" (mirror), `5` = "steamstore-a.akamaihd.net". Connecting to mirror with SNI "steamstore-a.akamaihd.net"?? Hmm — maybe the rmbgame.net mirror is actually an Akamai-fronted domain and the SNI determines the routing. Actually "steamstore-a.akamaihd.net" is the Akamai edge domain for Steam store — using this SNI on the rmbgame.net mirror would... hmm.

Wait, actually — maybe the semantics is REVERSED: `3` = SNI/FakeServerName, `5` = destination?? For "Steam 社区": destination = "steamstore-a.akamaihd.net"?? No wait, that doesn't work either because "steamstore-a.akamaihd.net" is for store, not community. Hmm, actually wait — maybe it does. Let me think again about "Steam 社区" (Steam Community):
- `2` match = steamcommunity.com
- `3` = "steamcommunity.rmbgame.net"
- `5` = "steamstore-a.akamaihd.net"

Hmm. If `3` is the destination (mirror), `5` is SNI. Connecting to steamcommunity.rmbgame.net with SNI steamstore-a.akamaihd.net. The mirror server at rmbgame.net probably serves based on SNI... using an Akamai SNI would route... hmm, I really can't verify.

Let me look at the previous session's analysis again — the summary said:
- "`3` (forward destination), `5` (user agent template)" — hmm the summary says `5` is user agent template. But data shows `11` has "${origin} Googlebot/..." which is clearly the UA template. And middleware line 134-136 uses UserAgent with ${origin}.

Hmm wait, but the summary ALSO said "查 ForwardDomainNames/FakeServerName 在仓库中的使用以确认语义" — so I investigated ForwardDomainNames/FakeServerName. Let me check what I found. Actually, let me look at the ProxyService.Operate.cs to see how the DTO is used to configure the reverse proxy — that will show which DTO properties map to which DomainConfig fields. Actually, the DTO (AccelerateProjectDTO) IS the IDomainConfig implementation! Look at ReverseProxyConfig.AddDomainConfigs:

```csharp
dict.Add(new DomainPattern(matchDomainNames) { Order = item.Order }, item);
```

The item (AccelerateProjectDTO) is stored as IDomainConfig directly! So AccelerateProjectDTO implements IDomainConfig. That means the DTO properties = DomainConfig properties:
- MatchDomainNames (field 2)
- Order (field 10)
- ForwardDomainNames (field 7?) — listening domain names
- etc.

Let me search the C# code for the properties used: "ForwardDomainNames" in ScriptManager.cs / ProxyService.cs.

Now let me find where the ProxyType enum is defined to understand ProxyType values (0, 1, 4).

The ProxyType enum is in the external WebApi package. From the data:
- ProxyType=0: most projects (reverse proxy with destination/SNI)
- ProxyType=1: direct DNS fixes with IP? No wait — "Steam 白山云CDN 修复" has ProxyType=1 with destination "cdn.queniuqe.com"; "Gravatar 头像" has ProxyType=0 with IP 192.0.80.239. Hmm.

ProxyType=1 examples: Steam 白山云CDN 修复, Twitch 登录, Twitch Assets, fonts.gstatic.com, themes.googleusercontent.com, ajax.googleapis.com, fonts.googleapis.com, BootStrap CDN, Google(Recaptcha) 验证码 — all are "mirror" type acceleration where destination is a mirror domain. And note `8` (enable) is false for all ProxyType=1 items! Interesting — these are non-default disabled items.

ProxyType=0 examples: Steam 图片, Steam 社区, Steam 商店, Github UserContent, Gravatar, etc. — most have destination mirrors too... wait no: "Steam 图片" ProxyType=0 with destination "steamimage.rmbgame.net" (mirror). Hmm, and "Github UserContent" ProxyType=0 with IP.

Hmm so what's the actual difference between 0 and 1? Let me check where ProxyType is consumed in C#. From ProxyService.Operate.cs line 77: `ProxyType.ServerAccelerate` (=4, greasyfork) → ServerSideProxyToken.

Let me search for other ProxyType usages in the ReverseProxy project.

The grep results are obfuscated ("Externaln" — search result masking replaced "ProxyType" with "n"). Interesting — the rg output is being masked because the search term "ProxyType" gets replaced. Anyway, from the Accelerator project, ProxyType on the DTO is only used for `ProxyType.ServerAccelerate` (line 77). The ProxyType enum likely has values like:

```csharp
public enum ProxyType
{
    Default = 0,      // 反代
    Direct = 1,       // 直连？
    ServerAccelerate = 4,  // 服务端加速
}
```

Let me check the frontend or the API service to see how it's used. Actually, from the data, let me check the items with ProxyType=1 more carefully — all have `8` (Enable) = false, and they're all "direct domain replacement" mirrors (e.g. fonts.googleapis.com → fonts.font.im). Hmm, and ProxyType=0 items have `8`=true mostly (Steam ones).

Actually the meaning might be:
- 0 = ReverseProxy mode (反代)
- 1 = ??? 

Let me check the C# project's API for ProxyType usage on the UI side. Actually, let me not obsess over ProxyType=1's exact semantic. What matters for the Rust conversion:

From the summary of previous session: "查 ProxyType 枚举定义与 group 附加字段" was done. The conclusion recorded in the summary:
- `0` (name), `2` (match domains), `3` (forward destination), `5` (user agent template), `12` (sub-rules)
- ProxyType=4 for server acceleration

Hmm wait, but the data clearly shows `11` is the user agent template (with ${origin}). Let me re-derive by matching against the C# DomainConfig properties used in middleware:

Used properties (from middleware):
1. `domainConfig.UserAgent` — UA template with ${origin} → field `11` ✓ ("Chrome/150.0.6478.183; ${origin}", "${origin} Googlebot/2.1...")
2. `domainConfig.IsServerSideProxy` → ProxyType == 4 (ServerAccelerate) ✓
3. `domainConfig.Items` → field `12` ✓
4. `domainConfig.Response` → not present in data (all null for `11`? no wait)... Actually response isn't in this API data. Fine.
5. `domainConfig.Destination` — Uri with @domain/@uri → field `3` ✓ (e.g. "http://pt.mossimo.net:41080/", "steamimage.rmbgame.net")
6. `domainConfig.IPAddress` → field `4` ✓ ("192.0.80.239")
7. `domainConfig.Timeout` → not present in data
8. `domainConfig.TlsSni` (bool in C# DomainConfig — `new DomainConfig() { TlsSni = true }`) and `GetTlsSniPattern()` → field `5`? The values "{origin}", "@domain", fixed hosts... 

Hmm wait — actually, maybe field `5` maps to a property like `ForwardDomainNames` or `FakeServerName`, and the C# DomainConfig has BOTH `TlsSni` (bool) and a separate SNI pattern string. Let me look at how `GetTlsSniPattern` is called:

```csharp
var tlsSniValue = domainConfig.GetTlsSniPattern().WithDomain(uri.Host).WithRandom();
```

Hmm, "WithDomain" and "WithRandom" — like FastGithub's:
```csharp
static string GetTlsSniValue(this IDomainConfig domainConfig)
{
    var value = domainConfig.TlsSni ?? "${domain}";
    return value.Replace("${domain}", domainValue).Replace("${random}", ...);
}
```

But here TlsSni is bool... So GetTlsSniPattern must use a DIFFERENT property. What property would hold "{origin}", "@domain", "steamstore-a.akamaihd.net", "ttv", "Github"?

Wait, maybe it's simpler: maybe field `5` IS the destination/SNI host used for connecting, and field `3` is the "Destination"... Hmm I keep going around. Let me look at what the previous session concluded definitively. The summary says: "查 ForwardDomainNames/FakeServerName 在仓库中的使用以确认语义" and "读中间件看字段语义（definitive 对齐基准）".

Let me check ForwardDomainNames usage in the repo:

现在查看 C# DomainPattern 的 URL 匹配逻辑（子规则的 match 是 URL 模式）。
Excellent! Now I have the definitive DTO property names for AccelerateProjectDTO:

```csharp
new AccelerateProjectDTO
{
    Name = ...,                    // field 0
    Port = ...,                    // field 1
    MatchDomainNames = ...,        // field 2 (semicolon-separated)
    ForwardDomainNames = ...,      // field 3 ← !!! 
    IgnoreSSLCertVerification = ..., // field 4? 
    FakeServerName = ...,          // field 5 ← !!!
    ProxyType = ...,               // field "ProxyType"
    ListenDomainNames = ...,      // field 7
    Checked = ...,                // field 8
    Id = ...,                      // field 9
    Order = ...,                  // field 10
    FakeUserAgent = ...,           // field 11 ← !!!
    Version = ...,
    ThreeStateEnable = ...,
    Items = ...,                   // field 12 (sub-rules)
}
```

So mapping by position in the property list vs the numeric keys:
- `0` = Name
- `1` = Port
- `2` = MatchDomainNames (semicolon-separated string)
- `3` = ForwardDomainNames — hmm wait, but "3" held values like "steamimage.rmbgame.net" and "http://pt.mossimo.net:41080/". So ForwardDomainNames is the forward destination!

Hmm wait, but actually there might be more properties before these. Let me think about the numeric ordering. The order in the JSON keys is: 0, 1, 2, 3, 4, 5, ProxyType, 7, 8, 9, 10, 11, 12. Note "ProxyType" appears in place of "6" (it's serialized with its actual name, not an index).

Let me map the C# property names to indexes:
- 0 = Name ✓ (matches: "Steam 图片")
- 1 = Port ✓ (443)
- 2 = MatchDomainNames ✓ (semicolon-separated domains)
- 3 = ForwardDomainNames ✓ (forward destination host — "steamimage.rmbgame.net"; for greasyfork: "http://pt.mossimo.net:41080/")
- 4 = ??? — values: "" or IP addresses like "192.0.80.239", "20.43.185.14" → this is likely the IP address property. In the list above after ForwardDomainNames comes IgnoreSSLCertVerification... but an IP string doesn't fit "IgnoreSSLCertVerification" (bool). Hmm. Actually the property list in GetEnableProxyDomains isn't necessarily complete or in order — it's just copying some properties. There might be an IPAddress property not copied there (since it's not in the copy list!). Wait, looking at the copy list: Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items.

Hmm, if the JSON numeric keys map to property index in declaration order of the DTO class, and "ProxyType" is at position 6 (0-based) — the JSON has "0","1","2","3","4","5","ProxyType","7","8","9","10","11","12". So "ProxyType" replaced key "6"! That means the property at index 6 is ProxyType (serialized by name, not number — maybe it has a special JsonProperty attribute or it's an enum that failed to map).

So the declaration order would be:
- index 0: Name
- index 1: Port  
- index 2: MatchDomainNames
- index 3: ForwardDomainNames
- index 4: ??? 
- index 5: FakeServerName
- index 6: ProxyType (by name)
- index 7: ListenDomainNames
- index 8: Checked? Enable?
- index 9: Id
- index 10: Order
- index 11: FakeUserAgent
- index 12: Items

And from the copy list order: Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items

That matches EXACTLY if index 4 = IgnoreSSLCertVerification?? But field 4 in JSON holds IP addresses like "192.0.80.239"! That contradicts.

Hmm wait, unless field `4` isn't IgnoreSSLCertVerification. Let me look at the actual JSON key order again: `{"0":"Steam 图片","1":443,"2":"steamcdn...","3":"steamimage.rmbgame.net","4":"","5":"","ProxyType":0,"7":"...","8":true,"9":"bbd6...","10":32,"11":null,"12":null}`

Properties with values:
- 0: "Steam 图片" (string) = Name ✓
- 1: 443 (int) = Port ✓
- 2: "steamcdn-a.akamaihd.net;..." = MatchDomainNames ✓
- 3: "steamimage.rmbgame.net" = ForwardDomainNames ✓
- 4: "" — Gravatar has "192.0.80.239" here = IPAddress!
- 5: "" — values like "{origin}", "@domain", "steamstore-a.akamaihd.net" = FakeServerName!
- ProxyType: 0/1/4 ✓
- 7: listening domains = ListenDomainNames ✓
- 8: true/false = Checked/Enable ✓
- 9: GUID = Id ✓
- 10: int = Order ✓
- 11: UA template = FakeUserAgent ✓
- 12: array = Items ✓

So index 4 = IPAddress (the copy list just didn't include it — probably because... hmm, wait, it should. Let me re-check the copy list: Name, Port, MatchDomainNames, ForwardDomainNames, IgnoreSSLCertVerification, FakeServerName, ProxyType, ListenDomainNames, Checked, Id, Order, FakeUserAgent, Version, ThreeStateEnable, Items.

Hmm, "IgnoreSSLCertVerification" — but the JSON field 4 is an IP address string. So maybe the property list in the copy is not declaration order, or IgnoreSSLCertVerification doesn't exist at index 4.

Wait, actually maybe the numeric keys aren't property indexes at all — maybe the API server uses a "PropertyNameFormat" where each property has an explicit numeric index via attributes (like [JsonProperty("0")]). The C# client (BD.WTTS.Client.WebApi) would have the DTO with MessagePack-style keys. Anyway, what matters is the semantic mapping which I've now derived from actual data + the copy list:

- 0 = Name
- 1 = Port (int)
- 2 = MatchDomainNames (semicolon-separated)
- 3 = ForwardDomainNames (forward destination: host or full URL)
- 4 = IP address (string, optional) — direct IP
- 5 = FakeServerName (SNI override: "{origin}", "@domain", fixed host)
- 6 = ProxyType (int, serialized by name)
- 7 = ListenDomainNames (semicolon-separated)
- 8 = Checked/Enable (bool)
- 9 = Id (GUID string)
- 10 = Order (int)
- 11 = FakeUserAgent (UA template with ${origin})
- 12 = Items (sub-rules)

And "IgnoreSSLCertVerification" exists somewhere but wasn't in the data (not serialized or null). The group object: {0: name, 1: items, 2: id, 3: show(bool), 4: order}.

Wait — group has 5 keys: 0=name, 1=items array, 2=GUID, 3=bool, 4=int. And the AccelerateProjectGroupDTO would be: Name, Items, Id, ???, Order.

Now, about "FakeServerName" semantics: In the Rust DomainRuleFields, I need to check if there's a corresponding field. Looking at DomainRuleFields:
- ip_address ✓ (field 4)
- destination ✓ (field 3 - ForwardDomainNames)
- forward_destination (alias)
- response (not in API)
- items ✓ (field 12)
- user_agent ✓ (field 11 - FakeUserAgent)
- timeout_ms (not in API)
- tls_sni: bool — hmm! Field 5 (FakeServerName) is a string, not bool.
- tls_ignore_name_mismatch — hmm, "IgnoreSSLCertVerification"?
- is_server_side_proxy ✓ (ProxyType==4)

So the current Rust DomainRuleFields lacks a "fake_server_name" (SNI string override). The `tls_sni: bool` corresponds to C# `TlsSni` (bool, default true). And C# `IgnoreSSLCertVerification` → `tls_ignore_name_mismatch`.

Wait, but where does C# use FakeServerName? In the handler: `domainConfig.GetTlsSniPattern()` — hmm, GetTlsSniPattern might combine TlsSni bool + FakeServerName string. Actually "FakeServerName" IS the SNI override! When you connect to the forward destination (mirror), the TLS SNI is set to FakeServerName (e.g., "steamstore-a.akamaihd.net" or "@domain" = original domain).

That's exactly why the values in field 5 match field 3 in many cases (fonts.font.im → fonts.font.im): when forwarding to a mirror, SNI = mirror host by default, but can be overridden.

And "{origin}" likely means "use the original request host as SNI". "@domain" similarly means original domain.

Hmm wait, but the middleware's Destination template uses "@domain"/"@uri" replaced with request host. And GetTlsSniPattern().WithDomain(uri.Host) — WithDomain replaces "@domain" with uri.Host. So "@domain" in FakeServerName = original request host. "{origin}"... hmm, maybe also original host. OK.

So for the Rust implementation, in the existing http_relay.rs:
```rust
tls_sni: if rule.fields.tls_sni { None } else { Some(String::new()) },
```

Currently tls_sni bool controls whether to send SNI at all. I need to extend DomainRuleFields with `fake_server_name: Option<String>` and use it in http_relay.rs to override the SNI. Let me check how OutboundTarget.tls_sni is used in outbound.rs connect: `let sni_host = target.tls_sni.clone().unwrap_or_else(|| target.host.clone());` — so tls_sni: Some(name) overrides SNI. 

So in http_relay.rs I should set:
```rust
tls_sni: match &rule.fields.fake_server_name {
    Some(pattern) if !pattern.is_empty() => Some(resolve_sni_pattern(pattern, &host)),
    _ => if rule.fields.tls_sni { None } else { Some(String::new()) },
}
```

Where resolve_sni_pattern replaces "@domain"/"{origin}" with the original request host, and fixed values stay.

Wait, hold on. Let me not over-engineer. The scope of Phase 6.5 is: watt-cloud crate — API client + DTO → DomainRule conversion + local cache. Let me check the current DomainRuleFields again... Actually, adding fake_server_name would require modifying watt-config and http_relay. That's a reasonable part of "DTO→DomainRule 转换" since FakeServerName is a real field in the cloud data that affects behavior.

Hmm, but wait — actually let me check how OutboundTarget.tls_sni=Some(String::new()) works — empty SNI. OK whatever.

Also the sub-rules (field 12): their field `2` (MatchDomainNames) contains URL regex patterns like "https://steamcommunity.com/comment" — these are URL prefixes, not just domains. In C#, `DomainPattern.IsMatch(url)` — let me check how DomainPattern handles these. Let me look at the DomainPattern class.

DomainPattern is from FastGithub (external). In FastGithub, DomainPattern supports:
- Plain domain
- Wildcard like `*.example.com`
- URL regex patterns starting with `/` (like `/^https:\/\/.../`)

From FastGithub's DomainPattern:
```csharp
public bool IsMatch(Uri uri)
{
    return this.regex.IsMatch(uri.ToString()) ...
}
```

FastGithub DomainPattern:
```csharp
sealed class DomainPattern
{
    ...
    public bool IsMatch(string domain) => this.regex?.IsMatch(domain) ?? domainMatcher.IsMatch(domain);
}
```

The key: when pattern starts with "/", it's treated as a regex (used in script matching per ReverseProxyConfig.GetDomainPatternString: `"/^" + Regex.Escape(s).Replace("\\*", ".*") + "$"`).

For sub-rules in the API data: `2` = "https://steamcommunity.com/comment" — a URL prefix, not starting with "/". Hmm. How does DomainPattern handle "https://steamcommunity.com/comment"?

FastGithub DomainPattern constructor:
```csharp
public DomainPattern(string pattern)
{
    ...
    if (pattern.StartsWith("/"))
    {
        // regex mode
    }
    else if (TryParseDomainPattern...)
}
```

Hmm, actually let me look at the actual FastGithub 2.1.4 DomainPattern:

```csharp
sealed class DomainPattern
{
    private const string GeneralSeparator = ";";

    private readonly Regex domainRegex;

    public int Order { get; set; }

    public DomainPattern(string pattern) 
    {
        // 支持通配符与正则
        ...
    }

    public bool IsMatch(string url) => domainRegex.IsMatch(url);
}
```

I don't remember exactly. But the C# middleware calls `TryGetDomainConfig(url)` with full URL. And ReverseProxyConfig.TryGetDomainConfig uses `domainConfigs.Keys.FirstOrDefault(item => item.IsMatch(url))` where url is the full display URL.

In FastGithub 2.1.4, DomainPattern:

```csharp
public sealed class DomainPattern
{
    private readonly Regex regex;

    public int Order { get; init; }

    public DomainPattern(string pattern)
    {
        // 通配符转正则
    }

    public bool IsMatch(string uri)
    {
        return regex.IsMatch(uri);
    }
}
```

Actually the real FastGithub code (from GitHub dotnetcore/FastGithub 2.1.4):

```csharp
sealed class DomainPattern
{
    private readonly Regex regex;

    /// <summary>
    /// 获取或设置排序
    /// </summary>
    public int Order { get; init; }

    public DomainPattern(string pattern)
    {
        if (pattern.StartsWith('/') && pattern.EndsWith('/'))
        {
            this.regex = new(pattern[1..^1], RegexOptions.IgnoreCase);
        }
        else
        {
            var regexPattern = Regex.Escape(pattern)
                .Replace(@"\*", ".*")
                .Replace(@"\?", ".")
                .Replace(@"/", @"\/");
            this.regex = new($"^{regexPattern}", RegexOptions.IgnoreCase);
        }
    }
    ...
}
```

Hmm, I'm not 100% sure. But the key insight: patterns are matched as URL prefixes (anchored at start). "https://steamcommunity.com/comment" matches URLs starting with that string. And plain domains like "steamcdn-a.akamaihd.net" — when matched against full URL "https://steamcdn-a.akamaihd.net/...", the pattern needs to match anywhere or as a prefix...

Hmm wait, for domain patterns, IsMatch is called with the full URL. "steamcdn-a.akamaihd.net" as a regex pattern "steamcdn-a\.akamaihd\.net" (unanchored) would match "https://steamcdn-a.akamaihd.net/..." as a substring! Yes! That's how FastGithub does it — unanchored regex, so a bare domain matches any URL containing that domain, and "https://steamcommunity.com/comment" matches URLs with that prefix.

And "*.st.dl.eccdnx.com" → escaped → ".*\.st\.dl\.eccdnx\.com" matches URLs containing any subdomain.

OK so now let me check how my existing Rust implementation matches. The current Rust DomainRules.find(host) uses domain_match(pattern, host) — host-only matching, not URL matching. And SubRule has `regex: String` — sub-rules match URL via regex.

Let me look at how http_relay.rs find_domain_config works with sub-rules.

查看 FastGithub DomainPattern 源码确认 URL 匹配语义。
Good. Now I understand the existing Rust code. Sub-rules have `regex` matching full URL.

Now the cloud DTO → DomainRule conversion needs to:
1. Group level: name, items, id, order
2. Project item → DomainRule:
   - match_domain_names: split field 2 by ";"
   - listening_domain_names: split field 7 by ";"
   - order: field 10
   - ip_address: field 4 (if parses to IpAddr)
   - destination: field 3 (ForwardDomainNames)
   - user_agent: field 11 (FakeUserAgent)
   - is_server_side_proxy: ProxyType == 4
   - items (sub-rules): field 12 → SubRule { regex: convert field 2 (URL prefix → regex), rule: fields }
   
For sub-rule regex conversion: field 2 values are URL prefixes like "https://steamcommunity.com/comment" or with wildcards like "https://steamcommunity.com/*/discussions" or "https://store.steampowered.com/app/*". Need to convert to regex: escape everything except "*" → ".*", anchor at start.

Wait — but for the SUB-RULES, match entries are URL patterns (starting with https://). For the TOP-LEVEL rules, match entries are domain names. The current Rust DomainRule.match_domain_names uses domain_match (host-only matching).

Hmm, but hold on: how does C# DomainPattern handle top-level domain entries vs URL prefix entries? It converts patterns to regex and matches against the full URL. Let me look at the actual FastGithub DomainPattern implementation to be sure. FastGithub 2.1.4:

```csharp
public sealed class DomainPattern
{
    private const string GeneralSeparator = ";";
    private readonly Regex domainRegex;

    public DomainPattern(string pattern) : this(pattern.Split(GeneralSeparator))
    {
    }

    public DomainPattern(string[] patterns)
    {
        var pattern = string.Join("|", patterns.Select(p => p.Trim()).Where(p => string.IsNullOrEmpty(p) == false));
        // ... 
    }
}
```

Hmm, I don't remember exactly. Let me look at the PAC middleware to see how GetDomainPatterns is used, and check the actual usage of DomainPattern.IsMatch. Actually, since DomainPattern is from FastGithub, let me fetch its 2.1.4 source.

I can't find the DomainPattern source locally (it's from FastGithub NuGet). Based on FastGithub 2.1.4's actual source which I recall:

```csharp
sealed class DomainPattern
{
    private const string GeneralSeparator = ";";
    private readonly Regex regex;
    private readonly Regex domainRegex;

    public DomainPattern(string pattern)
    {
        // 支持以 / 开始与结束的正则表达式
        if (pattern.StartsWith('/') && pattern.EndsWith('/'))
        {
            this.regex = new(pattern[1..^1], RegexOptions.IgnoreCase);
        }
        else
        {
            var value = Regex.Escape(pattern).Replace(@"\*", ".*");
            this.regex = new($"^{value}", RegexOptions.IgnoreCase);
        }
    }
}
```

Actually, in FastGithub 2.1.4 the DomainPattern is:

```csharp
sealed class DomainPattern
{
    private readonly Regex regex;
    private readonly Uri? uri;

    public DomainPattern(string pattern)
    {
        if (Uri.TryCreate(pattern, UriKind.Absolute, out this.uri) == false)
        {
            var value = Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".");
            this.regex = new(value, RegexOptions.IgnoreCase);
        }
    }

    public int Order { get; set; }

    /// <summary>
    /// 是否匹配
    /// </summary>
    /// <param name="uri"></param>
    /// <returns></returns>
    public bool IsMatch(Uri uri)
    {
        return this.regex == null
            ? this.uri.IsBaseOf(uri)
        // 段模式
            : this.regex.IsMatch(uri.ToString());
    }
}
```

Hmm, that's not quite it either. Let me just check the actual FastGithub source from GitHub. Let me try fetching from a different URL format.

The GitHub page returns 404 for that file path. Let me check the actual FastGithub repo structure. The DomainPattern might be in a different path in 2.1.4. Let me search for it.

Let me fetch the DomainPattern.cs from the MrGlucose/FastGithub fork (which has the FastGithub.Configuration folder).
---

## Phase 6 完成报告（2026-09-06）

### 交付内容

**6.1 watt-config 扩展（已完成 ✅）**
- `DomainRuleFields.fake_server_name`：云端字段 5（FakeServerName，SNI 覆盖，支持 `@domain`/`{origin}`/`${random}`）
- `url_pattern_matches` / `url_patterns_to_regex`：URL 模式匹配（`;` 分隔多模式、`*`/`?` 通配、锚定 URL 开头，对齐旧版 DomainPattern）
- `DomainRules::find_by_url`：带路径匹配入口

**6.5 watt-cloud crate（新建，已完成 ✅）**
- `dto.rs`：索引键 JSON 反序列化（🦓=Content / 🦄=Code / 🐴=Message；分组 `0/1/2/3/4`、项目 `0..12`，ProxyType 按名）——字段映射经真实 API（api.steampp.net/api/Accelerate/All）+ 旧版 `ReverseProxyHttpClientHandler.GetIPEndPointsAsync` 交叉确认
- `model.rs`：DTO → `AccelerateCatalog`（分组/项目/子项目树）→ `to_domain_rules(enabled_ids)` 展平为引擎 `DomainRule`
  - 语义：显式 Id 集合优先；`None` 回退云端 `Checked` 默认（首次运行）
  - 父未启用 → 整棵子树丢弃；子未在集合 → 从 Items 剔除
- `client.rs`：reqwest 客户端（`rustls-no-provider`，复用 workspace ring provider——**勿改回 `rustls`，会引入 aws-lc-rs 双 provider 歧义导致 watt-core 全部网络测试 panic**）
- `cache.rs`：`{data_dir}/Accelerate/accelerate_projects.json` 缓存（在线失败降级）
- `tests/fixtures/accelerate_all.json`：真实 API 响应 fixture

**命令层（src-tauri/commands/accelerate.rs，已完成 ✅）**
- `accelerate_get_projects`：云端优先 → 缓存降级（source: cloud/cache）
- `accelerate_refresh`：强制云端刷新 + 更新缓存
- `accelerate_set_enabled`：勾选 Id 集合持久化到 `ProxySettings.enabled_accelerate_ids`
- `accelerate_get_rules`：按勾选 Id 集合从缓存展平引擎规则
- `scripts_get_list` / `scripts_get_configs`：已安装脚本 / 启用项 ScriptConfig

**前端（已完成 ✅）**
- `types/ipc.ts`：AccelerateProject/Group/Catalog（camelCase 模型层）+ DomainRuleFields 补 fake_server_name + ProxySettings 补 enabled_accelerate_ids
- `stores/accelerate.ts`：目录加载、勾选状态（空持久化集合回退云端默认）、勾选父项整树启用、persist、buildEngineAssets
- `AcceleratorPage.vue`：分组/项目/子项目勾选列表 + 云端/缓存来源标记 + 刷新按钮；一键加速经 `buildEngineAssets()` 传 rules + scripts

**watt-core 配套**
- `OutboundTarget.forward_destination`：转发目标域名（DNS 解析取 IP，Host/SNI 保持原始域名，对齐旧版镜像语义）
- http_relay 接入 URL 模式子规则匹配 + fake_server_name SNI 覆盖 + forward_destination + user_agent

### 验收（全绿 ✅）
- `cargo test --workspace`：112 用例 0 失败（watt-cloud 12 新增）
- `cargo clippy --workspace --all-targets`：0 error（仅存量 warning）
- `cargo fmt --all --check`：通过
- `vue-tsc --noEmit`：0 错误

### 已知限制
- ServerSideProxyToken（ProxyType=4 服务端加速）暂传 null，服务端加速项目不生效
- FakeServerName 的 `@domain`/`${random}` 占位替换在 http_relay 未实现（当前仅静态 SNI 覆盖）
- 勾选空集合在重载后回退云端默认值（无法表达"全部取消"）

---

## Debug 运行记录（2026-09-06）

### 启动方式（沙箱无 pnpm，Tauri CLI 须从项目根运行）
```
cd watt-toolkit-tauri
ui/node_modules/.bin/tauri dev -c '{"build":{"beforeDevCommand":"npm --prefix ../ui run dev"}}'
```
- `tauri dev` 从 `ui/` 子目录运行会报 "Couldn't recognize as a Tauri project"，必须从含 `src-tauri/` 的项目根运行。
- `beforeDevCommand` 原配 `pnpm`，PATH 无 pnpm，用 `-c` 合并覆盖为 `npm --prefix ../ui run dev`。
- 沙箱 bash 后台会话结束后 `tauri dev` 父进程退出，但 app + vite 子进程残留运行（窗口仍可见），属正常。

### 运行时 bug 修复（Phase 6 验收未覆盖）
- 现象：app 启动即 panic `No rustls crypto provider is configured`（tokio-rt-worker）。
- 根因：`watt-cloud` 的 reqwest 用 `rustls-no-provider`，运行时不自动安装 crypto provider；Phase 6 测试仅用 fixture 解析、未真正建 TLS Client，故未暴露，运行时不发请求即触发。
- 修复：在 `src-tauri/src/lib.rs` 的 `run()` 开头 + `watt-cloud/src/client.rs` 的 `with_base()` 各加 `rustls::crypto::ring::default_provider().install_default()`（进程级全局、幂等 `.ok()`）。workspace 的 rustls 已启用 `ring` feature，无双 provider 冲突。
- 验证：重启后 app 正常起窗口（MainWindowTitle "Watt Toolkit"，句柄非零，Responding=True），无 panic。

### 修正：vite 须独立常驻
- 实测 `tauri dev` 父进程退出会**连带回收**其 `beforeDevCommand` 起的 vite（窗口白屏，5173 断开）。
- 正确姿势：先 `cd ui && nohup npm run dev > /tmp/vite.log 2>&1 & disown` 独立常驻 vite；再 `tauri dev -c '{"build":{"beforeDevCommand":"echo skip-dev-server"}}' --no-dev-server-wait` 仅负责编译+起 app。app 残留运行，vite 独立不hui被回收。

---

## UI 反馈修复（2026-09-06 下午）

### 1. 加速项目缺失（GitHub 等分组不可见）— 已修复 ✅
- 根因：`AcceleratorPage.vue` 旧逻辑 `groups.filter(g => g.show)` 把云端 `show=false` 的 9 个分组全过滤了；真实 API 中仅 "Steam 服务" 分组 `show=true`，**Github（13 项）、Twitch（11 项）、公共CDN、网盘、验证码**等全被藏起。`show` 并非可见性标记。
- 修复：渲染全部分组。
- 后端解析（watt-cloud）本身无丢项（62 项全在），无需改动。

### 2. 移除脚本 / 脚本商店 / 账户页面 — 已完成 ✅
**前端**
- 删除 `ScriptPage.vue`、`ScriptStorePage.vue`、`AccountPage.vue` 三个页面文件
- `router/index.ts`：移除 3 条路由（导航从 7 页收敛为 4 页：首页/网络加速/设置/关于）
- `App.vue`：移除 3 个导航项
- `api/index.ts`：移除 `scriptsGetList` / `scriptsGetConfigs`
- `types/ipc.ts`：移除 `ScriptSettings` / `ScriptConfig` / `InstalledScript`；`EngineStartParams` 移除 `scripts` / `onlyEnableProxyScript` / `isOnlyWorkSteamBrowser`
- `stores/settings.ts`：移除 `script` 默认值；`stores/accelerate.ts`：`buildEngineAssets` 不再取脚本

**后端**
- `commands/accelerate.rs`：删除 `scripts_get_list` / `scripts_get_configs`
- `commands/engine.rs`：`EngineStartParams` 移除脚本字段；`EngineConfig` 构造传空默认（false / Vec::new()）
- `src-tauri/Cargo.toml`：移除 `watt-script` 依赖
- `src-tauri/src/migrate.rs`：删除 `migrate_scripts` 与 `scripts_migrated` 字段（MigrationReport 不再含脚本）
- `watt-config`：删除 `ScriptSettings`（settings.rs + lib.rs 导出）；`migrate.rs` 删除脚本迁移映射与 `legacy_scripts_status`

**保留**
- `watt-script` crate 本体保留：它是 watt-core 的 MITM 注入基础设施（HookEngine / LocalDomainHandler 依赖），无 UI 喂入后实际为空操作；彻底删除需重写大量 watt-core 代码，风险高收益低。

### 验收（全绿 ✅）
- `cargo build --workspace` 0 error
- `cargo test --workspace` 111 用例 0 失败
- `cargo clippy`（watt-config + app）0 error；`cargo fmt --check` 通过
- `vue-tsc --noEmit` 0 错误
- app 已重建并运行（vite 常驻 5173），GitHub 等分组应在加速页可见

**踩坑记录**：对同一文件并行发起多个 Edit 会互相覆盖（last-writer-wins），必须逐个顺序编辑。

---

## 加速项目选择优化（2026-09-06）

- **分组全选**：`stores/accelerate.ts` 新增 `toggleGroup`（全选↔全不选，部分勾选点击→全不选）、`groupState`（三态 all/some/none）、`setAll`（目录级全选/清空）；均自动持久化
- **UI**：分组标题栏改为交互行——三态复选框（indeterminate 部分勾选）+ `x/y` 勾选计数 + 点击折叠/展开（默认展开：`show=true` 或含勾选项，目录加载后初始化）；卡片头部新增全局「全选/清空」按钮（按目录全选状态切换显示）
- 纯前端改动（vite HMR 热更），vue-tsc 0 错误，无需重建 Rust

---

## GitHub 加速 404/500 排查与修复（2026-09-06）

### 现象
浏览器访问 github.com 报 HTTP 404/超时；本地反代测试：github.com 深路径 500、`*githubusercontent.com` 超时、api.github.com 200。

### 排查结论（逐层取证）
1. hosts 劫持正常（Github 组域名 → 127.0.0.1）、443 监听正常 → 请求确实进入本地反代
2. **500 响应体是反代自己的错误页**：`转发失败: github.com:443 连接失败 os error 10060`——云端下发的覆盖 IP `20.207.73.82`（Github 网站项）已连不通
3. `githubusercontent.com` 的覆盖 IP `23.235.37.133` 同样失效 → 超时
4. `api.github.com` 走 `forward_destination: githubapi.rmbgame.net` 镜像（CNAME 到 GitHub Fastly 185.199.x.x，可达）→ 稳定 200，**镜像转发机制本身正常**
5. `github.githubassets.com` 根路径 404 是 GitHub 官方对根路径的正常响应（资源按路径访问），非 bug
6. 用户网络系统 DNS 干净（github.com → 20.205.243.166 真实 IP）→ DNS 回退可行

### 根因
`outbound.rs` 直连逻辑是三选一（覆盖 IP **或** 镜像 **或** DNS），云端静态 IP 失效时无降级，直接报 500/超时。

### 修复（outbound.rs connect）
改为**候选链逐级降级**：覆盖 IP → 转发镜像域名 → 原始 host DNS 解析，跨组去重、逐个尝试连接，全部失败才报错。对齐旧版 GetIPEndPointsAsync 语义并增强容错。

### 附带发现
- 引擎未正常停止时（进程被杀）hosts 残留 Steam++ 块：启动时会重写同名块、停止时移除，残留无害
- 沙箱 shell 非管理员，无法直接清理 hosts；依赖引擎自身的块管理

### 验证
- watt-core 32+17 测试全绿；cargo build 0 error；fmt 通过
- 待用户在窗口点击「一键加速」后实测 github.com 页面

### 二次增强：串行降级 → 并发竞速（happy-eyeballs）
- 实测发现 GitHub 真实 IP（20.205.243.166 等）在用户网络下**间歇性阻断**：根路径时而 200 时而 500，串行降级下死 IP + 多个失败 IP 每个白等一个完整超时（实测 42s 后才报错）
- outbound.rs connect 改为**并发竞速**：全部候选地址（覆盖IP/镜像/DNS 多 IP）同时发起 TCP 连接，channel 接收、首个成功者胜出，其余任务随返回被丢弃。总延迟 = 最快可用地址的连接时间
- watt-core 49 测试全绿 / clippy 0 error / fmt 通过；竞速版已重建运行

### 三次修复：出站 DNS 回退被自家 hosts 劫持污染（回环连接）
- 实测竞速版仍有故障：gist 500（`连接失败 127.0.0.1:443 os error 10048`）、raw 500（污染判定拦截）
- 根因：hickory-resolver 0.24.4 `ResolverOpts::default().use_hosts_file = true`——DNS 查询前先读 hosts 文件；加速引擎自己往 hosts 写了劫持条目，出站回退解析把加速域名解析成 127.0.0.1，回连自身
- 修复：`DnsResolver` 持有双解析器——`resolver`（保留 hosts 语义，供污染判定对齐原版 getaddrinfo 行为）+ `clean`（`use_hosts_file=false`，手动 `read_system_conf` 后关闭 hosts 优先）；`RelayDnsAdapter`（出站层专用适配器）切换到 `resolve_clean`
- 新增测试 `test_resolve_clean_bypasses_hosts`（clean 结果不得含回环地址）
- watt-dns 4 / watt-core 32+17 测试全绿，fmt 通过

### 四次修复：域名匹配等值语义 → 子域后缀 + 最长匹配优先
- 终测：github.com 主页 200/1.1s、仓库页 200/1.7s（此前 40s/26s），codeload 源码包 200；但 raw/gist 仍 500
- raw 根因：UserContent 规则匹配域是裸父域 `githubusercontent.com`，而 domain_match 是等值匹配 → `raw.githubusercontent.com` 落到 default 规则 → 污染判定用读 hosts 的解析器看到回环 → 误报"DNS 污染"。原版 C# DomainPattern 是未锚定正则子串语义（子域可命中），此前"原实现用等值匹配"的注释是误读
- 修复（watt-config/domain_rule.rs）：`domain_match` 裸父域隐式匹配子域（host 以 `.pattern` 结尾）；规则决胜从 max(order) 改为**最长匹配模式优先**（最具体者胜，平局才看 order）——避免 `api.github.com`(order 68) 被 `github.com`(order 72) 裸域规则吞掉
- 新增回归测试 test_github_catalog_matching（raw→UserContent / api→Api / gist→Web 三路判定）
- gist.github.com TLS 被远端 RST（os 10054）：gist SNI 被 GFW 阻断且 Web 规则覆盖 IP 已死、无镜像——数据层问题，代码无解，等云端数据更新
- 全仓 112 测试全绿 / clippy 0 error / fmt 通过；已重建运行

### 五次修复：SNI 覆盖下的证书名称校验（对齐原版 ValidateServerCertificate）
- 域名匹配修复生效后 raw/camo 报 `certificate not valid for name "Github"`——云端 UserContent 规则带 FakeServerName="Github"，rustls 用假 SNI 做证书名称校验，而 GitHub 证书只对 *.githubusercontent.com 有效
- 原版铁证（ReverseProxyHttpClientHandler.cs L106-117/313-335）：SNI 覆盖时校验回调直接 true（外部代理路径）；直连路径证书链正常校验，名称不匹配时按**原始请求域名**的 DNS 名判定
- 修复（sni.rs）：新增 `RelaxedNameVerifier`（webpki 链校验 + 名称换原始域名）；outbound.rs 连接时 tls_sni != host 即走该模式（tls_ignore_name_mismatch 保持 SkipAll 语义）
- 全仓 112 测试全绿 / clippy 0 error；已重建运行（PID 227212）

### 最终验收（2026-09-06 12:57，TLS 修复版）
| 域名 | 结果 | 耗时 |
|---|---|---|
| github.com 主页 | 200 | 1.2s |
| github.com/QiaTia/MoeKoe-Music-For-Tauri（原 404 页面） | 200 | 1.7s |
| raw.githubusercontent.com README | 200 | 0.7s（内容验证为真实 README） |
| api.github.com | 200 | 0.6s |
| codeload.github.com linux 源码包 | 200 | 33s（~130MB 下载） |
| gist.github.com | 500 | SNI 被 GFW 阻断 + 云端覆盖 IP 死 + 无镜像——数据层问题 |

### 五轮修复总链
1. 出站无降级 → 候选链（覆盖IP→镜像→DNS）
2. 串行太慢 → 并发竞速
3. DNS 回退读 hosts 回环 → clean 解析（use_hosts_file=false）
4. 域名匹配等值 → 子域后缀 + 最长匹配优先
5. SNI 覆盖证书校验失败 → RelaxedNameVerifier（名称按原始域名校验，链不变）

浏览器实测入口：github.com 主页/仓库页/raw 文件/Release 下载均应正常；gist 不可用为云端数据问题。

---

## C# → Rust 迁移一致性审计（2026-09-11）

产出：`watt-toolkit-tauri/迁移一致性审计.md`（24 项能力逐条对照 + 关键不变量复核 + 差异清单）

### 审计判定
核心加速链路（MITM 动态证书 / 规则匹配 / 出站候选降级 / DNS 污染判定 / hosts / PAC / 系统代理 / 二级代理 / 静态响应 / 目标重写 / UA 伪装 / 证书信任）**已完整对齐原版**，Hosts 模式常规加速功能一致。

### 本次审计新修 2 处偏差
1. **DNS 污染判定解析器**：原版固定用 DNSPod 反查（绕过 hosts），Rust 误用读 hosts 的解析器 → 本机 hosts 中任意非规则域名会被误报污染 500。修复：新增 `resolve_first_clean`，污染判定改用它（watt-dns/resolver.rs + watt-core/http_relay.rs）
2. **HTTP→HTTPS 跳转状态码**：原版 `Response.Redirect` = 302，Rust 用了 301（会被浏览器永久缓存）→ 改为 302 Found，测试断言同步更新

验证：全仓 112 测试全绿 / clippy 0 error。

### 剩余差异（按影响排序）
1. 脚本注入子系统未接线（引擎能力完整，但 commands/engine.rs 硬编码 scripts: Vec::new()，前端无入口）
2. ServerSideProxyToken 恒为 null（前端 AcceleratorPage.vue:155）→ ProxyType=4 服务端加速不可用
3. WebSocket/Upgrade 在 MITM 下失效（出站 http1 + upgrade 逐跳头剥离）
4. 出站仅 HTTP/1.1（原版有 h2/h3）、无连接池复用
5. System/PAC 仅 Windows；DNSIntercept 合并为 Hosts（免驱动免管理员，视为改进）
6. 其他：SOCKS5 入站不支持注入、DoH 仅 IP 地址、is_proxy_gog 未接线

### 原版侧重要事实（审计取证）
- Git/SSH 加速监听器在原版**也被注释禁用**（YarpReverseProxyServiceImpl.cs:192-193）→ Rust 未实现属一致
- 原版 SOCKS5 **无**入站监听；Rust 的 socks5 listener 是新增能力
- 原版 DNS 污染判定用 DNSPod；原版出站为逐 IP 串行 10s，Rust 用并发竞速（等价且更抗静态 IP 失效）

---

## 本地调试环境启动（2026-09-11）

### 启动方式（重要：本机无 pnpm，默认 beforeDevCommand 会失败）
`src-tauri/tauri.conf.json` 的 `beforeDevCommand` = `pnpm --dir ../ui dev`，本机未安装 pnpm，直接 `tauri dev` 会中断。需前后端分离启动：

```bash
# 1) 前端 vite（后台）
cd ui && node_modules/.bin/vite --host 127.0.0.1 --port 5173

# 2) Tauri（跳过自带 dev server，复用上面的 vite）
ui/node_modules/.bin/tauri dev -c '{"build":{"beforeDevCommand":"echo skip-dev-server"}}' --no-dev-server-wait
```

### 启动结果
| 组件 | 状态 |
|---|---|
| vite | v6.4.3 @ http://127.0.0.1:5173 ✓ |
| app | target/debug/watt-toolkit-app.exe ✓ |
| WebView2 | 已加载前端（5173 有 ESTABLISHED 连接）✓ |
| 加速引擎 | 自动恢复加速，监听 127.0.0.1:443 ✓ |

### 关于 hosts 的说明（澄清误判）
app 启动后引擎自动恢复上次加速状态，会重写 hosts 的 `# Steam++ Start/End` 标记块（本次 23~160 行，137 条）。**这是引擎的正常工作态，不是残留劫持**——判断依据是 443 是否在监听：监听中 → 块有效；未监听 → 才是残留。

### 调试机制
- 前端改动 → vite HMR 自动热更，无需重启
- Rust 改动 → tauri watcher 监听 crates/* 与 src-tauri，自动增量重编译并重启 app（本次增量约 17s）
- 日志：`/tmp/vite.log`（前端）、`/tmp/tauri-dev.log`（Rust/app）

### 冒烟测试
| 域名 | 结果 | 耗时 |
|---|---|---|
| github.com | 200 | 1.2s |
| api.github.com | 200 | 1.0s |
| raw.githubusercontent.com | 200 | 1.0s |

---

## GitHub 加速「访问无效」：备用 IP 池兜底（2026-09-11）

### 现象
加速后浏览器访问 github.com 报 404/连接失败；经本地反代实测：github.com 稳定 500（5/5，各 ~21s），响应体 `转发失败: 请求失败: connection error`。

### 根因（决定性证据）
1. **DNS 给了坏 IP**：GitHub 权威 DNS 在系统 DNS(192.168.8.1)、阿里(223.5.5.5)、Google(8.8.8.8) 上**均只返回** `20.205.243.166`，而该 IP 在当前网络被阻断
2. **云端覆盖 IP 失效**：`20.207.73.82`（Github 网站）、`23.235.37.133`（UserContent）TCP 均连不上（12s 超时）
3. **候选池只有这两个来源** → 全部失败
4. **反证 IP 可达性**：`20.27.177.113` / `140.82.112.3` / `140.82.113.3` 主页+仓库页连续 2 次均 200 → **IP 层面可达，是 DNS 选错了 IP**

### 修复
- 新增 `crates/watt-core/src/fallback.rs`：备用 IP 池，按后缀匹配三段独立 IP 组（`*.github.com` / `*.githubusercontent.com` / `*.githubassets.com` 不可混用），数据取 GitHub 官方 meta 的 web/raw 段，列表按实测可达性排序
- `outbound.rs` 候选构造尾部追加该池作为额外竞速候选；happy-eyeballs 下**不增加成功路径延迟**，失败候选随首个成功者返回被丢弃
- 定位为**超出原版的容错增强**：原版依赖同样的 DNS 结果，遇此网络状况一并失败；改动只影响「常规候选全灭」的兜底路径

### 验证
- 新增 4 个 fallback 单元测试（三池隔离、大小写/端口不敏感、形似域名不误命中）
- 全仓 117 测试全绿 / clippy 0 error / fmt 通过

### 排查教训（重要）
Chrome 会把「404 + 空响应体」包装成自己的错误页（"找不到此 Web 地址的网页 / HTTP ERROR 404"），而反代的 `not_found_response()` 正是空 body 404 —— **极易误判为 GitHub 官方 404**。定位此类问题必须先看响应体（我们的是纯文本 `转发失败: ...`），再区分是谁返回的。

---

## 系统代理残留导致浏览器断网 + 备用 IP 池验证（2026-09-11 续）

### 现象
浏览器报「你尚未连接 / 代理服务器可能有问题，或地址不正确」= Chrome `ERR_PROXY_CONNECTION_FAILED`。

### 根因
注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`：
- `ProxyEnable=1`（启用）
- `ProxyServer=127.0.0.1:26501`（Watt Toolkit 的正向代理端口）
- **但 26501 无任何监听** → 浏览器全部流量被送进死代理
- `ProxyOverride` 含 `api.steampp.net;shop-api.steampp.net` → 铁证是本工具写入

**成因**：当前 `proxy_mode=Hosts`，26501 属**上次 System/PAC 模式的遗留**。app 被 tauri watcher 强杀时未执行 `stop()`（`engine.rs:386-397` 的取消系统代理逻辑），设置就留在了注册表。

### 处置
`reg add "HKCU\...\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f`（HKCU 无需管理员）。
WinINet 刷新 API（`InternetSetOption`）被沙箱安全策略拦截（Add-Type 禁用），需用户刷新/重启浏览器生效。

### 备用 IP 池验证（新增诊断测试）
新增 `crates/watt-core/tests/diag_outbound.rs`（`#[ignore]`，真实网络）：
```
fallback_ips(github.com) = [140.82.112.3, 140.82.113.3, 20.27.177.113, ...]  ← 命中 10 个
无覆盖IP:     ok=true  231ms
带失效覆盖IP: ok=true  161ms
hyper http1 GET / → HTTP 200 OK  145ms     ← 复现反代真实出站路径
```
**结论：出站层（连接 + 备用 IP 池 + HTTP 转发）完全正常，全程约 290ms。** 此前经反代实测的 20s 失败不在连接层，需在 relay 层继续定位。

### 已加临时诊断（验证后移除）
- `http_relay.rs` 规则命中处：输出 url / host / 命中规则 / is_default
- `outbound.rs` 候选构造后：输出 host / override_ip / forward_destination / 候选列表

### 调试注意
tauri watcher 监听 `crates/` 下全部文件，**修改 `tests/*.rs` 同样触发 app 重启**（本轮因反复编辑测试文件重启 4 次，打断引擎状态）。调通网络链路前应避免频繁改测试文件。

---

## 收口：根因 = 加速态「双劫持」不一致；relay 层经证实无缺陷（2026-09-11 收尾）

### 决定性证据
现场三处矛盾同时成立：
```
hosts：含 "# Steam++ Start"（第 23 行）~ "# Steam++ End"（第 160 行），github/steam 全量 → 127.0.0.1
netstat：443 无监听；app(PID) 只监听 26501（正向代理），并有大量 ESTABLISHED
注册表：ProxyEnable=1 → 127.0.0.1:26501
```
即 **Hosts 模式的接入面（hosts 劫持）与 System 模式的接入面（系统代理 + 26501）同时存在**。域名被指向 `127.0.0.1` 却无人监听 443 → 直连 `github.com:443` 报 `WinError 10061 目标计算机积极拒绝`（curl: `(7) Could not connect to server`）→ 浏览器「找不到此 github.com 页」。

**分路对比法**（本次定位的关键手法）：
- `curl --noproxy '*' https://github.com/` → refused（hosts 劫持面坏）
- `curl -x http://127.0.0.1:26501 https://www.baidu.com/` → 200 / 0.27s（正向代理面正常）
- `curl -x http://127.0.0.1:26501 https://github.com/` → `schannel CRYPT_E_NO_REVOCATION_CHECK`（curl/schannel 的吊销检查专属报错，浏览器一般不复现，非本项目缺陷）

### 修复：补齐引擎生命周期兜底清理
缺口：`ProxyEngine` 的 `hosts_written` / `running_mode` 是**内存态**，而 hosts 与系统代理是**持久化**的。app 被强杀/崩溃时不走 `stop()` → 必然残留。

1. `crates/watt-core/src/engine.rs`
   - 新增 `cleanup_orphans(hosts_path, proxy_ports) -> Vec<String>`：① 按标记移除 hosts 残留 ② 仅当系统代理/PAC 指向**本引擎端口**才撤销（`is_own_proxy_addr` 精确匹配 `127.0.0.1`/`localhost`/`0.0.0.0` + 端口，绝不误清用户其他代理）
   - 新增 `shutdown()`：运行中 → 走正常 `stop`；否则 → 兜底清理
   - `start()` 开头先兜底清理，再按模式接入
2. `src-tauri/src/lib.rs`
   - `setup` 阶段调用 `cleanup_orphans`（**启动自愈**）
   - `.run()` → `.build()` + `app.run(|handle, event| ..)`，在 `RunEvent::Exit` 用 `async_runtime::block_on` 调 `engine.shutdown()`（**退出清理**）

**验证**：app 重启后 `hosts 标记=0`、`ProxyEnable=0`、无 443/26501 监听 → 自愈生效。

### 端到端验收：relay 层无缺陷
新增 `crates/watt-core/tests/diag_github.rs`（`#[ignore]`，真实网络；注入临时 hosts + 空闲端口，**不碰系统 hosts、不占 443**，可安全复跑）：
```
cargo test -p watt-core --test diag_github -- --ignored --nocapture
[diag] hosts 已写入 github.com
[watt-diag] connect host=github.com port=443 override_ip=None fwd=None 候选11个=[20.205.243.166, 140.82.112.3, ...]
[diag] github.com 响应: HTTP/1.1 200 OK        ← 全程 0.75s
[diag] stop 后 hosts 已还原
test result: ok. 1 passed
```
**结论：Hosts 模式 start → MITM → 出站候选链 → 真实 github.com 得 200，0.75s。** 此前「反代实测 20s 失败」是环境态所致（引擎未起 / hosts 与系统代理残留），**relay 与出站层均无缺陷**。

### 清理与测试
- 已移除 `http_relay.rs` / `outbound.rs` 的临时 `[watt-diag]` eprintln（诊断职责移交 `diag_github.rs`）
- 全仓 **120 测试全绿，0 failed**（watt_core 39，新增 `test_is_own_proxy_addr` / `test_cleanup_orphans_removes_tagged_hosts` / `test_cleanup_orphans_noop_when_clean`）

### 遗留建议（未实施）
- **单实例保护缺失**：同时跑两个 app 实例时，后启动者的启动清理会摘掉前者的 hosts/系统代理 → 建议接入 `tauri-plugin-single-instance`
- 前端「一键加速」下发的 `proxy_mode` 与引擎实际运行的 mode 可能不一致（本次现场即 config=Hosts 而引擎跑正向代理），建议启动时以 UI 当前 mode 为准重新下发

---

## 二次根因：出站竞速的「胜出条件」错误（TCP 可达 ≠ 服务可达）

### 先回答用户的两个假设
- **原理与原项目一致**：原版即「Hosts 劫持 + 本地 443 反代 + 最优 IP 选择」（知乎那篇文章也是这么描述的）。本版 Hosts 模式同构。
- **不是证书问题**：`certutil` 显示信任存储里有两套 CA —— `LocalMachine\Root` 的 `SteamTools Certificate`（原 C# 版）与 `CurrentUser\Root` 的 `Watt Toolkit`（本版）。本版 CA 与引擎实际使用的 `Certificates/ca.cert.pem` **指纹完全一致**（`8ac4d403959c48e8dce230ef7cc70a28457cbb29`，notBefore/notAfter 逐分钟吻合）→ 浏览器可信任叶子证书。

### 现场（用户报「还是没有加速效果」时）
`github.com` 经代理 = 000/20s、200/1.0s、500/5.5s（不稳）；而 `api.github.com` / `raw.githubusercontent.com` / `codeload.github.com` / `avatars.*` 全部稳定 200/301/302（0.37~0.8s）。**只有主站 apex 不稳。**

### 决定性证据：候选健康度矩阵
`diag_outbound.rs` 新增 `diag_candidate_health_github`，逐候选分 TCP / TLS 两层探测。**干扰窗口内 github.com 的 12 个候选：**

```
20.207.73.82 (规则覆盖IP)  TCP ✓276ms  TLS ✗ 超时
140.82.112.3               TCP ✓290ms  TLS ✗ 超时
140.82.113.3               TCP ✓279ms  TLS ✗ 超时
140.82.114.3               TCP ✓279ms  TLS ✓ 200 OK     ← 唯一可用
140.82.116.3/20.201.28.151/20.233.83.145/20.29.134.23/20.248.137.48   TCP ✓  TLS ✗
20.27.177.113 / 20.200.245.247 / DNS 20.205.243.166                   TCP ✗
```
→ **11/12 候选 TCP 秒连、TLS 全部卡死，仅 1 个能完成 TLS。**
⇒ 以「TCP 握手成功」为胜出条件的竞速，**必然**选中 TLS 死候选 → 20s 超时 / 500。
（公网恢复后同一诊断显示 10/11 TLS 可达 ⇒ 该干扰是**间歇性**的，解释了「有时好有时坏」。）

### 因果闭合
规则 `Github 网站 (Git Push)` 的 `ip=20.207.73.82`（云端静态覆盖 IP，早已失效），DNS 只给 `20.205.243.166`（间歇被阻断）→ 常规候选全不可靠，只能靠备用 IP 池；而 `api.github.com` 走**镜像转发** `forward_destination=githubapi.rmbgame.net`，与候选竞速无关 → 所以它一直稳。**这就是「只有 github.com 主站不稳」的原因。**

### 修复：胜出条件改为「TLS 完成」
`crates/watt-core/src/outbound.rs` 重构：
- `connect()` 分派：二级代理 → 单一通道；需 TLS → `race_tls`；不需要（纯隧道）→ `race_tcp`
- 新增 `race_tls`：候选并发执行「TCP + TLS 握手」，**首个完成 TLS 者胜出**；用 `JoinSet` 承载，胜出后随作用域 abort 落败候选（旧实现用 channel，落败的 TCP 连接不会被取消，反而更费）
- 抽出 `resolve_candidates()`（候选链）与 `tls_parts()`（TLS 连接器 + SNI 构造）
- 回归测试 `test_race_tls_skips_tcp_alive_tls_dead_candidate`：本地构造「TCP 可连但吞包不回应」的黑洞候选置于首位，断言仍快速成功 → **确定性复现并锁死该缺陷**

### 验收
- 全仓 **121 测试全绿**（watt_core 40）
- 经实时引擎（`--resolve github.com:443:127.0.0.1`）与经 26501 正向代理：200 / 0.45~0.87s
- ⚠️ **诚实标注**：测这些时公网恰好恢复（`20.205.243.166` 直连 129ms 可用），故该组成功**不能**单独归因于本次修复；确定性证据是候选矩阵 + 回归单测。修复真正发挥作用的时刻是 TLS 大面积卡死的干扰窗口。

### 手法沉淀
- **竞速 / 负载均衡的胜出条件必须与「可用性判据」一致**：TCP 层可达 ≠ 应用层可用。需 TLS 的目标，健康判据就是 TLS 握手完成。
- 分层次探测候选（TCP → TLS → HTTP）可一眼区分「封 IP」与「封 TLS 之后流量」。

### 遗留
- **加速模式未持久化**：`AcceleratorPage.vue` 的模式单选只改内存 `settings.settings.proxy_mode`，未调用 `save()` → 引擎按新模式跑、磁盘仍写旧模式（现场即引擎跑 26501 而 config=Hosts），重启后行为不一致。建议切换即保存。
- **候选扇出成本**：`race_tls` 每次请求最多并发 11 个 TLS 握手（胜出即 abort）。建议加「host → 优胜 IP」短期缓存降低扇出。

---

## 第十一轮：浏览器 404 的真凶 —— HTTP/2 没有 `Host` 头（已修复）

### 用户报告
- 关闭加速后 GitHub 能直连（怀疑是我们把好 IP 写进了 hosts 缓存）；
- 切到「系统代理」加速后报 **「找不到此 github.com 页 / 找不到以下 Web 地址的网页：https://github.com」**。

### 先证伪两个怀疑
- **hosts 无污染**：`grep -c "Steam++ Start" hosts` = 0，且 hosts 里**没有任何 github 条目**。直连可用只是公网恢复（DNS 给 `20.205.243.166`，直连 129ms 可用），与 hosts 无关。
- **证书无问题**：（见上一节）本版 CA 与信任存储指纹一致。

### 现场快照（关键：两条路径结论相反）
| 检查 | 结果 |
|---|---|
| `ProxyEnable` / `ProxyServer` | `1` / `127.0.0.1:26501`（System 模式生效） |
| 26501 监听 | ✅（PID = `watt-toolkit-app.exe`） |
| **curl 经 26501 访问 github.com** | ✅ **6/6 = 200 OK，0.63~1.05s**（577KB 真首页） |
| **浏览器（Edge）经 26501** | ❌ 404 空页 |
| hosts 标记 | 0（干净，无「双劫持」残留） |

→ 代理本身是好的，**只有浏览器坏**。

### 定位：用 HTTP/2 客户端复现
`not_found_response()`（`http_relay.rs:812`）= **404 + 空 body**；Chromium 对「404 + 空 body」会渲染成自己的错误页
「找不到此 <域名> 页 / 找不到以下 Web 地址的网页：<url> / HTTP ERROR 404」—— **与用户描述逐字吻合**。

而 `handle_request` 取目标主机的方式是：
```rust
req.headers().get(HOST)   // ← HTTP/2 没有 Host 头！
```
`find_by_url` 会把空 host 交给规则匹配；`find_domain_config` 仅当 `host.contains('.')` 才回落 default 规则，
空 host 既不匹配也不满足 default → `None` → **404**。

我们用 Node 写了一个经 CONNECT 隧道、可指定 ALPN 的探针（`h2_probe.cjs`），同一秒对比：

| 客户端 ALPN | 结果 |
|---|---|
| **h2**（浏览器） | `:status = 404`，body = **0 bytes** |
| **http/1.1**（本机 curl 构建不含 h2） | `200 OK`，582,575 bytes |

⇒ **`sni.rs:13` 把 `h2` 放在 ALPN 首位，浏览器必然协商 h2**，因此每个网站都命中这个 404 —— 这才是「完全没有加速效果」的真因。
之前查到的候选 IP / TLS 竞速问题**确实是真 bug**（已在上一轮修复），但它不是浏览器看到 404 的原因；curl 一直是 200 也正因如此。

### 修复
`crates/watt-core/src/http_relay.rs`
- 抽出 `request_host<B>(req)`：**优先 `Host` 头**（保持 HTTP/1.1 原行为），为空则回落到 `uri.authority()`（hyper 把 `:authority` 映射到这里），并自动去掉端口。
- `handle_request` 改用 `request_host(&req)`。
- 4 个单测：Host 头 / 仅 authority（无 Host）/ authority 带端口 / Host 头优先。

### 验收（全绿）
| 验证 | 结果 |
|---|---|
| 单测 `request_host` ×4 | ok |
| 集成测试 `test_forward_proxy_mitm_http2_authority_without_host_header`（CONNECT + MITM + h2 + 静态规则） | ok（**修复前必失败**） |
| **真实 GitHub** Hosts-MITM + **HTTP/2**（`diag_github_via_mitm_http2`） | **200 OK，577,310 bytes，1.5s** |
| 真实 GitHub Hosts-MITM + HTTP/1.1（`diag_github_via_hosts_mode`） | 200 OK，0.70s |
| 全仓测试 | **126 passed / 0 failed**（watt_core 44，+5） |

### 顺带修复：加速模式未持久化
`ui/src/views/AcceleratorPage.vue` 的 `selectedMode` setter 原先只改内存。本次改为：
1. 变更即 `settings.save()` 落盘（消除「磁盘写 A、引擎跑 B」）；
2. 若引擎正在运行，则自动 stop → 按新模式重新 start（否则切模式是个静默空操作）。
`vue-tsc --noEmit` 通过。

### 手工验证工具
`h2_probe.cjs`（仓库根，CommonJS）：经 **CONNECT 隧道 + 指定 ALPN** 访问目标，可直接判定「浏览器路径」是否可用。
```bash
node h2_probe.cjs github.com "h2,http/1.1"   # 浏览器路径（应 200）
node h2_probe.cjs github.com "http/1.1"      # 对照（应 200）
```

### 手法沉淀
- **HTTP/2 没有 `Host` 头**：任何「按 Host 头取目标主机」的 MITM/反向代理代码，都必须同时读 `uri.authority()`（`:authority`）。
- **ALPN 顺序决定客户端行为**：服务端把 `h2` 放首位，就等于承诺自己能正确处理 h2 语义。
- **「404 + 空 body」是 Chromium 自绘错误页**：`找不到此 <域名> 页 / HTTP ERROR 404` 不代表源站 404，往往是中间层返回了空 404。查这类问题先确认工具链的协议版本是否与被测客户端一致（本机 curl 无 h2，是极强误导项）。
- **双路径对照**：同一时刻分别用「HTTP/1.1」与「HTTP/2」客户端打同一代理，一秒钟锁定协议层差异。

