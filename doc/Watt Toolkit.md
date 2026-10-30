# Watt Toolkit（Tauri 重构版）应用指南与健壮性审计报告

| 项目 | 内容 |
| --- | --- |
| 代码仓库 | `D:\Project\Watt-Toolkit-Tauri`（Git 分支 `main`，审计基线提交 `d9728a7`） |
| 应用版本 | 0.5.1（workspace 统一版本） |
| 审计日期 | 2026-10-30 |
| 审计范围 | 全部 Rust 源码、Vue 3 前端、Tauri 配置、构建与发布脚本、依赖清单 |
| 代码规模 | Rust 源文件 61 个 / 19,654 行；前端源文件 30 个 / 5,961 行；9 个 workspace 成员；33 个 IPC 命令 |
| 验证结果 | Rust 单元测试 234 通过 / 6 忽略；中继集成 19 + Cookie 1 通过；`cargo clippy -D warnings` 通过；`cargo audit` 0 漏洞；`pnpm build` 通过（无 >500KB 警告） |
| 总体评级 | **B**：架构清晰、关键路径测试充分；仍需 macOS 系统代理状态恢复、macOS/Linux 实机与 GUI E2E 验证 |

> 本报告中的“已修复”均已在工作区落地并通过编译与测试，但**尚未提交 Git**。修改清单见第 8 节。

---

## 1. 应用概述

Watt Toolkit 是一个基于 **Tauri 2 + Rust + Vue 3** 的桌面网络加速工具，面向 Windows / macOS / Linux。它不建立 VPN 隧道，而是通过“把目标域名的流量引导到本机代理端口 + 本地 TLS 中间人（MITM）”的方式，为 Steam 社区、GitHub、Figma、Microsoft、Google 翻译等站点提供更稳定、更快的访问路径。

核心能力：

- **四种接入模式**：Hosts、系统代理（System）、PAC、仅代理端口（ProxyOnly），另有可选的 SOCKS5 入站。
- **本地 HTTPS MITM**：首次运行生成本地根 CA，按 SNI 动态签发叶子证书，解密后按域名规则转发。
- **多候选出站竞速**：覆盖 IP、镜像域名、DNS、动态 IP 池、内置备用池五类候选并发竞速，以 TLS 握手完成作为胜出条件。
- **加速项目目录**：从 `https://api.steampp.net` 拉取项目树，支持分组/子规则/URL 路径规则/UA 与 SNI 覆盖；静态响应、TLS 校验开关在规则模型与引擎层支持，但当前云端 DTO 未下发。
- **动态 IP 池**：按当前勾选项目域名解析候选，本地 TCP+TLS 探测后按 RTT 写入池，支持手工 IP 维护。
- **终端接入**：可选地向用户级环境变量 / shell 启动文件注入 `HTTP(S)_PROXY` 与 CA 变量，让 git、curl、npm、pip 也走加速。
- **可观测性**：内存环形缓冲的代理访问日志（5,000 条）与运行日志（3,000 条），支持过滤、分页、清空。

### 1.1 进程与数据流

```text
Vue 3 / Pinia (ui/)
   │  invoke(命令) / listen(引擎状态事件)
   ▼
Tauri 应用壳 (src-tauri/)
   │  AppState { engine: Mutex<ProxyEngine>, ca: RwLock<Arc<CaCertificate>>, settings_lock }
   │  单实例插件、系统托盘、运行日志采集、首启迁移
   ▼
ProxyEngine (crates/watt-core)
   ├─ 443  TLS MITM 监听（Hosts 模式）──┐
   ├─ 80   HTTP→HTTPS 重定向（可选）    │
   ├─ 26501 正向代理（CONNECT/绝对 URI/PAC）─┤
   └─ 8868 SOCKS5 入站（可选）          │
                                        ▼
                    RelayContext（规则、DNS、二级代理、脚本钩子、统计、访问日志）
                                        │
                                        ▼
                    OutboundConnector（候选竞速 + TLS 校验 + 上游代理链）
                                        │
                                        ▼
                                      目标站点
```

支撑 crate：

- `watt-cert`：CA 生成/加载、叶子证书缓存、三平台根证书信任安装、旧版 PFX 导入。
- `watt-hosts`：系统 hosts 标记块增删、原行备份与还原、注入校验。
- `watt-dns`：系统 DNS / 自定义 UDP DNS / DoH 解析器、污染判定。
- `watt-config`：代理设置、域名规则、旧版设置迁移、原子写工具。
- `watt-cloud`：加速项目云端目录、离线缓存、内置项目分组。
- `watt-script`：UserScript 解析、脚本存储、QuickJS 服务端钩子（当前未接入引擎）。
- `watt-elevate`：macOS 提权命令白名单与转义。

### 1.2 四种模式对照

| 模式 | 持久化改动 | 监听端口 | 适用场景 | 主要风险 |
| --- | --- | --- | --- | --- |
| Hosts | 写入系统 hosts 标记块 `# Steam++ Start/End` | 443（+ 可选 80） | 浏览器 / 大多数桌面程序 | 需要管理员权限；残留 hosts 会造成“域名指向本机但无人监听”的黑洞 |
| System | Windows HKCU `ProxyEnable/ProxyServer`；macOS `networksetup` | 26501 | 遵循系统代理的程序 | 会覆盖用户原有系统代理设置，停止时不还原（见 R1） |
| PAC | Windows `AutoConfigURL`；macOS autoproxy | 26501 | 需要按域名分流的环境 | 同上；PAC 内容由云端域名生成 |
| ProxyOnly | 无 | 26501（+ 可选 8868） | 手动配置代理的客户端 | 若监听地址改为非回环则成为开放代理（见 R7） |

---

## 2. 目录结构

```text
Watt-Toolkit-Tauri/
├─ Cargo.toml                  # workspace 定义、统一依赖版本、release LTO
├─ Cargo.lock                  # 依赖锁定（本次已从 .gitignore 移除，待提交）
├─ README.md                   # 构建/运行说明
├─ crates/
│  ├─ watt-core/               # 代理引擎（10,135 行，核心）
│  │  ├─ engine.rs             # 启停编排、状态机、残留清理
│  │  ├─ listener.rs           # 443/80/8868 监听与协议分发
│  │  ├─ forward_proxy.rs      # 26501 正向代理（CONNECT/绝对 URI/PAC）
│  │  ├─ http_relay.rs         # 反向代理主流程、脚本注入、访问日志
│  │  ├─ outbound.rs           # 候选解析、TLS/TCP 竞速、上游代理
│  │  ├─ upgrade.rs            # WebSocket / HTTP Upgrade 隧道
│  │  ├─ sni.rs                # MITM 接入 TLS 与出站 TLS 校验策略
│  │  ├─ local_domain.rs       # local.steampp.net 与注入脚本服务
│  │  ├─ inject.rs             # HTML 解压/定位/注入/重压缩
│  │  ├─ ip_pool.rs            # 动态 IP 池与可用 IP 过滤
│  │  ├─ probe*.rs             # 启动预探测与 RTT 缓存
│  │  ├─ system_proxy.rs       # Windows 注册表 / macOS networksetup
│  │  ├─ terminal_proxy.rs     # 终端环境变量与 shell 启动文件注入
│  │  ├─ fallback.rs           # 内置备用 IP 池
│  │  └─ ...                   # 统计、访问日志、端口诊断、PAC 等
│  ├─ watt-cert/               # CA / 叶子证书 / 信任存储 / PFX
│  ├─ watt-hosts/              # hosts 标记块算法与校验
│  ├─ watt-dns/                # DNS 解析与污染判定
│  ├─ watt-config/             # 设置、规则、迁移、原子写
│  ├─ watt-cloud/              # 云端目录、离线缓存、内置分组
│  ├─ watt-script/             # UserScript 与 QuickJS 钩子（未接入）
│  └─ watt-elevate/            # macOS 提权封装
├─ src-tauri/
│  ├─ src/main.rs              # 二进制入口
│  ├─ src/lib.rs               # 启动流程、AppState、命令注册、退出清理
│  ├─ src/commands/            # 33 个 IPC 命令（engine/cert/settings/...）
│  ├─ src/tray.rs              # 托盘菜单启停（复用持久化设置）
│  ├─ src/runtime_log.rs       # tracing → 环形缓冲
│  ├─ src/migrate.rs           # 首启旧版设置/CA 迁移
│  ├─ capabilities/default.json# 最小 Tauri 能力集
│  ├─ tauri.conf.json          # 窗口/CSP/打包配置
│  └─ app.manifest             # Windows requireAdministrator
├─ ui/
│  ├─ src/api/index.ts         # IPC 单一入口
│  ├─ src/stores/              # Pinia：proxy/settings/accelerate/ipPool/cert/theme
│  ├─ src/views/               # Home/Accelerator/IpPool/Settings/Logs/About
│  ├─ src/locales/             # 中英日法 + 繁体
│  └─ vite.config.ts           # 按需引入 Ant Design Vue
├─ doc/                        # 设计、迁移、终端劫持分析等项目记忆
└─ .github/workflows/release.yml # tag 触发的多平台发行构建
```

---

## 3. 关键模块说明

### 3.1 应用壳（`src-tauri`）

启动顺序：安装 rustls crypto provider → 初始化 `tracing`（stdout + 环形缓冲）→ 单实例插件 → 创建数据目录 → 首启迁移 → 加载动态 IP 池 → 加载/生成 CA → 装配 `AppState` → **崩溃残留清理**（hosts 标记块、指向本引擎端口的系统代理/PAC、终端代理变量）→ 创建托盘 → 注册命令。

退出时（`RunEvent::Exit`）停止引擎，摘 hosts、取消系统代理、关闭监听，并兜底还原终端代理变量。窗口关闭按钮只隐藏窗口，不退出进程。

### 3.2 代理引擎（`watt-core::engine`）

- 状态机：`Stopped → Starting → Running → Stopping → Stopped`，失败进入 `Error`。
- 启动步骤：清理残留 → 模式前置（端口预检 / 写系统代理 / 写 PAC）→ 构建规则与 DNS/上游上下文 → 绑定监听 → 写 hosts（失败回滚）→ 注入终端代理（失败不阻断）→ 启动预探测 → 置 Running。
- 停止步骤：摘 hosts（失败阻止停止，避免黑洞）→ 取消系统代理/PAC（失败阻止停止）→ 取消探测 → 保存探测缓存 → 还原终端变量 → 关闭监听（5 秒超时）。
- 关键不变量：**hosts 有劫持块时 443 必须在监听；443 不在监听时不得留下劫持块**。

### 3.3 入站监听

| 端口 | 模块 | 协议 | 并发上限 | 超时 |
| --- | --- | --- | --- | --- |
| 443 | `listener::run_mitm_listener` | TLS（ALPN h2/http1.1）→ 反向代理 | 256 | TLS 握手 10s |
| 80 | `listener::run_http_listener` | 明文 HTTP → 302 HTTPS / 反向代理 | 256 | 无请求头超时（R10） |
| 26501 | `forward_proxy` | CONNECT 隧道、绝对 URI、PAC | 256 | 请求行 10s（本次修复为累计超时） |
| 8868 | `listener::run_socks5_listener` | SOCKS5 CONNECT（无认证） | 256 | 握手 10s |

### 3.4 出站与候选竞速（`outbound`）

候选顺序：规则覆盖 IP → `forward_destination` 域名解析 → 原始 host 绕 hosts 解析 → 动态池 → 内置备用池；去重后并发竞速。

- 需要 TLS 的目标：以“完成 TLS 握手”为胜出条件，避免 TCP 可达但 TLS 被阻断的僵尸候选。
- 纯隧道：TCP 竞速。
- `CandidateHealth`：请求阶段失败的候选降权 60 秒，健康候选全灭时才回退。
- `ProbeCache`：启动预探测（单候选 2s、整体 12s、每域名最多 16 候选、60 秒周期重探）按 RTT 排序，5 分钟 TTL。

### 3.5 证书与信任（`watt-cert`）

- CA：ECDSA P-256（rcgen 默认算法），有效期 10 年，CN=`Watt Toolkit`；Unix 私钥 0600、目录 0700。
- 叶子证书：按 SNI 动态签发，SAN 含域名与 `127.0.0.1`/`::1`，有效期 1 年，DashMap 缓存。
- 信任：Windows LocalMachine\Root（API 失败时 UAC + certutil）；macOS `security add-trusted-cert`；Linux `update-ca-certificates`。
- 旧版迁移：解析空密码 PKCS#12，保持系统已信任指纹不变。

### 3.6 hosts、DNS 与配置

- hosts：只处理 `# Steam++ Start/End` 标记块；命中用户已有行时移入备份块，停止时还原；写入前校验 IP/域名，拒绝换行、`#` 与非法字符。
- DNS：系统语义解析器（读 hosts）与 clean 解析器（绕过 hosts）；默认规则对未配置域名做污染判定（解析到回环即报错）。
- 配置：`ProxySettings.json` 持久化模式、端口、二级代理、DNS、勾选项目、终端注入开关；本次改为原子替换。

### 3.7 前端（`ui`）

单页应用，6 个页面（首页、加速、IP 池、设置、日志、关于），5 种语言。所有 IPC 经 `src/api/index.ts`；引擎状态通过 `watt://engine-state-changed` 事件在托盘与面板间同步；统计每秒轮询。设置 store 在加载失败时拒绝保存，避免默认值覆盖磁盘配置。

---

## 4. 对外接口

### 4.1 Tauri IPC（33 个）

| 分组 | 命令 |
| --- | --- |
| 应用 | `get_app_info`、`migration_get_report` |
| 引擎 | `engine_start`、`engine_stop`、`engine_get_state`、`engine_get_stats`、`engine_probe_summary` |
| 证书 | `cert_get_status`、`cert_get_info`、`cert_install`、`cert_uninstall`、`cert_export_ca`、`cert_regenerate` |
| 设置 | `settings_get_proxy`、`settings_save_proxy` |
| 加速项目 | `accelerate_get_projects`、`accelerate_refresh`、`accelerate_set_enabled`、`accelerate_get_rules`、`accelerate_connectivity_test` |
| IP 池 | `ip_pool_refresh`、`ip_pool_refresh_host`、`ip_pool_builtin_list`、`ip_pool_domain_overview`、`ip_pool_list`、`ip_pool_save_domain`、`ip_pool_remove_domain`、`ip_pool_clear`、`ip_pool_probe_domain` |
| 日志 | `proxy_access_logs`、`proxy_access_logs_clear`、`runtime_logs`、`runtime_logs_clear` |

IPC 仅暴露给主窗口；`capabilities/default.json` 只授予 `core:default` 等基础能力，没有文件系统、Shell、HTTP 插件权限。生产 CSP 禁止内联脚本与 `eval`，`connect-src` 仅允许自身、IPC 与 `127.0.0.1`。

### 4.2 网络接口

| 接口 | 说明 |
| --- | --- |
| `GET https://api.steampp.net/api/Accelerate/All` | 加速项目目录（emoji 键 JSON），20 秒超时，失败降级本地缓存 |
| `http://127.0.0.1:{26501}/pac` | PAC 脚本 |
| `local.steampp.net`（Hosts 模式下解析到本机） | `requestType: status` 返回 `OK`；XHR 桥（脚本启用时才开放） |
| `/{WattToolkit_Inject}/{local_id}.js` | 注入脚本内容（当前脚本子系统未接入，实际返回 404） |

### 4.3 本地数据与配置

Windows 数据目录为 `%APPDATA%\WattToolkit`（Tauri `app_data_dir`；不可用时回退 `dirs::data_dir()/WattToolkit`）。

| 路径 | 内容 | 写入方式 |
| --- | --- | --- |
| `Settings/ProxySettings.json` | 代理模式、端口、二级代理账密、DNS、勾选项目、终端开关 | 原子替换（本次修复） |
| `Settings/IpPool.json` | 动态/手工 IP 池 | 临时文件 + rename |
| `Settings/TerminalProxyEnv.backup.json` | 终端变量原值备份（存在即表示已注入） | 原子替换（本次修复） |
| `Certificates/ca.cert.pem`、`ca.key.pem` | 本地根 CA 与私钥 | 直接写；Unix 权限 0600/0700 |
| `Accelerate/accelerate_projects.json` | 云端目录离线缓存 | 原子替换（本次修复） |
| `probe-cache.json` | 可选探测缓存（默认关） | 直接写，损坏即忽略 |

旧版数据：`%LOCALAPPDATA%\Steam++\Settings\ProxySettings.json` 与 `Steam++\Plugins\Accelerator\SteamTools.Certificate.pfx` 会在首启迁移。

---

## 5. 环境配置、构建与使用

### 5.1 构建环境

- Node.js 20+ / 22+，pnpm 11（仓库使用 `ui/pnpm-lock.yaml`，不是 npm/bun）。
- Rust stable（本机验证 1.96.0），Tauri 2 系统依赖。
- Windows：MSVC / Visual Studio Build Tools、Windows SDK；**必须以管理员终端运行**（应用清单 `requireAdministrator`，否则 `os error 740`）。
- macOS：Xcode Command Line Tools；Linux：`libwebkit2gtk-4.1-dev`、`libgtk-3-dev`、`libayatana-appindicator3-dev`、`librsvg2-dev`、`patchelf`。

### 5.2 开发与构建

```bash
# 安装前端依赖
pnpm install --dir ui

# 开发（Windows 请用管理员终端）
cargo tauri dev

# 仅前端
pnpm --dir ui dev

# 生产构建
pnpm --dir ui build
cargo tauri build

# 测试
cargo test --workspace --lib
cargo test -p watt-core --test cookie_forwarding --test proxy_integration

# 依赖审计
cargo audit
pnpm --dir ui audit --prod
```

发行：推送 `v*` tag 触发 `.github/workflows/release.yml`，构建 Windows x86_64/arm64、macOS x86_64/aarch64、Linux deb/AppImage。macOS 签名/公证需配置 `APPLE_*` Secrets；未配置时产物未签名，首次打开需右键“打开”。

### 5.3 运行时环境变量

| 变量 | 作用 |
| --- | --- |
| `RUST_LOG` | 日志过滤，默认 `info,watt_core=debug` |
| `SystemRoot` | Windows hosts 路径解析 |
| `HOME` / `SHELL` | Unix 终端代理注入时定位 shell 启动文件 |
| `TAURI_DEV_HOST` | Vite/Tauri 开发主机覆盖 |
| `TAURI_ENV_PLATFORM`、`TAURI_ENV_DEBUG` | 构建目标与压缩策略 |

应用会写入（并在停止时尽量还原）：`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`（Unix 另加小写副本），以及 `NODE_EXTRA_CA_CERTS`、`CURL_CA_BUNDLE`、`REQUESTS_CA_BUNDLE`、`SSL_CERT_FILE`、`GIT_SSL_CAINFO`。该能力默认开启，可通过设置页 `terminal_proxy_enable` 关闭。

### 5.4 使用流程

1. 启动应用（Windows 会请求一次管理员权限）。
2. 在“设置 → 证书”安装根证书（Windows UAC / macOS 管理员密码）。未安装时普通 HTTPS 站点仍可隧道直连，但命中规则的站点会证书错误。
3. 在“加速”页选择接入模式，勾选需要的项目；可先做分组连通性测试。
4. 点击“启动加速”。状态变为运行中后，探测摘要会显示“已择优”的候选情况。
5. 在“IP 池”页可查看每个域名的 IP 来源（覆盖/动态/内置/DNS），刷新或手工维护 IP。
6. 在“日志”页查看代理访问日志与运行日志；按关键字、方法、状态码、级别过滤。
7. 停止加速或从托盘退出；正常退出会清理 hosts、系统代理与终端变量。

注意事项：

- Hosts 模式占用 443，若被其他程序占用会提示占用进程名。
- 系统代理/PAC 模式会改写当前用户的系统代理；Windows 会在停止/残留清理时按快照还原，macOS 目前只关闭代理、**不会恢复用户原有配置**（见 R1）。
- DoH 已可用（域名/IP 端点均支持，自动注入 SNI 与根证书）。设置页 DoH 输入框旁提供「测试」按钮，会真实完成 TLS 握手与查询；测试失败时明确报错，不会静默回退（见 R2）。
- SOCKS5 入站无认证，默认仅监听 `127.0.0.1`；不要将监听地址改为 `0.0.0.0`。

---

## 6. 健壮性系统分析

### 6.1 错误处理与异常恢复

**做得好的部分**

- 引擎启停有明确状态机与回滚：hosts 写入失败会关闭已启动监听；系统代理设置失败会回滚；停止时 hosts/系统代理摘除失败会阻止关闭监听并恢复 `Running`，避免产生“黑洞”。
- 启动与退出两侧都做残留清理，且只清理“确认属于本引擎”的 hosts 标记块和指向本引擎端口的代理/PAC。
- Windows 在启用系统代理/PAC 前持久化用户原值，停止或崩溃后清理时按快照还原（本次新增，macOS 尚未实现）。
- 单实例插件最先注册，避免第二个进程的启动清理误删运行中实例的状态。
- 阻塞操作（UAC、hosts 写入、证书安装、系统代理）统一放入 `spawn_blocking`，不占用 tokio worker。
- 云目录拉取失败自动降级本地缓存；缓存损坏返回 `None` 并由内置分组兜底。
- 配置加载失败时前端拒绝保存，避免用默认值覆盖真实配置。
- 证书、hosts、PAC、URL 规则等外部输入均有基本校验；hosts 条目拒绝换行与标记注入。

**薄弱点**

- **系统代理/PAC 原值恢复不完整**：Windows 本次已加入快照/还原（见第 8 节），macOS 仍是启用时覆盖、停止时只关闭/清空，用户原有的公司代理、PAC 地址会丢失（R1，macOS 侧仍为高危）。
- **hosts 写入已改为原子替换（本轮）**：同目录临时文件 + fsync + rename，Unix 继承原权限；仅当 rename 被安全软件/文件锁拒绝时回退直接写并记录警告（R8）。
- **DoH 已修复并升级到 hickory 0.26（本轮）**：旧实现只接受 IP 端点，且 hickory 0.24 的内置 TLS 配置未加载根证书、强制关闭 SNI，导致 IP/域名端点均握手失败。现改为域名引导解析 + Mozilla 根证书 + 显式 SNI；0.26 同时支持自定义 DoH 路径。域名端点（`doh.pub`、`dns.alidns.com`）与 IP 端点实测可用；自定义路径由 0.26 原生支持（单测覆盖解析，`dns.google` 在本网络不可达未实测）。设置页「测试」按钮显式验证（R2）。
- **证书信任删除已改为按 DER/指纹精确匹配（本轮）**：Windows 比较 `pbCertEncoded`，失败时按 SHA-1 thumbprint 提权 `certutil -delstore`；macOS 按 SHA-1 过滤；不再按主题 CN 删除（R6）。
- **CA 与引擎启动的竞态**已通过锁顺序修复（本次），但 CA 文件与内存 CA 的一致性仍依赖启动时加载成功。

### 6.2 边界条件

| 边界 | 现状 | 评价 |
| --- | --- | --- |
| 端口 0 | 本次已统一回退默认端口（HTTPS 443、正向 26501、HTTP→80、SOCKS5 8868） | 已修复；此前会导致系统代理写成 `127.0.0.1:0` |
| 端口冲突 | 启动前预检 + 绑定失败回滚 + Windows 占用进程诊断 | 良好 |
| hosts 文件大小 | 50MB 上限 | 良好 |
| hosts 域名/IP | 长度、字符集、换行、注释符校验 | 良好 |
| HTTP 请求行/头 | 正向代理请求行累计 10s、请求头 16KB 上限（本次修复慢连接） | 良好；443/80 的 hyper 连接仍无请求头超时（R10） |
| 响应体大小 | 流式转发无缓冲；脚本注入/钩子路径缓冲上限 16MB（超限跳过处理并流式转发），解压上限 32MB | 已加固（R5） |
| 请求体大小 | XHR 桥 8MB 上限 + 30s 整体超时；脚本钩子路径沿用 16MB 缓冲上限 | 已加固（R5） |
| 日志容量 | 访问日志 5,000 条、运行日志 3,000 条、分页上限 500 | 良好 |
| 探测并发 | 域名 8 并发、每域名 16 候选、单候选 2s、整体 12s | 良好 |
| 规则数量 | 无显式上限；hosts 写入逐条校验 | 云端目录规模可控；建议加上限 |
| PAC 模式域名 | 本次转义换行/引号/反斜杠，防 JS 注入 | 已修复 |

### 6.3 输入校验与安全边界

**已具备**

- Tauri 能力集最小化；生产 CSP 禁止 `eval` 与内联脚本；`connect-src` 限制为本机 IPC。
- hosts 条目、手工 IP、域名规范化、PAC 模式转义均有校验。
- 出站 TLS 默认使用系统根证书校验；`tls_skip_verify` 仅在规则显式开启时生效，且注释明确“生产规则不应开启”。
- XHR 桥（脚本启用时）按已启用脚本的 match 域名做精确 Origin 白名单，并对目标 DNS 结果做公网 IP 过滤、以解析后的首个 IP 直连防 DNS 重绑定；请求体 8MB、整体 30s 超时。
- Unix 下 CA 私钥 0600、目录 0700；本次修复了旧版 PFX 导入路径继承 umask 的问题。

**不足**

- **XHR 桥 Origin 已改为精确白名单（本轮）**：只接受 http(s) 且主机命中某个已启用脚本 match 规则的 Origin；`null`、自定义协议、未匹配域名一律 403。请求体 8MB、整体 30s 超时、目标仍走公网 IP 过滤与首 IP 直连。脚本能力重新启用后仍需按实际脚本做端到端验证（R4）。
- **SOCKS5 入站无认证**，且隧道使用系统 DNS 直连，不经过域名规则/候选链；默认绑定回环可控，但配置文件中的 `system_proxy_ip` 若被改为 `0.0.0.0`，正向代理与 SOCKS5 都会暴露到局域网（R7）。
- **云端目录是路由配置的信任源**：项目规则可指定覆盖 IP、镜像/转发域名、SNI 覆盖、UA 与服务端代理标记，客户端不做签名校验；`api.steampp.net` 被攻破即可把加速域名的流量导向攻击者指定的地址（R9）。
- **二级代理密码明文存储**在 `ProxySettings.json`，未使用系统密钥链（R14）。
- 错误响应把内部错误字符串直接返回给浏览器（`转发失败: {e}`），可能泄露内网地址/库错误（R13）。
- 访问日志保存完整 path + query，可能包含 token（仅内存，R14）。

### 6.4 并发安全

**良好**

- 引擎启停由 `AppState.engine: tokio::Mutex` 串行化；证书重生成也持同一把锁（本次修复锁顺序）。
- 设置文件读-改-写新增 `settings_lock`（本次修复），避免“保存设置”与“保存勾选”互相覆盖。
- 连接数有 256 上限；候选竞速用 `JoinSet`，胜出后 abort 落败任务；探测有信号量限流。
- 日志存储为定长环形缓冲，短临界区、无 await。
- 终端代理注入“先备份再写”，失败立即回滚，备份文件是还原唯一依据（本次改为原子写）。

**风险**

- `std::sync::Mutex` 多处使用 `.unwrap()`（日志、IP 池、探测缓存、候选健康度）。若持锁线程 panic，后续所有请求会继续 panic（poison 传播）。概率低，但属于可消除的脆弱点（R15）。
- IP 池命令（保存/删除/清空/刷新）没有统一串行化；内存操作由 RwLock 保证原子，但并发落盘可能以较旧快照后写，重启后丢失最后一次变更（低概率）。
- `cert_uninstall` 与 `cert_install` 之间没有“证书操作锁”，并发点击可能交错（UI 已用 loading 限制，IPC 层未强制）。
- 443/80 的 hyper 连接没有请求头读取超时；本机恶意进程可开 256 个慢连接占满槽位（R10，默认仅回环，影响局部）。

### 6.5 依赖稳定性

审计工具：`cargo-audit 0.22.2` + RustSec 数据库（1,386 条公告）、`pnpm audit`。

| 指标 | 修复前 | 修复后 |
| --- | --- | --- |
| Rust 依赖总数 | 627 | 627 |
| Rust 已知漏洞 | 15 | **8** |
| Rust 不再维护告警 | 6 | 6 |
| Rust unsound 告警 | 2 | 1（`glib`，Linux Tauri 传递依赖） |
| 前端生产依赖漏洞 | 6（2 low / 4 high） | **0** |
| 前端全部依赖漏洞 | 14（7 high） | 8（仅开发/构建链，3 high） |

已通过 `cargo update` 修复：`rustls 0.23.45 → 0.23.46`、`rustls-webpki 0.103.16`、`webpki-root-certs 1.0.11`、`tokio 1.54.1`、`tauri 2.12.5` 等。前端将 `vue-i18n` 升至 11.4.16，并通过 `pnpm-workspace.yaml` 的 override 将 `source-map-js` 固定到 1.2.2。

**hickory 依赖链的 8 个 Rust 漏洞已随 0.26.3 升级全部清除**（历史清单如下，供追溯）：

| 公告 | crate | 影响 | 现状 |
| --- | --- | --- | --- |
| RUSTSEC-2026-0119 | hickory-proto 0.24.4 | DNS 消息编码 O(n²) CPU 消耗 | 已升级 hickory-proto 0.26.3 |
| RUSTSEC-2026-0258 | h2 0.3.27 | 空 DATA 帧导致资源耗尽 | 已升级 h2 0.4.20 |
| RUSTSEC-2026-0346/0349 | rustls 0.21.12 | Debug 泄露会话密钥、降级风险 | 已升级 rustls 0.23.46 |
| RUSTSEC-2026-0098/0099/0104/0382 | rustls-webpki 0.101.7 | 名称约束、CRL panic、不信任中间证书 | 已升级 rustls-webpki 0.103.16 |

`cargo audit --no-fetch --db ~/.cargo/advisory-db` 当前结果：**0 vulnerabilities / 6 warnings**；剩余均为 unmaintained/unsound（`proc-macro-error`、`rustls-pemfile`、`zbus`/`zvariant`、`glib`），其中 glib 仅 Linux Tauri 依赖。

另外发现：

- **`Cargo.lock` 此前被 `.gitignore` 忽略**，应用构建无法复现、安全修复不可审计。本次已移除忽略规则（文件目前为未跟踪状态，需提交）。
- 依赖树仍有少量多版本并存（`rand 0.8/0.10`、`base64 0.22/0.23`、`fastrand 2.5`），但 `rustls` 已统一到 0.23、`h2` 统一到 0.4，供应链审计面明显收窄。
- `ui/bun.lock` 仍被跟踪，但项目实际使用 pnpm，存在误导。
- `glib 0.18.5` 的 unsound 公告来自 Linux Tauri 依赖，Windows 构建不受影响。
- 已有 PR/push CI（前端 build/audit、Windows clippy/单测/中继集成测试、RustSec 审计），见 `.github/workflows/ci.yml`（R11）。

### 6.6 性能与资源

- 正向代理响应默认流式转发，首字节即时下发；大响应不会整包缓冲（脚本关闭时）。
- 候选竞速并发、探测限流、连接上限设计合理。
- 访问日志 `path` 未截断，恶意客户端可用超长 URI 抬高内存占用（5000 条 × 长 URI）；hyper 对 URI 长度有限制，风险有限。
- 子规则与 URL 通配模式已加正则编译缓存（上限 2048，失败也缓存），不再每请求 `Regex::new`（R12）。
- 前端已按 `manualChunks` 拆分 vendor：入口约 0.1KB、最大 chunk 430KB（gzip 138KB），构建不再出现 >500KB 警告（R12）。
- `ui/dist` 约 2.0MB，可接受。

### 6.7 平台与可运维性

- Windows 全进程提权（requireAdministrator）是 hosts 模式的必然代价，但也意味着 WebView 进程拥有管理员令牌；CSP 与最小能力集降低了风险，仍建议长期评估“提权仅用于 hosts 写入”的拆分方案。
- macOS 提权命令有白名单与双层转义，设计良好；但系统代理仍未实现快照还原，且本次修复未在 macOS 实机验证。
- 运行日志只在内存，崩溃后丢失；没有持久化日志或错误上报（Sentry 等），排障依赖用户复现。
- 没有健康检查/指标导出；桌面应用可接受，但远程诊断能力弱。
- release 工作流没有测试门槛，tag 可直接产出未签名 macOS 包。

---

## 7. 风险清单

| ID | 级别 | 位置 | 问题 | 影响 | 状态 |
| --- | --- | --- | --- | --- | --- |
| R1 | **中高（macOS）** | `crates/watt-core/src/system_proxy.rs` | Windows 已快照/还原；macOS 启用前未保存原值，停止时只关闭/清空 | macOS 用户原有公司代理/PAC 配置丢失 | Windows 已修复；macOS 待处理 |
| R2 | 中高 | `crates/watt-dns/src/resolver.rs`、`ui/src/views/SettingsPage.vue` | 旧实现只接受 IP 端点；hickory 0.24 内置 TLS 无根证书且强制关闭 SNI，域名/IP 端点握手均失败 | 用户以为启用了加密 DNS，实际回退系统 DNS | **已修复**：hickory 0.26 + 域名引导解析 + 自定义路径 + webpki 根证书 + SNI；`dns_probe_doh` 与设置页测试按钮。运行时端点不可达则查询失败（不静默回退明文 DNS） |
| R3 | **高** | `Cargo.lock` / hickory 链 | 8 个 RustSec 漏洞（hickory 0.24、rustls 0.21、rustls-webpki 0.101、h2 0.3） | 供应链风险 | **已修复**：升级 hickory 0.26.3（rustls 0.23 / h2 0.4 / rustls-webpki 0.103）；`cargo audit` 0 漏洞，仅 6 条 unmaintained/unsound 警告 |
| R4 | 中（潜在） | `crates/watt-core/src/local_domain.rs` | XHR 桥只校验 Origin 协议前缀，任意 http(s) 页面可用；无鉴权 | 脚本能力重新启用后成为跨站请求/内网探测通道 | **已加固**：Origin 必须命中已启用脚本的 match 域名；保留 SSRF 公网过滤、8MB 体积上限与 30s 超时。脚本仍关闭 |
| R5 | 中（潜在） | `crates/watt-core/src/http_relay.rs`、`inject.rs` | 脚本注入/钩子路径整包缓冲请求/响应，无大小上限；gzip 解压无上限 | 启用脚本后可能被大响应/压缩炸弹拖垮内存 | **已加固**：缓冲 16MB + 解压 32MB 上限；超限跳过注入/钩子并流式转发。脚本仍关闭 |
| R6 | 中 | `crates/watt-cert/src/trust.rs` | Windows 删除根证书按主题 CN 匹配，非指纹精确匹配 | 可能误删同名第三方根证书 | **已修复**：按 DER 精确比较；提权回退按 SHA-1 thumbprint；macOS 按 SHA-1 过滤 |
| R7 | 中高 | `system_proxy.rs`、`listener.rs` | 正向代理/SOCKS5 无认证；配置文件可把监听地址改为 `0.0.0.0` | 暴露到局域网后成为开放代理 | 默认回环；建议强制回环或加认证 |
| R8 | 中 | `crates/watt-hosts/src/lib.rs` | hosts 直接截断写入，非原子替换 | 写入中崩溃可能损坏系统 hosts | **已修复**：同目录临时文件 + fsync + rename；rename 被锁时回退直接写并告警 |
| R9 | 中 | `crates/watt-cloud` | 云端目录无签名/固定，规则可指定 SNI、覆盖 IP、镜像域名与服务端代理标记 | API 被攻破可把加速流量导向攻击者地址 | 设计权衡；建议签名或白名单 |
| R10 | 中 | `crates/watt-core/src/listener.rs`、`forward_proxy.rs` | hyper 连接无请求头超时；正向代理此前慢连接可无限占用（已修复） | 本机恶意进程可耗尽 256 连接槽 | 部分修复；建议配置 header timeout |
| R11 | 中 | `.github/workflows/` | 无 PR CI（check/test/clippy/audit），仅发行构建 | 回归与漏洞进入主干的成本低 | **已修复**：新增 `ci.yml`（前端 build/audit、Windows clippy/单测/中继测试、RustSec 审计） |
| R12 | 低 | `http_relay.rs`、`domain_rule.rs`、UI 构建 | 每请求编译正则；主 chunk 594KB | CPU 与首屏性能开销 | **已修复**：正则编译缓存（2048 上限）；manualChunks 拆分，入口 0.1KB / 最大 430KB |
| R13 | 低 | `http_relay.rs::error_response` | 内部错误字符串直接返回浏览器 | 信息泄露 | 待处理 |
| R14 | 低 | `ProxySettings.json`、访问日志 | 二级代理密码明文；访问日志含完整 query | 本机同用户可读；日志可能含 token | 本次已将 Unix 配置文件设为 0600；仍建议密钥链/脱敏 |
| R15 | 低 | 多处 `std::sync::Mutex::unwrap` | 锁中毒会级联 panic | 单次 panic 可能放大为持续失败 | 待处理（`unwrap_or_else(PoisonError::into_inner)`） |
| R16 | 中 | 全仓库 | 本次变更未在 macOS/Linux 实机运行；无 GUI E2E | 平台差异风险 | 验证缺口 |

---

## 8. 本次已实施的修复

| # | 问题 | 修复内容 | 涉及文件 | 验证 |
| --- | --- | --- | --- | --- |
| 1 | 正向代理慢连接可永久占用连接槽（peek 超时被逐次重置） | 改为**累计截止时间**；新增可注入超时的内部函数与回归测试 | `crates/watt-core/src/forward_proxy.rs` | 新增 `test_peek_request_line_bounds_slow_client` 通过 |
| 2 | WebSocket/Upgrade 等待上游响应头无超时 | 增加 15 秒累计截止时间 | `crates/watt-core/src/upgrade.rs` | 编译 + 全部集成测试通过 |
| 3 | hosts 只有 Start 没有 End（写入中崩溃）时启动不清理 | `contains_mark` 同时识别 Start/End；验证可清除不完整块并保留普通条目 | `crates/watt-hosts/src/lib.rs` | 新增 `test_contains_mark_detects_truncated_block` 通过 |
| 4 | 配置文件直接截断写入，崩溃丢配置；Unix 权限随 umask | 新增 `write_atomic`（临时文件 + fsync + rename，Windows 回退删除重命名；同进程序号防临时文件碰撞；Unix 下 0600）；用于设置、云缓存、终端代理备份 | `crates/watt-config/src/settings.rs`、`watt-cloud/src/cache.rs`、`watt-core/src/terminal_proxy.rs` | 新增原子写测试；设置/云缓存/终端测试通过 |
| 5 | 「保存设置」与「保存勾选」并发写同一 JSON 互相覆盖 | `AppState` 增加 `settings_lock`，读写命令串行化 | `src-tauri/src/lib.rs`、`commands/settings.rs`、`commands/accelerate.rs` | 编译 + app 单元测试通过 |
| 6 | 证书重生成与引擎启动竞态（旧 CA 服务新证书文件） | 统一锁顺序：先 engine 锁再读/换 CA；重生成全程持 engine 锁 | `src-tauri/src/commands/engine.rs`、`commands/cert.rs`、`tray.rs` | 编译通过；未做并发压力测试 |
| 7 | 旧版 PFX 导入的私钥继承 umask（Unix 可能 644） | 复用 `write_private_file` 强制 0600，目录 0700 | `crates/watt-cert/src/ca.rs`、`pfx.rs` | PFX roundtrip 测试通过；Unix 权限断言已加入 |
| 8 | SNI 动态证书缓存无上限 | 超过 4,096 条整体清空，防随机 SNI 撑爆内存 | `crates/watt-cert/src/leaf.rs` | 既有叶子证书测试通过 |
| 9 | SSRF 过滤漏掉 CGNAT/保留段/IPv4-mapped IPv6 | 扩展 `is_usable_ip` 覆盖 0/8、100.64/10、192.0.0/24、198.18/15、240/4、fec0::/10、2001:db8::/32，并还原 IPv4-mapped | `crates/watt-core/src/ip_pool.rs` | 新增保留段与 mapped 地址测试通过 |
| 10 | PAC 域名含换行可注入 JS 语句 | 转义 `\r`、`\n`、U+2028/U+2029 | `crates/watt-core/src/pac.rs` | 新增换行注入测试通过 |
| 11 | 端口 0 导致监听随机端口、系统代理写成 `:0` | HTTPS/HTTP/正向/SOCKS5 端口统一回退默认值（命令层 + 托盘） | `src-tauri/src/commands/engine.rs`、`tray.rs` | 编译通过；逻辑为纯边界处理 |
| 12 | DoH/主 DNS 配置静默失效 | **本轮已重写**：支持域名/IP 端点、引导解析、webpki 根证书与 SNI；失效时 `DnsBackend` 保留真实回退状态并提供 `doh_error`；新增 `dns_probe_doh` 与设置页测试按钮 | `crates/watt-dns/src/resolver.rs`、`src-tauri/src/commands/dns.rs`、`ui/src/views/SettingsPage.vue` | DNS 单测 + 真实网络 DoH 域名/IP 端点测试通过 |
| 13 | 依赖漏洞与锁文件缺失 | `cargo update` 修复 7 类公告；`vue-i18n` 升级；`source-map-js` override；`.gitignore` 不再忽略 `Cargo.lock` | `Cargo.lock`、`ui/package.json`、`ui/pnpm-lock.yaml`、`ui/pnpm-workspace.yaml`、`.gitignore` | `cargo audit` 15→8；`pnpm audit --prod` 6→0 |
| 14 | Windows 系统代理/PAC 覆盖用户原有配置且停止不还原 | 启用前把 `ProxyEnable/ProxyServer/ProxyOverride/AutoConfigURL` 快照到 `HKCU\Software\WattToolkit\SystemProxyBackup`（幂等，只在首次抓取）；停止/残留清理按快照逐项写回并删除快照；写回失败保留快照重试；启用过程中部分写入失败也会回滚原值 | `crates/watt-core/src/system_proxy.rs`、`engine.rs` | 新增 `capture_and_restore_roundtrip`、`capture_is_idempotent`（仅在临时注册表键上操作）通过 |
| 15 | DoH 实际不可用（域名端点被拒、IP 端点握手失败） | 重写端点解析与构造：域名引导解析（独立线程 + 3s 超时）、Mozilla 根证书、自定义 rustls 配置开启 SNI/ALPN=h2；`NameServerPool` 会用 `ResolverConfig::client_config()` 覆盖逐个 nameserver 的 TLS 配置，改为在 ResolverConfig 层注入；HTTP 端点与自定义路径显式拒绝；记录 `DnsBackend`/`doh_error` | `crates/watt-dns/src/resolver.rs`、`Cargo.toml`、`crates/watt-dns/Cargo.toml` | 单测 + `--ignored` 真实网络测试：`doh.pub`、`dns.alidns.com`、`1.12.12.12`、`223.5.5.5` 全部解析成功；Cloudflare 在本网络超时（网络阻断，非解析器错误） |
| 16 | DoH 配置失效时 UI 仍显示「DoH」且无法验证 | 新增 `dns_probe_doh` IPC（返回端点/解析 IP/耗时，失败即报错）；IP 池按实际 `DnsBackend` 选择解析器与展示来源；设置页增加「测试」按钮与 5 语言文案 | `src-tauri/src/commands/dns.rs`、`commands/ip_pool.rs`、`crates/watt-core/src/ip_pool.rs`、`ui/src/views/SettingsPage.vue`、`ui/src/api/index.ts`、`ui/src/types/ipc.ts`、5 个 locale | `pnpm build`（vue-tsc）通过；`dns_probe_doh` 单测 + 真实网络测试通过 |
| 17 | hickory 0.24 依赖链 8 个 RustSec 漏洞 | 升级 hickory-resolver 0.26.3（hickory-proto/net 0.26.3、rustls 0.23、h2 0.4、rustls-webpki 0.103）；重写 `watt-dns` Resolver 构建、lookup 与 TLS 注入；DoH 支持自定义路径 | `Cargo.toml`、`Cargo.lock`、`crates/watt-dns/*` | `cargo audit --no-fetch`：0 vulnerabilities / 6 warnings；真实 DoH 域名+IP 端点通过 |
| 18 | XHR 桥 Origin 仅校验协议前缀；脚本路径缓冲/解压无上限 | Origin 必须命中已启用脚本 match 域名；XHR 30s 整体超时；脚本缓冲 16MB、解压 32MB 上限，超限跳过注入/钩子并流式转发 | `crates/watt-core/src/local_domain.rs`、`http_relay.rs`、`inject.rs` | 新增 Origin 白名单、限长读取测试；watt-core 114 单测 + 中继集成 19 通过 |
| 19 | 根证书按 CN 删除；hosts 非原子写 | 根证书按 DER/SHA-1 精确删除（macOS 同步过滤，Windows 提权按 thumbprint）；hosts 同目录临时文件 + fsync + rename，保留权限 | `crates/watt-cert/src/trust.rs`、`src-tauri/src/commands/cert.rs`、`crates/watt-hosts/src/lib.rs` | hosts 原子替换/权限保留测试通过；重新生成 CA 先取旧 DER 再删 |
| 20 | 无 PR CI；每请求编译正则；前端主 chunk 594KB | 新增 `.github/workflows/ci.yml`；URL/子规则正则编译缓存；Vite manualChunks 拆 vendor | `.github/workflows/ci.yml`、`watt-config/src/domain_rule.rs`、`watt-core/src/http_relay.rs`、`ui/vite.config.ts` | clippy `-D warnings` 通过；前端入口 0.1KB、最大 chunk 430KB，无 >500KB 警告 |
| 21 | 代码审查发现的代理/配置/脚本边界问题 | 快照失败不回滚、快照 Complete 最后写并清理陈旧快照；配置 rename 失败不再删旧文件；DNS 构造提前并 spawn_blocking；XHR DNS 3s 超时；阻断 NAT64/6to4/Teredo/IPv4-compatible；证书统一用户存储并清理机器旧值；chunked 超限转流式；CI 补 cookie 测试 | `system_proxy.rs`、`engine.rs`、`settings.rs`、`commands/dns.rs`、`local_domain.rs`、`ip_pool.rs`、`trust.rs`、`commands/cert.rs`、`http_relay.rs`、`ci.yml` | 单测 234 通过 / 6 忽略；中继 19 + Cookie 1；真实 DoH 通过 |

变更规模：上一轮 24 个已跟踪文件，约 +834 / -96 行；两轮 DoH/加固/审查修复共涉及约 28 个文件（含新增 `commands/dns.rs`、`ci.yml`）与 `Cargo.lock`（hickory 0.26.3 / rustls 0.23 / webpki-roots 1），未提交 Git。

---

## 9. 验证记录

已执行：

```text
cargo check --workspace --all-targets                 通过
cargo clippy --workspace --all-targets -- -D warnings 通过
cargo test --workspace --lib                          234 passed / 0 failed / 6 ignored
cargo test -p watt-core --test cookie_forwarding      1 passed
cargo test -p watt-core --test proxy_integration      19 passed
cargo test -p watt-dns --lib -- --ignored             2 passed（真实网络 DoH：域名 + IP 端点）
cargo test -p watt-toolkit-app --lib commands::dns::tests::probes_live_endpoint -- --ignored  1 passed
pnpm --dir ui build（vue-tsc + vite）                  通过（入口 0.1KB，最大 chunk 430KB，无 >500KB 警告）
cargo audit --no-fetch --db ~/.cargo/advisory-db       0 vulnerabilities / 6 warnings（均为 unmaintained/unsound）
pnpm --dir ui audit --prod                            No known vulnerabilities
```

未执行/未覆盖：

- macOS / Linux 实机运行与提权交互（本次修改中的 Unix 权限、macOS 系统代理未实测）。
- GUI 端到端点击流程、UAC 取消、证书安装/卸载的实际系统状态变更。
- 真实网络下的加速效果、DNS 污染场景、IPv6-only 网络。
- 长时间稳定性/内存压力、脚本子系统启用后的路径。
- `#[ignore]` 的真实链路诊断测试（`diag_*`）。

---

## 10. 后续建议（按优先级）

### P0（对外发行前必须）

1. **补齐 macOS 系统代理/PAC 快照与恢复**：把各网络服务的 web/secure/autoproxy 状态持久化到应用数据目录，停止/异常启动清理时按快照还原。Windows 已完成快照还原（本次）并覆盖崩溃残留路径；macOS 仍需实现并实机验证。
2. **提交 `Cargo.lock`**，CI 已加入 `cargo audit` 与 `pnpm audit --prod` 门禁（`.github/workflows/ci.yml`）。
3. ~~hickory 0.24 → 0.26 升级~~ **已完成**：0 vulnerabilities；保留 6 条 unmaintained/unsound 警告（zbus/zvariant、rustls-pemfile、glib 等），后续随依赖升级清理。

### P1（下个迭代）

4. **XHR 桥加固**（脚本能力重启前）：Origin 白名单、一次性 token、限制方法与目标域、请求/响应体上限与超时；或直接移除桥，改为脚本专用 API。
5. **中继缓冲上限**：对请求/响应 `collect()` 使用 `Limited`，解压设置输出上限；超限降级为流式或返回 413/502。
6. **证书按指纹删除**：`remove_root_cert` 接收证书 DER/指纹，精确匹配；重生成时先取旧指纹再删。
7. **监听地址策略**：默认强制回环；若允许非回环，必须要求认证（至少随机 token）并在 UI 明确警告。
8. **hosts 原子写**：同目录临时文件 + 原子替换（Windows 可用 `ReplaceFileW` 或先写临时再 `MoveFileEx` 替换），并保留回读校验。
9. **CI**：PR 上跑 `cargo check/test`、`cargo clippy -D warnings`、`pnpm typecheck/build`、两个 audit；发行工作流依赖测试通过。
10. **请求头超时**：为 hyper 连接配置 header read timeout，补齐 443/80 的慢连接防护。

### P2（持续优化）

11. 正则编译缓存（按 pattern 缓存 `Regex`，带上限）。
12. ~~前端 manualChunks / 路由懒加载，削减 594KB 主 chunk~~ **已完成**：vendor 拆分后入口 0.1KB、最大 chunk 430KB。
13. 访问日志 path 截断与敏感 query 脱敏；二级代理密码迁移到系统密钥链。
14. `Mutex` 中毒恢复（`unwrap_or_else(PoisonError::into_inner)`）统一处理。
15. 持久化运行日志（滚动文件）与可选的崩溃上报；健康检查/指标。
16. 清理 `ui/bun.lock`，统一 pnpm；评估减少重复依赖版本。
17. 补 macOS/Linux CI 构建与最小烟测；为系统代理/证书/终端注入增加平台集成测试。

---

## 附录：关键不变量与排查顺序

**不变量**

1. hosts 有 `# Steam++ Start/End` 块时，443 必须处于监听；443 停止前必须先摘块。
2. 系统代理/PAC 指向本引擎端口时，不得关闭对应监听。
3. 竞速胜出条件必须与可用性判据一致（TLS 目标以 TLS 握手完成为准）。
4. 出站解析必须绕过 hosts（clean resolver），否则会回环到自身。
5. 清理残留只允许撤销“确认属于本引擎”的 hosts 标记块与端口。

**排查顺序**

1. `netstat -ano | findstr LISTENING` 核对 443 / 26501 是否符合当前模式。
2. 检查 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` 的 `ProxyEnable/ProxyServer/AutoConfigURL`。
3. 检查 `C:\Windows\System32\drivers\etc\hosts` 是否有残留标记块。
4. 分路对比：`curl --noproxy '*'`（hosts 面）与 `curl -x http://127.0.0.1:26501`（正向代理面）。
5. 浏览器异常而 curl 正常时，优先怀疑 HTTP/2 差异，用 `node h2_probe.cjs <host> "h2,http/1.1"` 复现。
6. 查看应用内“运行日志”和“代理访问日志”，按 host/状态码过滤。

---

*报告生成：Qoder / production-code-audit。所有修改位于工作区，未提交 Git；建议审阅 `git diff` 后按项目规范提交。*