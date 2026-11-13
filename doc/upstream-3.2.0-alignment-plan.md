# 上游 SteamTools 3.2.0 变更对齐技术规划

> 版本：v0.5.3 → 目标 v0.6.0（建议）
> 编写日期：2026-11-13
> 上游基线：`BeyondDimension/SteamTools` tag `3.2.0`（commit `1eeeae7e`，2026-11-09 发布）
> 上一基线：tag `3.1.0`（commit `86122510`，2026-03-11）
> 结论状态：✅ 已核对上游源码 / 🟡 推断 / ⚠️ 待人工确认
>
> **实施进度：P0（A1–A5）已完成并验证** —— 见 §9。

---

## 9. 实施记录（P0 已落地）

| 项 | 状态 | 落点 | 验证 |
| --- | --- | --- | --- |
| A1 出站握手 IPv6/ATYP | ✅ 完成 | `outbound.rs`：`host_for_authority` / `socks5_connect_request` | 单测 `test_host_for_authority_ipv6`、`test_socks5_connect_request_atyp` |
| A2 DNS 有序列表 | ✅ 完成 | `watt-dns/resolver.rs`：`ResolverServer`、逐项回退、按 server 隔离缓存 | 单测 6 例（解析去重/替换/截断/严格单端点/回退） |
| A3 配置迁移与接线 | ✅ 完成 | `DnsSettings.resolver_servers`、`expand_dns_server_list`、`before_dns_check` 接线 | `watt-config` 迁移用例；全工作区测试 |
| A4 Hosts 防回环 | ✅ 完成 | `engine.rs` `prefer_public_dns`；`http_relay` 与 `outbound` 双重回环兜底 | `diag_github` 双路径 200 |
| A5 UI 列表编辑 | ✅ 完成 | `SettingsPage.vue` 有序列表 + 行内 DoH 测试 + 预检查开关；5 语言包 | `vue-tsc --noEmit`、`vite build` |

**整体质量门**：`cargo clippy --workspace --all-targets -- -D warnings` 零告警；`cargo test --workspace` 全绿；`diag_github`（HTTP/1.1 + h2）均 200。

**实现细节与上游的差异（有意）**

1. DoH 探测走 `DnsResolver::single`（严格单端点），保证「点测试就得真实结果」，不会被列表回退掩盖。
2. `before_dns_check` 预算收紧到 3s 且仅记日志——它是诊断而非守门，不应把启动拖成十几秒。
3. 迁移时不把用户**关掉**的 DoH 重新打开（上游会合并两类字段）。
4. 列表去重后上限 8 个，避免用户粘一长串地址拖慢每次解析。
5. 回环兜底分两层：默认规则在转发前拒绝（返回可读错误页），出站解析过滤回环候选（防其它规则路径自环）。

---

## 0. 结论先行

1. **上游 3.1.0 → 3.2.0 共 59 个提交**，其中与「网络加速」相关的改动集中在 **56 个文件、+2794 / −1840 行**，几乎全部落在 `BD.WTTS.Client.Plugins.Accelerator` 与 `...Accelerator.ReverseProxy` 两个工程内。
2. 上游这一版的加速器改动**不是加功能，而是修稳定性**：DNS 从「单后端开关」改为「有序服务器列表 + 逐项回退」；启动时序从「先改系统代理再起监听」改为「先起监听再改系统代理」；出站二级代理握手全面补齐分段读 / IPv6 / 资源释放；错误码细分到「可诊断、可提示」。**这四类问题我们目前全部存在**。
3. 需要跟进的共 **8 项**，其中 **P0 3 项**（出站握手健壮性、DNS 服务器列表、Hosts 模式 DNS 回环）、**P1 4 项**（启动时序、host 端口归一化、错误码体系、Linux 系统代理）、**P2 1 项**（KeyIso 诊断）。另有 **4 项已天然对齐**，不必重复投入。
4. 范围控制：不跟随上游的 Avalonia/.NET 11/Steam 令牌二维码/挂卡/库存等**非加速领域**改动（占 59 个提交中的大多数），也不跟随其「加速子进程 + IPC」模型——我们是单进程 Rust + 前端 IPC，架构上已消除该类问题。

---

## 1. 拉取与基线核对

### 1.1 本轮实际执行

```bash
# 上游未配置为本仓库 remote，采用独立 blobless 克隆，避免污染工作区
git clone --filter=blob:none --no-checkout --single-branch \
  --branch main https://github.com/BeyondDimension/SteamTools.git /tmp/SteamTools-upstream
git fetch origin refs/tags/3.1.0:refs/tags/3.1.0 refs/tags/3.2.0:refs/tags/3.2.0
```

| 项 | 值 |
| --- | --- |
| 上游最新正式版 | `3.2.0`（2026-11-09） |
| 上游主干 HEAD | `0286ed1e`（Merge PR #986 from develop） |
| 本仓库当前版本 | `0.5.3`（`src-tauri/tauri.conf.json`） |
| 本仓库基线性质 | **功能等价重写**，非 fork 同步；不存在可直接 cherry-pick 的提交 |

> 🟡 本仓库不是上游的分支，无法 `git merge`。对齐方式是**逐条行为移植**：读上游 diff → 找到我方对应实现 → 按我方架构重写 → 用我方真机验收链路验证。

### 1.2 上游加速器改动规模

| 工程 | 变更文件 | 增删 |
| --- | --- | --- |
| `BD.WTTS.Client.Plugins.Accelerator` | 40 | +2115 / −1414 |
| `BD.WTTS.Client.Plugins.Accelerator.ReverseProxy` | 16 | +679 / −426 |
| 合计 | **56** | **+2794 / −1840** |

> 另有 `BD.WTTS.Client` 平台层（Linux 系统代理重构，`11f35fcf`：5 文件 +82/−25）与本仓库加速域相关，计入 §3.7。

---

## 2. 上游迭代内容全景

### 2.1 与网络加速强相关（必须评估）

| 提交 | 主题 | 实质改动 | 影响我方 |
| --- | --- | --- | --- |
| `529cac5a` | 优化 DNS 配置与自动检测 | DNS 单后端 → **有序服务器列表**（DoH + 明文混合）；逐项回退、缓存隔离、预检查语义变更 | ✅ 是（P0） |
| `cb18e2d9` | 端口绑定失败提示 + 异常传输修复 | 新增 `ListenerBindFailed(131)`；TCP 端口占用/拒绝访问单独归类 | ✅ 是（P1） |
| `1eeeae7e` | 代理错误处理收尾 | 错误文案按实际端口（Hosts=443/80）；证书失败走专用提示 | ✅ 是（P1） |
| `9b66636a` | HTTP→HTTPS 默认配置 | `EnableHttpProxyToHttps` 默认 `true → false`，JSON 键改名 `EnableHttpProxyToHttps2` 强制旧值失效 | ✅ 已对齐 |
| `de1c04c1` | CNG Key Isolation 禁用提示 | 新增 `CertificateFailureDiagnostics`：注册表 `KeyIso` Start 值 + SCM 服务状态双重判定 | 🟡 部分（P2） |
| `11f35fcf` | 重构 Linux 系统代理 | `gsettings` 改为逐键 exec + 校验退出码，失败抛异常；新增进程内 `LinuxAcceleratorWebProxy` 动态切换 | ✅ 是（P1） |
| `048fb345` | 安全：特权任意路径文件覆盖 | 删除 `-clt ayaneo -path <任意路径>` 子命令（提权进程写任意路径） | ✅ 自查（P2） |
| `4ed8319f` | 移除 `ConfigureAwait(false)` + IPC 校验 | 子进程校验、退出处理 | ❌ 架构已不同 |
| `3d855ef2` | Linux IPC 进程校验 / 原生 UI 退出 | 同上 | ❌ 架构已不同 |
| `0918d776` | 统一日志提供程序 | 清除 Kestrel 默认日志 | ✅ 已对齐（tracing 单栈） |

### 2.2 与加速无关（明确不跟进）

Steam 令牌二维码登录、挂卡（含黑名单）、库存游戏加载优化、账号切换修复、ASF 插件、Avalonia 12 / .NET 11 升级、macOS 菜单项、首页商城移除、NSIS 打包接口。**这些不在本仓库功能范围内**（本仓库只重写加速域，见 `doc/task.md` 范围定义）。

---

## 3. 差距逐项分析

### 3.1 P0-1 出站二级代理握手健壮性

**上游改法**（`ReverseProxyHttpClientHandler.cs`）：

| 缺陷 | 上游修法 |
| --- | --- |
| `CONNECT` 响应只 `ReadAsync` 一次，可能读到隧道正文 | **逐字节**读到 `\r\n\r\n` 为止，不吞正文 |
| 状态行判定过松 | 校验 `HTTP/1.x` 前缀 + 状态码 == 200 |
| SOCKS5 协商响应可能被拆包 | `ReadExactly` 严格读满 |
| 认证方式不被接受仍继续 | 校验 `response[0]==0x05 && response[1]==offer` |
| SOCKS5 长度字段越界 | 显式校验 1..=255 |
| IPv6 目标 | `CONNECT` 目标与 `Host` 头对 IPv6 加方括号 |
| 连接/握手无超时、失败泄漏 socket | `CancelAfter(connectTimeout)` + `catch { socket.Dispose(); throw; }` |
| **上游自身曾信任所有上游证书** | 改为 `ValidateServerCertificate`（含名称不匹配时的 SNI 豁免） |

**我方现状**（`crates/watt-core/src/outbound.rs`）：

| 项 | 状态 |
| --- | --- |
| CONNECT 逐字节读到 `\r\n\r\n`（L687-L706） | ✅ 已对齐 |
| 响应上限 8192（L703） | ✅ 优于上游 |
| 读超时 `read_exact_deadline`（L850） | ✅ 已对齐 |
| 连接超时（L458） | ✅ 已对齐 |
| SOCKS5 分段读（L737/756/781） | ✅ 已对齐 |
| **IPv6 目标格式**（L679 `CONNECT {host}:{port}`） | ❌ **缺失方括号**：`2001:db8::1:443` 无法解析 |
| **SOCKS5 地址类型恒为域名 `0x03`**（L774） | ❌ 目标是 IP 时仍当域名发送，IPv6 字面量直接失败 |
| SOCKS4 目标为域名时的 `0.0.0.x` 判定（L830） | 🟡 可用，但 `0.0.0.0`/`0.0.0.1` 边界语义与 RFC 有偏差 |

**影响**：二/三级代理链路在 IPv6 网络或「上游返回 AAAA」场景下必然失败，且报错是模糊的 `SOCKS5 CONNECT 失败`。

**方案（推荐 A）**

- **A（推荐）**：在 `http_connect_tunnel` 统一 `host_for_header()` 工具（IPv6 → `[addr]`）；`socks5_tunnel` 按 `target.host.parse::<IpAddr>()` 选择 `0x01/0x04`，域名才用 `0x03`。改动约 30 行，风险低。
- **B**：只修 CONNECT 方括号（最小改动）。治不了 SOCKS5 IP 化，后续仍会踩。
- 取舍：A 覆盖全，且与上游行为一致；B 省 20 行但留坑。

**验收**：新增 `outbound` 单测——假 SOCKS5 服务端分别校验 `0x01/0x03/0x04` 三种 ATYP；`diag_outbound` 增加 IPv6 字面量用例。

---

### 3.2 P0-2 DNS：单后端 → 有序服务器列表

**上游模型**（`IDnsAnalysisService.Constants.cs` + `DnsAnalysisServiceSwitchImpl`）：

```
默认列表 = 3 个 DoH + 3 个明文 DNS，按行分隔，顺序即优先级
https://doh.pub/dns-query
https://dns.alidns.com/dns-query
https://dns.google/dns-query
223.5.5.5
119.29.29.29
114.114.114.114
```

| 行为 | 上游实现 |
| --- | --- |
| 列表解析 | 逐行 → `System Default` / `https://` / IP 三类，任一非法项**跳过而非整体失败** |
| 查询策略 | 按顺序逐个试，**首个有结果即返回**；异常吞掉继续下一个 |
| 缓存 | 单服务器场景用独立 client（避免 DnsClient 按 question 缓存把回退结果冒充首选）；多服务器场景 `UseCache=false` |
| 超时 | 单次 2s，DoH 3s，`Retries=0` |
| DoH 校验 | 端点必须 `https`，否则抛 `ArgumentException`；解析结果只取 `DnsIpAddressResource`，TTL 取 `Min` 且上限 9.9 分钟 |
| 旧值迁移 | `ProxySettings.Dns`：`UseDoh=true` → DoH 优先，否则明文优先；`/resolve` 端点统一改写为 `/dns-query`；写 `ResolverServersMigrated` 标志 |
| 启动预检查 | 语义从「选最快」改为「**至少一个可用即可**」，15s 总超时，失败只 Toast 警告不阻断启动 |

**我方现状**（`crates/watt-dns/src/resolver.rs` L30-L59）：`DnsConfig { master_dns, use_doh, custom_doh_address }`，`DnsBackend` 为**单值** `System | Udp | Doh`。一个 DoH 端点失效即整体回退系统 DNS（`doh_error` 记录原因）。

**差距**：
1. 无法配置多 DNS、无顺序回退 → 首个 DNS 被墙/失效即整体降级，这正是上游 rc.14 起反复修复的用户故障。
2. `DnsSettings.before_dns_check`（`settings.rs` L131）**只存不用**——`engine_start` 从未读取（已核实全仓库仅迁移与前端引用）。
3. 迁移层 `migrate.rs` L197 只做布尔映射，未做端点规范化。

**方案（推荐 B）**

- **A**：保留 `use_doh` 布尔，仅在内部做「DoH 失败 → 主 DNS → 系统」三级回退。改动最小，但仍无法表达「多个 DoH 轮换」，且与上游配置模型分叉，后续每次上游调整都要再映射一次。
- **B（推荐）**：`DnsConfig` 增加 `resolver_servers: Vec<ResolverServer>`（`SystemDefault | Doh(url) | Udp(ip)`），旧三字段标 `#[serde(default)]` 保留读取用于迁移，新字段为空时按旧字段合成列表。查询层改为「有序尝试 + 首成功即返回」。
- **C**：直接改用 hickory 的 `NameServerConfigGroup` 多 nameserver。省事，但丢失「DoH 与明文混排优先级」语义（hickory 按组内并发/轮询，不是严格顺序），且 DoH 端点路径处理不如现有实现可控。**不推荐**。

**取舍**：B 需要改 4 处（config/engine/command/UI），但把「DNS 可用性」从「全有全无」变成「降级可用」，收益最大；A 只是把现有降级链补全，仍不解决多端点。

**迁移兼容**：`ProxySettings.json` 新增字段全部 `#[serde(default)]`，旧文件可直接读；写入新字段后仍保留旧字段（置 `None`），保证 v0.5.x 可回滚读取。

**验收**：
- 单测：列表含非法项（`"abc"`、`http://`）→ 跳过并继续；
- 单测：首项超时 → 自动落到第二项并成功（用本地 UDP DNS 桩）；
- 单测：旧配置 `use_doh=true + /resolve 端点` → 迁移后为 `/dns-query` 且顺序正确；
- 真机：断掉 `doh.pub`（hosts 屏蔽）后加速仍可用，日志显示降级到第二项。

---

### 3.3 P0-3 Hosts 模式 DNS 回环防护

**上游**：`DomainResolver` / `DnsAnalysisServiceSwitchImpl` 在 `ProxyMode.Hosts`（及已移除的 DNSIntercept）下，若配置为 `System Default`，**强制替换为公共 DNS 常量 `DNS_Dnspods`**，注释明确「系统解析会把加速域名解析回本代理」。另在中间件入口增加「解析结果为空或 `IPAddress.IsLoopback` → 500」的兜底。

**我方现状**：
- 已有 `DnsResolver` 双解析器设计（`resolver` 读 hosts、`clean` 绕过 hosts），出站一律走 `clean`（`resolver.rs` L63-L66 注释）——**这一层已对齐**。
- 但 §3.2 改造后若引入 `SystemDefault` 项，必须保证 Hosts 模式下该项不被用来解析**被劫持域名**，否则 `clean` 只绕过 hosts 文件、绕不过「系统 DNS 被运营商或本机 DNS 服务污染」。
- 缺少「解析结果为 loopback → 拒绝转发」的显式兜底（当前仅做污染 IP 判定）。

**方案**：把上游语义参数化为 `resolve_for_outbound(host, mode)`：`mode ∈ {Hosts}` 时 `SystemDefault` 一律降级为内置公共 DNS 列表；转发前若目标解析结果全部为 loopback/unspecified → 返回 502 并记日志（避免自环）。

**验收**：`diag_github` 系列（HTTP/1.1 与 h2 两条）在「DNS 设为 System Default」下仍 200；人为把规则 IP 改成 127.0.0.1 时得到明确错误页而非死循环。

---

### 3.4 P1-1 启动时序：监听先于接入面

**上游**：`ProxyService.Operate.cs` 把 System/PAC 的 `SetAsSystemProxyAsync` 从「启动前」移到 `StartProxyAsync` **成功之后**，失败时 `StopProxyAsync` 回滚并返回错误。

**我方现状**（`crates/watt-core/src/engine.rs`）：
- L408-L455：**先写注册表 / AutoConfigURL**；
- L502-L535：**后绑定监听**；
- 绑定失败时 `bind_or_fail` → `revert_proxy_settings` 回滚（L297-L317）。

**风险**：L408→L524 之间存在「系统代理已指向未监听端口」的窗口（含 `spawn_blocking` 调度与 DNS 初始化后的上下文构建，实测毫秒到数十毫秒级）。若进程此刻被强杀，用户浏览器会短暂全断——虽有 `cleanup_orphans` 兜底，但那是**下次启动**才生效。

**方案（推荐 B）**：
- **A**：维持现状，只在文档标注窗口期。零改动，但违反项目自定的「接入面必须与运行态一致」铁律。
- **B（推荐）**：抽出 `apply_access_surface(mode)` 函数，在**所有 listener 绑定成功、任务 spawn 之后**调用；失败则 `shutdown_tx` + 回收 listener 并返回错误。Hosts 模式已是这个顺序（先 443 后写 hosts），改造后四种模式时序统一。
- 取舍：B 需要重排 `start()` 中约 120 行，但逻辑更线性，可读性反而提升；风险集中在一处，测试可覆盖。

**验收**：单测——`forward_proxy_port` 预占端口时，`start(System)` 返回 `BindPortError` 且**注册表未被写入**（可用注入的 `system_proxy` 假实现或断言 `should_rollback_proxy_on_failure()==false`）。

---

### 3.5 P1-2 host 端口归一化

**上游**：`HttpReverseProxyMiddleware` 把 `context.Request.Host.Value`（含端口）改为 `context.Request.Host.Host`（不含端口）再送 DNS 解析。

**我方现状**：`http_relay::request_host()`（L1373）对 HTTP/1.1 直接返回 `Host` 头**原值**，可能含 `:443` / `:8080`。
- `DomainRules::find_by_url` 内部 `host.split(':').next()` 已容错（`domain_rule.rs` L161）；
- **但** 污染判定 `self.dns.resolve_first_clean(&host)`（L331）与转发目标构造直接用原值 → 形如 `resolve("github.com:443")` 必然失败 → 落入「解析失败 = 污染」分支，返回错误页。

**触发条件**：`ProxyOnly`/`System` 模式下访问非默认端口的 HTTP 站点（`Host: example.com:8080`），或客户端显式带端口。日常 443 流量多数不带端口，故为**潜伏缺陷**。

**方案**：在 `perform()` 入口统一归一化一次：`let host = normalize_host(request_host(req));`（去端口、IPv6 去方括号并保留原值用于 `Host` 头回写），后续全部使用归一化值；回写上游 `Host` 头时保留原始 authority。约 15 行 + 2 个单测。

**验收**：单测——`Host: example.com:8080` 时规则命中且 DNS 查询参数为 `example.com`；`Host: [::1]:8080` 不 panic。

---

### 3.6 P1-3 错误码体系

**上游**：`StartProxyResultCode` 新增 `KeyIsolationServiceDisabled=128`、`KeyIsolationServiceStopped=129`、`CertificateOperationFailed=130`、`ListenerBindFailed=131`；`StartProxyResult.Exception` 由 `Exception` 改为 `string`（避免跨 IPC 序列化异常对象）。

**我方现状**：`EngineError` 仅 `BindPortError | AlreadyRunning | NotRunning | Other(String)`（`engine.rs` L135-L145），证书失败与一般异常都归 `Other`，前端只能展示字符串。

**方案**：引入 `EngineErrorCode` 枚举（`BindPort / ListenerBindFailed / CertTrustFailed / CertKeyIsolation / AccessSurfaceFailed / AlreadyRunning / Other`），随 `EngineState::Error` 一并以结构化 DTO 返回前端；前端按 code 决定「给复制日志按钮 / 给重试按钮 / 给证书引导」。**不改动现有字符串**，仅追加字段，保证旧 UI 不炸。

**验收**：`cargo test -p watt-core engine` 增补 code 断言；前端 `stores/proxy.ts` 按 code 分支的 UI 快照。

---

### 3.7 P1-4 Linux 系统代理

**上游**：`gsettings` 由「拼一整段 shell 一次执行」改为**逐键 exec + 读 stderr + 校验 exit code**，失败抛异常（原先永远返回 true，用户以为设置成功实际没生效）；新增进程内 `LinuxAcceleratorWebProxy`，让应用自身的 HTTP 请求也能动态跟随加速代理。

**我方现状**：`crates/watt-core/src/system_proxy.rs` L7 明确「其他平台本阶段不接入」，仅 Windows + macOS。CI 却产出 linux deb/AppImage → **Linux 上 System/PAC 模式点了没反应且无报错**。

**方案（推荐 B）**：
- **A**：UI 在 Linux 隐藏 System/PAC，仅保留 Hosts/ProxyOnly。诚实但砍功能。
- **B（推荐）**：实现 `linux` 分支——`gsettings set` 逐键执行 + 退出码校验；无 `gsettings`（非 GNOME）时明确返回「当前桌面环境不支持自动系统代理，请用 PAC 或手动配置」，不静默成功。约 120 行，可复用手写 `Command` 模式（已在 `watt-cert/trust.rs` 有先例）。
- 取舍：B 覆盖主流 GNOME/KDE（KDE 需 `kwriteconfig5`，可作二期）；A 省事但 Linux 包等于残废。

**验收**：Linux 容器内 `gsettings` 不存在 → 返回明确错误而非 Ok；GNOME 真机（若有）切换后 `gsettings get org.gnome.system.proxy mode` == `'manual'`。

---

### 3.8 P2-1 KeyIso 诊断（低优先）

**上游**：证书操作失败时，读取 `HKLM\SYSTEM\CurrentControlSet\Services\KeyIso` 的 `Start`（=4 表示 Disabled）与 SCM 当前状态（=1 表示 Stopped），据此给出「CNG 密钥隔离服务被禁用/已停止」的定向提示，而不是笼统「证书失败」。

**我方现状**：`watt-cert/trust.rs` 装根证书走 `CertAddEncodedCertificateToStore` + `certutil -addstore`，**不导入私钥**，理论上不依赖 KeyIso；`pfx.rs` 是纯 Rust PKCS#12 解析，也不走 CNG。

**结论**：真正踩 KeyIso 的概率低 → 优先级 P2。但**建议顺手实现诊断函数**，因为它同时能覆盖「证书存储被组策略锁定」「certutil 被安全软件拦截」两类真实故障的区分。成本约 80 行（注册表 + 一次 `QueryServiceStatus`，可用 `windows-sys` 现有 feature 集，无需新增依赖）。

---

### 3.9 P2-2 特权 CLI 路径校验（自查）

**上游**：删除 `-clt ayaneo -path <任意路径>` —— 提权进程按用户传入路径写文件 = 任意文件覆盖。

**我方自查项**：`crates/watt-elevate`（382 行）+ `src-tauri/app.manifest`（`requireAdministrator`）。需要确认：
1. 是否存在接受外部路径参数并以管理员身份写盘的入口；
2. `watt-elevate` 的 helper 参数是否做了「仅允许白名单目录 + 固定文件名」约束；
3. hosts 写入路径是否只能来自 `watt_hosts::HostsManager::new()` 的系统常量。

> ⚠️ 该项为**审计项而非改造项**，需在 P2 阶段出一份结论（有则修，无则记录）。

---

### 3.10 已天然对齐（不重复投入）

| 项 | 上游 3.2.0 | 我方 |
| --- | --- | --- |
| HTTP→HTTPS 默认关闭 | 默认 `false` + JSON 键改名使旧值失效 | `settings.rs` L222 默认已为 `false`；无历史包袱，无需键改名 |
| 绑定失败即时暴露 | 去掉 650ms 轮询 + `Task.WaitAny`，改 `await StartAsync()` | tokio 在 spawn 前同步 `bind`，错误必然在 `start()` 返回前暴露 |
| 加速目录加载超时 + 离线降级 | 20s `WaitAsync` + 本地缓存 | `watt-cloud/client.rs` timeout 20s；`accelerate_get_projects` 云端失败降级缓存 |
| 启停互斥 | `ProxyStarting` + `finally` 复位 | `AppState.engine: Mutex<ProxyEngine>` + `AlreadyRunning` 状态机 |
| 日志单栈 | 清 Kestrel 默认日志 | 全量 `tracing` + `runtime_log.rs` 落盘 |

---

## 4. 关键技术设计

### 4.1 DNS 服务器列表模型（P0-2 核心）

```rust
// crates/watt-dns/src/resolver.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverServer {
    /// 系统默认（Hosts 模式下会被替换为公共 DNS，防回环）
    SystemDefault,
    /// 明文 UDP/TCP DNS
    Udp(std::net::IpAddr),
    /// RFC 8484 DoH 端点（必须 https）
    Doh(String),
}

#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// 有序服务器列表；空 = 由旧字段合成（兼容 v0.5.x）
    pub resolver_servers: Vec<ResolverServer>,
    // —— 旧字段保留，仅用于读取旧配置与迁移，写入时置 None ——
    pub master_dns: Option<String>,
    pub use_doh: bool,
    pub custom_doh_address: Option<String>,
}
```

**解析流程**

```
resolve(host):
  for server in effective_servers():        # Hosts 模式下 SystemDefault → 公共 DNS 常量
      match try_query(server, host):        # 单项 2s（DoH 3s）、Retries=0
          Ok(ips) if !ips.is_empty() => return Ok(ips)
          _ => continue                     # 任何异常吞掉，继续下一个
  Err(DnsError::AllServersFailed)           # 仅当全部失败才报错
```

**必须遵守的三条约束**（直接来自上游踩坑记录）

1. **缓存必须按 server 隔离**：hickory 的 cache 以 question 为键，共享 client 会让「回退服务器的答案」冒充「首选服务器的答案」，导致下次首选正常时仍返回旧值。
2. **顺序即优先级，不许并发**：并发会让「能通但被污染」的服务器抢先返回。上游明确用 for 循环而非 `select_all`。
3. **列表解析容错**：单个非法项跳过，不允许整表失效（否则用户多打一个空格就全盘降级）。

### 4.2 启动时序改造（P1-1）

```
start(config):
  1. 前置校验（macOS 特权端口拦截 / hosts 模式 443 预检）
  2. cleanup_orphans（清上次残留）
  3. 构建 DNS / 规则 / 脚本 / 探测上下文
  4. 绑定全部 listener（443 / 80 / 26501 / SOCKS5）  ← 先
  5. spawn 监听任务
  6. apply_access_surface(mode)                      ← 后：写 hosts / 系统代理 / PAC / 终端变量
     失败 → 关闭 listener + 回滚已写入的接入面 + 返回错误
  7. 启动后台预探测
  8. 状态 → Running
```

与现状的差异：第 4/5 步从「第 6 步之后」提前。Hosts 模式实际顺序不变（已是先监听后写 hosts），收益在 System/PAC。

### 4.3 错误码映射

| 场景 | 现状 | 目标 code | 前端表现 |
| --- | --- | --- | --- |
| 443/80/26501 绑定被占用 | `BindPortError(port, String)` | `BindPort` | 显示占用进程名 + 建议换模式 |
| 绑定权限拒绝（<1024 非管理员） | 同上（拼进字符串） | `ListenerBindFailed` | 引导提权 / 换系统代理模式 |
| 根证书未安装且安装失败 | `Other("证书...")` | `CertTrustFailed` | 跳证书设置卡片 |
| KeyIso 禁用/停止（P2） | 无 | `CertKeyIsolation` | 定向修复指引 |
| 系统代理/PAC 写入失败 | `Other` | `AccessSurfaceFailed` | 「已自动回滚」提示 |
| 已在运行 / 未运行 | 独立 variant | `AlreadyRunning` / `NotRunning` | 静默（幂等） |

---

## 5. 任务拆解（TASK）

> 顺序即依赖顺序。每项完成即勾选，并附对应验收命令。

### 阶段 A：P0（v0.6.0 必须）

- [x] **A1 出站握手 IPv6/IP 化**（0.5d）✅
  - 文件：`crates/watt-core/src/outbound.rs`
  - 改动：`host_for_authority()` 工具；`socks5_tunnel` 按 `IpAddr` 选 ATYP；SOCKS4 边界整理
  - 验收：新增 `outbound::tests::socks5_atyp_*` 三例；`cargo test -p watt-core --lib outbound`

- [x] **A2 DNS 数据模型与解析器**（1.5d）✅
  - 文件：`crates/watt-dns/src/{resolver.rs,lib.rs}`
  - 改动：`ResolverServer` + 有序回退 + 按 server 隔离缓存 + 容错解析
  - 依赖：无
  - 验收：`cargo test -p watt-dns`（新增 6 例）

- [x] **A3 DNS 配置迁移与命令层贯透**（1d）✅
  - 文件：`crates/watt-config/src/settings.rs`、`crates/watt-config/src/migrate.rs`、`src-tauri/src/commands/engine.rs`
  - 改动：`DnsSettings.resolver_servers`；旧字段 → 列表迁移（含 `/resolve` → `/dns-query`）；`before_dns_check` 真正接线（15s 总超时、失败仅告警）
  - 依赖：A2
  - 验收：`cargo test -p watt-config` 迁移用例；旧 `ProxySettings.json` 原地读取不丢失

- [x] **A4 Hosts 模式 DNS 回环防护**（0.5d）✅
  - 文件：`crates/watt-dns/src/resolver.rs`、`crates/watt-core/src/http_relay.rs`
  - 改动：`SystemDefault` 在 Hosts 模式替换为公共 DNS；转发前 loopback 兜底
  - 依赖：A2

- [x] **A5 UI：DNS 列表编辑**（1d）✅
  - 文件：`ui/src/views/SettingsPage.vue`、`ui/src/stores/settings.ts`、`ui/src/types/ipc.ts`、`ui/src/locales/*.ts`
  - 改动：单输入框 → 有序列表（增删/上移下移/预设一键填充），顺序即优先级提示
  - 依赖：A3

### 阶段 B：P1

- [ ] **B1 启动时序重排**（1d）—— `engine.rs`；单测覆盖「端口占用时不写注册表」
- [ ] **B2 host 端口归一化**（0.5d）—— `http_relay.rs`；单测两例
- [ ] **B3 错误码体系**（0.5d）—— `engine.rs` / `commands/engine.rs` / `ui/src/stores/proxy.ts`
- [ ] **B4 Linux 系统代理**（1.5d）—— `system_proxy.rs`；`gsettings` 逐键 + 退出码校验 + 不支持时明确报错

### 阶段 C：P2

- [ ] **C1 KeyIso 诊断**（0.5d）—— `watt-cert/trust.rs`；注册表 + SCM 状态
- [ ] **C2 特权 CLI 审计**（0.5d）—— `watt-elevate` / `app.manifest` / 所有接受路径参数的入口；产出审计结论
- [ ] **C3 文档与回归**（0.5d）—— `doc/` 更新对齐说明；`cargo test --workspace` + `vue-tsc` + 三平台 CI

**合计约 8.5 人日**（单人串行）。

---

## 6. 验收标准（整体）

| 维度 | 标准 |
| --- | --- |
| 静态检查 | `cargo clippy --workspace --all-targets -- -D warnings` 零告警；`pnpm --dir ui typecheck` 通过 |
| 单测 | `cargo test --workspace` 全绿；新增用例覆盖 A1/A2/A3/B1/B2 |
| 真机链路 | `cargo test -p watt-core --test diag_github -- --ignored`（HTTP/1.1 + h2 两条）均 200 |
| 降级能力 | 手动屏蔽首选 DoH 后仍可加速，日志可见「已降级到第 N 项」 |
| 无黑洞 | System/PAC 启动失败后 `reg query ...ProxyEnable` 为 0 或还原为原值 |
| 兼容 | 用 v0.5.3 的 `ProxySettings.json` 直接启动，无报错、勾选与 DNS 设置不丢 |

---

## 7. 风险与回滚

| 风险 | 概率 | 影响 | 缓解 |
| --- | --- | --- | --- |
| DNS 列表改造引入解析回归（加速域名解析失败） | 中 | 高（加速不可用） | 保留旧字段读路径；新逻辑以「空列表 → 旧字段合成」兜底；灰度用 `resolver_servers` 长度判断 |
| 启动时序重排导致 Hosts 模式写 hosts 时序错乱 | 低 | 高（黑洞） | Hosts 分支保持原顺序；仅移动 System/PAC 的接入面；`cleanup_orphans` 仍在最前 |
| Linux `gsettings` 在 KDE/无 GUI 环境不可用 | 高 | 中 | 明确报错而非静默成功；文档标注仅 GNOME 自动，KDE 二期 |
| 错误码结构变更影响前端 | 低 | 低 | 只追加字段，字符串保持原样；前端按可选字段分支 |

**回滚策略**：每阶段独立提交，`A1`→`A5` 可分次发布；DNS 改造保留 `use_doh/master_dns` 读取路径，回滚只需把 `resolver_servers` 置空即可退回旧行为（无需回滚代码）。

---

## 8. 明确不跟进项

| 上游内容 | 不跟进理由 |
| --- | --- |
| 加速子进程 + 命名管道 IPC + 进程校验 | 我方单进程 Rust，无 IPC 层，该类问题不存在 |
| Kestrel / YARP / .NET 11 / Avalonia 12 | 技术栈不同，仅移植其**行为语义** |
| Steam 令牌二维码、挂卡、库存、账号切换、ASF | 不在本仓库功能范围（`doc/task.md` 已界定仅加速域） |
| `ProxyDNS` → `ProxyDNSAddresses` 的 MP2 二进制序列化兼容 | 我方用 JSON，字段名即契约，无需二进制兼容层 |
| Win11 26H2 加速启动失败修复 | 🟡 变更位于 `ref/Common` 子模块与 .NET 运行时升级，**无法从主仓库 diff 定位**；需在 26H2 环境实测确认我方是否复现（当前真机为 Android/Win 环境未覆盖） |

---

## 附录 A：上游关键文件 → 我方模块映射

| 上游 | 我方 |
| --- | --- |
| `ProxyService.Operate.cs` | `crates/watt-core/src/engine.rs` |
| `ReverseProxyServiceImpl.cs` / `YarpReverseProxyServiceImpl.cs` | `engine.rs` + `listener.rs` |
| `HttpReverseProxyMiddleware.cs` | `crates/watt-core/src/http_relay.rs` |
| `ReverseProxyHttpClientHandler.cs` | `crates/watt-core/src/outbound.rs` |
| `DnsAnalysisServiceSwitchImpl.cs` / `DnsDohAnalysisService.cs` | `crates/watt-dns/src/resolver.rs` |
| `CertificateManagerImpl.cs` / `CertificateFailureDiagnostics.cs` | `crates/watt-cert/src/{ca,trust}.rs` |
| `ProxySettings*.cs` / `ProxySettings.Dns.cs` | `crates/watt-config/src/{settings,migrate}.rs` |
| `LinuxPlatformServiceImpl.SystemProxy.cs` | `crates/watt-core/src/system_proxy.rs` |
| `KestrelServerOptionsExtensions.cs` | `crates/watt-core/src/listener.rs` |

## 附录 B：本轮扫描已确认的「我方独有、上游没有」能力

避免在后续对齐中误删：

1. **IP 池 + 候选健康度矩阵 + TLS 层竞速**（`ip_pool.rs` / `probe.rs` / `probe_cache.rs` / `outbound::CandidateHealth`）——上游只有单次 DNS 解析，无竞速择优。
2. **服务端脚本钩子**（`watt-script/hooks.rs`，rquickjs）——上游脚本只在浏览器页内运行。
3. **终端接入面**（`terminal_proxy.rs`，CLI 环境变量 + CA 注入）——上游无此能力。
4. **访问日志与流量统计**（`access_log.rs` / `stats.rs`）。
