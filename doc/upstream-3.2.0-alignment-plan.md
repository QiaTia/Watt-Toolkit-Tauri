# 上游 SteamTools 3.2.0 变更对齐技术规划

> 版本：v0.5.3 → 目标 v0.6.0（建议）
> 编写日期：2026-11-13
> 上游基线：`BeyondDimension/SteamTools` tag `3.2.0`（commit `1eeeae7e`，2026-11-09 发布）
> 上一基线：tag `3.1.0`（commit `86122510`，2026-03-11）
> 结论状态：✅ 已核对上游源码 / 🟡 推断 / ⚠️ 待人工确认
>
> **实施进度：P0（A1–A5）+ P1（B1–B4）+ P2（C1–C2）已完成并验证** —— 见 §9。

---

## 9. 实施记录（P0 / P1 / P2 全部落地）

| 项 | 状态 | 落点 | 验证 |
| --- | --- | --- | --- |
| A1 出站握手 IPv6/ATYP | ✅ 完成 | `outbound.rs`：`host_for_authority` / `socks5_connect_request` | 单测 `test_host_for_authority_ipv6`、`test_socks5_connect_request_atyp` |
| A2 DNS 有序列表 | ✅ 完成 | `watt-dns/resolver.rs`：`ResolverServer`、逐项回退、按 server 隔离缓存 | 单测 6 例（解析去重/替换/截断/严格单端点/回退） |
| A3 配置迁移与接线 | ✅ 完成 | `DnsSettings.resolver_servers`、`expand_dns_server_list`、`before_dns_check` 接线 | `watt-config` 迁移用例；全工作区测试 |
| A4 Hosts 防回环 | ✅ 完成 | `engine.rs` `prefer_public_dns`；`http_relay` 与 `outbound` 双重回环兜底 | `diag_github` 双路径 200 |
| A5 UI 列表编辑 | ✅ 完成 | `SettingsPage.vue` 有序列表 + 行内 DoH 测试 + 预检查开关；5 语言包 | `vue-tsc --noEmit`、`vite build` |
| B1 启动时序 | ✅ 完成 | `engine.rs`：绑定 → spawn → 接入面；新增 `teardown_listeners`；`bind_or_fail` 不再回滚接入面 | 单测 `test_engine_system_mode_bind_failure_keeps_state_error` |
| B2 host 归一化 | ✅ 完成 | `http_relay.rs`：`normalize_host`，规则匹配/DNS/SNI 用纯主机名；转发仍用原始 authority | 单测 `test_normalize_host` |
| B3 错误码 | ✅ 完成 | `EngineErrorCode` + `AccessSurface`/`HostsWrite` 变体；`EngineStateDto::Error.code`；前端类型同步 | 单测断言 BindPort 分类 |
| B4 Linux 系统代理 | ✅ 完成 | `system_proxy.rs`：`gsettings` 逐键 + 退出码校验，端点先写、`mode` 后切；缺失时明确报错 | 模块级交叉编译校验 + Linux CI |
| C1 证书失败归因（替代 KeyIso 探测） | ✅ 完成 | `TrustError::Cancelled` + `classify_shell_execute_error`（保留 `GetLastError`）+ 新 `diagnose.rs` 与 `cert_diagnose` 命令 + 设置页诊断按钮 | 单测 6 例 + 真机诊断（见下） |
| C2 提权面审计与加固 | ✅ 完成 | 审计 42 个 IPC 命令；`watt-hosts` 提权目标白名单、gatekeeper 脚本引号、`is_elevated` 编码修复 | 单测 `elevated_target_must_be_system_hosts` |

**整体质量门**：`cargo clippy --workspace --all-targets -- -D warnings` 零告警；`cargo test --workspace` 全绿（watt-cert 24 / watt-core 126 / watt-config 16 / watt-hosts 15）；`diag_github`（HTTP/1.1 + h2）均 200；`vue-tsc --noEmit` + `vite build` 通过。

**真机诊断记录（2026-11-13，Windows 11 中文版）**：`cargo test -p watt-cert --test diag_trust -- --ignored --nocapture` 首次运行即查出本机 Root 存储中 **2 张同名 "Watt Toolkit" 根证书** —— 正是「重新生成 CA 后旧根残留」这个此前无法自查的场景；同一次运行暴露了 `is_elevated` 在中文 Windows 恒为 false 的缺陷（已修）。

**实现细节与上游的差异（有意）**

1. DoH 探测走 `DnsResolver::single`（严格单端点），保证「点测试就得真实结果」，不会被列表回退掩盖。
2. `before_dns_check` 预算收紧到 3s 且仅记日志——它是诊断而非守门，不应把启动拖成十几秒。
3. 迁移时不把用户**关掉**的 DoH 重新打开（上游会合并两类字段）。
4. 列表去重后上限 8 个，避免用户粘一长串地址拖慢每次解析。
5. 回环兜底分两层：默认规则在转发前拒绝（返回可读错误页），出站解析过滤回环候选（防其它规则路径自环）。
6. 绑定失败不再回滚系统代理——按新时序，失败时尚未写入任何接入面，盲目
   `set_system_proxy(false)` 会关掉用户原有代理（比绑定失败本身伤害更大）。
7. Linux 不做代理快照，`should_rollback_proxy_on_failure()` 返回 false：
   失败只可能残留「端点已写、mode 未变」的中间态，切 `mode=none` 反而会关掉用户原有代理。
8. Linux 模块无法在本机做完整交叉编译（缺 `x86_64-linux-gnu-gcc`，ring 需要 C 工具链），
   采用「抽出模块在宿主平台编译」的方式做语法/类型校验；真实运行需 Linux CI 覆盖。
9. **不做上游的 KeyIso 注册表探测**：本项目的私钥从不进 CNG，那条故障链不存在；
   改做「同 CN 证书计数 + 提权状态 + `GetLastError` 归因」——同一目的，贴着真实故障面。
10. **提权目标白名单放在提权入口而非配置层**：`is_system_hosts_path` 在
    `write_file_elevated` 里逐次校验，即使将来 hosts 路径可配置也绕不过去；
    上游的做法是删掉那个子命令，属于「移除能力」，我们是「保留能力 + 锁死目标」。

### 9.1 代码审阅修复（推送前，2026-11-13）

P0–P2 落地后对整批未推送改动做了一次审阅，发现 8 处问题，全部已修：

| # | 问题 | 严重度 | 修法 | 验证 |
|---|---|---|---|---|
| 1 | 「刷新 IP 池」用 `set_entry` 整体替换，会清空社区源候选 | P1 | `refresh_one` 探测前并入池内**动态** IP，统一按实测裁决 | `diag_refresh_keeps_existing_pool_ips`（实测 candidates=2） |
| 2 | 拉取期间改设置被旧快照整体回写覆盖 | P1 | `record_fetch_result` 保存前重读，只改 `last_fetch_ms`/`last_error` | `record_result_keeps_user_edits` |
| 3 | DNS 串行回退无总预算（最坏 15–24s） | P1 | `TOTAL_LOOKUP_BUDGET = 6s` + `min(remaining)` 截断单项超时 | `test_server_list_falls_back_on_timeout` |
| 4 | Windows hosts 路径取自 `SystemRoot` 环境变量，无校验 | P2 | `is_valid_system_root` 只认 `<盘符>:\Windows` | `system_root_shape_is_strict` |
| 5 | `backend()` 是「列表首项」，回退后来源标注失真 | P2 | 新增 `last_hit`/`hit_server`/`hit_backend`/`effective_backend`，展示层改用实际命中 | `test_hit_is_unknown_before_first_lookup` + 回退用例断言 `effective_backend != backend` |
| 6 | 重定向可把 https 降级成 http | P2 | `ensure_transport_secure(resp.url())`，仅回环允许 http | `rejects_plaintext_redirect_targets` |
| 7 | chunked 响应绕过 512KB 上限 | P2 | `resp.chunk()` 流式累加，超限即断 | `rejects_oversized_chunked_body`（本地 chunked 服务发 1.5MB） |
| 8 | 手动与后台拉取可并发（2×40 次 TLS 握手） | P2 | 全局 `REFRESH_GATE`；后台在闸门内再判到期 | `refresh_gate_is_exclusive`、`refresh_if_due_skips_when_not_due` |

其中 #5 的语义约定：`backend()` 只表示「首选（构建期结论）」，运行时来源一律用
`effective_backend()`。两者在回退时必然不同——回退恰恰是常态，不能拿首项冒充。

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

**✅ 实施结论（2026-11-13）—— 不跟进 KeyIso 注册表探测，改为等价诊断**

逐行核对 `watt-cert/trust.rs` 后确认：Windows 装根证书分两条路——`CertAddEncodedCertificateToStore` 直接写用户 Root，失败才 `run_elevated("certutil", ...)`；`pfx.rs` 是纯 Rust PKCS#12 解析。**两条路都不把私钥交给 CNG**，私钥始终以文件形式留在 `Certificates/` 目录参与 rustls 握手。也就是说，上游那个「KeyIso 被禁用 → 导入 PFX 失败」的故障链路在我们这里**没有对应代码路径**，复制它的注册表探测只会得到「服务正常」这个恒定答案。

因此把 C1 的目标从「探测 KeyIso」改回它真正要解决的问题：**让证书失败可归因**。落地三件事：

1. `TrustError::Cancelled` 新变体 —— 用户取消 UAC 与提权失败分开。前者是预期行为，不该弹红色错误，也不该引导用户去查组策略；
2. `classify_shell_execute_error` —— 保留 `ShellExecuteExW` 的 `GetLastError`（原先被整个丢弃，导致「取消 UAC / 组策略禁止 / 安全软件拦截」三种成因在日志里长得一模一样）：`1223 → Cancelled`、`5 → 策略或会话拒绝`、`740 → 安全软件拦截`，其余保留原始码；
3. `cert_diagnose` 命令 —— 一次性查清 `certFileExists` / `installed` / `sameCnCerts` / `elevated`，并生成可直接展示的建议列表。

`sameCnCerts` 是本次最实用的产出：**旧根残留**是「证书显示装好了但浏览器仍报错」的头号成因，而它此前只能靠用户自己打开 certmgr 数。本机首次运行即查出 **2 张同名根证书**（见 §9 验证记录）。

---

### 3.9 P2-2 特权 CLI 路径校验（自查）

**上游**：删除 `-clt ayaneo -path <任意路径>` —— 提权进程按用户传入路径写文件 = 任意文件覆盖。

**我方自查项**：`crates/watt-elevate`（382 行）+ `src-tauri/app.manifest`（`requireAdministrator`）。需要确认：
1. 是否存在接受外部路径参数并以管理员身份写盘的入口；
2. `watt-elevate` 的 helper 参数是否做了「仅允许白名单目录 + 固定文件名」约束；
3. hosts 写入路径是否只能来自 `watt_hosts::HostsManager::new()` 的系统常量。

> ⚠️ 该项为**审计项而非改造项**，需在 P2 阶段出一份结论（有则修，无则记录）。

**✅ 审计结论（2026-11-13）—— 无等价漏洞，但补了 3 处纵深防御**

逐项核对 42 个 IPC 命令与全部写盘点：

| 审计项 | 结论 |
|---|---|
| 上游那个 `-clt ayaneo -path` 子命令 | **不存在**。本项目无 CLI 子命令体系，`main` 只做 `tauri::Builder` 启动 |
| `EngineStartParams`（前端启动参数） | 无任何路径字段；`hosts_path` 在 `commands/engine.rs:202` 与 `tray.rs:245` 均为 `None`，只有单测传临时目录 |
| `cert_export_ca` | 返回 PEM **字符串**给前端，不落盘（上游对应实现是写用户指定路径） |
| `update_install` | `endpoint` 经 `parse_endpoint` 强制 HTTPS（仅回环允许 http）；安装包由 updater 插件写入自身临时目录 |
| `open_external` | 仅允许 `http` / `https` scheme |
| `update_gatekeeper_script` | 只返回字符串供用户手动粘贴，不执行 |
| `terminal_proxy` | 目标文件固定为 `~/.zshenv` / `~/.bashrc` / `~/.config/fish/config.fish` / `~/.profile`，无外部输入 |
| `watt-elevate`（382 行） | 程序白名单 + POSIX/AppleScript 双层转义 + 复合脚本逐段校验，已有 12 个单测覆盖注入面 |
| `scripts`（JS 注入执行面） | 生产恒为 `Vec::new()`（`commands/engine.rs:200`），当前不开放 |

**结论：不存在「前端可控路径 → 管理员写盘」的等价入口。** 但审计过程发现三处值得加固的点，已一并修掉：

1. **提权写入目标无白名单**（与上游漏洞同性质，只是当前调用方恰好传常量）：
   `watt_hosts::write_file_elevated` 加 `is_system_hosts_path` 校验，只认 `/etc/hosts` 与 `/private/etc/hosts`（macOS 的 `/etc` 是软链）。校验前做**词法归一化**（消 `.` / `..` / 重复分隔符），既避免 `/etc/./hosts` 被误拒，也堵住 `/tmp/../etc/hosts` 这类字面绕过。护栏放在提权入口而非配置层——这样即使将来 hosts 路径被做成可配置项，提权也写不出系统 hosts 之外的文件。
2. **`update_gatekeeper_script` 的引号**：原用双引号包裹 bundle 路径，而安装位置由用户决定，路径含 `"` / `$()` / 反引号时会被 shell 解释（该命令带 `sudo`）。改为单引号 + `'''` 闭合转义。
3. **`is_elevated` 在中文 Windows 上恒为 false**（`watt-cert` 与 `watt-elevate` 各一处）：`whoami /groups` 按 OEM 代码页（GBK）输出，`String::from_utf8` 严格解码整段失败 → 把「已提权」误判成「未知/false」。改用 `from_utf8_lossy`（SID 是 ASCII，替换不影响匹配）。

**补充审计（2026-11-13 二轮）—— 上一版「无等价入口」的结论不完整**

上面的核对只覆盖了**进程内**的路径来源（IPC 参数、配置字段、命令白名单），漏了
**进程启动环境**这一层：

`watt-hosts::hosts_file_path()` 在 Windows 上用 `std::env::var("SystemRoot")` 拼
hosts 路径。该值由父进程设置，而本进程声明了 `requireAdministrator`——构造
`SystemRoot=C:\evil` 启动，hosts 写入就会以管理员身份落到任意路径，与本报告要
对齐的上游漏洞（提权进程写任意路径）同性质。

已在 `hosts_file_path()` 里加形态校验：只接受 `<盘符>:\Windows`（大小写不敏感、
不允许尾随段），其余回退默认路径并告警。`is_valid_system_root` 有单测覆盖
`C:\Windows` / `C:\WINDOWS` / `C:\Windows\Temp` / `C:\Windows\..\evil` /
`C:Windows` 等形态。

由此，审计结论应修正为：**IPC 层不存在等价入口；进程启动环境曾存在一处，已修。**

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

- [x] **B1 启动时序重排**（1d）✅—— `engine.rs`；单测覆盖「端口占用时不写注册表」
- [x] **B2 host 端口归一化**（0.5d）✅—— `http_relay.rs`；单测两例
- [x] **B3 错误码体系**（0.5d）✅—— `engine.rs` / `commands/engine.rs` / `ui/src/stores/proxy.ts`
- [x] **B4 Linux 系统代理**（1.5d）✅—— `system_proxy.rs`；`gsettings` 逐键 + 退出码校验 + 不支持时明确报错

### 阶段 C：P2

- [x] **C1 证书失败归因**（0.5d）✅ —— **不做 KeyIso 注册表探测**（不走 CNG，无该故障链路）；改为 `Cancelled` 变体 + `GetLastError` 分类 + `cert_diagnose`
- [x] **C2 特权 CLI 审计**（0.5d）✅ —— 42 个 IPC 命令无等价入口；补 3 处加固（提权目标白名单 / gatekeeper 引号 / `is_elevated` 编码）
- [x] **C3 文档与回归**（0.5d）✅ —— `doc/` 已更新（§3.8/§3.9/§9）；`cargo test --workspace` + `vue-tsc` + `vite build` 通过；三平台 CI 待推送后验证

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
