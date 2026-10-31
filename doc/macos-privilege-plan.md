# macOS 特权模型与接入面方案（A 已落地 / B·C 待实施）

> 状态：**A 已实施（v0.5.2）**；B、C 待实施。
> 本文档回答一个问题：为什么 macOS 上「点一下加速」这么难，以及三条可选的解法各自要付出什么。

## 1. 结论先行

macOS 上的问题不是零散 bug，是**权限模型**。三条接入面对 root 的依赖完全不同：

| 能力 | 是否需要 root | 代码位置 | 现状 |
|---|---|---|---|
| PAC / 系统代理（`networksetup`） | **否**（待实机确认，见 §6） | `watt-core/src/system_proxy.rs` | 可用 |
| 写 `/etc/hosts` | **是** | `watt-hosts`（osascript 提权） | 每次启动/停止各弹一次密码框 |
| **监听 443** | **是**（1024 以下为特权端口） | `engine.rs::bind_or_fail` | **非 root 必 EACCES，Hosts 模式不可用** |
| 根证书信任 | 否（用户域 + 一次系统确认） | `watt-cert/src/trust.rs` | v0.4.1 起可用 |

关键硬约束有两条，都是「绕不过去」的类型：

1. **443 是特权端口**。macOS 没有 Linux 的 `net.ipv4.ip_unprivileged_port_start`
   那样放开特权端口的手段，非 root 进程 `bind` 必然 `EACCES`。
2. **`osascript ... with administrator privileges` 拿到的授权只能「以 root 执行一条命令」**。
   它无法让**已经运行的非 root 进程**获得绑定特权端口的能力，其 `AuthorizationRef`
   也不含修改 trust settings 所需的 right（这就是那个 `0:290` 的由来）。
   因此「多弹几次密码框」不可能解决 Hosts 模式，也不可能解决证书信任。

推论：**macOS 上 Hosts 模式要么整体以 root 运行，要么由一个特权进程代绑 443**。
没有第三条路。

## 2. A：接入面收敛（已实施，v0.5.2）

最小代价把 macOS 变成「能正常用」，代价是暂时失去 Hosts 模式。

| 改动 | 文件 |
|---|---|
| `ProxyMode` 默认值平台相关：macOS → `Pac`，其余 → `Hosts` | `watt-config/src/settings.rs` |
| 新增 `privileged` 模块，集中判定「能否绑特权端口」 | `watt-core/src/privileged.rs` |
| `engine.start()` 在**写 hosts 之前**拦截 Hosts 模式并落 `Error` | `watt-core/src/engine.rs` |
| 绑定失败文案：权限拒绝 + 特权端口 → 给可执行指引 | `engine.rs::describe_bind_error` |
| macOS 上 Hosts 选项置灰（加速页 + 设置页），五语文案改为「不可用」 | `ui/src/views/*`、`ui/src/locales/*` |
| 设置载入时磁盘残留 Hosts → 内存降级为 `Pac`（不改磁盘） | `ui/src/stores/settings.ts` |

拦截必须在写 hosts **之前**：否则会出现「域名已指向 127.0.0.1，但 443 没人监听」的
黑洞窗口——写进去了再报错，用户所有相关站点直接打不开。

## 3. B：一次性授权的特权 helper（推荐，待实施）

目标：**每次启动只输一次密码**（helper 存活期间 0 次），并把 Hosts 模式真正找回来。

### 3.1 架构

```
┌───────────────────────────┐         ┌──────────────────────────────┐
│ 普通权限的 App 进程        │         │ root helper 进程              │
│                           │  Unix   │ （由 osascript 提权启动一次）  │
│  TLS/MITM、规则匹配、      │  socket │                              │
│  请求转发 —— 全部逻辑不变  │◀───────▶│  只做三件白名单操作：          │
│                           │  JSON   │   ① bind 443 并把 listener    │
│  拿到 fd 后自己 accept     │  + fd   │      fd 通过 SCM_RIGHTS 传回  │
│                           │         │   ② 写/摘 /etc/hosts 标记块    │
└───────────────────────────┘         │   ③ 刷 DNS 缓存                │
                                      └──────────────────────────────┘
```

设计要点：**helper 里没有业务逻辑**。它不解析 TLS、不认识域名、不碰规则表，
只交付「一个已经绑好的监听 fd」和「一次受控的文件写入」。这样即使 helper 被
利用，攻击面也只有这三个操作，而不是任意 root 命令执行。

### 3.2 为什么用 SCM_RIGHTS 而不是让 helper 跑代理

| 方案 | 问题 |
|---|---|
| helper 直接跑完整代理 | 业务代码以 root 运行，解析器/转发链上一个漏洞就是完整的 root 沦陷 |
| App 以 root 重启（`sudo open`） | GUI 会话权限错乱（钥匙串、托盘、Finder 集成都出问题），且需要用户改启动方式 |
| **helper 只绑端口并传 fd** | 业务仍以普通权限运行，helper 代码量小到可以逐行审计 ✅ |

### 3.3 协议（Unix socket，JSON Lines）

```rust
enum Request {
    Ping,
    Listen { port: u16 },              // 回 Ok 后紧跟一个 SCM_RIGHTS fd
    HostsWrite { content: String },    // 内容必须含 "# Steam++ Start" 与 "# Steam++ End"
    HostsRemove,
    Shutdown,
}
```

约束（安全关键，实现时必须逐条落实）：

- **不接受路径参数**。`/etc/hosts` 路径写死在 helper 里，杜绝「换个路径写任意文件」。
- **不接受任意命令**。没有 `Exec` 这类操作，白名单之外一律拒绝并记日志。
- **写入前校验标记块**：内容必须首尾包含 `# Steam++ Start` / `# Steam++ End`，
  拒绝对无标记内容的整文件覆盖。
- **peer 校验**：macOS 用 `LOCAL_PEERCRED`（Linux 用 `SO_PEERCRED`）确认对端 uid
  与启动 helper 的用户一致。
- **socket 权限**：目录 `0700`、socket `0600`，放在 App 数据目录下。
- **无状态**：helper 不做缓存、不落盘、不监听网络。

### 3.4 生命周期

| 事件 | 行为 |
|---|---|
| App 首次点加速 | 尝试连接 socket；失败 → `osascript` 提权启动 `self --watt-helper`（**唯一一次密码框**）→ 等待 socket 就绪（≤10s） |
| helper 启动 | 建 socket、写 pid、进入 accept 循环 |
| App 正常退出 | 发 `Shutdown`，helper 退出 |
| App 崩溃 | socket 读到 EOF → helper 自杀（**不留常驻后门**） |
| helper 崩溃 | App 下次启动重新提权拉起；运行中检测到断连则落 `Error` 并提示重启 |

### 3.5 集成点（改动范围）

| 位置 | 改动 |
|---|---|
| 新 crate `crates/watt-privhelper` | `protocol.rs` / `fdpass.rs`（SCM_RIGHTS）/ `server.rs` / `client.rs` |
| `watt-core/src/engine.rs::bind_or_fail` | 直接 `bind` 失败且 `PermissionDenied` → 走 helper 取 fd，`tokio::net::TcpListener::from_std` |
| `watt-core/src/privileged.rs` | `hosts_mode_block_reason()` → helper 可用时返回 `None` |
| `watt-hosts` | macOS 写入优先走 helper（省掉每次都弹密码） |
| `src-tauri/main` | 识别 `--watt-helper` 参数，进入 helper 模式并退出 GUI 分支 |
| 前端 | macOS 上 Hosts 选项恢复可用；首次点加速提示「将请求一次管理员授权」 |

`watt-privhelper` 只依赖 `libc` + `serde` + `serde_json` + `watt-elevate`，
**不引入 ring/tokio**，因此可以在非 macOS 机器上 `cargo check --target x86_64-apple-darwin`
完整校验（当前 `watt-core` 做不到这点，见 §5）。

## 4. C：签名 + 公证 + 常驻守护（终极形态，待账号就绪）

这一层解决的是「连那一次密码都不想输」以及「Gatekeeper 不要拦我」。

### 4.1 前置（必须先做，否则后面全部无效）

1. 加入 **Apple Developer Program**（$99/年），拿到 Team ID
2. 创建 **Developer ID Application** 证书，导出 `.p12`
3. 配 GitHub Secrets：`APPLE_CERTIFICATE`、`APPLE_CERTIFICATE_PASSWORD`、
   `APPLE_SIGNING_IDENTITY`、`APPLE_ID`、`APPLE_PASSWORD`（App 专用密码）、`APPLE_TEAM_ID`

`release.yml` 里这六个注入点**已经预留并注释好**（搜索 `APPLE_CERTIFICATE`），
填好 secrets 后取消注释即可，Tauri 会自动完成签名 + 公证。

### 4.2 还要补的两块

| 项 | 内容 |
|---|---|
| `src-tauri/Entitlements.plist` | Hardened Runtime 下允许 JIT/网络客户端所需的最小权限集；不建议开 `allow-unsigned-executable-memory` |
| CI 公证产物 | `dmg` 需 `notarytool submit --wait` + `stapler staple`，否则首次打开仍会提示 |

### 4.3 免密常驻（取代 B 的 osascript 启动方式）

拿到签名之后，B 的 helper 可以升级成系统级 LaunchDaemon：

- `SMAppService.daemon(plistName:)`（macOS 13+；`SMJobBless` 已废弃）
- 第一次授权由系统「登录项与扩展」面板完成，**之后永久免密、开机即用**
- 前提：App 与 daemon 必须用**同一 Team ID 签名**，ad-hoc 签名无法建立信任关系

也就是说 C 是 B 的升级而非替代：B 的协议与白名单设计原样保留，只换「谁来启动 helper」。

## 5. 风险与诚实披露

| 项 | 说明 |
|---|---|
| macOS 代码在本机无法完整编译 | `watt-core`/`watt-cert` 依赖的 ring 需要 macOS SDK，Windows 上只能对 `watt-elevate`/`watt-hosts` 做 darwin 交叉 check。B 的新 crate 刻意只依赖 `libc`，正是为了保住「可交叉校验」这条底线 |
| B 的 fd 传递无法在 Windows 验证 | SCM_RIGHTS 是 unix 专属 API，只能靠 Mac 实机验收；验收脚本见 §7 |
| ad-hoc 签名下 helper 不可行 | 若最终不买开发者账号，B 每次启动仍需一次密码（这是 macOS 的授权模型决定，不是实现缺陷） |
| Gatekeeper | 未签名/未公证的 dmg 需用户右键 → 打开；已在 release 说明中写明 |

## 6. 待实测的一个前提（影响 B 的边界）

代码注释断言 `networksetup` 修改代理「普通用户权限即可」。若该断言不成立，
则 **PAC / 系统代理模式同样需要提权**，B 的 helper 必须把 `networksetup` 也纳入白名单。

在 Mac 上跑这一句即可定论（不会改变任何设置，只看退出码与提示）：

```bash
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 26501; echo "exit=$?"
networksetup -setwebproxystate "Wi-Fi" off; echo "restore-exit=$?"
```

- `exit=0` → 免 root，B 只需覆盖 443 与 hosts
- `exit≠0` 且提示 `You must be root` → **B 的范围要扩大**，`networksetup` 一并进 helper

## 7. 验收清单（B 实施后）

```bash
# 1. helper 是否拉起、权限是否正确
ls -l ~/Library/Application\ Support/net.steampp.watttoolkit/helper.sock   # 期望 srw------- 
ps aux | grep watt-helper | grep -v grep                                    # 期望 uid=0

# 2. 443 是否由 helper 绑好、App 是否真在用它
sudo lsof -iTCP:443 -sTCP:LISTEN                                            # 期望 watt-toolkit-app 或 helper

# 3. hosts 是否写入且属主正确
grep -A3 "Steam++ Start" /etc/hosts && ls -l /etc/hosts                      # 期望 -rw-r--r-- root wheel

# 4. App 退出后 helper 必须消失（不留后门）
ps aux | grep watt-helper | grep -v grep                                     # 期望无输出
```
