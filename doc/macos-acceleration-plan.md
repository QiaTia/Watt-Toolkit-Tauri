# macOS 加速模式实施方案

> 目标：让 Hosts / System / Pac / ProxyOnly 四种加速模式在 macOS 上正常运行。  
> 特权操作（写 /etc/hosts、装根证书）采用 **osascript 管理员弹窗** 方案。  
> 本文档只做方案，不含实现。撰写日期：2026-10-14。

## 一、现状盘点

加速核心链路（MITM/rustls、正向代理 26501、SOCKS5 8868、PAC 生成、DNS/DoH、  
规则匹配、http_relay、二级代理出站、连通性测试）**全部为 tokio 跨平台代码**，  
macOS 编译与运行本身没有障碍。平台相关缺口共 4 处：

| # | 缺口             | 位置                                                                        | 影响模式               | 现状                                                                                                              |
| - | -------------- | ------------------------------------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------- |
| 1 | 系统代理/PAC 设置    | `crates/watt-core/src/system_proxy.rs:130-134, 194-198, 272-275`          | System、Pac         | 非 Windows 分支为占位 `Err`，引擎在 `crates/watt-core/src/engine.rs:277-288` 直接中止                                                              |
| 2 | 根证书安装到系统钥匙串    | `crates/watt-cert/src/trust.rs:258-323`（macOS 分支已存在）                      | Hosts（MITM 需信任根证书） | 已调 `security add-trusted-cert`，但写 System.keychain 需要管理员，当前无提权，失败仅返回 `TrustError::Elevation`                     |
| 3 | 写 `/etc/hosts` | `crates/watt-hosts/src/lib.rs:40-54`（路径已适配）+ `HostsManager::update_hosts` | Hosts              | 需要 root，当前无提权，失败报 `HostsError::Unauthorized`                                                                    |
| 4 | 绑定 443/80 特权端口 | `crates/watt-core/src/engine.rs:274, 339`（`check_port_available` / `bind_or_fail`）                                                  | Hosts              | **大概率无需处理**：macOS 10.14 (Mojave) 起允许非 root 进程绑定 <1024 端口。仅需验证 + 失败时给出友好诊断（`port_diag.rs` 非 Windows 分支目前返回 None） |

已有的良好基础：

- `trust.rs` macOS 分支已实现 install / remove / is_installed（SHA-1 比对），只差提权包装。
- `trust.rs:385-391` 已定义 `install_requires_elevation()`，但目前无任何调用方——正好用它驱动 UI 提示。
- `watt-hosts` 的标记块算法（`# Steam++ Start/End`）、默认内容、换行符均已分平台。
- `doc/task.md:112` 早已规划特权 helper 方向（macOS 走 osascript），本方案是其落地。
- UI 侧 `SettingsPage.vue` 未按平台禁用任何模式，无需前端 gating 改动（仅文案需补充）。

## 二、总体设计

新增一个平台特权模块 + 补齐 `system_proxy.rs` 的 macOS 分支，其余文件小改。  
不引入常驻特权进程（launchd helper），全部特权操作即时弹窗。

```
┌────────────────────────────────────────────────────────┐
│ src-tauri (commands/cert.rs, commands/engine.rs)       │
└──────┬─────────────────────────────────────────────────┘
       │
┌──────▼─────────────────────────────────────────────────┐
│ watt-cert::trust::platform::install_root_cert          │──┐
│ watt-hosts::HostsManager::update_hosts / remove_by_tag │──┤ 特权操作失败时
└────────────────────────────────────────────────────────┘  │ 走统一提权通道
                                                            ▼
                        ┌───────────────────────────────────────────┐
                        │ 新增 watt-core::elevate（或独立小 crate）  │
                        │ macOS: osascript                          │
                        │   do shell script "..."                   │
                        │   with administrator privileges           │
                        │ Windows: 保持现状（runas / 直写）          │
                        │ Linux: 预留 pkexec（本期不做）             │
                        └───────────────────────────────────────────┘
```

### 模块归属决策

提权模块建议放 **`watt-core` 下新建 `src/elevate.rs`**（或 `crates/watt-elevate` 独立  
crate，供 watt-core 与 watt-cert 共用——**推荐独立 crate**，因为 watt-cert 也要用，  
而 watt-cert 目前不依赖 watt-core，避免循环依赖）。

职责：

```rust
// crates/watt-elevate/src/lib.rs（示意签名，非最终 API）
pub fn is_elevated() -> bool;                    // macOS: geteuid()==0；Windows: token 检查
pub fn run_as_admin(program: &str, args: &[&str]) -> Result<String, ElevateError>;
// macOS 实现: osascript -e 'do shell script "<escaped cmd>" with administrator privileges'
// 用户取消 → ElevateError::Cancelled（UI 需区分"取消"与"失败"）
```

**安全要点（必须遵守）**：

- 参数逐个做 POSIX shell 单引号转义（`'` → `'\''`），再整体做 AppleScript 字符串转义  
  （`\` 和 `"` 前加反斜杠）。绝不允许字符串拼接未转义的用户可控内容（域名、路径）。
- 传给提权 shell 的命令只允许白名单程序：`security`、`cp`、`mkdir`、`killall`、`dscacheutil`。
- `ElevateError::Cancelled`（osascript 退出码 -128）单独建模，UI 文案区分处理。

## 三、分项实施

### 工作项 1：macOS 系统代理 / PAC（System、Pac 模式）— 无需提权

改 `crates/watt-core/src/system_proxy.rs`，替换非 Windows 占位分支为  
`#[cfg(target_os = "macos")]` 实现（Linux 仍保留占位 Err，本期不做 gsettings）。

**网络服务名解析**（networksetup 以"服务名"而非接口名操作）：

1. `route -n get default` → 取 `interface:` 行（如 `en0`）；
2. `networksetup -listnetworkserviceorder` → 解析 `(1) Wi-Fi` 段落中  
   `(Device: en0)` 匹配，得到服务名（如 `Wi-Fi`）；
3. **VPN / 多活动服务兜底**（重要，勿只回退服务名字符串）：
   - 若默认路由接口是 VPN 隧道（`utunX` 等），该设备**不对应任何可设代理的
     networksetup 服务**（VPN 类服务无 `-setwebproxy` 语义），此时不能把默认路由
     设备当唯一目标；
   - 策略：默认路由设备能匹配到服务名 → 只设该服务；匹配不到（VPN 在线、
     无默认路由、解析失败）→ 对 `-listnetworkserviceorder` 中**所有硬件类活动
     服务**（`Hardware Port` 为 `Wi-Fi` / `Ethernet` / `AirPort` /
     `Thunderbolt Bridge` 等，即 `Device` 为 `en*` / `bridge*`、排除 `utun*`
     的服务）**统一设置**；
   - 服务名识别只认 `Hardware Port` / `Device` 字段，**不认本地化服务名**
     （中文系统下服务名是"无线局域网"，硬编码字符串必然失败）；
   - 取消（enable=false）时必须对**同一集合**执行 off，避免只关一个服务
     导致其余服务残留代理；
   - `get_system_proxy_status` 同样按该集合读取：以默认路由服务（或集合中
     任一已启用的服务）为准，返回首个 `Enabled=Yes` 的结果。
4. 每次 start 重新解析，不做进程内长缓存（网络切换后接口/服务集会变化）。

**API 映射**：

| 函数                        | enable=true                                                                                                                                                                        | enable=false                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `set_system_proxy`        | `networksetup -setwebproxy <svc> <ip> <port>`<br />`networksetup -setsecurewebproxy <svc> <ip> <port>`<br />`networksetup -setproxybypassdomains <svc> <no_proxy_host_names()...>` | `-setwebproxystate <svc> off`<br />`-setsecurewebproxystate <svc> off` |
| `set_system_pac`          | `-setautoproxyurl <svc> <url>`<br />`-setautoproxystate <svc> on`                                                                                                                  | `-setautoproxystate <svc> off`                                         |
| `get_system_proxy_status` | 解析 `-getwebproxy <svc>`（Enabled/Server/Port）与 `-getautoproxyurl <svc>`，返回 `(enabled, Some("ip:port"), Some(pac_url))`                                                              | 同左（只读）                                                                 |

注意事项：

- macOS 上 `networksetup` 修改代理**普通用户即可执行**（无需 sudo），已实测约定俗成；  
  若目标机器为受限 MDM 环境返回错误，透出原始 stderr 即可。
- bypass 域名：Windows 版 `ProxyOverride` 用 `;` 分隔，macOS  
  `-setproxybypassdomains` 是空格分隔多参数，`no_proxy_host_names()` 通配格式  
  （`10.*`）macOS 支持 `*.domain` 风格，需做一次格式转换（`10.*` 这类 IP 段通配  
  macOS 不完全等价——按原样传入，行为差异记录到验收清单，不阻塞）。
- 引擎 `stop()`（`crates/watt-core/src/engine.rs:457-486`）与崩溃兜底 `cleanup_orphans`（`:163`）已统一走  
  `set_system_proxy(false,…)`/`set_system_pac(false,…)`，macOS 分支实现后自动生效，  
  引擎侧无需改动。
- `connect_test.rs:24` 的 `system_proxy_addr()` 依赖 `get_system_proxy_status`，  
  实现后连通性测试自动恢复"经系统代理探测"能力，无需单独改。
- 该模块函数目前是同步阻塞 `std::process::Command`；调用点已在  
  `spawn_blocking`/同步上下文内的保持现状，若在 async 上下文中直接调用需包  
  `spawn_blocking`（核对 `crates/watt-core/src/engine.rs:277/292` 调用栈——`start()` 是 async，  
  **需将 set_system_proxy/set_system_pac 调用包进 spawn_blocking**（调用点：`crates/watt-core/src/engine.rs:277` / `:292`），Windows 分支  
  同样受益，属小重构）。

### 工作项 2：提权通道 crate `watt-elevate`（新增）

见"总体设计"。macOS 实现细节：

- `osascript -e 'do shell script "<cmd>" with administrator privileges'`；
- 首次弹窗文案由 AppleScript `with prompt "Watt Toolkit 需要管理员权限以…"` 提供，  
  按操作类型传入不同 prompt（hosts 写入 / 证书安装），减少用户困惑；
- 输出捕获 stdout/stderr；退出码 -128 → `Cancelled`；
- Windows 分支：`is_elevated` 用 token 检查，`run_as_admin` 本期可直接返回  
  `Err(Unsupported)`（Windows 现有 runas 逻辑在 trust.rs 内自洽，不迁移）；
- Linux 分支：预留 `pkexec`，本期返回 `Err(Unsupported)`。

### 工作项 3：证书安装提权（Hosts 模式前置）

改 `crates/watt-cert/src/trust.rs` macOS 分支（258-323 行）：

- `install_root_cert`：先直接执行 `security add-trusted-cert …`（若进程恰好有权限），  
  失败且判定为权限问题时，改经 `watt-elevate::run_as_admin("security", [...])` 重试，  
  prompt 文案"Watt Toolkit 需要安装根证书以启用 HTTPS 加速（MITM）"；
- `remove_root_cert`：同样两段式（直接 → 提权重试），且**必须补删证书本体**：
  `security remove-trusted-cert -d` 只移除**信任设置**，证书本身可能仍留在
  System.keychain。若只删信任设置，`is_root_cert_installed`（钥匙串 SHA-1 比对）
  仍返回 true → 重复安装会误报"已安装"。因此提权命令串联为：
  `security remove-trusted-cert -d -r trustRoot CN=<CA_SUBJECT_CN> && security delete-certificate -Z <sha1> /Library/Keychains/System.keychain`
  （sha1 由 cert_pem_path 现场计算，走白名单参数传递，禁止拼接未转义内容）；
  验收时以 `security find-certificate -a -Z /Library/Keychains/System.keychain`
  无该指纹匹配为准（见验收清单）。
- `is_root_cert_installed`：只读操作，`security find-certificate` 无需提权，保持不变；
- `src-tauri/src/commands/cert.rs:83/111` 已在 `spawn_blocking` 内调用，osascript  
  弹窗阻塞在该线程上不影响 UI；但需确认 **Tauri 主线程激活策略**——osascript 弹窗  
  属于其他进程（System Events/osascript），焦点抢占在 macOS 上一般正常，若发现弹窗  
  被压在窗口后，方案 B：`osascript` 前加 `activate`（记录为验证项）。
- UI：`CertPage`/相关 store 对 `TrustError::Elevation` 与"用户取消"分别给文案  
  （locales 三语补充）。

### 工作项 4：hosts 写入提权（Hosts 模式）

改 `crates/watt-hosts`（`lib.rs` + `tagged_block.rs` 调用侧）：

- 策略：**先直写，失败再提权**。`update_hosts` / `remove_hosts_by_tag` 现有逻辑  
  完全不变（读文件、内存中重排标记块、生成最终内容），仅把最后的落盘步骤抽成  
  `write_file(path, content)`：
  1. `std::fs::write` 直接写 `/etc/hosts`；
  2. `PermissionDenied` 时（macOS）：内容写入临时文件  
     `std::env::temp_dir()/watt-hosts-<pid>.tmp`（该路径无用户可控段，安全），  
     经 `watt-elevate` 执行  
     `cp <tmp> /etc/hosts && chmod 644 /etc/hosts && dscacheutil -flushcache && killall -HUP mDNSResponder`  
     （单条 shell，一次弹窗完成写+刷 DNS），随后删除临时文件；
  3. 用户取消 → 映射为 `HostsError::Unauthorized`（现有错误类型可复用，或加  
     `Cancelled` 变体供 UI 区分——**建议加变体**）。
- watt-hosts 需新增对 `watt-elevate` 的依赖（仅 target macOS）。
- 引擎侧无需改动：`crates/watt-core/src/engine.rs:422-441`（启动写入+失败回滚）、
  `:457-467`（停止摘除）、`cleanup_orphans`（`:163`，启动前清残留）都经由
  HostsManager，自动获得提权。
- **弹窗频率控制**：正常一次 start/stop 各弹一次；`cleanup_orphans` 只在检测到残留  
  标记块时才会触发写入，无残留时静默——保持该行为，避免每次启动都弹窗。
- 原子性：`cp` 到 /etc/hosts 非原子，但 hosts 文件小、窗口极短，可接受；  
  如要更稳，提权命令改为 `cat <tmp> > /etc/hosts`（同样一次弹窗）。

### 工作项 5：443/80 绑定验证与诊断（Hosts 模式）

- **预期无需代码改动**：macOS ≥10.14 允许非 root bind 443。需在目标机验证  
  （最低支持版本建议在 `tauri.conf.json` / README 标注 macOS 11+）。
- `port_diag.rs` 非 Windows 分支（19-24 行返回 None）可选增强：  
  `lsof -nP -iTCP:<port> -sTCP:LISTEN` 解析占用进程名，仅用于错误提示，低优先级。
- 若实测某些 macOS 版本/沙盒环境 bind 443 失败（EACCES），备选方案（本期不实现，  
  仅记录）：提权起一个 `socat`/自监听转发子进程，或引导用户改用 System/Pac 模式。

### 工作项 6：UI 文案与设置页

- `ui/src/locales/{zh-Hans,zh-Hant,en}.ts`：
  - 证书安装说明补充 macOS 表述（"系统会弹出管理员密码框"），现有文案以 Windows/UAC 为主（如 zh-Hans.ts:134）；
  - Hosts 模式说明补充"写入 /etc/hosts 需要管理员权限"；
  - 提权被取消的错误 toast 文案。
- `SettingsPage.vue` 模式选项不需要平台 gating（四种模式实现后全平台可用）。
- 可选：About/设置页显示当前平台检测到的活动网络服务名，便于诊断（低优先级）。

### 工作项 7：构建、打包与验证环境

- Windows 侧（本开发机）只能保证：`cargo check --workspace`、  
  `cargo test --workspace`（watt-elevate 的转义函数可写纯单测，跨平台可测）、  
  Windows 行为零回归。
- **macOS 编译验证必须在 Mac 上进行**（windows-sys 为条件依赖不影响，但 osascript/  
  networksetup 分支代码只有 macOS target 才编译）。路径：
  1. 本地 Mac：`cargo tauri dev` 直跑（开发调试首选，不受签名限制）；
  2. CI：GitHub Actions 增加 `macos-latest` matrix（现有 CI 已有 beforeBuildCommand  
     修复经验，见 f4e1841）；CI 无签名证书，需显式配置
     `tauri.conf.json` → `bundle.macOS.signingIdentity: null`，避免构建期签名告警；
  3. 打包分发：未签名 app 首次打开需右键→打开或 `xattr -cr`；本期不处理签名/公证，  
     仅记录。
- Tauri 配置：`tauri.conf.json` `bundle.targets = "all"` 已就绪；确认  
  `macOS.minimumSystemVersion` 设为 11.0（或按团队决策）。

## 四、macOS 验收清单（在 Mac 上逐项实测）

| 场景         | 步骤                | 预期                                                                                                |
| ---------- | ----------------- | ------------------------------------------------------------------------------------------------- |
| ProxyOnly  | 启动引擎（ProxyOnly）   | 无弹窗；26501/8868 监听；浏览器手动挂代理可访问加速域名                                                                 |
| System     | 启动/停止             | 无提权弹窗；系统设置→网络→代理中 HTTP/HTTPS 代理指向 127.0.0.1:26501，bypass 列表写入；停止后恢复 off                           |
| Pac        | 启动/停止             | 自动代理配置 URL = <http://127.0.0.1:26501/pac；停止后> off                                                 |
| 连通性测试      | System 模式下执行      | 走系统代理探测（非直连退化）                                                                                    |
| 证书安装       | 设置页安装根证书          | 弹一次管理员密码框；钥匙串访问中可见 Watt CA 且"始终信任"；重复安装提示已安装                                                      |
| 证书卸载       | 设置页卸载             | 弹窗一次；`find-certificate -Z` 无该指纹匹配（证书本体已删）；`is_installed` 返回 false                                                     |
| Hosts 全链路  | 装证书→Hosts 模式启动    | 弹一次密码框（写 hosts）；/etc/hosts 出现 `# Steam++ Start` 块；443 监听成功；浏览器访问 steamcommunity.com 命中 MITM 且证书受信 |
| Hosts 停止   | 停止引擎              | 再弹一次密码框；标记块移除；DNS 恢复                                                                              |
| 取消弹窗       | 任意提权操作点"取消"       | 引擎回到 Stopped/Error 态，UI 提示"已取消授权"，无 hosts 残留                                                      |
| 崩溃兜底       | 加速中 kill -9 应用，重启 | 检测到残留→提示并弹窗清理（仅一次）                                                                                |
| Wi-Fi/有线切换 | 换网络后启动 System 模式  | networksetup 作用于新的活动服务                                                                            |
| VPN + Wi-Fi 并存 | 连 VPN 后启动 System 模式 | 默认路由走 utun 时对全部硬件类活动服务设置代理；浏览器走系统代理仍生效；停止后全部服务恢复 off                                   |
| Windows 回归 | 全模式在 Windows 走一遍  | 行为与改动前一致                                                                                          |

## 五、实施顺序与工作量估算

| 阶段 | 内容                                                     | 依赖        | 估算             |
| -- | ------------------------------------------------------ | --------- | -------------- |
| P1 | `watt-elevate` crate（含转义单测）                            | 无         | 0.5 天          |
| P2 | `system_proxy.rs` macOS 分支 + engine 调用包 spawn_blocking | 无（不依赖 P1） | 1 天            |
| P3 | `trust.rs` macOS 提权重试 + cert 命令/UI 文案                  | P1        | 0.5 天          |
| P4 | `watt-hosts` 提权落盘 + flush DNS                          | P1        | 0.5~1 天        |
| P5 | locales 三语文案 + port_diag lsof（可选）                      | P2-P4     | 0.5 天          |
| P6 | Mac 实机联调（验收清单）+ CI macos matrix                        | P1-P5     | 1~2 天（取决于实机环境） |

P2 可独立先行合并——完成后 System/Pac/ProxyOnly 三模式即可在 Mac 使用；  
P3+P4 完成后 Hosts 模式可用。

## 六、风险与开放问题

1. **osascript 弹窗焦点**：从后台 spawn 的 osascript 弹窗可能被遮挡，需实机验证；


   备选：AppleScript 中加 `activate` 或改用 `AuthorizationExecuteWithPrivileges`
   的替代（Security.framework 现代 API 无直接等价物，弹窗方案仍是主流做法）。
2. **`security add-trusted-cert` 版本差异**：macOS 11+ 对信任设置偶有额外确认弹窗
   （系统级"允许"按钮），属 OS 行为，文案中提示用户即可。
3. **networksetup 服务名本地化**：中文系统下服务名可能是"无线局域网"，因此必须走
   `route → device → listnetworkserviceorder` 解析而非硬编码英文名（方案已覆盖）。
4. **IP 段 bypass 通配差异**：`10.*` 在 macOS bypass 中语义与 Windows 不完全一致，
   内网直连行为需实测（验收清单已列）。
5. **每次启停各弹一次密码框**的体验成本：本期接受；若反馈差，后续再做 launchd
   privileged helper（doc/task.md:112 的远期方向），接口层（watt-elevate）已为此
   预留抽象。
6. **最低系统版本**：443 免 root 依赖 macOS ≥10.14；建议直接声明 macOS 11+。
7. **VPN / 多活动服务**：默认路由走 VPN 隧道时不存在可设代理的 networksetup 服务，
   已在工作项 1 给出"全部硬件类活动服务统一设置"兜底，需实机验证（连 VPN 与
   断开两种状态各走一遍）。
8. **证书卸载彻底性**：`remove-trusted-cert` 可能只删信任设置、证书残留钥匙串，
   已在工作项 3 补 `delete-certificate -Z`，需实机验证卸载后 `find-certificate` 无匹配。
9. **Linux**：本方案不做（占位 Err 保留），gsettings/pkexec 另行排期。
