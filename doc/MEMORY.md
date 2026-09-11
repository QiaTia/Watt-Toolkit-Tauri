# watt-toolkit-tauri 长期项目记忆

SteamTools（Watt Toolkit）加速插件的 Tauri + Rust 重写，位于 `watt-toolkit-tauri/`。
用户强调「迁移需保持与原 C# 版功能一致」，验收以真实站点端到端可达为准。

## 架构要点
- 代理模式与接入面**一一对应，不可并存**：
  - `Hosts` → 写系统 hosts（`域名 → 127.0.0.1`）+ 监听 **443**（TLS MITM）
  - `System` / `Pac` / `ProxyOnly` → 监听 **26501** 正向代理 + 写注册表 `ProxyEnable/ProxyServer`（或 `AutoConfigURL`）
- 端口常量：`watt_config::constants::{HTTPS_PORT=443, DEFAULT_HTTP_PROXY_PORT=26501}`
- 出站候选链：覆盖 IP → 镜像转发 → DNS → `fallback.rs` 备用 IP 池（happy-eyeballs 并发竞速）
- hosts 标记：`# Steam++ Start` / `# Steam++ End`（与原 C# 版共用同一标记）

## 铁律：接入面必须与运行态一致（否则必出黑洞）
- **核心不变量**：只要 hosts 处于劫持态，443 就必须在监听；反之 443 不在监听时绝不能留有 hosts 劫持块
- `ProxyEngine` 的 `hosts_written` / `running_mode` 是**内存态**，进程被强杀即丢失；而 hosts 与系统代理是**持久化**的 → 必须在 app 启动（`cleanup_orphans`）与退出（`RunEvent::Exit` → `shutdown`）两侧兜底清理
- 清理只允许撤销**确认属于本引擎**的东西：hosts 标记块 + 指向本引擎端口的系统代理/PAC

## 铁律：MITM/反代取「目标主机」必须兼容 HTTP/2
- **HTTP/2 没有 `Host` 头**，目标主机只在 `:authority` 伪头（hyper 映射到 `uri.authority()`）。而 `sni.rs` 的 MITM 配置把 **`h2` 放在 ALPN 首位** → 浏览器必然协商 h2。只读 `Host` 头会让 host 变空字符串：域名规则失配、且不满足 `find_domain_config` 的 default 判据 `host.contains('.')` → 直接回落 `not_found_response()`（**404 + 空 body**）
- 症状是 Chromium 自绘错误页「**找不到此 <域名> 页 / 找不到以下 Web 地址的网页 / HTTP ERROR 404**」——**不是源站 404**，极易误判
- 正解：`http_relay::request_host()` —— 优先 `Host` 头（保 HTTP/1.1 行为），为空回落 `uri.authority()`（`Authority::host()` 自动去端口）
- **排查陷阱**：本机 curl 构建**不支持 HTTP/2**（`--http2` 报 not supported），用 curl 验浏览器路径会得出完全相反的结论（curl 200 / 浏览器 404）。必须用能协商 h2 的客户端复现：`node h2_probe.cjs <host> "h2,http/1.1"`（仓库根，经 CONNECT 隧道 + 指定 ALPN）
- 通用原则：**服务端把 `h2` 放进 ALPN，就等于承诺自己能正确处理 h2 语义**（无 Host 头、伪头、无逐跳头等）

## 铁律：竞速的「胜出条件」必须与「可用性判据」一致
- **TCP 握手成功 ≠ 服务可用**。存在只放行 TCP、阻断 TLS 之后流量的网络：实测 `github.com` 12 个候选中 11 个 TCP 秒连但 TLS 全部卡死。以 TCP 为胜出条件的竞速会**稳定选中死候选** → 表现为 20s 超时 / 500，且**间歇性**（网络好时看不出问题）
- 因此 `outbound.rs` 中：需 TLS 的目标一律走 `race_tls`（胜出 = TLS 握手完成）；不需要 TLS 的纯隧道才走 `race_tcp`
- 用 `JoinSet` 承载候选并在胜出后 abort 落败者，避免握手在后台空跑
- 排查时**分层次探测候选**（TCP → TLS → HTTP），可一眼区分「封 IP」与「封 TLS 之后流量」
- 注意区分**镜像转发**路径（`forward_destination`，如 `githubapi.rmbgame.net`）与**候选竞速**路径：前者稳定，后者受此缺陷影响，这是「只有 github.com 主站不稳、其他子域正常」的原因

## 诊断顺序（网络类故障）
1. `netstat -ano | grep LISTENING` 核对 443/26501 是否符合当前模式
2. `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable`（=1 且端口无监听 → 死代理，必断网）
3. `grep "Steam++ Start" /c/Windows/System32/drivers/etc/hosts`（有块但 443 未听 → 黑洞）
4. 分路对比：`curl --noproxy '*'`（hosts 面）vs `curl -x http://127.0.0.1:26501`（正向代理面）
5. **若 curl 正常但浏览器异常 → 优先怀疑协议层差异（HTTP/1.1 vs HTTP/2）**，用 `node h2_probe.cjs <host> "h2,http/1.1"` 复现
6. 再看响应体：本项目的错误页是纯文本 `转发失败: ...`；Chrome 会把「404 + 空 body」包装成自己的错误页，**极易误判成 GitHub 官方 404**

## 可复跑的真实链路验收
- `cargo test -p watt-core --test diag_github -- --ignored --nocapture`
  （**两条路径都验**：`diag_github_via_hosts_mode` = HTTP/1.1；`diag_github_via_mitm_http2` = **HTTP/2，浏览器路径**。
  注入临时 hosts + 空闲端口，不碰系统 hosts、不占 443。修复 h2/Host 缺陷后两条均 200）
- `cargo test -p watt-core --test diag_outbound -- --ignored --nocapture`（测出站候选链/备用 IP 池）
- `cargo test -p watt-core --test diag_outbound -- --ignored --nocapture diag_candidate_health_github`
  （**候选健康度矩阵**：逐候选分 TCP / TLS 两层探测，判断是否处于「封 TLS 之后流量」的干扰窗口）
- `node h2_probe.cjs <host> "h2,http/1.1"`（仓库根；经**正向代理 26501 隧道**验浏览器路径，需引擎在运行）

## 本地调试环境
- **本机无 pnpm**：须分离启动（先 `ui/node_modules/.bin/vite --host 127.0.0.1 --port 5173`，再
  `tauri dev -c '{"build":{"beforeDevCommand":"echo skip-dev-server"}}' --no-dev-server-wait`）
- tauri watcher 监听 `crates/` 与 `src-tauri/`，**改 `tests/*.rs` 也会重启 app**，会打断引擎运行态；调通前少改测试文件
- 日志：`/tmp/vite.log`、`/tmp/tauri-dev.log`
