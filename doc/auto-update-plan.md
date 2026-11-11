# Watt Toolkit 自动更新项目规划书

> 目标：从 GitHub Releases 自动检测新版本，用户在应用内一键下载并完成更新安装，体验对齐 cc-switch 这类 Tauri 桌面应用。
>
> 文档定位：实施蓝图。所有结论均基于当前仓库代码事实（Tauri 2 / v0.5.2 / NSIS + dmg + deb/AppImage）。

---

## 1. 目标与验收标准

### 1.1 一句话目标

应用启动后静默查询 GitHub Releases，发现新版本时在界面内提示；用户点击后**在应用内**完成下载、显示进度，下载完成即自动安装并重启，全程不打开浏览器、不手动找安装包。

### 1.2 用户体验目标（对标 cc-switch）

| 场景 | 期望行为 |
|---|---|
| 启动后 | 延迟若干秒静默检查，**不阻塞启动、不弹窗打扰** |
| 有新版本 | 顶栏右上角出现红点/角标，首页与「关于」页出现更新入口 |
| 点击入口 | 弹窗展示：当前版本 → 新版本、发布日期、更新说明（Markdown）、安装包大小 |
| 点击「立即更新」 | 应用内下载，实时进度条 + 百分比 + 速度 + 剩余时间 |
| 下载完成 | 展示「重启并安装」，或按配置自动安装 |
| 安装 | 应用退出 → 静默安装 → 自动拉起新版，用户无需操作 |
| 无更新 | 静默结束（手动点击检查时才提示「已是最新版本」） |
| 检查失败 | 不打扰用户，仅在「关于」页显示可重试的错误与「手动下载」兜底链接 |
| 「稍后」 | 本次会话不再提示，下次启动再检查 |
| 「跳过此版本」 | 该版本不再提示，直到出现更高版本 |

### 1.3 硬性验收标准（DoD）

1. Windows x64 真机：v0.5.2 → v0.5.3 全流程成功，重启后版本号显示 0.5.3。
2. 更新全程**不出现额外的 UAC 弹窗**（应用本身已 `requireAdministrator`）。
3. 更新前若加速引擎正在运行，退出后**系统 hosts 无 `Steam++ Start` 残留块**、系统代理已还原、终端代理环境变量已还原。
4. 更新后用户配置（`%APPDATA%/net.steampp.watttoolkit/Settings/*.json`）与 CA 证书、动态 IP 池全部保留。
5. 更新包签名校验失败时**拒绝安装**并给出明确错误，不得静默继续。
6. 断网 / GitHub 不可达时，检查失败不阻塞应用，且「关于」页可跳转 Release 页面手动下载。
7. 版本号三处一致（`Cargo.toml` / `tauri.conf.json` / `ui/package.json`），CI 强制校验。

---

## 2. 现状盘点

### 2.1 已有基础

| 事实 | 位置 |
|---|---|
| Tauri 2.x，`productName = "Watt Toolkit"`，`identifier = net.steampp.watttoolkit` | [tauri.conf.json](file:///d:/Project/Watt-Toolkit-Tauri/src-tauri/tauri.conf.json) |
| 版本 0.5.2（workspace + tauri.conf + ui/package.json 三处当前一致） | [Cargo.toml](file:///d:/Project/Watt-Toolkit-Tauri/Cargo.toml#L19-L22) |
| 已有 Release 流水线：`v*` tag 触发，三平台矩阵，`tauri-action@v0` | [release.yml](file:///d:/Project/Watt-Toolkit-Tauri/.github/workflows/release.yml) |
| Windows 产物为 NSIS（x64 / arm64 各一），macOS 为 dmg（x86_64 / aarch64），Linux 为 deb + AppImage | 同上，`--bundles` 参数 |
| 应用以管理员权限运行（`requireAdministrator`） | [app.manifest](file:///d:/Project/Watt-Toolkit-Tauri/src-tauri/app.manifest#L30-L36) |
| 单实例插件最先注册；退出时 `RunEvent::Exit` 做引擎清理 | [lib.rs](file:///d:/Project/Watt-Toolkit-Tauri/src-tauri/src/lib.rs#L67-L76) |
| 启动时 `cleanup_orphans` 兜底清理 hosts / 系统代理 / 终端代理 | [lib.rs](file:///d:/Project/Watt-Toolkit-Tauri/src-tauri/src/lib.rs#L100-L139) |
| 前端 Vue 3 + Pinia + ant-design-vue + 5 语言 i18n | [ui/src](file:///d:/Project/Watt-Toolkit-Tauri/ui/src) |
| 顶栏右上角已有「按路由显示操作按钮」的插槽模式 | [AppHeader.vue](file:///d:/Project/Watt-Toolkit-Tauri/ui/src/components/AppHeader.vue#L65-L78) |

### 2.2 缺口

- 无任何更新相关代码（`tauri-plugin-updater` 未引入，`capabilities/default.json` 只有 core 权限）。
- Release 产物未签名（无 `createUpdaterArtifacts`），未生成 `latest.json`。
- `releaseBody` 是固定模板，没有逐版本更新说明，弹窗无内容可展示。
- 无「更新」设置项、无更新状态持久化。

---

## 3. 技术选型

| 方案 | 说明 | 结论 |
|---|---|---|
| **A. 官方 `tauri-plugin-updater` + GitHub Releases `latest.json`** | 静态 JSON 描述各平台产物；插件负责下载、**minisign 签名校验**、安装、重启。配合 `tauri-action` 自动上传 | ✅ **推荐** |
| B. 自研：自己请求 GitHub API + 比对 tag + 下载 exe 调安装器 | 完全可控，但要自己做签名校验、平台判定、增量、回滚、macOS 替换 .app | ❌ 重复造轮子且安全风险高 |
| C. 自建更新服务器 / OSS 分发 | 国内速度好，但需要运维与费用 | ⏸ 作为 Phase 4 的可选更新源（镜像），不替代 A |

**选 A 的核心理由**：签名校验、静默安装、macOS `.app` 替换、重启拉起这些易错环节都由官方插件实现，我们只需接好 CI 与 UI；同时插件允许**动态指定 endpoint**，为后续加国内镜像留了口子。

---

## 4. 总体设计

### 4.1 数据流

```
GitHub Actions (tag v0.5.3)
  └─ tauri-action 构建 NSIS / dmg / AppImage
     ├─ 生成 *.sig（minisign，私钥来自 Secrets）
     └─ 生成并上传 latest.json（version / notes / platforms[]）

客户端启动
  └─ 延迟 5s → update_check（可带自定义 endpoint 镜像）
       └─ GET latest.json → 与本地版本比对（semver）
            ├─ 无更新 → 静默
            └─ 有更新 → 顶栏红点 + 弹窗
                 └─ 用户点击「立即更新」
                      ├─ [关键] 优雅停止加速引擎（hosts/系统代理/终端代理全部还原）
                      ├─ 下载到临时目录，实时进度事件 → 前端进度条
                      ├─ minisign 校验（失败即中止）
                      ├─ 静默安装 → 应用退出
                      └─ 安装器拉起新版 → setup() 的 cleanup_orphans 二次兜底
```

### 4.2 模块划分

| 层 | 新增/修改 | 职责 |
|---|---|---|
| CI | `release.yml` | 签名、产出 latest.json、校验版本一致性 |
| 配置 | `tauri.conf.json` | `pubkey`、`endpoints`、`createUpdaterArtifacts` |
| 后端 | `src-tauri/src/lib.rs`、`commands/update.rs`、`capabilities/default.json` | 注册插件、动态 endpoint、暴露 IPC |
| 配置模型 | `crates/watt-config/src/settings.rs` | 更新设置项（自动检查、频率、镜像、跳过版本） |
| 前端 | `stores/update.ts`、`components/UpdateModal.vue`、`UpdateBanner.vue`、`AppHeader.vue`、`AboutPage.vue`、`SettingsPage.vue`、5 份 locale | 状态机、UI、文案 |

---

## 5. 详细设计

### 5.1 签名与产物

1. 生成密钥对（**只做一次，私钥必须长期备份**——换钥后老客户端将无法校验新版本）：

```powershell
cargo tauri signer generate -w "$env:USERPROFILE\.tauri\watt-toolkit.key"
```

产出 `watt-toolkit.key`（私钥）与 `watt-toolkit.key.pub`（公钥）。

2. `tauri.conf.json` 增加：

```json
{
  "bundle": {
    "createUpdaterArtifacts": true
  },
  "plugins": {
    "updater": {
      "pubkey": "<watt-toolkit.key.pub 的内容>",
      "endpoints": [
        "https://github.com/QiaTia/Watt-Toolkit-Tauri/releases/latest/download/latest.json"
      ]
    }
  }
}
```

> ⚠️ **注意仓库地址**：`Cargo.toml` 的 `repository` 字段指向上游 `WattToolkit/WattToolkit`，而实际发布仓库是 `QiaTia/Watt-Toolkit-Tauri`（见 `git remote`）。endpoint 必须用**实际发布仓库**，否则永远查不到更新。

3. GitHub Secrets 新增：

| Secret | 内容 |
|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | 私钥文件全文（由 `tauri-action` 读取） |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | 私钥口令 |

私钥文件**绝不能提交**，加入 `.gitignore`。

4. 产物结构（action 自动生成）：

```json
{
  "version": "0.5.3",
  "pub_date": "2026-11-20T10:00:00Z",
  "notes": "<Release body，弹窗直接渲染>",
  "platforms": {
    "windows-x86_64": { "signature": "...", "url": "https://.../Watt%20Toolkit_0.5.3_x64-setup.exe" },
    "windows-aarch64": { "signature": "...", "url": "..." },
    "darwin-x86_64":   { "signature": "...", "url": "..." },
    "darwin-aarch64":  { "signature": "...", "url": "..." },
    "linux-x86_64":    { "signature": "...", "url": "..." }
  }
}
```

### 5.2 CI 改造（`release.yml`）

1. 各构建 job 的 `env` 增加签名变量（现在是空，需补）：

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
  TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
```

2. **新增版本一致性校验 job**（先于 build 跑，避免发布版本号错乱的包）：

```yaml
  version-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: 校验版本号一致
        run: |
          WS=$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
          TC=$(grep -m1 '"version"' src-tauri/tauri.conf.json | sed 's/.*"\([0-9].*\)".*/\1/')
          PKG=$(grep -m1 '"version"' ui/package.json | sed 's/.*"\([0-9].*\)".*/\1/')
          TAG="${GITHUB_REF_NAME#v}"
          echo "workspace=$WS tauri=$TC package=$PKG tag=$TAG"
          [ "$WS" = "$TC" ] && [ "$WS" = "$PKG" ] && [ "$WS" = "$TAG" ] || exit 1
```

3. `releaseBody` 改为可维护的更新说明：建议引入 `CHANGELOG.md`，用 `releaseBody: ${{ ... }}` 或 `softprops/action-gh-release` 读取对应版本段落。**这一步直接决定更新弹窗有没有内容**。

4. **（必查风险）多矩阵 `latest.json` 合并**：Windows/macOS/Linux 三个 job 都会调用 `tauri-action` 上传 `latest.json`。需确认 action 会**合并**已有 `latest.json` 的 `platforms` 字段，否则后跑的 job 会覆盖前面的，导致某些平台永远收不到更新。
   - 验证方法：发布一个测试 tag，下载 Release 里的 `latest.json` 检查 `platforms` 是否 5 个 key 齐全。
   - 若不合并：新增一个汇总 job，收集全部 `*.sig` 与产物 URL，手工生成 `latest.json` 后上传。

5. `tauri.conf.ci.json` 无需改（它只覆盖 `build.beforeBuildCommand`，与主配置合并）。

### 5.3 后端接入

1. `src-tauri/Cargo.toml` 增加：

```toml
tauri-plugin-updater = "2"
```

2. `ui/package.json` 增加：

```json
"@tauri-apps/plugin-updater": "^2"
```

3. `src-tauri/src/lib.rs`：在 `single_instance` **之后**注册（保持单实例最先）：

```rust
#[cfg(desktop)]
{
    app = app.plugin(tauri_plugin_updater::Builder::new().build());
}
```

4. `capabilities/default.json` 增加权限：

```json
"updater:default"
```

5. 新增 `src-tauri/src/commands/update.rs`（Phase 4 才需要，Phase 1 用纯前端 JS API 即可）：

```rust
use tauri_plugin_updater::UpdaterExt;

/// 检查更新。endpoint 为空时使用 tauri.conf.json 中的默认 GitHub 源；
/// 传入时用于国内镜像或自建源，签名校验仍由插件完成。
#[tauri::command]
pub async fn update_check(
    app: tauri::AppHandle,
    endpoint: Option<String>,
) -> Result<Option<UpdateInfo>, String> {
    let mut builder = app.updater_builder();
    if let Some(url) = endpoint {
        let url = url.parse().map_err(|e| format!("更新源地址非法: {e}"))?;
        builder = builder.endpoints(vec![url]).map_err(|e| e.to_string())?;
    }
    let updater = builder.build().map_err(|e| e.to_string())?;
    let Some(update) = updater.check().await.map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    Ok(Some(UpdateInfo {
        version: update.version.clone(),
        current_version: update.current_version.clone(),
        date: update.date.map(|d| d.to_string()),
        body: update.body.clone(),
    }))
}
```

> 说明：`UpdateInfo` 只需回传元信息；**下载与安装仍交给前端 `downloadAndInstall`**，以复用插件的进度事件与签名校验，避免自己实现 minisign。

### 5.4 前端实现

1. 新增 `ui/src/stores/update.ts`，状态机：

```
idle → checking → (upToDate | available | error)
available → downloading{percent,speed,eta} → downloaded → installing → (exit)
error → idle（可重试）
```

关键逻辑：

```ts
const { check } = await import('@tauri-apps/plugin-updater');

async function checkUpdate(manual = false) {
  if (!manual && shouldSkip()) return;      // 自动检查：频率/跳过版本
  status.value = 'checking';
  const update = await check();             // dev 模式下会抛错，需 try/catch
  if (!update) { status.value = 'upToDate'; return; }
  if (update.version === skippedVersion.value) { status.value = 'idle'; return; }
  info.value = update;
  status.value = 'available';
}

async function downloadAndInstall() {
  // 【关键】先优雅停止引擎，确保 hosts / 系统代理 / 终端代理全部还原
  await proxyStore.stopIfRunning();

  await info.value!.downloadAndInstall((event) => {
    // Started {contentLength} / Progress {chunkLength} / Finished
  });
  // 进入 downloaded → 调用 install() 或由下载完成回调直接安装
}
```

> 若插件版本不支持「先下载后安装」分离（`download()` / `install()` 需 v2.2+），则统一用 `downloadAndInstall`，把 `Finished` 事件视为「正在安装」状态。

2. 组件：

| 文件 | 内容 |
|---|---|
| `components/UpdateBanner.vue` | 首页/加速页顶部横幅：「发现新版本 v0.5.3 → 查看」 |
| `components/UpdateModal.vue` | 主体弹窗：版本对比、日期、`body` Markdown 渲染、大小、进度条、速度、剩余时间、按钮组 |
| `AppHeader.vue` | 右上角红点按钮（复用现有 `header-right` 模式） |
| `AboutPage.vue` | 版本行旁「检查更新」；显示最新版本与更新源 |
| `SettingsPage.vue` | 「软件更新」卡片：自动检查开关、检查间隔、更新源（默认/自定义）、已跳过版本（可清除） |

3. i18n：`zh-Hans / zh-Hant / en / ja / fr` 五份 locale 同步新增 `update.*` 命名空间。

4. 启动时机：`App.vue` `onMounted` 后延迟 5s 触发一次静默检查；仅在 `auto_check = true` 时执行。

### 5.5 配置与持久化

`crates/watt-config/src/settings.rs` 新增（并入 `ProxySettings` 或独立段）：

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateSettings {
    /// 启动后自动检查更新
    pub auto_check: bool,
    /// 自动检查的最小间隔（小时）
    pub check_interval_hours: u64,
    /// 自定义更新源（镜像 / 自建），None = 用 tauri.conf.json 默认
    pub endpoint: Option<String>,
    /// 用户选择「跳过」的版本
    pub skipped_version: Option<String>,
}
```

运行态时间戳（上次检查时间）单独存 `{AppData}/Settings/UpdateState.json`，避免为写一个时间戳而频繁重写 `ProxySettings.json`。

---

## 6. 关键风险（本项目特有，实施时必须逐条处理）

### 6.1 【最高优先级】引擎运行态与 hosts 黑洞

这是本仓的铁律（见项目记忆）：**只要 hosts 处于劫持态，443 就必须在监听；反之 443 不在监听时绝不能留有 hosts 劫持块**。

更新流程会在应用退出时替换可执行文件，若清理没跑完就退出，用户重启后就是「域名解析到 127.0.0.1 但无人监听 443」的全网黑洞，比更新失败严重得多。

**强制要求（缺一不可）**：

1. 调用 `downloadAndInstall` **之前**，显式执行 `engine_stop` 并等待返回，确认 hosts 块与系统代理已还原。
2. 在 `install()` 前再走一次与 `RunEvent::Exit` 相同的 shutdown 路径（作为二道保险）。
3. 新版启动时 `setup()` 的 `cleanup_orphans` 已存在，作为三道兜底——**不要移除**。
4. 验收时必须检查：更新完成后 `C:\Windows\System32\drivers\etc\hosts` 无 `Steam++ Start` 块；注册表 `ProxyEnable = 0`；`TerminalProxyEnv.backup.json` 已被还原并删除。

### 6.2 管理员权限与 UAC

应用以 `requireAdministrator` 运行，安装器作为子进程**继承提权**，预期不会二次弹 UAC。但需真机验证两条：
- NSIS 静默安装期间是否出现 UAC（若出现，说明安装器走了独立提权，需要改为由应用直接 `ShellExecute runas` 或接受一次确认）。
- 安装器替换正在运行的 exe 时是否存在文件占用竞态。若出现「无法写入」，需在 `install()` 前确保进程已完全退出（插件内部会处理，但要实测）。

### 6.3 GitHub 可达性

**这是本产品最反讽的风险**：Watt Toolkit 存在的意义就是帮用户访问 GitHub 等境外站点。相当一部分用户环境**打不开 github.com / objects.githubusercontent.com**，默认 endpoint 会直接失败。

#### 6.3.1 关键事实：通用 GitHub 加速前缀对更新源**无效**

这是最容易踩的坑。`latest.json` 的结构是：

```json
{ "platforms": { "windows-x86_64": { "url": "https://github.com/<owner>/<repo>/releases/download/...", "signature": "..." } } }
```

`url` 是**绝对地址**。把 endpoint 写成 `https://ghfast.top/https://github.com/.../latest.json` 只能代理那一份 JSON，**JSON 里的 `url` 仍然指向 github.com**，随后下载安装包依旧失败。Tauri 不提供 URL 重写能力。

因此「镜像」必须满足其一：

| 方案 | 做法 | 优缺点 |
|---|---|---|
| **A. 自建 manifest（推荐）** | 把 `latest.json` 发布到自己的 CDN / R2 / OSS，`url` 改写成镜像地址 | 稳定可控；需 CI 多一步生成与上传；`.sig` 与 URL 无关，签名不受影响 |
| **B. 无服务 Worker 重写** | Cloudflare Worker / 边缘函数：取 GitHub 的 latest.json，替换 `url` 前缀后返回 | 零存储、零运维；依赖 Worker 平台本身可达 |
| **C. 用 `proxy()` 借自己的引擎** | `UpdaterBuilder::proxy("http://127.0.0.1:26501")`，走本项目加速引擎直连 GitHub | **本项目独有优势**；但要求引擎在运行且 GitHub 加速分组已启用 |
| D. 手动兜底 | 打开 Release 页面 | 最终保险，始终保留 |

> 签名安全边界：镜像**只能加速、不能伪造**。`.sig` 是 minisign 对安装包内容的签名，私钥在我们手里；换任何 CDN 都无法构造出能通过校验的包。

#### 6.3.2 关键事实：多 endpoint 的切换条件很窄

官方文档明确：**只有返回非 2XX 状态码时才会尝试下一个 endpoint**。连接超时 / DNS 失败 / TLS 失败都**不会**自动落到下一个源。

而「GitHub 不可达」在网络层通常表现为超时或连接重置，不是 4xx/5xx —— 所以**不能把兜底寄托在 `endpoints` 数组上**。

正解：在 Rust 侧按顺序逐个尝试，每次用单 endpoint 构造 updater 并设短超时（5~8s），捕获错误后再试下一个（见 6.3.3）。

#### 6.3.3 建议的检查顺序

```
1) 本地自定义源（若用户配置）—— 单次尝试，timeout 5s
2) 默认 GitHub 源 —— 单次尝试，timeout 8s
3) 若引擎正在运行且 GitHub 分组已启用 —— 带 proxy 再试一次
4) 全部失败 → 静默 + 「关于」页展示「手动下载」入口
```

所有 endpoint 必须是 **HTTPS**（release 构建下非 https 会直接报 `InsecureTransportProtocol`）。

### 6.4 版本号一致性

仓库历史上出现过 workspace 版本与 `tauri.conf.json` 不一致（见 `src-tauri/Cargo.toml` 顶部注释）。一旦不一致，客户端会**反复提示同一个更新**或**永远检测不到更新**。→ 必须由 CI 强校验（见 5.2）。

### 6.5 macOS 签名

当前 workflow 的 Apple 签名 secrets 全部被注释，产物是未签名 dmg。已核实的结论：

| 事实 | 依据 |
|---|---|
| 在 Apple Silicon 上，从互联网下载的应用**必须**有代码签名，否则系统提示「已损坏」 | 官方 macOS 签名文档 |
| Ad-hoc 签名只能消除「已损坏」提示，**仍会被 Gatekeeper 拦截**，用户需去「隐私与安全性」手动放行 | 同上 |
| 使用 **Developer ID Application** 证书分发时，**公证（notarization）是必需的** | 同上 |
| Tauri 更新包（`.app.tar.gz`）的 **minisign 签名是强制的、不可关闭**；这与 Apple 代码签名是两套独立机制 | 更新器文档 |

结论：**要做 macOS 自动更新，$99/年的 Apple Developer 账号是硬性前置**。签名+公证就绪前，macOS 端降级为「提示有新版本 + 打开 Release 页面手动下载」，不启用自动安装。

具体 secret 清单与 workflow 写法见 **附录 B**。

> 另注：本项目 macOS 的 hosts 模式依赖 `osascript` 提权（特权 helper 方案仍为「待实施」，见 [macos-privilege-plan.md](file:///d:/Project/Watt-Toolkit-Tauri/doc/macos-privilege-plan.md)）。这**不影响**更新流程，但更新后首次启动仍会弹一次系统密码框，属预期行为。

### 6.6 Linux 分发格式

更新器源码中已能识别三种 Linux 安装类型（`appimage` / `deb` / `rpm`），但不同插件版本的**实际替换行为**不一致，且 deb 更新需要 root 权限写 `/usr`。

当前 Linux 同时产出 deb 与 AppImage，因此：
- 运行在 AppImage 中 → 启用自动更新（最稳）；
- 运行在 deb 安装环境 → 默认隐藏「立即更新」，只给下载链接，待真机实测确认可行后再放开。

判定方式：检查 `APPIMAGE` 环境变量是否存在。

### 6.7 多矩阵 latest.json 覆盖

见 5.2 第 4 条。这是最容易在上线后才暴露的问题（Windows 用户能更新、macOS 用户永远没反应）。

---

## 7. 分阶段实施计划

### M1 签名与产物（CI 打通）

| 任务 | 产出 |
|---|---|
| 生成 minisign 密钥对并备份 | 私钥 + 公钥 |
| `tauri.conf.json` 配 `pubkey` / `endpoints` / `createUpdaterArtifacts` | 配置 |
| Secrets 配置签名变量 | CI 可签名 |
| 版本一致性校验 job | CI 门禁 |
| 发布测试 tag（如 v0.5.3-rc1） | 验证产物：`*.sig` + `latest.json` 五项齐全 |

**验收**：手动下载 `latest.json`，`platforms` 五个 key 齐全，`signature` 非空。

### M2 后端接入

| 任务 | 产出 |
|---|---|
| 引入 `tauri-plugin-updater`（Rust + npm） | 依赖 |
| `lib.rs` 注册插件、capability 加权限 | 可调用 |
| `ProxyEngine` 暴露「确保已停」的幂等入口（若现有 `engine_stop` 已幂等则复用） | 后端 |

**验收**：dev 下前端 `check()` 返回明确错误（dev 不支持），release 构建下能拿到更新信息。

### M3 前端更新 UI（核心体验）

| 任务 | 产出 |
|---|---|
| `stores/update.ts` 状态机 | 逻辑 |
| `UpdateModal.vue` + `UpdateBanner.vue` | UI |
| `AppHeader.vue` 红点、`AboutPage.vue` 检查按钮 | 入口 |
| 5 语言 i18n | 文案 |

**验收**：本地把 `latest.json` 指向测试版本，弹窗能展示说明与进度条（可用 mock server）。

### M4 健壮性（本项目的重点）

| 任务 | 产出 |
|---|---|
| 更新前强制停引擎（6.1） | 防黑洞 |
| 检查失败静默 + 手动下载兜底（6.3） | 弱网友好 |
| 更新源可配置 + `update_check` 命令 | 镜像能力 |
| 「跳过此版本」「稍后」 | 体验 |
| Linux deb 判定降级（6.6） | 平台适配 |

**验收**：断网、hosts 模式运行中、引擎加速中三种场景下分别执行更新，均无残留、无黑洞。

### M5 真机验收与发布

| 任务 | 产出 |
|---|---|
| Windows x64 / arm64 全流程真机验收 | 报告 |
| macOS 签名（若具备条件） | 打通 |
| 灰度发布 1~2 个版本观察 | 稳定 |

**验收**：DoD（1.3）全部满足。

---

## 8. 测试方案

### 8.1 单元测试（Rust）

- 版本比较：`0.5.2 < 0.5.10 < 0.6.0`（语义化，不能按字符串比）。
- 跳过版本逻辑：`skipped = 0.5.3` 时，`0.5.3` 不提示、`0.5.4` 仍提示。
- endpoint 解析：非法 URL 返回错误而非 panic。
- 检查间隔计算：上次检查距今不足间隔时不请求。

### 8.2 集成测试（mock 更新源）

本地起一个 HTTP 服务返回构造好的 `latest.json`，用 `update_check(endpoint = localhost)` 验证：
- 有更新 / 无更新 / 版本更低 / 签名缺失四种响应的处理分支。

### 8.3 端到端真机

| 用例 | 步骤 | 期望 |
|---|---|---|
| 正常更新 | 0.5.2 检测到 0.5.3 → 下载 → 安装 → 重启 | 版本 0.5.3，配置保留 |
| 加速中更新 | 先启动 hosts 模式加速，再更新 | 无 hosts 残留、无死代理 |
| 断网检查 | 禁用网卡触发检查 | 静默失败，「关于」页可重试 |
| 签名篡改 | 手工改 latest.json 的 signature | 拒绝安装并提示 |
| 跳过版本 | 跳过 0.5.3 后重启 | 不再提示；0.5.4 发布后提示 |
| 重复检查 | 连续点 5 次「检查更新」 | 无并发请求、无状态错乱 |

---

## 9. 回滚与灰度

- **回滚**：updater 不支持降级，只能发布更高的补丁版本修复。因此在 Release 说明中始终保留上一版本安装包链接，作为紧急手动回滚通道。
- **灰度**：先把 `latest.json` 只发到 prerelease 通道（`include_prerelease` 开关），内部验证 1~2 天后再转为正式 Release。注意 `releases/latest` 只指向**非 prerelease** 的最新版，因此灰度版需要单独 endpoint（`releases/tags/v0.5.3-rc1`）。
- **熔断**：若某版本有严重缺陷，可在 GitHub 上删除或改为 draft 该 Release 的 `latest.json`，使新检查失败（已安装的无法回滚，只能靠新版本修复）。

---

## 10. 待决事项（需产品/负责人拍板）

| # | 问题 | 选项 |
|---|---|---|
| 1 | 是否预置国内更新镜像？ | A. 仅留自定义输入框（安全，需用户自行配置）<br>B. 预置 1~2 个公共 GitHub 加速镜像（开箱可用，但依赖第三方可用性与信任） |
| 2 | 是否启用预发布通道？ | A. 不启用，只更正式版<br>B. 设置里提供「接收测试版」开关 |
| 3 | macOS 是否采购 Apple 开发者账号？ | 影响 macOS 能否自动更新（6.5） |
| 4 | 下载完成后自动安装还是等用户点「重启」？ | A. 自动（更接近 cc-switch，但可能打断工作）<br>B. 用户确认（更稳妥） |
| 5 | 自动检查默认间隔 | 24 小时 / 每次启动都查（启动查更及时但更耗流量） |

---

## 11. 依赖与前置条件

- 拥有发布仓库 `QiaTia/Watt-Toolkit-Tauri` 的 Secrets 写权限。
- 密钥对一旦生成**不可更换**（更换需发布一个过渡版本内置双公钥），需立即异地备份。
- macOS 自动更新依赖 Apple 签名（可选但强烈建议）。
- 需要一个稳定可写的 `CHANGELOG.md` 流程，否则更新弹窗无内容。

---

## 附录 A：一句话总结给决策者

用官方 `tauri-plugin-updater` + GitHub Releases 的 `latest.json`，CI 加签名与版本校验，前端做一个带进度的更新弹窗，即可达到 cc-switch 级别的更新体验；本项目真正的难点不在更新本身，而在**更新前必须把加速引擎的 hosts / 系统代理完整还原**，否则会把「更新成功」变成「用户断网」。

---

## 附录 B：macOS 签名配置清单（已核实）

### B.1 前置条件

| 项 | 要求 |
|---|---|
| Apple Developer Program | **$99/年**，个人或公司账号 |
| 证书类型 | **Developer ID Application**（用于 App Store 外分发；不是 Apple Development） |
| 公证 | 使用 Developer ID 证书分发时**必须**公证 |
| 构建机 | 需 macOS（GitHub Actions 的 `macos-latest` 即可） |

### B.2 生成凭据

1. 在 [developer.apple.com](https://developer.apple.com/account/resources/certificates) 创建 **Developer ID Application** 证书，导出为 `.p12` 并设密码。
2. 取 Team ID（Membership 页）。
3. 在 [appleid.apple.com](https://appleid.apple.com) 生成**App 专用密码**（用于公证）。
4. 导出 base64：

```bash
base64 -i Certificate.p12 -o certificate-base64.txt
```

5. 查签名身份字符串（需在装有该证书的 macOS 上）：

```bash
security find-identity -v -p codesigning
# 输出形如：Developer ID Application: Your Name (TEAMID)
```

### B.3 GitHub Secrets 清单

| Secret | 值 |
|---|---|
| `APPLE_CERTIFICATE` | `certificate-base64.txt` 全文 |
| `APPLE_CERTIFICATE_PASSWORD` | 导出 `.p12` 时设的密码 |
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: Your Name (TEAMID)` |
| `KEYCHAIN_PASSWORD` | 任意随机串（CI 临时钥匙串密码，无需与 Apple 相关） |
| `APPLE_ID` | Apple 账号邮箱 |
| `APPLE_PASSWORD` | **App 专用密码**（不是登录密码） |
| `APPLE_TEAM_ID` | Team ID |

> 也可改用 App Store Connect API Key（`APPLE_API_ISSUER` / `APPLE_API_KEY` / `APPLE_API_KEY_PATH`，后者须为**绝对路径**）。两种方式二选一。

### B.4 workflow 片段

```yaml
  - name: 构建（macOS）
    if: matrix.platform == 'macos-latest'
    uses: tauri-apps/tauri-action@v0
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
      TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
      APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}
      APPLE_CERTIFICATE_PASSWORD: ${{ secrets.APPLE_CERTIFICATE_PASSWORD }}
      APPLE_SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
      KEYCHAIN_PASSWORD: ${{ secrets.KEYCHAIN_PASSWORD }}
      APPLE_ID: ${{ secrets.APPLE_ID }}
      APPLE_PASSWORD: ${{ secrets.APPLE_PASSWORD }}
      APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
```

验收方式：

```bash
codesign -dv --verbose=4 "Watt Toolkit.app"     # Authority 应为 Developer ID Application
spctl -a -vv "Watt Toolkit.app"                 # 应输出 accepted，source=Notarized Developer ID
```

### B.5 若不签名的降级方案

- 仅可用于**内部测试**，或 macOS 端只提供「手动下载 dmg」。
- Ad-hoc 签名（`signingIdentity: "-"`）能让应用不再提示「已损坏」，但用户仍需逐次在「隐私与安全性」中放行，且**无法自动更新**，不建议面向用户发布。

---

## 附录 C：国内镜像配置清单（已核实）

### C.1 为什么不能直接填 `ghproxy` 前缀

`latest.json` 里 `platforms.*.url` 是**绝对地址**，脚本会自动请求该地址下载安装包。通用加速前缀只能代理 `latest.json` 本身，**不会改写 JSON 内部的 URL**，因此下载阶段仍会直连 github.com 而失败。

### C.2 推荐做法：自建 manifest（方案 A）

CI 在 `tauri-action` 之后追加一步，拉取 Release 的 `latest.json`，把所有 `url` 前缀替换为镜像域名，再上传到自有存储（R2 / OSS / CDN）。签名字段 `.sig` **原样保留，不可改动**。

```jsonc
// 发布到镜像的 latest.json（仅 url 前缀变化）
{
  "version": "0.5.3",
  "platforms": {
    "windows-x86_64": {
      "signature": "（原样保留）",
      "url": "https://cdn.example.com/watt/0.5.3/Watt%20Toolkit_0.5.3_x64-setup.exe"
    }
  }
}
```

客户端把「更新源」指向镜像的 `latest.json` 即可。

### C.3 方案 B：边缘函数重写

Cloudflare Worker 伪代码：

```js
export default {
  async fetch(req) {
    const upstream = await fetch('https://github.com/QiaTia/Watt-Toolkit-Tauri/releases/latest/download/latest.json');
    const json = await upstream.json();
    for (const p of Object.values(json.platforms)) {
      p.url = p.url.replace('https://github.com/', 'https://ghfast.top/https://github.com/');
    }
    return new Response(JSON.stringify(json), {
      headers: { 'content-type': 'application/json', 'cache-control': 'max-age=300' },
    });
  },
};
```

> 注意：Worker 自身域名必须可达；不建议在客户端代码里硬编码第三方加速站的品牌。

### C.4 方案 C：借本项目引擎的代理

```rust
let mut builder = app.updater_builder().timeout(Duration::from_secs(8));
if engine_running && github_group_enabled {
    builder = builder.proxy("http://127.0.0.1:26501".parse()?);
}
let updater = builder.build()?;
```

仅当引擎在运行且 GitHub 加速分组已启用时有效，作为**自动增强**而非唯一路径。注意：`proxy()` 与 `no_proxy()` 仅在 Rust 侧可用，需通过自定义命令调用。

### C.5 配置项契约（写入设置页文案）

- 「更新源」必须是 **HTTPS** 的 `latest.json` 地址；
- 填第三方加速前缀**不生效**（见 C.1），设置页需明确提示；
- 留空 = 使用官方 GitHub 源。

### C.6 端到端冒烟

```bash
curl -s https://<mirror>/latest.json | jq '.platforms["windows-x86_64"].url'
# 期望：输出镜像域名，而不是 github.com
```
