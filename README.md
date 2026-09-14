# Watt Toolkit

Watt Toolkit 是一个基于 Tauri 2 + Rust + Vue 3 的桌面端网络加速工具，目标是为 Windows / macOS / Linux 平台提供轻量、可扩展的代理与网络管理能力。

本仓库为重构后的 Tauri 版本，前端位于 `ui/`，后端/应用壳位于 `src-tauri/`，核心能力实现位于 `crates/`。

## 目录结构

- `ui/`：Vue 3 + Vite 前端界面
- `src-tauri/`：Tauri 应用壳与原生集成
- `crates/`：Rust 业务模块（核心代理、证书、DNS、Hosts、配置、云端能力等）
- `doc/`：设计文档、迁移说明与实施记录

## 技术栈

- Tauri 2
- Rust 2021
- Vue 3 + TypeScript
- Vite
- pnpm

## 运行要求

- Node.js 20+ / 22+
- pnpm 9+
- Rust stable
- 以及 Tauri 2 所需的系统依赖

Windows 需要额外确认以下环境：

- MSVC / Visual Studio Build Tools
- Windows SDK

Linux 可能还需要安装：

- `libwebkit2gtk-4.1-dev`
- `libgtk-3-dev`
- `libayatana-appindicator3-dev`
- `librsvg2-dev`
- `patchelf`

macOS 需要：

- Xcode Command Line Tools

## 本地开发

在仓库根目录执行：

```bash
# 安装前端依赖
pnpm install --dir ui

# 运行 Tauri 开发模式（会自动启动前端 dev server）
cargo tauri dev
```

如果你希望单独启动前端：

```bash
pnpm --dir ui dev
```

## 生产构建

在项目根目录执行：

```bash
# 1) 安装前端依赖
pnpm install --dir ui

# 2) 构建前端
pnpm --dir ui build

# 3) 构建 Tauri 桌面应用
cargo tauri build
```

如果是 Tauri CLI 直接构建，也可以使用：

```bash
cd src-tauri
cargo tauri build
```

## 发行构建

仓库中已提供 GitHub Actions 发布工作流：

- [.github/workflows/release.yml](.github/workflows/release.yml)

该工作流会在推送 `v*` tag 或手动触发时执行，自动构建：

- Windows x86_64 / arm64
- macOS x86_64 / aarch64
- Linux `deb` / `AppImage`

发布时使用的 tag 语义为：

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 备注

- 本仓库前端使用 `pnpm`，不是 npm；CI 中也应使用 `pnpm install --dir ui --frozen-lockfile`。
- Tauri 配置中 `beforeDevCommand` 与 `beforeBuildCommand` 已按当前仓库路径设定为 `pnpm --dir ../ui dev` 和 `pnpm --dir ../ui build`。
- 发布脚本中的项目名已从原来其他项目的命名改为当前仓库的 `Watt Toolkit`。

##
参考项目:
[https://github.com/WattToolkit/WattToolkit](https://github.com/WattToolkit/WattToolkit)
## 许可证

本项目采用 GPL-3.0 许可证，详情见 [LICENSE](LICENSE)。
