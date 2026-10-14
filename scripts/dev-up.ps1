#requires -Version 5
<#
.SYNOPSIS
    F5 调试前置任务：确保 vite dev server 就绪 + 构建 debug 二进制。
.DESCRIPTION
    由 .vscode/tasks.json 的 "dev-up" 任务调用（launch.json 的 preLaunchTask）。
    1) 若 5173 端口已有 vite 在服务则跳过，否则以后台进程启动 pnpm --dir ui dev 并等待就绪；
    2) 执行 cargo build -p watt-toolkit-app（错误经 $rustc 问题匹配器汇总到 IDE 问题面板）。
    重复按 F5 不会重复启动 vite（端口已占用检测）；vite 输出重定向到
    $env:TEMP\watt-vite.log，排查启动问题时查看该文件。
.NOTES
    文件必须以 UTF-8 with BOM 保存：Windows PowerShell 5.1 对无 BOM 的 .ps1
    按系统 ANSI 代码页（中文机器为 GBK）解码，中文注释会变乱码导致解析失败。
    vite 用 cmd.exe /c 启动：Start-Process 'pnpm' 会解析到 PATH 中的 pnpm.ps1
    （PowerShell 脚本无法作为进程执行），必须经 cmd 解析到 pnpm.cmd。
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$viteLog = Join-Path $env:TEMP 'watt-vite.log'

function Test-ViteReady {
    try {
        $r = Invoke-WebRequest -Uri 'http://127.0.0.1:5173' -UseBasicParsing -TimeoutSec 2
        return $r.StatusCode -eq 200
    } catch {
        return $false
    }
}

# —— 1) vite dev server ——
if (Test-ViteReady) {
    Write-Host '[dev-up] vite 已在运行（127.0.0.1:5173）'
} else {
    Write-Host '[dev-up] 启动 vite dev server (127.0.0.1:5173) ...'
    Start-Process -FilePath 'cmd.exe' `
        -ArgumentList '/c', "pnpm --dir ui dev --host 127.0.0.1 > `"$viteLog`" 2>&1" `
        -WorkingDirectory $root -WindowStyle Hidden
    $ready = $false
    for ($i = 0; $i -lt 120; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-ViteReady) { $ready = $true; break }
    }
    if (-not $ready) {
        Write-Host "[dev-up] vite 日志（$viteLog）:"
        if (Test-Path $viteLog) { Get-Content $viteLog -Tail 20 }
        Write-Error '[dev-up] vite 60s 内未就绪'
        exit 1
    }
    Write-Host "[dev-up] vite 已就绪（日志: $viteLog）"
}

# —— 2) 构建 debug 二进制 ——
Write-Host '[dev-up] cargo build -p watt-toolkit-app ...'
cargo build -p watt-toolkit-app
if ($LASTEXITCODE -ne 0) {
    Write-Error "[dev-up] cargo build 失败（exit=$LASTEXITCODE）"
    exit $LASTEXITCODE
}
$exe = Join-Path $root 'target\debug\watt-toolkit-app.exe'
if (-not (Test-Path $exe)) {
    Write-Error "[dev-up] 未找到调试二进制: $exe"
    exit 1
}
Write-Host "[dev-up] 构建完成: $exe"
