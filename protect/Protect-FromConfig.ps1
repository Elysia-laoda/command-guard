# Protect-FromConfig —— ACL 这条线的"力度旋钮"：改 protected.json 里的 lock 列表即可。
#
# 为什么是列表而不是层数：命令护栏（src/policy.mjs）检查的是"命令的目标"，所以它能精确
# 到第几层；ACL 检查的是操作系统的删除动作，没有层数可调 —— 非继承的拒绝规则只会留下
# 空壳（内容照样被清空）。实测见 Test-Protection.ps1 第 7 节。
#
# 默认什么都不锁：lock 为空是安全默认值。

[CmdletBinding()]
param(
    [string]$Config = (Join-Path $PSScriptRoot 'protected.json'),
    [switch]$Unprotect,
    [switch]$WhatIf
)
#psr7-selfroute-begin
# This script has to run under PowerShell 7. Launched by Windows PowerShell 5.1, it restarts
# itself in pwsh with the same arguments. That covers the callers a PATH shim cannot reach: a
# hardcoded System32 path, someone else's scheduled task, another program, a double-click in a
# guest. If pwsh is not installed the script simply continues on 5.1.
if ($PSVersionTable.PSEdition -ne 'Core') {
    $__psr7 = 'C:\Program Files\PowerShell\7\pwsh.exe'
    if (-not (Test-Path -LiteralPath $__psr7)) { $__psr7 = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pwsh.exe' }
    if (Test-Path -LiteralPath $__psr7) {
        $__psrArg = @()
        $__psrFound = $false
        $__psrCmd = [Environment]::GetCommandLineArgs()
        for ($__psrI = 1; $__psrI -lt $__psrCmd.Count; $__psrI++) {
            $__psrHit = $false
            try { $__psrHit = ([IO.Path]::GetFullPath($__psrCmd[$__psrI].Replace('/', '\')) -ieq [IO.Path]::GetFullPath($PSCommandPath)) } catch { }
            if ($__psrHit) {
                $__psrFound = $true
                if ($__psrI + 1 -lt $__psrCmd.Count) { $__psrArg = $__psrCmd[($__psrI + 1)..($__psrCmd.Count - 1)] }
                break
            }
        }
        # Redirect only when the caller's own invocation can be rebuilt faithfully. Reached through
        # -Command ("& 'x.ps1' -Tag y") the path never appears as an argument of its own, and
        # restarting with no arguments would silently drop them -- worse than staying on 5.1.
        if ($__psrFound) {
            & $__psr7 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @__psrArg
            exit $LASTEXITCODE
        }
    }
}
#psr7-selfroute-end


$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Config)) {
    throw "找不到配置文件：$Config"
}

$data = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
# ConvertTo-Json 会把单元素数组退化成标量，读回来也要按同样方式兼容
$targets = @()
if ($data.lock) { $targets = @($data.lock) }

if ($targets.Count -eq 0) {
    Write-Output "protected.json 的 lock 列表为空 —— 什么都不做（这是安全默认值）。"
    exit 0
}

$script = if ($Unprotect) { 'Unprotect-Path.ps1' } else { 'Protect-Path.ps1' }
$tool = Join-Path $PSScriptRoot $script
$failed = 0

foreach ($entry in $targets) {
    # 条目可以是字符串，也可以是 { "path": "...", "denyWrite": true }
    $t = if ($entry -is [string]) { $entry } else { $entry.path }
    $denyWrite = $false
    if ($entry -isnot [string]) { $denyWrite = [bool]$entry.denyWrite }

    if ([string]::IsNullOrWhiteSpace($t)) { continue }
    if (-not (Test-Path -LiteralPath $t)) {
        Write-Output "跳过（路径不存在）：$t"
        $failed += 1
        continue
    }
    $suffix = if ($denyWrite) { ' -DenyWrite' } else { '' }
    if ($WhatIf) {
        Write-Output ("将执行：" + $script + " -Path '" + $t + "'" + $suffix)
        continue
    }
    if ($Unprotect -or -not $denyWrite) { & $tool -Path $t }
    else { & $tool -Path $t -DenyWrite }
}

if ($WhatIf) { Write-Output "（干跑，未改动任何权限）" }
elseif ($failed -gt 0) { Write-Output "完成，但有 $failed 个条目因路径不存在被跳过。" }
else { Write-Output "完成。" }
