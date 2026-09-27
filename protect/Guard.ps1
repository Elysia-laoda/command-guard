# Guard.ps1 —— 唯一的前门。改 guard.json，然后跑这里，不用再分别记四个脚本。
#
#   .\protect\Guard.ps1 status                 # 体检：两层各自到位了吗
#   .\protect\Guard.ps1 install                # 干跑：打印将要做什么
#   .\protect\Guard.ps1 install -Apply         # 真装
#   .\protect\Guard.ps1 remove  -Apply         # 全撤
#
# 它只读 guard.json（项目根），里面每个 root 两项设置：
#   depth  0=只护根本身 / 1=根+第一层 / n=往下 n 层 / -1=整棵子树
#   level  sentinel=绊线（目录不会被整棵删掉，内部照常干活）｜tree=锁死｜archive=锁死+拒写
#
# 引擎（src/cli.mjs）也读同一份文件里的 depth —— 两层共用一个数字。

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'install', 'remove')]
    [string]$Action = 'status',

    [string]$Config = (Join-Path (Split-Path -Parent $PSScriptRoot) 'guard.json'),

    # 默认干跑：安装会改权限、建目录，必须显式加 -Apply
    [switch]$Apply
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


$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$sentinelName = if ($cfg.sentinelName) { [string]$cfg.sentinelName } else { '!000-guard' }
$sentinelTool = Join-Path $here 'GuardSentinel.ps1'
$protectTool = Join-Path $here 'Protect-Path.ps1'
$unprotectTool = Join-Path $here 'Unprotect-Path.ps1'
$cli = Join-Path (Split-Path -Parent $here) 'src\cli.mjs'

if (-not (Test-Path -LiteralPath $Config)) { throw "找不到配置文件：$Config" }
$cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$roots = @($cfg.roots)
if ($roots.Count -eq 0) { Write-Output "guard.json 里没有 roots，什么都不做。"; exit 0 }

# ---------------------------------------------------------------- 目标集合
function Get-Targets($root) {
    $depth = if ($null -eq $root.depth) { 1 } else { [int]$root.depth }
    $level = if ($root.level) { $root.level } else { 'sentinel' }
    $exclude = @()
    if ($root.exclude) { $exclude = @($root.exclude) }
    if (-not (Test-Path -LiteralPath $root.path)) { return @() }

    if ($level -ne 'sentinel') {
        # 树保护靠继承覆盖整棵子树，只需要保护根本身
        return @($root.path)
    }
    if ($depth -eq 0) { return @($root.path) }
    if ($depth -lt 0) { $depth = [int]::MaxValue }

    $out = @($root.path)
    $level_dirs = @($root.path)
    for ($i = 1; $i -le $depth; $i++) {
        $next = @()
        foreach ($d in $level_dirs) {
            $next += @(Get-ChildItem -LiteralPath $d -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $exclude -notcontains $_.Name -and
                    $_.Name -ne $sentinelName -and
                    (-not $_.Name.StartsWith('.')) -and
                    (-not ($_.Attributes -band [IO.FileAttributes]::Hidden)) -and
                    (-not ($_.Attributes -band [IO.FileAttributes]::System))
                })
        }
        if ($next.Count -eq 0) { break }
        $out += $next.FullName
        $level_dirs = $next.FullName
    }
    return $out
}

# ---------------------------------------------------------------- 体检
function Get-SentinelState($dir, $name) {
    $s = Join-Path $dir $name
    if (-not (Test-Path -LiteralPath $s)) { return 'missing' }
    $a = Get-Acl -LiteralPath $s
    $hasOwn = @($a.Access | Where-Object {
            $_.AccessControlType -eq 'Deny' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Delete) -ne 0
        }).Count -gt 0
    $pa = Get-Acl -LiteralPath $dir
    $hasParent = @($pa.Access | Where-Object {
            $_.AccessControlType -eq 'Deny' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -ne 0
        }).Count -gt 0
    if ($hasOwn -and $hasParent) { return 'ok' }
    if ($hasOwn) { return 'own-only' }   # 只关了第一条路
    return 'unprotected'
}

function Get-TreeState($dir, $denyWrite) {
    if (-not (Test-Path -LiteralPath $dir)) { return 'missing' }
    $a = Get-Acl -LiteralPath $dir
    $want = [System.Security.AccessControl.FileSystemRights]::Delete -bor `
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    if ($denyWrite) { $want = $want -bor [System.Security.AccessControl.FileSystemRights]::WriteData }
    $deny = @($a.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
    if ($deny.Count -eq 0) { return 'unprotected' }
    if (($deny[0].FileSystemRights -band $want) -eq $want) { return 'ok' }
    return 'partial'
}

function Invoke-Status {
    $problems = 0
    Write-Output ("配置：" + $Config)
    Write-Output ""
    foreach ($r in $roots) {
        $level = if ($r.level) { $r.level } else { 'sentinel' }
        $depth = if ($null -eq $r.depth) { 1 } else { [int]$r.depth }
        Write-Output ("■ " + $r.path + "   level=" + $level + "  depth=" + $depth)

        if (-not (Test-Path -LiteralPath $r.path)) {
            Write-Output "    路径不存在，跳过"; $problems++; Write-Output ""; continue
        }

        $targets = @(Get-Targets $r)
        Write-Output ("    目标目录 " + $targets.Count + " 个")
        foreach ($t in $targets) {
            if ($level -eq 'sentinel') {
                $st = Get-SentinelState $t $sentinelName
                $mark = if ($st -eq 'ok') { 'OK  ' } else { 'FAIL' }
                if ($st -ne 'ok') { $problems++ }
                Write-Output ("      " + $mark + "  " + $t + "   -> " + $st)
            }
            else {
                $st = Get-TreeState $t ($level -eq 'archive')
                $mark = if ($st -eq 'ok') { 'OK  ' } else { 'FAIL' }
                if ($st -ne 'ok') { $problems++ }
                Write-Output ("      " + $mark + "  " + $t + "   -> " + $st)
            }
        }

        # 引擎那一层：拿根做一次实际判定，看两层是不是一致
        $probe = "Remove-Item '" + $r.path + "' -Recurse -Force"
        $engineOut = ($probe | & node $cli check --raw 2>$null | Out-String)
        $verdict = 'unknown'
        try { $verdict = (($engineOut | ConvertFrom-Json).verdict) } catch { }
        Write-Output ("    引擎判定：对 '" + $r.path + "' 递归删除 -> " + $verdict)
        if ($verdict -ne 'block') { $problems++ }
        Write-Output ""
    }
    Write-Output ("体检结论：问题 " + $problems + " 处" + $(if ($problems -eq 0) { "（两层都到位）" } else { "" }))
    $script:rc = $problems
}

function Invoke-Install {
    $changed = 0
    foreach ($r in $roots) {
        $level = if ($r.level) { $r.level } else { 'sentinel' }
        if (-not (Test-Path -LiteralPath $r.path)) { Write-Output ("跳过（不存在）：" + $r.path); continue }
        $targets = @(Get-Targets $r)
        Write-Output ("■ " + $r.path + "   level=" + $level + "  目标 " + $targets.Count + " 个")
        foreach ($t in $targets) {
            if ($level -eq 'sentinel') {
                if (-not $Apply) { Write-Output ("    [干跑] GuardSentinel -Action Install -Path '" + $t + "'"); continue }
                & $sentinelTool -Path $t -Action Install -Name $sentinelName | ForEach-Object { Write-Output ("    " + $_) }
                $changed++
            }
            else {
                $dw = if ($level -eq 'archive') { ' -DenyWrite' } else { '' }
                if (-not $Apply) { Write-Output ("    [干跑] Protect-Path -Path '" + $t + "'" + $dw); continue }
                if ($level -eq 'archive') { & $protectTool -Path $t -DenyWrite | ForEach-Object { Write-Output ("    " + $_) } }
                else { & $protectTool -Path $t | ForEach-Object { Write-Output ("    " + $_) } }
                $changed++
            }
        }
        Write-Output ""
    }
    if ($Apply) { Write-Output ("已处理 " + $changed + " 个目标。跑一次 status 确认。") }
    else { Write-Output "干跑结束，未改动任何权限。加 -Apply 才落盘。" }
}

function Invoke-Remove {
    $n = 0
    foreach ($r in $roots) {
        $level = if ($r.level) { $r.level } else { 'sentinel' }
        if (-not (Test-Path -LiteralPath $r.path)) { continue }
        $targets = @(Get-Targets $r)
        # 从最深层往回撤，避免先撤掉外层后内层路径失效
        [array]::Reverse($targets)
        foreach ($t in $targets) {
            if ($level -eq 'sentinel') {
                if (-not $Apply) { Write-Output ("    [干跑] GuardSentinel -Action Remove -Path '" + $t + "'"); continue }
                & $sentinelTool -Path $t -Action Remove -Name $sentinelName | ForEach-Object { Write-Output ("    " + $_) }
                $n++
            }
            else {
                if (-not $Apply) { Write-Output ("    [干跑] Unprotect-Path -Path '" + $t + "'"); continue }
                & $unprotectTool -Path $t | ForEach-Object { Write-Output ("    " + $_) }
                $n++
            }
        }
    }
    if ($Apply) { Write-Output ("已解除 " + $n + " 个目标。") }
    else { Write-Output "干跑结束，未改动任何权限。加 -Apply 才落盘。" }
}

switch ($Action) {
    'status' { $script:rc = 0; Invoke-Status; exit $script:rc }
    'install' { Invoke-Install }
    'remove' { Invoke-Remove }
}
