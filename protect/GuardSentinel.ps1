# GuardSentinel —— 在目录里放一个"绊线哨兵"：一个被 ACL 保护的空目录，排在走查第一位。
#
# 原理（见 README）：删除是逐项顺序走的；撞上一个删不掉的项时，只要错误偏好是 Stop，
# 整条递归就会被打断。所以第一个位置放一个删不掉的空目录 = 断路器。
#
#   Install  建哨兵 + 上保护 + 验证（在同名合成树上做真实删除，绝不在你的真目录上试）
#   Test     体检：哨兵还在吗、还带保护吗、名字还排第一吗
#   Remove   解除保护并删掉哨兵（要删受保护的根之前，必须先做这一步）
#
# 硬前提：删除命令必须带 -ErrorAction Stop（或调用方用 Remove-Item.shim.ps1，它会自动补）。

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [ValidateSet('Install', 'Test', 'Remove')]
    [string]$Action = 'Install',

    # 名字必须排在同级第一位才有效。用 '!'（0x21）打头 —— 它是可打印 ASCII 里最小的，
    # 比 '.'（0x2E；任何 git 仓库都有 .git）和 '0'（0x30）都靠前。
    [string]$Name = '!000-guard'
)
# 身份从当前 Windows 身份取，不用 $env:USERDOMAIN/$env:USERNAME —— 远程会话里那两个是空的，
# 拼出来的身份无法解析，AddAccessRule 会抛 "identity references could not be translated"（实测踩到过）。
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
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
$scriptDir = $PSScriptRoot

if (-not (Test-Path -LiteralPath $Path)) { throw "路径不存在：$Path" }
$target = (Get-Item -LiteralPath $Path -Force).FullName
$sentinel = Join-Path $target $Name

# ---------------------------------------------------------------- 排序验证
# 在同名的合成树上做一次真实删除：这是唯一能证明"它确实排在第一位"的办法。
# 绝不拿真目录做这个实验。
function Test-SentinelOrdering {
    param([string]$Parent, [string]$SentinelName)

    $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ("gsp-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        New-Item -ItemType Directory -Path (Join-Path $probeRoot $SentinelName) -Force | Out-Null
        $siblings = @(Get-ChildItem -LiteralPath $Parent -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne $SentinelName })
        foreach ($s in $siblings) {
            if ($s.PSIsContainer) {
                $sub = Join-Path $probeRoot $s.Name
                New-Item -ItemType Directory -Path $sub -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $sub 'file.txt') -Value 'x'
            }
        }
        $before = @(Get-ChildItem -LiteralPath $probeRoot -Recurse -File -Force -ErrorAction SilentlyContinue).Count

        # 给探针树里的哨兵上保护 —— 必须与 Install 装出来的配置一致，否则验的不是真实状态。
        # 两条路都要关：①哨兵自己的 DELETE ②探针父目录的 DeleteSubdirectoriesAndFiles。
        $sp = Join-Path $probeRoot $SentinelName
        $aclP = Get-Acl -LiteralPath $sp
        $ruleP = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me,
            [System.Security.AccessControl.FileSystemRights]::Delete,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny)
        $aclP.AddAccessRule($ruleP)
        Set-Acl -LiteralPath $sp -AclObject $aclP

        $pr = Get-Acl -LiteralPath $probeRoot
        $rulePr = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me,
            [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny)
        $pr.AddAccessRule($rulePr)
        Set-Acl -LiteralPath $probeRoot -AclObject $pr

        $threw = $false
        try { Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction Stop } catch { $threw = $true }
        $after = @(Get-ChildItem -LiteralPath $probeRoot -Recurse -File -Force -ErrorAction SilentlyContinue).Count

        return [pscustomobject]@{
            Siblings   = $siblings.Count
            Threw      = $threw
            Loss       = $before - $after
            First      = ($threw -and ($before - $after) -eq 0)
        }
    }
    finally {
        # 探针树自带保护，必须先解锁再删
        $sp = Join-Path $probeRoot $SentinelName
        if (Test-Path -LiteralPath $sp) {
            $a = Get-Acl -LiteralPath $sp
            foreach ($r in @($a.Access)) { if ($r.AccessControlType -eq 'Deny') { $a.RemoveAccessRuleSpecific($r) | Out-Null } }
            Set-Acl -LiteralPath $sp -AclObject $a
        }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- Install
function Install-Sentinel {
    if (-not (Test-Path -LiteralPath $sentinel)) {
        New-Item -ItemType Directory -Path $sentinel -Force | Out-Null
        Write-Output "已建哨兵目录：$sentinel"
    }
    else {
        Write-Output "哨兵目录已存在：$sentinel"
    }

    # 哨兵自己：拒删除（用与 Protect-Path 相同的一套权限，别再手搓 ACE）
    & (Join-Path $scriptDir 'Protect-Path.ps1') -Path $sentinel | Out-Null
    Write-Output "已给哨兵上保护（拒绝删除）"

    # 关键补充：要删一个子项，Windows 认两条路 —— ①子项自己的 DELETE ②父目录的
    # DeleteSubdirectoriesAndFiles（FILE_DELETE_CHILD）。对象上的 Deny 只关掉①。
    # 实测：在父目录授予②的位置（例如 %TEMP%），只关①的空哨兵会被从父目录那条路删掉。
    # 所以这里把②也关掉 —— 只关这一条，不影响别的：普通子项靠自己的 DELETE 照样能删。
    $parent = Split-Path -Parent $sentinel
    $dsf = [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $pacl = Get-Acl -LiteralPath $parent
    $already = @($pacl.Access | Where-Object {
            $_.AccessControlType -eq 'Deny' -and
            $_.IdentityReference.Value -eq $me -and
            ($_.FileSystemRights -band $dsf) -ne 0
        }).Count -gt 0
    if (-not $already) {
        $prule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $me, $dsf,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny)
        $pacl.AddAccessRule($prule)
        Set-Acl -LiteralPath $parent -AclObject $pacl
        Write-Output "已在父目录上加一条拒绝规则，关掉『从父目录删子项』这条路：$parent"
    }
    else {
        Write-Output "父目录上已有同样的拒绝规则：$parent"
    }

    Write-Output ""
    Write-Output ("排序验证：拿同级 " + (@(Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue).Count - 1) + " 个条目的名字，在一棵合成树上做一次真实删除…")
    $r = Test-SentinelOrdering -Parent $target -SentinelName $Name
    if ($r.First) {
        Write-Output ("  PASS —— 损失 0/" + $r.Siblings + "，走查确实先撞上哨兵，整批被截断")
    }
    else {
        # 不只报 FAIL，还要指出是哪个同级名字挡在前面 —— 否则没法修。
        $sib = @(Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $Name })
        $min = $null
        foreach ($s in $sib) {
            if ($null -eq $min -or [string]::Compare($s.Name, $min, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { $min = $s.Name }
        }
        Write-Output ("  FAIL —— 损失 " + $r.Loss + "（抛异常=" + $r.Threw + "）。")
        if ($min) { Write-Output ("  同级里排在最前的是 '" + $min + "'，哨兵名必须比它更靠前。") }
        Write-Output "  换名字重装：先 -Action Remove，再用 -Name 指定一个更靠前的名字。"
    }
    Write-Output ""
    Write-Output "别忘了：删除命令必须带 -ErrorAction Stop，否则哨兵会被跳过（实测：不带 Stop 时损失 = 全部）。"
}

# ---------------------------------------------------------------- Test
function Test-Sentinel {
    $script:rc = 0
    if (-not (Test-Path -LiteralPath $sentinel)) {
        Write-Output "FAIL  哨兵不存在：$sentinel"
        $script:rc = 1
        return
    }
    Write-Output "OK    哨兵存在：$sentinel"

    $acl = Get-Acl -LiteralPath $sentinel
    $has = @($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Deny' -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Delete) -ne 0
        }).Count -gt 0
    if ($has) { Write-Output "OK    哨兵自己带拒绝删除规则" }
    else { Write-Output "FAIL  哨兵自己的拒绝规则丢了 —— 它现在只是个普通空目录"; $script:rc = 1 }

    # 父目录那条路也要关掉，否则在父目录授予 DeleteSubdirectoriesAndFiles 的位置会被绕过
    $parent = Split-Path -Parent $sentinel
    $dsf = [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $pacl = Get-Acl -LiteralPath $parent
    $pHas = @($pacl.Access | Where-Object {
            $_.AccessControlType -eq 'Deny' -and ($_.FileSystemRights -band $dsf) -ne 0
        }).Count -gt 0
    if ($pHas) { Write-Output "OK    父目录上也关了『从父目录删子项』那条路" }
    else { Write-Output "WARN  父目录上没有关那条路 —— 如果它授予了 DeleteSubdirectoriesAndFiles，哨兵会被绕过"; }

    $r = Test-SentinelOrdering -Parent $target -SentinelName $Name
    if ($r.First) { Write-Output ("OK    排序验证通过（损失 0/" + $r.Siblings + "）") }
    else { Write-Output ("FAIL  排序验证失败（损失 " + $r.Loss + "）"); $script:rc = 1 }
}

# ---------------------------------------------------------------- Remove
function Remove-Sentinel {
    if (-not (Test-Path -LiteralPath $sentinel)) { Write-Output "哨兵不存在，无需处理"; return }
    $acl = Get-Acl -LiteralPath $sentinel
    $removed = 0
    foreach ($r in @($acl.Access)) {
        if ($r.AccessControlType -eq 'Deny' -and ($r.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Delete) -ne 0) {
            $acl.RemoveAccessRuleSpecific($r) | Out-Null
            $removed++
        }
    }
    if ($removed -gt 0) { Set-Acl -LiteralPath $sentinel -AclObject $acl }
    Remove-Item -LiteralPath $sentinel -Recurse -Force
    Write-Output ("已解除并删除哨兵（移除 $removed 条拒绝规则）")
}

switch ($Action) {
    'Install' { Install-Sentinel }
    'Test' { $script:rc = 0; Test-Sentinel; exit $script:rc }
    'Remove' { Remove-Sentinel }
}
