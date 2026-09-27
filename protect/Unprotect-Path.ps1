# Unprotect-Path —— 撤掉 Protect-Path 加的"拒绝删除"规则（打破玻璃）。
#
# 只移除"拒绝删除"这一类 ACE，其他权限项原样保留，不动继承关系。

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path
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

if (-not (Test-Path -LiteralPath $Path)) {
    throw "路径不存在：$Path"
}
$target = (Get-Item -LiteralPath $Path -Force).FullName

$acl = Get-Acl -LiteralPath $target
# 覆盖两种模式：只拒删除，以及拒删除 + 拒写（-DenyWrite）
$rights = [System.Security.AccessControl.FileSystemRights]::Delete -bor `
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor `
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
    [System.Security.AccessControl.FileSystemRights]::AppendData

$removed = 0
foreach ($r in @($acl.Access)) {
    if ($r.AccessControlType -ne 'Deny') { continue }
    if (($r.FileSystemRights -band $rights) -eq 0) { continue }
    # 注意：这里会移除所有"拒绝删除/拒绝写"的规则，不限于本工具加的那一条。
    $acl.RemoveAccessRuleSpecific($r) | Out-Null
    $removed += 1
}

if ($removed -eq 0) {
    Write-Output "没有找到 '拒绝删除/写' 规则，无需改动：$target"
    exit 0
}

Set-Acl -LiteralPath $target -AclObject $acl
Write-Output "已解除保护：$target（移除 $removed 条拒绝规则）"
