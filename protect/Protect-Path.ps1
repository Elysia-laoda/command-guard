# Protect-Path —— 在**操作系统层面**禁止删除某棵目录树。
#
# 为什么需要它：命令的作者（甲方）不一定听劝，传送方式（快递方）五花八门。
# ACL 是唯一不依赖这两者的地方 —— 它不关心命令从哪来，只管拒绝。
#
# 做法：给对方一个"拒绝删除"的 ACE（Deny Delete + DeleteSubdirectoriesAndFiles），
# 并让子项继承。树内**仍然可以读、可以改、可以新建**，只是删不掉任何东西。
# 要恢复可删，跑 Unprotect-Path.ps1（这就是"打破玻璃"的那一下）。
#
# 能力边界（必须说清楚）：
#   - 它挡的是"删除"这个动作，不是恶意篡改：对象所有者随时可以改回 ACL。
#   - 对"写 + 重命名覆盖"式的原子保存（临时文件 + 替换）可能一并挡住，见 README 的实测表。

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    # 默认针对当前用户；也可以指定 SID、用户或组名（例如 BUILTIN\Users）。
    # ⚠ 不要用 "$env:USERDOMAIN\$env:USERNAME" 作默认值：**在 WinRM/PSSession 里这两个环境变量是空的**，
    # 拼出来的身份无法解析，AddAccessRule 会抛 "Some or all identity references could not be translated"，
    # 而 ACE 根本没写上 —— 远程部署时踩过。WindowsIdentity::GetCurrent().Name 在远程会话里也可靠。
    [string]$Identity,

    # 只拒删除时，文件内容仍然可以被清空 —— 写只需要 WRITE 位，不需要 DELETE 位（实测）。
    # 加这个开关把写也拒掉，代价是这棵树变成只读，谁都不能在里面工作。
    # 不可再生的归档数据（素材、成品）用这个；还在用的工作目录不要用。
    [switch]$DenyWrite
)
if (-not $Identity) { $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
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

$rights = [System.Security.AccessControl.FileSystemRights]::Delete -bor `
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

if ($DenyWrite) {
    # 拒绝"写数据 / 追加数据"这两个位，足以挡住内容被清空与续写。
    # 用具体位而不是泛型 FileSystemRights::Write，是为了让拒绝的范围在代码里一眼可读。
    # 记一笔实测结论：泛型 Write 也**不会**影响读 —— 两组拒绝规则下 ReadAllText /
    # ReadAllBytes / Get-Content / Get-Item 全部正常（Write = 0x278，不含 Synchronize）。
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
        [System.Security.AccessControl.FileSystemRights]::AppendData
}

foreach ($r in @($acl.Access)) {
    if ($r.AccessControlType -eq 'Deny' -and
        $r.IdentityReference.Value -eq $Identity -and
        $r.FileSystemRights -eq $rights) {
        Write-Output "已存在同样的拒绝规则，跳过：$target -> $Identity"
        exit 0
    }
}

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $Identity,
    $rights,
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Deny)

$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $target -AclObject $acl

Write-Output "已保护：$target"
Write-Output "  被拒绝的主体：$Identity"
if ($DenyWrite) {
    Write-Output "  被拒绝的权限：Delete, DeleteSubdirectoriesAndFiles, WriteData, AppendData（子项继承）"
    Write-Output "  模式：拒绝删除 + 拒绝写。树内变成只读 —— 内容清空也被挡住了。"
}
else {
    Write-Output "  被拒绝的权限：Delete, DeleteSubdirectoriesAndFiles（子项继承）"
    Write-Output "  模式：只拒绝删除。注意内容仍可被覆盖清空（写不需要 DELETE 位）——要连内容一起保护请加 -DenyWrite。"
}
Write-Output "  恢复可写可删：Unprotect-Path.ps1 -Path '$target'"
