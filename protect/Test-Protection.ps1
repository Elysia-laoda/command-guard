# 验证乙方层：ACL 拒绝删除是不是真的挡得住 Remove-Item -Recurse -Force。
# 全部活动都在 E:\_acl-test 内。这个目录由本脚本自己创建。
# ASCII 标签，中文只出现在说明里。


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
# 测试根：默认 E:\_acl-test；换机器用 COMMAND_GUARD_TEST_ROOT 指定一个可写的 NTFS 位置。
# 本文件其余位置沿用字面量 'E:\_acl-test' —— 要换根就改这一行 + 全文替换那个字面量。
$root = if ($env:COMMAND_GUARD_TEST_ROOT) { $env:COMMAND_GUARD_TEST_ROOT } else { 'E:\_acl-test' }
$projectRoot = Split-Path -Parent $PSScriptRoot
$protect = Join-Path $PSScriptRoot 'Protect-Path.ps1'
$unprotect = Join-Path $PSScriptRoot 'Unprotect-Path.ps1'

$pass = 0; $fail = 0
function Check($name, $ok, $detail) {
    if ($ok) { $script:pass++; Write-Output ("PASS  " + $name) }
    else { $script:fail++; Write-Output ("FAIL  " + $name + "  -> " + $detail) }
}

# ---------------- 0. 先做语法检查：本项目所有 .ps1/.psm1/.psd1 能被解析 ----------------
Write-Output "--- syntax check of every PowerShell file in this project ---"
$files = @(Get-ChildItem -LiteralPath $projectRoot -Recurse -File -Include *.ps1, *.psm1, *.psd1 -ErrorAction SilentlyContinue)
$bad = 0
foreach ($f in $files) {
    $errs = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs) | Out-Null
    if ($errs -and $errs.Count) {
        $bad++
        Write-Output ("  [SYNTAX] " + $f.Name + " -> " + ($errs[0].Message))
    }
}
Check 'all PowerShell files parse' ($bad -eq 0) ("$bad file(s) failed to parse")

# ---------------- 1. 建测试树 ----------------
if (Test-Path $root) { throw "scratch dir already exists: $root" }
New-Item -ItemType Directory -Path $root | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'inner') | Out-Null
Set-Content -LiteralPath 'E:\_acl-test\keep.txt' -Value 'keep-me'
Set-Content -LiteralPath 'E:\_acl-test\inner\deep.txt' -Value 'deep'
Write-Output "--- fixtures ready ---"

# ---------------- 2. 上保护 ----------------
& $protect -Path 'E:\_acl-test'
$acl = Get-Acl -LiteralPath 'E:\_acl-test'
$deny = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
Check 'deny ACE is present on the folder' ($deny.Count -eq 1) ("deny rules = " + $deny.Count)
if ($deny.Count -eq 1) {
    Write-Output ("      deny -> " + $deny[0].IdentityReference.Value + " : " + $deny[0].FileSystemRights + " (" + $deny[0].InheritanceFlags + ")")
}

# ---------------- 3. 树整体删除必须失败 ----------------
$blocked = $false
try { Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction Stop }
catch { $blocked = $true; Write-Output ("      tree delete threw: " + $_.Exception.Message.Split([char]10)[0]) }
Check 'Remove-Item -Recurse -Force on the tree FAILS' $blocked 'it succeeded - ACL did not stop it'
Check 'the tree is still there' (Test-Path 'E:\_acl-test')

# ---------------- 4. 树内文件删除必须失败 ----------------
$fileBlocked = $false
try { Remove-Item -LiteralPath 'E:\_acl-test\keep.txt' -Force -ErrorAction Stop } catch { $fileBlocked = $true }
Check 'deleting a file INSIDE the tree FAILS' $fileBlocked 'it succeeded'
Check 'that file is still there' (Test-Path 'E:\_acl-test\keep.txt')

$innerBlocked = $false
try { Remove-Item -LiteralPath 'E:\_acl-test\inner' -Recurse -Force -ErrorAction Stop } catch { $innerBlocked = $true }
Check 'deleting a subdirectory FAILS' $innerBlocked 'it succeeded'

# ---------------- 5. 树还能不能正常用？ ----------------
$ok = $true
try { Set-Content -LiteralPath 'E:\_acl-test\new.txt' -Value 'created' } catch { $ok = $false; Write-Output ("      create threw: " + $_.Exception.Message.Split([char]10)[0]) }
Check 'creating a NEW file inside still works' ($ok -and (Test-Path 'E:\_acl-test\new.txt'))

$ok = $true
try { Set-Content -LiteralPath 'E:\_acl-test\keep.txt' -Value 'modified' } catch { $ok = $false }
Check 'modifying an existing file still works' ($ok -and ((Get-Content -LiteralPath 'E:\_acl-test\keep.txt' -Raw).Trim() -eq 'modified'))

# 原子保存模式：写临时文件再覆盖过去。很多编辑器和工具是这么保存的。
$atomic = 'untested'
try {
    Set-Content -LiteralPath 'E:\_acl-test\keep.txt.tmp' -Value 'tmp'
    Move-Item -LiteralPath 'E:\_acl-test\keep.txt.tmp' -Destination 'E:\_acl-test\keep.txt' -Force -ErrorAction Stop
    $atomic = 'works'
}
catch { $atomic = 'BLOCKED' }
Write-Output ("INFO  atomic-save pattern (temp + Move-Item -Force over existing): " + $atomic)

# ---------------- 6. 解除保护后必须能删 ----------------
& $unprotect -Path 'E:\_acl-test'
$acl2 = Get-Acl -LiteralPath 'E:\_acl-test'
$deny2 = @($acl2.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
Check 'deny ACE is gone after unprotect' ($deny2.Count -eq 0) ("deny rules = " + $deny2.Count)

$deleted = $false
try { Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction Stop; $deleted = $true } catch { Write-Output ("      post-unprotect delete threw: " + $_.Exception.Message.Split([char]10)[0]) }
Check 'after unprotect, Remove-Item -Recurse -Force SUCCEEDS' $deleted 'it still failed'
Check 'the tree is gone' (-not (Test-Path 'E:\_acl-test'))

# ---------------- 7. 反向验证：为什么 ACL 没有"层数"这个可调参数 ----------------
# 非继承的拒绝规则会留下"空壳"：内容被删光，目录还在。看起来像保护，实际什么都没保护。
# 实测三组（同目录下跑过 A/B/C）：
#   只锁根不继承      -> 内容全没了，只剩一个空的根目录
#   锁根+第一层不继承 -> 第一层目录被清空，只剩壳
#   锁根且继承        -> 一个文件都没丢
# 这一节把那个陷阱钉成断言，防止以后有人把 Protect-Path 改成非继承版本。
$rights = [System.Security.AccessControl.FileSystemRights]::Delete -bor `
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

New-Item -ItemType Directory -Path 'E:\_acl-test' -Force | Out-Null
Set-Content -LiteralPath 'E:\_acl-test\inside.txt' -Value 'inside'
$aclTrap = Get-Acl -LiteralPath 'E:\_acl-test'
$nonInherited = New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name, $rights,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Deny)
$aclTrap.AddAccessRule($nonInherited)
Set-Acl -LiteralPath 'E:\_acl-test' -AclObject $aclTrap

try { Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction Stop } catch { }
$shell = Test-Path 'E:\_acl-test'
$left = @(Get-ChildItem -LiteralPath 'E:\_acl-test' -Force -ErrorAction SilentlyContinue).Count
Check 'non-inherited deny leaves an EMPTY SHELL (the trap this assertion exists to prevent)' ($shell -and $left -eq 0) ("shell=" + $shell + " itemsLeft=" + $left)

$aclTrap2 = Get-Acl -LiteralPath 'E:\_acl-test'
foreach ($r in @($aclTrap2.Access)) {
    if ($r.AccessControlType -eq 'Deny') { $aclTrap2.RemoveAccessRuleSpecific($r) | Out-Null }
}
Set-Acl -LiteralPath 'E:\_acl-test' -AclObject $aclTrap2
try { Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction Stop } catch { }
Check 'trap fixture cleaned up' (-not (Test-Path 'E:\_acl-test'))

# ---------------- 8. 拒绝对"任何工具"都成立，不只 Remove-Item ----------------
# 递归删除不是一次操作，而是 N 次独立的删除操作：拦下其中一个不会让整批停下来。
# 实测（见 README 的金丝雀实验）：一个被独占打开的文件只保护了它自己，树里其它文件照样
# 被清空，命令 199ms 跑完、既不中断也不挂起。唯一能让整批失败的办法是让**每一项**都被
# 拒 —— 这正是"继承"做到的，也是这个测试要钉住的结论。
function New-SmallTree {
    if (Test-Path 'E:\_acl-test') { Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path 'E:\_acl-test\sub' -Force | Out-Null
    Set-Content -LiteralPath 'E:\_acl-test\data1.txt' -Value 'd1'
    Set-Content -LiteralPath 'E:\_acl-test\sub\data2.txt' -Value 'd2'
}
function TreeIntact {
    return (Test-Path 'E:\_acl-test') -and (@(Get-ChildItem -LiteralPath 'E:\_acl-test' -Recurse -File -Force -ErrorAction SilentlyContinue).Count -eq 2)
}

$emptyDir = 'E:\_acl-empty'
if (Test-Path $emptyDir) { Remove-Item -LiteralPath $emptyDir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $emptyDir | Out-Null

New-SmallTree
& $protect -Path 'E:\_acl-test' | Out-Null

cmd /c "rd /s /q E:\_acl-test" 2>&1 | Out-Null
Check 'cmd rd /s /q cannot delete a protected tree' (TreeIntact) 'it got through'

try { [System.IO.Directory]::Delete('E:\_acl-test', $true) } catch { }
Check '.NET Directory.Delete cannot delete a protected tree' (TreeIntact) 'it got through'

robocopy $emptyDir 'E:\_acl-test' /MIR /NFL /NDL /NJH /NJS /NP 2>&1 | Out-Null
Check 'robocopy /MIR cannot empty a protected tree' (TreeIntact) 'it got through'

cmd /c "del /f /s /q E:\_acl-test\* >nul 2>&1"
Check 'cmd del /f /s /q cannot empty a protected tree' (TreeIntact) 'it got through'

# 正对照：同样这条命令打在未保护的目录上确实能毁掉它。
# 没有这个对照，"文件还在"也可能只是那条命令本来就没用。
& $unprotect -Path 'E:\_acl-test' | Out-Null
cmd /c "rd /s /q E:\_acl-test" 2>&1 | Out-Null
Check 'control: the same command DOES destroy an unprotected tree' (-not (Test-Path 'E:\_acl-test')) 'the control did nothing, so the four results above prove nothing'

Remove-Item -LiteralPath $emptyDir -Recurse -Force -ErrorAction SilentlyContinue

# ---------------- 9. 只拒删除时，内容仍然可以被清空（本层的真实边界） ----------------
# 写只需要 WRITE 位，不需要 DELETE 位 —— 所以"删不掉"完全不妨碍"把内容抹掉"。
# 这一节把这个边界钉成断言，免得有人以为"删不掉"就等于"数据安全"。
New-Item -ItemType Directory -Path 'E:\_acl-test' -Force | Out-Null
Set-Content -LiteralPath 'E:\_acl-test\keep.txt' -Value 'ORIGINAL'
& $protect -Path 'E:\_acl-test' | Out-Null

$rawBefore = (Get-Content -LiteralPath 'E:\_acl-test\keep.txt' -Raw)
Set-Content -LiteralPath 'E:\_acl-test\keep.txt' -Value ''
$rawAfter = (Get-Content -LiteralPath 'E:\_acl-test\keep.txt' -Raw)
Check 'existence-only mode: content CAN still be wiped (known limit, not a bug)' `
    ((Test-Path 'E:\_acl-test\keep.txt') -and ($rawAfter -ne $rawBefore)) `
    ("exists=" + (Test-Path 'E:\_acl-test\keep.txt') + " before=[" + $rawBefore.Trim() + "] after=[" + $rawAfter.Trim() + "]")
Write-Output ("      -> 文件还在(" + (Test-Path 'E:\_acl-test\keep.txt') + ")，内容 [" + $rawBefore.Trim() + "] 变成 [" + $rawAfter.Trim() + "]")
& $unprotect -Path 'E:\_acl-test' | Out-Null
Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction SilentlyContinue

# ---------------- 10. -DenyWrite：连内容一起保护 ----------------
# 给不可再生的归档数据用的形态：删不掉、也改不了，但仍然读得到、列得出。
New-Item -ItemType Directory -Path 'E:\_acl-test' -Force | Out-Null
Set-Content -LiteralPath 'E:\_acl-test\keep.txt' -Value 'ORIGINAL'
& $protect -Path 'E:\_acl-test' -DenyWrite | Out-Null

$wiped = $false
try { Set-Content -LiteralPath 'E:\_acl-test\keep.txt' -Value '' } catch { $wiped = $true }
Check '-DenyWrite: overwriting the content is refused' $wiped 'the content was wiped'

$appended = $false
try { [System.IO.File]::AppendAllText('E:\_acl-test\keep.txt', 'x') } catch { $appended = $true }
Check '-DenyWrite: appending is refused' $appended 'the append went through'

$readable = $false
try { $readable = ([System.IO.File]::ReadAllText('E:\_acl-test\keep.txt').Trim() -eq 'ORIGINAL') } catch { }
Check '-DenyWrite: the file is still readable (archival data must stay listable)' $readable 'reading broke'

$deletable = $false
try { Remove-Item -LiteralPath 'E:\_acl-test\keep.txt' -Force -ErrorAction Stop; $deletable = $true } catch { }
Check '-DenyWrite: deletion is still refused' (-not $deletable) 'the file was deleted'

& $unprotect -Path 'E:\_acl-test' | Out-Null
Remove-Item -LiteralPath 'E:\_acl-test' -Recurse -Force -ErrorAction SilentlyContinue
Check 'DenyWrite fixture cleaned up' (-not (Test-Path 'E:\_acl-test'))

Write-Output ""
Write-Output ("RESULT  pass=" + $pass + "  fail=" + $fail)
