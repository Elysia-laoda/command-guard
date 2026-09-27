# Fidelity test for the Remove-Item shim.
# The risk with shadowing a cmdlet is silent behaviour change, so this runs the SAME operation
# set twice (before and after dot-sourcing the shim) and requires identical results, then checks
# that the shim actually intercepts the one case it is there for.
# ASCII labels. Everything happens inside the test root (E:\_shim-test by default).
$ErrorActionPreference = 'Continue'
$root = if ($env:COMMAND_GUARD_TEST_ROOT) { Join-Path $env:COMMAND_GUARD_TEST_ROOT '_shim-test' } else { 'E:\_shim-test' }
$shim = Join-Path (Split-Path -Parent $PSScriptRoot) 'adapters\Remove-Item.shim.ps1'

$pass = 0; $fail = 0
function Check($name, $ok, $detail) {
    if ($ok) { $script:pass++; Write-Output ("PASS  " + $name) }
    else { $script:fail++; Write-Output ("FAIL  " + $name + "  -> " + $detail) }
}

function New-Tree($name) {
    $d = Join-Path $root $name
    if (Test-Path $d) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

# 每一步都返回一个可比较的结果串
function Invoke-Ops {
    $r = [ordered]@{}

    # 1 delete by -Path
    $d = New-Tree 'op1'; $f = Join-Path $d 'a.txt'; Set-Content -LiteralPath $f -Value 'x'
    Remove-Item -Path $f -ErrorAction SilentlyContinue
    $r['1 delete -Path'] = "exists=" + (Test-Path $f)

    # 2 delete by -LiteralPath
    $d = New-Tree 'op2'; $f = Join-Path $d 'a.txt'; Set-Content -LiteralPath $f -Value 'x'
    Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
    $r['2 delete -LiteralPath'] = "exists=" + (Test-Path $f)

    # 3 delete a directory tree
    $d = New-Tree 'op3'; New-Item -ItemType Directory -Path (Join-Path $d 'sub') | Out-Null
    Set-Content -LiteralPath (Join-Path $d 'sub\b.txt') -Value 'y'
    Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
    $r['3 delete -Recurse'] = "exists=" + (Test-Path $d)

    # 4 pipeline
    $d = New-Tree 'op4'; 1..3 | ForEach-Object { Set-Content -LiteralPath (Join-Path $d "f$_.txt") -Value 'z' }
    Get-ChildItem -LiteralPath $d -File | Remove-Item -ErrorAction SilentlyContinue
    $r['4 pipeline'] = "left=" + @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue).Count

    # 5 -WhatIf leaves everything
    $d = New-Tree 'op5'; $f = Join-Path $d 'a.txt'; Set-Content -LiteralPath $f -Value 'x'
    Remove-Item -LiteralPath $f -WhatIf *> $null
    $r['5 -WhatIf'] = "exists=" + (Test-Path $f)

    # 6 missing path produces an error and nothing else
    $d = New-Tree 'op6'; $ev = $null
    Remove-Item -LiteralPath (Join-Path $d 'nope.txt') -ErrorAction SilentlyContinue -ErrorVariable ev
    $r['6 missing path'] = "errors=" + @($ev).Count

    # 7 non-filesystem provider: Variable
    Set-Variable -Name cg_tmpv -Value 1 -Scope Global -Force
    Remove-Item -Path Variable:cg_tmpv -ErrorAction SilentlyContinue
    $r['7 Variable: provider'] = "gone=" + ($null -eq (Get-Variable -Name cg_tmpv -Scope Global -ErrorAction SilentlyContinue))

    # 8 non-filesystem provider: Function
    function cg_tmpf { 'x' }
    Remove-Item -Path Function:cg_tmpf -ErrorAction SilentlyContinue
    $r['8 Function: provider'] = "gone=" + ($null -eq (Get-Command cg_tmpf -ErrorAction SilentlyContinue))

    # 9 read-only file without -Force errors, file survives
    $d = New-Tree 'op9'; $f = Join-Path $d 'ro.txt'; Set-Content -LiteralPath $f -Value 'x'
    Set-ItemProperty -LiteralPath $f -Name IsReadOnly -Value $true
    Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
    $r['9 readonly, no -Force'] = "exists=" + (Test-Path $f)

    # 10 read-only file with -Force
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    $r['10 readonly, -Force'] = "exists=" + (Test-Path $f)

    # 11 several targets in one call
    $d = New-Tree 'op11'; $a = Join-Path $d 'a.txt'; $b = Join-Path $d 'b.txt'
    Set-Content -LiteralPath $a -Value 'x'; Set-Content -LiteralPath $b -Value 'x'
    Remove-Item -Path $a, $b -ErrorAction SilentlyContinue
    $r['11 two targets'] = "left=" + @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue).Count

    # 12 wildcard
    $d = New-Tree 'op12'; 1..2 | ForEach-Object { Set-Content -LiteralPath (Join-Path $d "x$_.log") -Value 'l' }
    Set-Content -LiteralPath (Join-Path $d 'keep.txt') -Value 'k'
    Remove-Item -Path (Join-Path $d '*.log') -ErrorAction SilentlyContinue
    $r['12 wildcard'] = "left=" + @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue).Count

    return $r
}

# ---------------- baseline: no shim ----------------
if (Test-Path $root) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $root | Out-Null
$baseline = Invoke-Ops
Write-Output "--- baseline (real cmdlet) captured ---"

# ---------------- with the shim ----------------
. $shim
Write-Output ("shim loaded: Remove-Item is now a " + (Get-Command Remove-Item).CommandType)
Check 'shim shadows the cmdlet' ((Get-Command Remove-Item).CommandType -eq 'Function') ("type=" + (Get-Command Remove-Item).CommandType)

if (Test-Path $root) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $root | Out-Null
$shimmed = Invoke-Ops

# ---------------- compare ----------------
foreach ($k in $baseline.Keys) {
    Check ("fidelity: " + $k) ($baseline[$k] -eq $shimmed[$k]) ("baseline=" + $baseline[$k] + " shimmed=" + $shimmed[$k])
}

# ---------------- does it actually intercept? ----------------
# 受保护目标从 guard.json 的第一个根推导出来 —— 受保护路径属于部署配置，不写死在测试里。
$cfgPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'guard.json'
$canary = $null
if (Test-Path -LiteralPath $cfgPath) {
    try {
        $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
        $roots = @($cfg.roots)
        if ($roots.Count -gt 0 -and $roots[0].path) { $canary = Join-Path ([string]$roots[0].path) '__shim_canary_never_exists__' }
    }
    catch { }
}
if ($canary) {
    $ev2 = $null
    Remove-Item -LiteralPath $canary -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable ev2
    $msgs = (@($ev2) | ForEach-Object { $_.Exception.Message }) -join ' | '
    Write-Output ("      errors: " + $msgs.Substring(0, [Math]::Min(140, $msgs.Length)))
    Check 'the shim blocks a protected target (message names command-guard)' ($msgs -like '*command-guard*') 'no command-guard message - the shim did not intercept'
}
else {
    Write-Output "SKIP  no guard.json (or empty roots) - skipping the protected-target interception check"
}

# a legitimate deep delete must still go through
$d = New-Tree 'ok'; $f = Join-Path $d 'normal.txt'; Set-Content -LiteralPath $f -Value 'x'
Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
Check 'a legitimate delete is still allowed' (-not (Test-Path $f)) 'the shim blocked a normal delete'

# ---------------- circuit breaker: one refusal stops the whole recursion ----------------
# The source shows a refusal is a WriteError, which obeys -ErrorAction. So adding -ErrorAction Stop
# to a recursive delete turns "skip and continue" into "abort at the first refusal".
function New-BreakerTree {
    $d = Join-Path $root 'breaker'
    if (Test-Path $d) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    foreach ($i in 1..5) {
        $sub = Join-Path $d ("d{0:d3}" -f $i)
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
        foreach ($j in 1..6) { Set-Content -LiteralPath (Join-Path $sub ("f{0:d3}.txt" -f $j)) -Value 'x' }
    }
    # first file in the first directory the walk visits
    Set-ItemProperty -LiteralPath (Join-Path $d 'd001\f001.txt') -Name IsReadOnly -Value $true
    return $d
}
function Count-Left($d) { return @(Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue).Count }

$d = New-BreakerTree
$threwOnRefusal = $false
try { Remove-Item -LiteralPath $d -Recurse } catch { $threwOnRefusal = $true }
$leftStop = Count-Left $d
Check 'shim adds -ErrorAction Stop to a recursive delete and one refusal aborts the batch' ($threwOnRefusal -and $leftStop -ge 25) ("threw=" + $threwOnRefusal + " left=" + $leftStop + "/30 (native semantics would leave 1)")
Write-Output ("      circuit breaker: left=" + $leftStop + "/30 after the first refusal")

# escape hatch: restore native semantics
$env:COMMAND_GUARD_STOP_ON_REFUSAL = '0'
$d = New-BreakerTree
try { Remove-Item -LiteralPath $d -Recurse } catch { }
$leftNative = Count-Left $d
Remove-Item Env:\COMMAND_GUARD_STOP_ON_REFUSAL -ErrorAction SilentlyContinue
Check 'COMMAND_GUARD_STOP_ON_REFUSAL=0 restores native semantics (only the refused item survives)' ($leftNative -eq 1) ("left=" + $leftNative + "/30, expected 1")

# ---------------- clean up ----------------
Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
Write-Output ""
Write-Output ("RESULT  pass=" + $pass + "  fail=" + $fail)
