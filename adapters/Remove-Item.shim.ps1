# Remove-Item.shim —— 让每一条 Remove-Item 都先过判断程序，而命令的写法不用改。
#
# 机制：PowerShell 的命令优先级是 Alias > Function > Cmdlet。定义一个同名函数，就能拦下
# 当前会话里所有 Remove-Item 调用 —— 不管它来自 AI、手敲、还是别人的脚本。甲方不需要配合。
#
# 装法（二选一）：
#   1) profile 里加一行 dot-source：
#        . D:\path\to\command-guard\adapters\Remove-Item.shim.ps1
#   2) 手动 dot-source 到当前会话：
#        . .\adapters\Remove-Item.shim.ps1
#
# 覆盖范围与已知旁路（必须知道）：
#   - 只覆盖**加载了 profile** 的 PowerShell 会话。`-NoProfile` 的调用绕过它。
#   - 显式写 `Microsoft.PowerShell.Management\Remove-Item` 可绕过（模块限定名比函数优先级高）。
#   - 命令里不含 Remove-Item 的删法（[IO.File]::Delete、cmd del、robocopy /MIR…）看不到。
#   - 非文件系统的 provider（Function:/Variable:/Alias:/Env:/HKLM:…）原样放过，不判断。
#   - 判断程序起不来时**失败开放**（放行 + 警告），否则一次依赖故障会让所有删除都不可用。

$script:CgNode = if ($env:COMMAND_GUARD_NODE) { $env:COMMAND_GUARD_NODE } else { 'node' }
$script:CgCli = if ($env:COMMAND_GUARD_CLI) {
    $env:COMMAND_GUARD_CLI
}
else {
    Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) 'src\cli.mjs'
}

function Remove-Item {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Path')]
        [string[]]$Path,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath', 'LP')]
        [string[]]$LiteralPath,

        [string]$Filter,
        [string[]]$Include,
        [string[]]$Exclude,
        [switch]$Recurse,
        [switch]$Force,
        [System.Management.Automation.PSCredential]$Credential,
        [int[]]$Stream
    )
    process {
        $targets = if ($PSBoundParameters.ContainsKey('LiteralPath')) { @($LiteralPath) } else { @($Path) }
        $allowed = New-Object 'System.Collections.Generic.List[string]'
        $blocked = 0

        foreach ($t in $targets) {
            if ([string]::IsNullOrWhiteSpace($t)) { continue }

            # 非文件系统 provider：Function:/Variable:/Alias:/Env:/HKLM: 这类是两个以上字母加冒号。
            # 盘符是单个字母，所以这个判据不会误伤 C:\...
            if ($t -match '^[A-Za-z]{2,}:') {
                $allowed.Add($t)
                continue
            }

            # 用结构化目标喂引擎：已解析过的调用方不该把命令拼回文本再解析一遍。
            # targets 必须是数组 —— ConvertTo-Json 有把单元素数组退化成标量的毛病，所以
            # 用 [string[]] 显式定型，并在下面按"引擎是否认得这个载荷"做自检。
            $payload = [pscustomobject]@{
                verb      = 'Remove-Item'
                targets   = [string[]]@([string]$t)
                recursive = [bool]$Recurse
                force     = [bool]$Force
            } | ConvertTo-Json -Compress

            $previousEncoding = $OutputEncoding
            $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
            try {
                $out = $payload | & $script:CgNode $script:CgCli check
                $rc = $LASTEXITCODE
            }
            catch {
                $out = $null
                $rc = 3
            }
            finally {
                $OutputEncoding = $previousEncoding
            }

            if ($rc -eq 3 -or $null -eq $out) {
                Write-Warning "command-guard 未能判定 '$t'（判断程序异常），按失败开放放行。"
                $allowed.Add($t)
                continue
            }

            $verdict = $null
            try { $verdict = ($out | Out-String) | ConvertFrom-Json } catch { }
            if ($null -eq $verdict -or $null -eq $verdict.verdict) {
                Write-Warning "command-guard 返回了无法解析的裁决，按失败开放放行：$t"
                $allowed.Add($t)
                continue
            }

            if ($verdict.verdict -eq 'block') {
                if ($WhatIfPreference) {
                    # -WhatIf 本来就不会删任何东西，所以这里只提示、不拦截，保持 cmdlet 语义。
                    Write-Warning ("command-guard 认为这条命令会被拦下（规则 " + $verdict.matched + "）：" + $verdict.reason)
                }
                else {
                    $blocked += 1
                    Write-Error ("command-guard 拦下了 Remove-Item '" + $t + "'（规则 " + $verdict.matched + "）：" + $verdict.reason)
                }
                continue
            }

            if ($verdict.verdict -eq 'warn') {
                Write-Warning ("command-guard 提示：" + $verdict.reason)
            }
            $allowed.Add($t)
        }

        if ($allowed.Count -eq 0) { return }

        # 转发：把原样的绑定参数交给真身，只把目标换成通过检查的那批。
        $forward = @{}
        foreach ($k in $PSBoundParameters.Keys) { $forward[$k] = $PSBoundParameters[$k] }
        if ($forward.ContainsKey('LiteralPath')) { $forward['LiteralPath'] = $allowed.ToArray() }
        else { $forward['Path'] = $allowed.ToArray() }

        # 断路器：源码里"拒绝删除"是 WriteError，而 WriteError 服从 -ErrorAction。
        # 默认(Continue)下，拒绝会被跳过、其余照删（实测：60 个文件、每 4 个设只读 -> 只剩 15 个；
        # 第 9 个文件起就被拒，但后面的 45 个照样被删）。Stop 下第一次拒绝就终止整条递归
        # （同一棵树 -> 剩 57 个，整批中断）。于是**一个受保护项就能打断整批删除**，
        # 而且 -Force 破不了它 —— ACL 的拒绝是操作系统级的访问拒绝，不是属性问题。
        # 只在调用方**没有显式指定** -ErrorAction 时才补上，不覆盖别人的选择。
        # 想要完全原生语义：设 COMMAND_GUARD_STOP_ON_REFUSAL=0
        if ($Recurse -and $env:COMMAND_GUARD_STOP_ON_REFUSAL -ne '0' -and -not $forward.ContainsKey('ErrorAction')) {
            $forward['ErrorAction'] = 'Stop'
        }

        Microsoft.PowerShell.Management\Remove-Item @forward
    }
}
