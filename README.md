# command-guard ｜ anti-ai-rm-rf

> ## 防 AI 删库：给删除命令装一道绊线
>
> 一条命令就能把整个工作区清空 —— 2026-09-15 真的发生过一次。这个项目做的是：
> **让删除命令在撞上第一道绊线时整批停下**，而不是报个错继续往下删。

[English](README.en.md) ｜ 别名 **anti-ai-rm-rf** ｜ 关键词：**防AI删库** · agent guardrail · anti-delete · tripwire · Windows/PowerShell

**先把定位说清楚**：这是**防手滑**的工具，不是安全软件。它挡得住"打错路径、变量被吃掉、
AI 随手一条递归删除"，挡不住有意的对手 —— 绕过方法全部写在[能力边界](#能力边界part比功能更重要)一节，不藏。

---

## 30 秒上手

```powershell
# 1) 看现在两层都到位没有（一层是命令判断，一层是操作系统权限）
.\protect\Guard.ps1 status

# 2) 按 guard.json 装保护（默认干跑，加 -Apply 才落盘）
.\protect\Guard.ps1 install -Apply

# 3) 让每条 Remove-Item 都先过判断程序（写进 profile）
. D:\path\to\command-guard\adapters\Remove-Item.shim.ps1
```

改保护范围只改一个文件 `guard.json`：

```json
{ "path": "D:\\MyWorkspace", "depth": 1, "level": "sentinel", "exclude": ["_trash"] }
```

`depth` 在两层里**是同一个意思 —— 保护到第几层**：`0`=只护根 / `1`=根+第一层 / `n`=往下 n 层 / `-1`=整棵子树。

---

## 它拦的是什么

2026-09-15 那次事故的命令长这样：

```bash
powershell -NoProfile -Command "
$new = 'Win11-Video-LockScreen-Shinjuku-Battle'
if (Test-Path \"D:\ZCodeprojecttt\\$new\") { Remove-Item \"D:\ZCodeprojecttt\\$new\" -Recurse -Force }"
```

三层错误叠在一起：bash 双引号吃掉了 `$new`，路径塌缩成**工作目录根**；`if (Test-Path ...)` 是对
**变量**求值而非字面量，等于没守；`-Force` 让这条命令**连带删掉三个同任务无关的项目目录**。

这个项目拦的正是这一类**形状**，而不是靠"记得小心点"。

---

## 运作机理：一条命令从发出到落地的四道关口

```
甲方写好命令 ──▶ ① 引擎判定 ──▶ ② PowerShell 执行 ──▶ ③ 操作系统权限 ──▶ ④ 哨兵截断
（AI/人/脚本）     （不执行）       （闸门服从偏好）      （两条路任一即可）   （整批停下）
```

1. **命令层（引擎）** —— 命令先过 `cli.mjs check`：目标落在受保护范围的 depth 内吗？是 → **拦下，根本不执行**，并给出理由。同时遮蔽层会给递归删除补上 `-ErrorAction Stop`（**上膛**）。
2. **执行中（PowerShell）** —— provider **自己顺序递归、逐项判定**；删不掉就 `WriteError`。上过膛的话，**第一次拒绝直接抛异常、整批中断**。
3. **操作系统层（ACL）** —— 拒绝来自两条路之一：**对象自己的 `DELETE`**，或**父目录的 `DeleteSubdirectoriesAndFiles`**。两条都要关。
4. **哨兵** —— 走查遇到第一个删不掉的项就整批停，所以把哨兵放在**第一位** = 零损失截断。

**三层是链式关系，缺一环效果掉一半**：引擎在发出前拦，ACL 在系统里拒，哨兵把"拒一次"升级成"停一批"。

---

## 三层，各自能拦什么

| 角色 | 是谁 | 本项目里的东西 | 换 agent 还管用吗 |
|---|---|---|---|
| **甲方** | 写命令的 | ——（不需要它配合） | —— |
| **快递方** | 把命令送过去 | `adapters/`（ZCode 钩子、shell 包装器、同名函数遮蔽） | 每个宿主一个薄适配器 |
| **引擎** | 判该不该放行 | `src/policy.mjs` + `src/cli.mjs` | 是（它只是个函数） |
| **乙方** | 真正执行的 | `protect/`（ACL + 哨兵） | **完全不关心命令从哪来** |

按**绕过难度**排：

| 层 | 绕过难度 | 拦的是 |
|---|---|---|
| 遮蔽层 / 引擎 | **一句话**（`-NoProfile`、模块限定名、`[IO.File]::Delete`、`cmd /c del`） | 手滑、随手一条危险命令 |
| 快递方钩子 | 换个 agent 就没了 | 经过它的工具调用 |
| **ACL + 哨兵** | **绕不过**（除非去改权限 —— 那是个明显动作） | 操作系统级的删除动作 |
| 备份 / 版本控制 | —— | 前面全被绕过之后，还能救回来 |

---

## 实测结论

每条都在 Windows 本机跑过，多数在 **PowerShell 5.1.26100 与 7.6.6 双引擎**各验一遍。带数字的都是量出来的。

### 删除的机制（读过源码）

`src/System.Management.Automation/namespaces/FileSystemProvider.cs` 里，递归删除是**托管代码的顺序循环**：

```csharp
// RemoveDirectoryInfoItem，3036 行起
foreach (DirectoryInfo childDir in directory.EnumerateDirectories())
{
    if (Stopping) { return; }
    RemoveDirectoryInfoItem(childDir, recurse, force, false);   // 自己递归，一个一个来
}
```

```csharp
// RemoveFileSystemItem，3209 行起
if (!Force && (Attributes & (Hidden | System | ReadOnly)) != 0)
{
    WriteError(errorRecord);   // 拒绝 = 写一个错误
    return;                    // 然后 return —— 不是抛异常，所以外层循环继续
}
```

| 结论 | 实测 |
|---|---|
| **没有"删除整棵树"的系统调用** | 逐项 `foreach`；耗时随条目线性（200→3.7s、400→7.3s、800→15.2s、1600→33.9s，条目 ×8、耗时 ×9.1） |
| **顺序、深度优先、不是并行** | 拒绝对准第一个请求 → 零损失；对准第 3 个 → 丢 12；第 5 个 → 丢 24 |
| **失败被跳过，其余照删** | 60 文件里 15 个只读 → 报 22 条错误、**只剩那 15 个**，其余 45 个被删 |

### 断路器：`-ErrorAction Stop` 把"跳过"变成"停下"

`WriteError` 服从 `-ErrorAction`。默认 `Continue` 下拒绝被跳过；设成 `Stop`，第一次拒绝就抛异常、**整批中断**。

| 场景 | 结果 |
|---|---|
| 15 个只读文件，默认 `ErrorAction` | 只剩 **15/60**（其余 45 个照删） |
| 同样，`-ErrorAction Stop` | 剩 **57/60**，抛异常 |
| 60 文件全普通，**只有 1 个子目录受保护** + `Stop` | 剩 **41/60**，受保护目录及其之后全在 |
| 正对照：完全无保护 + `Stop` | 照删光，不抛异常 |

**一个受保护项就能打断整批删除，而且 `-Force` 破不了它**（ACL 拒绝是操作系统级访问拒绝，不是属性问题）。代价：它是**伤害限制**不是盾牌，且改变了语义 —— 所以遮蔽层只在调用方**没显式指定** `-ErrorAction` 时才补 `Stop`（要完全原生语义：`COMMAND_GUARD_STOP_ON_REFUSAL=0`）。

### `Remove-Item` 从不走回收站（和 `-Force` 无关）

| 做法 | 进回收站 |
|---|---|
| `Remove-Item`（普通 / `-Force` / `-Recurse -Force` / 只读 + `-Force`） | **都不进** |
| 正对照：`Microsoft.VisualBasic.FileIO.FileSystem::DeleteFile(..., SendToRecycleBin)` | **进** |

`-Force` 的真实作用是**掩掉 Hidden/System/ReadOnly 并压掉确认提示** —— 实测不带 `-Force` 时只读文件与其所在目录会幸存；但**不带 `-Force` 也救不了事故**：只含普通文件的目录树用 `Remove-Item -Recurse` 同样**静默全删、不弹提示**。

### 删一个子项有两条路，对象级拒绝只关掉一条

> 要删掉一个目录，它必须**先为空**，且你至少握有：**① 该对象自己的 `DELETE`**，或 **② 它父目录的 `DeleteSubdirectoriesAndFiles`**。

| 位置 | 父目录是否授予② | 空目录（哨兵形态）拦得住吗 |
|---|---|---|
| `E:\<父>\<哨兵>` | 否 | **拦住了** |
| `%TEMP%\<父>\<哨兵>` | **是** | **没拦住**（连错误都没有） |
| `D:\ZCodeprojecttt\_session-temp\<父>\<哨兵>` | 否 | **拦住了** |

这条模型能解释全部观测：非空目录"看起来更安全"，只是因为**空目录才能被删**；一旦内容被清空，它同样会从父目录那条路被拿走。所以**在任何位置做保护，两条路都要关** —— 关②只需在父目录上加一条拒绝 `DeleteSubdirectoriesAndFiles`，它是**窄**的（只移除备选路径，其余子项靠各自的 `DELETE` 照常可删）。

### 哨兵：给目录装一条绊线

在被保护目录的**第一位**放一个被保护的空目录。撞上它就整批停。

| 做法 | 损失 |
|---|---|
| 哨兵名排最前 + `Stop` | **0/30** |
| 哨兵名排最后 + `Stop` | 30/30 |
| 哨兵排最前，但**没有** `Stop` | 30/30 |
| 哨兵在，但命令只删某棵子树 | 该子树照删（**设计如此**：这就是"把伤害稀释到一个子树"） |

**名字必须排在同级第一位**：`000-guard` 会输给 `.git`（`.` = 0x2E < `0` = 0x30），而任何 git 仓库都有 `.git` —— 所以默认名是 **`!000-guard`**（`!` = 0x21，可打印 ASCII 里最小）。工具会在装的时候**真删一次**验证它确实排第一，失败时还会指出是哪个同级名字挡在前面。

### 三种保护强度

| 模式 | 挡住删除 | 挡住清空内容 | 树内可编辑 | 适合 |
|---|---|---|---|---|
| **哨兵**（`level: sentinel`） | 整目录删除被截断 | 否 | **是**（原子保存也正常） | 还在用的项目 |
| **树锁**（`level: tree`） | 是 | 否 | 否（只读式） | 半归档 |
| **归档**（`level: archive`） | 是 | 是 | 否，但**仍可读** | 不可再生的数据 |

树锁的实测边界：`Remove-Item -Recurse -Force` 零损失、`cmd rd /s /q` / .NET `Directory.Delete` / `robocopy /MIR` / `cmd del /f /s /q` 全部被挡，而树内**新建与修改照常**、**原子保存（临时文件 + 覆盖）被挡**。归档模式实测：覆盖与追加被拒、删除被拒、**读取与列举完全正常**。

### 被实测否掉的做法

- **单只金丝雀**（把一个文件独占打开）：命令 199 ms 跑完、**不中断也不挂起**，只有金丝雀自己活下来，树里其它文件全没 —— 它只保护自己。
- **把每个文件都置于运行态**（全部持句柄）：50/50 全存活，确实是一层有效的壳。但比 ACL 差在：`Set-Content` 被挡、改名被挡、**重启即失效**、`taskkill` 掉守卫就解除、每文件一个句柄。
- **非继承的 ACL**：留下"空壳"—— 内容被清空、目录还在，看着像保护、实际全丢。
- **用户态的文件访问路由器**：不存在。拦截别的进程的文件访问只有内核态 minifilter 能做到（本机构建不起来：无内核头、无签名证书、Secure Boot 开着、非管理员）。而且它**不会比 ACL 更拦得住**，多的只是"逐请求条件判断" —— 那在命令层的规则里就能写。

---

## 能力边界（这部分比功能更重要）

**文本匹配的固有局限。** 引擎读的是命令原文：

- 命令里不出现破坏性动词的写法：`[IO.File]::Delete()`、`.Delete()`、把命令写进 `.ps1` 再跑；
- 动词被拼出来或被替换的：`Invoke-Expression`、`$cmd`、base64、字符串拼接；
- **变量只看得到形状看不到内容** —— 所以那条规则拦的是"见了变量 + 递归开关"这个**形状**。

**遮蔽层的绕过（一句话）。** `-NoProfile`、模块限定名 `Microsoft.PowerShell.Management\Remove-Item`、
`Remove-Item Function:Remove-Item` 把函数删掉、`[IO.File]::Delete()`、`cmd /c del`。
**它的价值是把"自觉"写成一条机械规则**，不是防住对手。

**ACL 的局限。** 它挡的是"删除"这个动作，不是恶意：**对象所有者随时可以改回权限** —— 所以它防的是事故，不是对手。它**只有"整棵子树"或"每层一个哨兵"这类有效形态**，只覆盖一部分会留下空壳。它也**不提供任何恢复能力**。

**真正"删了还能回来"的只有一层：备份与版本控制。** 上面三层让删除更难发生、更早被拦住；不是让它可以撤销。这两件事要同时做。

---

## 目录

```
command-guard/
  guard.json                  唯一配置：depth 给引擎，level 给安装器
  src/policy.mjs              策略引擎（纯函数，不含任何宿主知识）
  src/cli.mjs                 check / run / describe / selftest，支持 --depth
  tests/policy.test.mjs       引擎契约测试（22 条）
  tests/Test-ShimFidelity.ps1 遮蔽保真度测试（17 条，装壳前后逐项对比）
  adapters/zcode-hook.mjs     ZCode PreToolUse 适配器（薄，含审计日志）
  adapters/guard.sh           任何 shell 都能用的包装器（薄）
  adapters/Remove-Item.shim.ps1  同名函数遮蔽：让每条 Remove-Item 先过判断程序
  protect/Guard.ps1           前门：status / install / remove（默认干跑）
  protect/GuardSentinel.ps1   哨兵：装 + 真删验证 + 体检
  protect/Protect-Path.ps1    子树锁（-DenyWrite = 归档模式）
  protect/Unprotect-Path.ps1  打破玻璃
  protect/Test-Protection.ps1 操作系统层测试（25 条）
  logs/audit.jsonl            适配器每次被调用的审计记录
```

**装进工作区之后**（本机实测）：16 个哨兵全部行为验证通过；验收 10/10 —— 根级与项目级的
新建 / 改写 / **原子保存** / 删文件 / 删子目录全部正常，而**整目录删除被截断且零损失**。

## 许可

MIT。
