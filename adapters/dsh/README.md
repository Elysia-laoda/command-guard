# 🛡 dsh-command-guard · DSH 侧的命令闸门

**这不是"把 command-guard 在 DSH 再部署一遍"**，而是给同一个策略引擎加一个 DSH 入口。

## 为什么要单独一个入口

command-guard 是分层设计的，两层各管一段：

| 层 | 装在哪 | 覆盖谁 | DSH 要不要重装 |
|---|---|---|---|
| **文件系统层**（哨兵 + ACL 保护） | 磁盘上的实体：\`!000-guard\` 哨兵目录、\`protect\*.ps1\` | **任何程序**，包括 DSH／你自己在资源管理器里删 | 不用。它已经在盘上，DSH 一样会被绊住 |
| **命令层**（执行前拦） | 每个宿主一个**薄适配器** | 只有它自己那个宿主 | **要**：ZCode 的 \`adapters/zcode-hook.mjs\` 看不到 DSH 的工具调用 |

两层的性质也不同：文件系统层是"命令已经跑起来、开始动了才拦住"（可能已经被删掉一部分）；命令层是**根本不让它执行**。所以 DSH 侧这份适配器补的是"提前一巴掌"。

## 共享什么、不复制什么

- **不复制规则**：受保护范围、\`depth\`、破坏性动词表全部来自 \`<guardRoot>/guard.json\` 与 \`<guardRoot>/src/policy.mjs\`（默认 \`D:\ZCodeprojecttt\command-guard\`）。要调力度只改那一处。
- **共用审计流水**：默认写 \`<guardRoot>/logs/audit.jsonl\`，每行带 \`party\` 字段（\`dsh\` / ZCode 那边的来源），事后复盘一个文件看全。
- 本包**一行规则都没有** —— 它只做字段搬运、决策映射、审计。

## 装

~~~bash
node scripts/install.mjs              # 装进 desktop 档案（先备份 package.json）
node scripts/install.mjs --dry-run    # 只说不做
node scripts/uninstall.mjs            # 摘 bundles + 删包目录（引擎/guard.json/审计日志都不动）
~~~

装完**完全退出并重开 DSH**。配置在 \`cordis.patch.yml\`：

| 字段 | 默认 | 含义 |
|---|---|---|
| \`guardRoot\` | \`D:/ZCodeprojecttt/command-guard\` | 引擎与 guard.json 所在（也可用环境变量 \`COMMAND_GUARD_ROOT\`） |
| \`auditFile\` | \`<guardRoot>/logs/audit.jsonl\` | 审计流水 |
| \`mode\` | \`enforce\` | \`enforce\`=命中就拒绝；\`advise\`=只记账放行 |
| \`audit\` | \`true\` | 设 \`false\` 关审计 |
| \`allowlist\` | \`true\` | 设 \`false\` 关删除白名单 |
| \`allowlistFile\` | \`<DSH_HOME>/command-guard/delete-allowlist.json\` | 白名单清单路径 |
| \`integrity\` | \`true\` | 删前快照 / 删后比对（见下节） |

## 判定语义（来自引擎，不改）

- **受保护范围**：命中 \`guard.json\` 的 \`roots[].path\` 且距根层数 ≤ \`depth\` → 拦；**更深的文件不拦**（故意的：让"删错一项"只伤到一项）。
- 卷根 / \`/\` / \`~\` 作为删除目标 → 拦。
- 递归/强制开关 **且** 路径里出现变量（\`$VAR\`、\`%VAR%\`）→ 拦（跨 shell 展开没法在命令文本里核对，这正是那次工作区被整目录删除的形状）。
- 带 \`..\` 的未规范化相对路径 → 拦。
- 绝对路径上的递归删除 → **warn**（放行但记账，提示走 \`Remove-Safely\`）。

## 删除白名单（给临时产物留一条窄缝）

受保护根往下 1 层是红线，但 agent 的临时工具（`_probe.mjs`、`_tmp/` 之类）正好长在这一层——删不掉只会越堆越多。于是给一条**显式、一次性、会过期**的缝：先把目标写进清单，删除命令才放行。

~~~bash
node scripts/allow.mjs add "D:\dshproject\_probe.mjs" --note "临时探查脚本"
node scripts/allow.mjs add "D:\dshproject\_tmp" --note "临时目录" --kind dir --uses 2 --ttl-hours 6
node scripts/allow.mjs list
node scripts/allow.mjs revoke "D:\dshproject\_probe.mjs"
node scripts/allow.mjs purge      # 清过期/用尽
node scripts/allow.mjs resume     # 解除挂起
~~~

清单默认在 `<DSH_HOME>/command-guard/delete-allowlist.json`（DSH 侧，不写进共享引擎的 guard.json），也可以用 `--file` 指定。

**硬约束（每一条都是为了"清单本身不能变成洞"）**：

| 约束 | 说明 |
|---|---|
| 只对 `protected-depth` 生效 | 变量插值、通配符、卷根、哨兵、注册表等规则**不被绕过** |
| 精确匹配 | 命令里的目标必须逐字命中条目，不做前缀/正则 |
| **一次只删一个目标** | 一条命令里出现 ≥2 个绝对路径目标直接拒绝（批删最容易误伤） |
| 一次性 + 24h 过期 | `usesLeft=1`，用掉即失效；过期条目不再放行 |
| 写入即校验 | 卷根、系统目录、`.dsh`、哨兵目录 `!000-guard`、目录联接/符号链接 一律拒绝入单 |
| 必须写 note | 没写原因不给加 |

**删前删后扫描（时间换安全）**：放行时给目标父目录做快照（直接子项的类型/大小/mtime，小文件额外算 sha256），命令执行后比对——

- 通过条件：**目标消失，且邻近条目零增删改**；
- 不通过：审计写 `rule: integrity, verdict: block`，并**自动挂起整个白名单**（保留条目但拒绝放行），必须人工 `allow.mjs resume` 才能再用；
- 审计与清单自身文件不参与比对（否则"写审计"会被自己判成违规）。

**服务接口**（别的插件/脚本可直接用）：

~~~js
const guard = ctx.get('commandGuard');
guard.allowlist.add('D:\\dshproject\\_probe.mjs', { note: '临时探查脚本' });
guard.allowlist.list();     // { file, suspended, entries:[{path,kind,note,usesLeft,expiresAt,valid}] }
guard.allowlist.purge();
guard.allowlist.resume();
~~~

## 能力边界（写清楚，别指望它管不该管的）

- **只管 shell 类工具**：默认匹配 \`pwsh / powershell / bash / sh / zsh / cmd / shell / terminal\`，可用 \`config.tools\` 改成正则数组。
  其余工具的载荷里**可以把命令文本当数据**（run_code 程序、写文件、文档正文、测试用例），一律不看、不记 ——
  这和参考实现的适配器只处理 Bash 工具调用是同一个理由。没这条限定，"写一条删除类测试用例"就会被当成真要删。
- **只看得到经过 DSH 工具层**的命令；绕过工具层直接执行的东西它看不到，那归文件系统层管。
- **不做语义理解**：判据是动词 + 目标 + 开关 + 变量，全是可复核的文本特征（这也是它能被审计的原因）。

## 三条纪律

1. **失败开放**：适配器自己出错（引擎缺失、命令解析异常、审计写不进去）一律放行并记 warning —— 闸门坏了不能把 agent 卡死。
2. **只搬字段**：不猜语义、不改写命令。
3. **每次都审计**：\`allow\` 也留一行，那是"闸门到底生效没有"的唯一证据。

## 自测

~~~bash
npm test              # 24 个用例：真实引擎 + guard.json，含失败开放、深度语义、白名单与完整性校验
node e2e/run.mjs      # 真运行时：临时档案里装载本包，用真 waterfall 派发 tools/pre-execute
~~~

\`status()\` 会顺手报告**两层**的状态（受保护范围里每个根下有没有哨兵），避免"以为装了两层其实只有一层"：

~~~js
const guard = ctx.get('commandGuard');
guard.status();               // { active, mode, protectedRoots:[{path,depth,sentinel}], stats }
guard.evaluate('rm -rf $X');  // 纯判定，不执行、不审计
guard.tail(10);               // 读审计尾部
~~~

## 出处

策略引擎与分层设计来自 [Elysia-laoda/command-guard](https://github.com/Elysia-laoda/command-guard)（本机已部署）。本包是它的**DSH 适配器**，与 \`adapters/zcode-hook.mjs\` 平级。