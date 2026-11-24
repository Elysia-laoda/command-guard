/**
 * dsh-command-guard — 规则表与判定（纯逻辑，无 IO、无宿主依赖）。
 *
 * 设计取向（借自 WorkBuddy 的 windows_command_safety 与命令安全审查、以及本机
 * command-guard 项目的经验，全部重写）：
 *   - 只拦"不可逆且目标含糊"的命令；明确指向自己临时产物的递归删除走 advise 而不是 deny；
 *   - 每条规则都要给出 why（为什么危险）与 fix（怎么写才安全）—— 错误模式速查表的思路；
 *   - 判定是确定性的：不调模型、不看网络，毫秒级，可以放在每次工具调用的前置关口上。
 *
 * @module dsh-command-guard/rules
 */

/** 严重度：P0 = 默认拒绝（enforce），P1 = 只记日志并放行（advise）。 */
export const SEVERITY = { P0: 'P0', P1: 'P1' };

/** 从工具入参里抠出"将要执行的命令文本"。不同工具的字段名不一样，全试一遍。 */
export function extractCommand(args) {
  if (args === undefined || args === null) return '';
  if (typeof args === 'string') return args;
  if (Array.isArray(args)) return args.map(extractCommand).filter((part) => part.length > 0).join('\n');
  if (typeof args !== 'object') return String(args);
  const fields = ['command', 'cmd', 'script', 'code', 'input', 'source', 'snippet'];
  const parts = [];
  for (const field of fields) {
    const value = args[field];
    if (typeof value === 'string' && value.length > 0) parts.push(value);
  }
  // run_code 之类的工具会把代码放在嵌套结构里
  for (const key of Object.keys(args)) {
    const value = args[key];
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) parts.push(extractCommand(value));
  }
  return parts.filter((part) => part.length > 0).join('\n');
}

const ROOTISH = '(?:[a-zA-Z]:[\\\\/]|\\\\\\\\|/(?!\\S)|~|\\.|\\*|\\$HOME|%USERPROFILE%|%SystemDrive%|\\$env:USERPROFILE)';
const RECURSIVE = '(?:-Recurse|-r\\b|--recursive|-rf\\b|-fr\\b|/s\\b)';
const FORCE = '(?:-Force|-f\\b|--force|/f\\b|/q\\b)';

/** 规则表。test 对着"命令文本"跑；命中即进裁决。 */
export const RULES = [
  {
    id: 'recursive-force-delete-root',
    severity: SEVERITY.P0,
    test: new RegExp('(?:Remove-Item|rm|del|rd|rmdir|erase)\\b[^\\n]*' + RECURSIVE + '[^\\n]*' + FORCE + '[^\\n]*\\s' + ROOTISH + '(?:\\s|$)', 'i'),
    why: '递归 + 强制删除，目标看着像盘符根 / 家目录 / 通配符 —— 这类命令误伤的代价不可逆。',
    fix: '写成字面量的、最具体的路径；删除前先算出清单并落盘，或先移动到回收位置再删。',
  },
  {
    id: 'junction-recursive-delete',
    severity: SEVERITY.P0,
    test: /rmSync\s*\([^)]*recursive\s*:\s*true|rm\s+-rf\b|Remove-Item[^\n]*-Recurse[^\n]*(?:node_modules|\.pnpm|link)/i,
    why: 'Windows 上 fs.rmSync(recursive) / rm -rf 会穿透目录联接（junction）去删真正的目标；本项目真的这样删过源码。',
    fix: '先递归 lstat + unlinkSync 摘掉链接本身，再删实体目录；或直接删具体文件而不是整棵树。',
  },
  {
    id: 'disk-destructive',
    severity: SEVERITY.P0,
    test: /\b(?:format\s+[a-z]:|diskpart|Clear-Disk|Initialize-Disk|mkfs\.\w+|dd\s+if=\S+\s+of=\/dev\/)/i,
    why: '磁盘级操作：一次误跑就可能清掉整块盘。',
    fix: '这类操作只在用户明确要求且已知目标设备时手动执行，不要让 agent 代跑。',
  },
  {
    id: 'registry-write',
    severity: SEVERITY.P0,
    test: /\breg\s+(?:add|delete|import)\b|(?:Set|New|Remove)-ItemProperty[^\n]*(?:HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER)\s*:/i,
    why: '注册表写入可造成不可逆的系统级改动（自启、劫持、策略）。',
    fix: '先导出要改的键（reg export）留档，改动限定在用户级且可回滚的键。',
  },
  {
    id: 'download-and-execute',
    severity: SEVERITY.P0,
    test: /(?:curl|wget|iwr|Invoke-WebRequest)[^\n|]*\|[^\n]*(?:bash|sh|pwsh|powershell|iex|Invoke-Expression)|(?:iex|Invoke-Expression)\s*\(?\s*(?:\(?New-Object\s+Net\.WebClient\)?|Invoke-WebRequest|iwr|curl)/i,
    why: '下载即执行 = 把远端内容直接当代码跑，执行前没有审的余地。',
    fix: '先下载到本地落盘，读一遍内容再执行；固定版本与哈希。',
  },
  {
    id: 'credential-exposure',
    severity: SEVERITY.P0,
    test: /(?=[\s\S]*(?:\.credentials|\.ssh[\\/]|id_rsa|credentials\.yaml|\.env\b|Get-ChildItem\s+Env:|\[Environment\]::GetEnvironmentVariables))(?=[\s\S]*(?:curl|wget|Invoke-RestMethod|Invoke-WebRequest|iwr|nc\s|netcat|ftp|scp|Send-MailMessage))/i,
    why: '同一条命令里既有凭据读取又有外发动作 —— 典型的外泄形态。',
    fix: '凭据只从环境变量或密钥服务取，且绝不出现在会联网的命令里；需要外发就用专门的白名单接口。',
  },
  {
    id: 'credential-print',
    severity: SEVERITY.P1,
    test: /(?:Get-Content|type|cat|more)\b[^\n]*(?:\.credentials|id_rsa|\.env\b|credentials\.(?:yaml|yml|json|txt))/i,
    why: '把凭据正文打进终端/日志会留下痕迹（本机铁律之一：凭据不打印）。',
    fix: '只看结构或长度（例如按行数与键名统计），不要在输出里出现值。',
  },
  {
    id: 'git-destructive',
    severity: SEVERITY.P0,
    test: /\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-z]*[fdx]|\bgit\s+checkout\s+--\s+\.|\bgit\s+restore\s+\./i,
    why: '丢弃工作区改动不可逆；而且在有构建产物的仓库里，git 不管被 gitignore 的东西 —— 旧产物会被当成当前源码。',
    fix: '先 git stash 或复制一份备份；确认没有未提交的产物后再清理。',
  },
  {
    id: 'git-force-push',
    severity: SEVERITY.P1,
    test: /\bgit\s+push\b[^\n]*(?:--force\b|-f\b)[^\n]*(?:main|master)\b/i,
    why: '强推主干会覆盖远端历史。',
    fix: '改推分支并开 PR；确实要覆盖时先确认没有他人提交。',
  },
  {
    id: 'persistence-install',
    severity: SEVERITY.P1,
    test: /\bschtasks\b[^\n]*\/create|New-ScheduledTask|Register-ScheduledTask|New-ItemProperty[^\n]*Run\b|startup\b[^\n]*\.lnk/i,
    why: '建立开机自启/计划任务属于持久化改动，用户很在意（本机明确要求 dsh 不自启）。',
    fix: '先问用户；能手动跑的活不要装成常驻任务。',
  },
  {
    id: 'system-path-write',
    severity: SEVERITY.P1,
    test: /(?:Set-Content|Add-Content|Out-File|New-Item|Copy-Item|Move-Item)[^\n]*(?:C:\\\\Windows|C:\\\\Program Files|%SystemRoot%)/i,
    why: '写系统目录会影响其它程序，且通常需要提权。',
    fix: '改用户目录或工作区；确实需要动系统目录时先备份并说明回滚方式。',
  },
  {
    id: 'mass-permission-change',
    severity: SEVERITY.P1,
    test: /\bicacls\b[^\n]*\/grant|\btakeown\b|\bchmod\s+-R\s+777\b|\bchown\s+-R\b/i,
    why: '大范围改权限会削弱系统的既有保护（本机沙箱与哨兵都依赖 ACL/权限）。',
    fix: '只对最具体的对象改权限，改完记录原来的值。',
  },
  {
    id: 'process-kill-broad',
    severity: SEVERITY.P1,
    test: /\btaskkill\b[^\n]*\/im\b|\bStop-Process\b[^\n]*-Name\s+\S+[^\n]*-Force|\bkillall\b/i,
    why: '按名字杀进程会连带杀掉无关实例（本机有过 pkill 匹配到自己而自杀的实例）。',
    fix: '先拿到 PID 再按 PID 杀；用括号技巧避免匹配到自己的命令行。',
  },
];

/** 允许清单：命中这些就放行（用户自己的白名单）。 */
export function isAllowed(command, allowPatterns = []) {
  for (const pattern of allowPatterns) {
    try {
      if (new RegExp(pattern, 'i').test(command)) return true;
    } catch { /* 白名单写错了就当没有 */ }
  }
  return false;
}

/**
 * 判定一条命令。
 * @param command - 命令文本。
 * @param options - { allow?: string[] } 白名单正则。
 * @returns { decision: 'allow'|'advise'|'deny', matches: [{id,severity,why,fix,evidence}] }
 */
export function classify(command, options = {}) {
  const text = String(command ?? '');
  if (text.trim().length === 0) return { decision: 'allow', matches: [] };
  if (isAllowed(text, options.allow ?? [])) return { decision: 'allow', matches: [], allowed: true };
  const matches = [];
  for (const rule of RULES) {
    try {
      if (rule.test.test(text)) matches.push({ id: rule.id, severity: rule.severity, why: rule.why, fix: rule.fix });
    } catch { /* 单条规则出错不影响其它规则 */ }
  }
  if (matches.length === 0) return { decision: 'allow', matches: [] };
  const decision = matches.some((match) => match.severity === SEVERITY.P0) ? 'deny' : 'advise';
  return { decision, matches };
}

/** 给模型的拒绝说明：说清命中哪条、为什么、怎么写才对。 */
export function formatReason(verdict, command) {
  const lines = ['command-guard 拦下了这条命令（未执行）：'];
  for (const match of verdict.matches) {
    lines.push('- [' + match.severity + '] ' + match.id + '：' + match.why);
    lines.push('  改法：' + match.fix);
  }
  lines.push('命令原文：' + String(command ?? '').slice(0, 400));
  lines.push('如果你确认这条命令是安全的，请说明理由并把目标写成字面量后再试，或者让用户自己执行。');
  return lines.join('\n');
}
