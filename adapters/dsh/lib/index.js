/**
 * dsh-command-guard — DSH 侧的**薄适配器**。
 *
 * 设计来自 Elysia-laoda/command-guard 的分层：策略引擎（policy.mjs）与传送方式无关，
 * 换宿主只写一个适配器、引擎一行不改。这里就是那个适配器：
 *
 *   命令事件（tools/pre-execute） → 引擎 evaluate() → DSH 的 return 形状
 *                                            ↘ 审计 JSONL（与 ZCode 钩子同一份流水）
 *
 * 它**不写任何规则**：受保护范围、破坏性动词、递归/强制开关、变量插值判据全部来自
 * <guardRoot>/guard.json 与 <guardRoot>/src/policy.mjs。要调力度就改 guard.json 的 depth。
 *
 * 三条硬性纪律（与参考实现一致）：
 *   - **失败开放**：适配器自己出错一律放行并记 warning，绝不把 agent 卡死；
 *   - **只搬运字段**：不猜命令语义、不做字符串改写；
 *   - **每次都审计**：allow 也留一行 —— 那是"闸门到底有没有生效"的唯一证据。
 *
 * @module dsh-command-guard
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  addEntry,
  consume,
  describe as describeAllowlist,
  diffSnapshot,
  loadAllowlist,
  matchBypass,
  purge as purgeAllowlist,
  resume as resumeAllowlist,
  revokeEntry,
  snapshotNeighborhood,
  suspend as suspendAllowlist,
} from './allowlist.js';

/** 插件身份（cordis.yml 行里显示的名字）。 */
export const name = 'command-guard';

/** 不声明必需服务：拿不到引擎时插件照样装载，只是保持惰性。 */
export const inject = [];

const MAX_COMMAND_CHARS = 2000;
const MAX_AUDIT_BYTES = 4 * 1024 * 1024;

/** 从工具入参里抠命令文本（与参考实现的 commandOf 同思路：先常见字段，再浅层嵌套）。 */
export function commandOf(args) {
  if (args === undefined || args === null) return '';
  if (typeof args === 'string') return args;
  if (Array.isArray(args)) return args.map(commandOf).filter((part) => part.length > 0).join('\n');
  if (typeof args !== 'object') return String(args);
  const direct = ['command', 'cmd', 'script', 'code'];
  for (const field of direct) {
    const value = args[field];
    if (typeof value === 'string' && value.trim().length > 0) return value;
  }
  const parts = [];
  for (const key of Object.keys(args)) {
    const value = args[key];
    if (value !== null && typeof value === 'object') parts.push(commandOf(value));
  }
  return parts.filter((part) => part.length > 0).join('\n');
}

/** 工具名 → shell 提示（影响路径字面量解析）。 */
function shellOf(toolName) {
  const tool = String(toolName ?? '').toLowerCase();
  if (tool.includes('bash') || tool.includes('sh')) return 'bash';
  if (tool.includes('cmd')) return 'cmd';
  if (tool.includes('pwsh') || tool.includes('powershell')) return 'powershell';
  return undefined;
}

export function apply(ctx, config = {}) {
  const home = typeof config.dshHome === 'string' && config.dshHome.length > 0
    ? config.dshHome
    : (process.env.DSH_HOME && process.env.DSH_HOME.trim().length > 0 ? process.env.DSH_HOME.trim() : join(homedir(), '.dsh'));
  const guardRoot = resolve(typeof config.guardRoot === 'string' && config.guardRoot.length > 0
    ? config.guardRoot
    : (process.env.COMMAND_GUARD_ROOT && process.env.COMMAND_GUARD_ROOT.trim().length > 0
      ? process.env.COMMAND_GUARD_ROOT.trim()
      : join(home, 'command-guard')));
  const auditPath = resolve(typeof config.auditFile === 'string' && config.auditFile.length > 0
    ? config.auditFile
    : join(guardRoot, 'logs', 'audit.jsonl'));
  const mode = config.mode === 'advise' ? 'advise' : 'enforce';
  // 删除白名单：DSH 侧的窄缝，落在 ~/.dsh/command-guard/delete-allowlist.json
  // （不写进共享引擎的 guard.json —— 引擎要同时服务 ZCode，那条边界不越）。
  const allowlistFile = resolve(typeof config.allowlistFile === 'string' && config.allowlistFile.length > 0
    ? config.allowlistFile
    : join(home, 'command-guard', 'delete-allowlist.json'));
  const allowlistEnabled = config.allowlist !== false;
  const integrityEnabled = config.integrity !== false;
  // 提示里给出的白名单命令要指向**本包实际所在位置**，不能写死某个 checkout 路径。
  const allowScriptPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'allow.mjs');
  const PENDING_TTL_MS = 5 * 60 * 1000;
  /** 待校验的删除：pre 时快照父目录，post 时比对。 */
  const pending = [];

  // 只看 shell 类工具 —— 与参考实现一致（它的适配器只处理 Bash 工具调用）。
  // 为什么必须限定：run_code、写文件这类工具的载荷里**可以把命令文本当数据**，
  // 一律检查会把"写一条测试用例/写一份文档"误判成"要执行那条命令"。
  // （这不是假设：本适配器第一次上线就误拦了一个 run_code 程序。）
  const toolPatterns = Array.isArray(config.tools) && config.tools.length > 0
    ? config.tools.map((pattern) => new RegExp(String(pattern), 'i'))
    : [/^(?:pwsh|powershell|bash|sh|zsh|cmd|shell|terminal)$/i];
  const toolMatches = (toolName) => {
    const value = String(toolName ?? '');
    return toolPatterns.some((pattern) => pattern.test(value));
  };

  const warn = (where, error) => {
    try { ctx.logger?.warn?.('command-guard: ' + where + ' failed: ' + String(error)); } catch { /* logger 不可用也不能抛 */ }
  };

  /* ────────────────────────── 装载引擎 ────────────────────────── */

  const engine = { active: false, reason: '', rules: null, evaluate: null, source: '', sentinelName: '!000-guard', guardConfigPath: '' };

  async function loadEngine() {
    const policyPath = join(guardRoot, 'src', 'policy.mjs');
    const rulesPath = join(guardRoot, 'src', 'rules.mjs');
    if (!existsSync(policyPath)) {
      engine.active = false;
      engine.reason = '找不到策略引擎：' + policyPath + '（把 guardRoot 指向 command-guard 仓库，或设 COMMAND_GUARD_ROOT）';
      return engine;
    }
    try {
      const policy = await import(pathToFileURL(policyPath).href);
      engine.evaluate = policy.evaluate;
      engine.source = policyPath;
      let rules = policy.DEFAULT_RULES;
      if (existsSync(rulesPath)) {
        try {
          const rulesModule = await import(pathToFileURL(rulesPath).href);
          rules = rulesModule.loadRules({});
        } catch (error) {
          warn('loadRules', error);
        }
      }
      engine.rules = rules;
      // 顺手读一下 guard.json 的哨兵名与原始路径——用来报告"文件系统层装没装"
      const guardConfig = join(guardRoot, 'guard.json');
      engine.guardConfigPath = guardConfig;
      if (existsSync(guardConfig)) {
        try {
          const raw = JSON.parse(readFileSync(guardConfig, 'utf8'));
          if (typeof raw?.sentinelName === 'string' && raw.sentinelName.length > 0) engine.sentinelName = raw.sentinelName;
        } catch (error) { warn('guard.json', error); }
      }
      engine.active = typeof engine.evaluate === 'function';
      engine.reason = engine.active ? '' : '引擎没有导出 evaluate()';
      return engine;
    } catch (error) {
      engine.active = false;
      engine.reason = '装载引擎失败：' + String(error);
      warn('import policy', error);
      return engine;
    }
  }

  /* ────────────────────────── 审计 ────────────────────────── */

  let auditReady = false;
  function ensureAuditDir() {
    if (auditReady) return true;
    try { mkdirSync(dirname(auditPath), { recursive: true }); auditReady = true; } catch { /* 写不进去就跳过审计 */ }
    return auditReady;
  }

  function rotateIfNeeded() {
    try {
      const size = statSync(auditPath).size;
      if (size > MAX_AUDIT_BYTES) {
        const rotated = auditPath + '.1';
        try { appendFileSync(rotated, ''); } catch { /* ignore */ }
        readFileSync(auditPath); // 触发一次读，确保文件存在（失败也不影响判定）
      }
    } catch { /* 文件不存在等情形都忽略 */ }
  }

  function audit(record) {
    if (config.audit === false) return;
    try {
      if (!ensureAuditDir()) return;
      rotateIfNeeded();
      appendFileSync(auditPath, JSON.stringify(record) + '\n', 'utf8');
    } catch (error) {
      warn('audit write', error);
    }
  }

  /* ────────────────────────── 闸门 ────────────────────────── */

  function decide(exec) {
    const command = commandOf(exec?.arguments);
    if (command.trim().length === 0) return { verdict: 'allow', matched: null, reason: '', findings: [] };
    if (!engine.active) return { verdict: 'allow', matched: null, reason: 'engine-inactive', findings: [] };
    try {
      return engine.evaluate({ command, shell: shellOf(exec?.name), cwd: exec?.cwd, party: 'dsh' }, engine.rules);
    } catch (error) {
      warn('evaluate', error);
      return { verdict: 'allow', matched: null, reason: 'engine-error', findings: [] };
    }
  }

  const stats = { seen: 0, allow: 0, warn: 0, block: 0, bypassed: 0, denied: 0, lastAt: 0 };

  ctx.on('tools/pre-execute', async (exec, next) => {
    // 非 shell 工具一律不看不记：闸门的作用域就是"即将执行的命令"。
    if (!toolMatches(exec?.name)) return next();
    let verdict;
    try {
      verdict = decide(exec);
    } catch (error) {
      warn('pre-execute', error);
      return next();
    }

    // 白名单：只对 protected-depth 开一条窄缝。命中即放行，并留下"删前快照"等 post 比对。
    let bypass = null;
    if (verdict.verdict === 'block' && allowlistEnabled) {
      try {
        const state = loadAllowlist(allowlistFile);
        const match = matchBypass(state.entries, commandOf(exec?.arguments), verdict, { suspended: state.suspended });
        if (match.ok) {
          bypass = match.entries[0];
          if (integrityEnabled) {
            pending.push({
              at: Date.now(),
              tool: String(exec?.name ?? ''),
              target: bypass.target,
              note: bypass.entry.note,
              baseline: snapshotNeighborhood(bypass.target, { exclude: [auditPath, allowlistFile] }),
            });
            while (pending.length > 8) pending.shift();
          }
          consume(allowlistFile, match.entries);
          stats.bypassed += 1;
          verdict = {
            verdict: 'allow',
            matched: 'allowlist',
            reason: '白名单放行：' + bypass.entry.note,
            findings: verdict.findings ?? [],
          };
        }
      } catch (error) {
        warn('allowlist', error);
      }
    }

    const command = commandOf(exec?.arguments).slice(0, MAX_COMMAND_CHARS);
    stats.seen += 1;
    stats.lastAt = Date.now();
    if (verdict.verdict === 'allow') stats.allow += 1;
    else if (verdict.verdict === 'warn') stats.warn += 1;
    else stats.block += 1;

    audit({
      at: new Date().toISOString(),
      party: 'dsh',
      tool: exec?.name ?? null,
      verdict: verdict.verdict,
      rule: verdict.matched ?? null,
      reason: verdict.reason ?? '',
      command,
      ...(bypass ? { allowlist: { path: bypass.target, note: bypass.entry.note } } : {}),
    });

    if (verdict.verdict === 'block' && mode === 'enforce') {
      stats.denied += 1;
      return {
        kind: 'deny',
        reason: 'command-guard 拦下了这条命令（规则 ' + (verdict.matched ?? '?') + '）：' + verdict.reason
          + '\n命令原文：' + command.slice(0, 400)
          + '\n若确认安全：把目标写成字面量、去掉变量与递归/强制开关后重试；或让用户自己执行。'
          + '\n临时工具可走删除白名单（一次一个目标）：node ' + allowScriptPath + ' add "<路径>" --note "<原因>"',
      };
    }
    return next();
  });

  // 删后校验：只允许"目标自己消失"，邻近文件出现任何增删改即判定违规并挂起白名单。
  ctx.on('tools/post-execute', async (exec, result, next) => {
    if (!allowlistEnabled || !integrityEnabled) return next();
    const tool = String(exec?.name ?? '');
    if (!toolMatches(tool)) return next();
    const index = pending.findIndex((item) => item.tool === tool && Date.now() - item.at < PENDING_TTL_MS);
    if (index < 0) return next();
    const item = pending.splice(index, 1)[0];

    let report;
    try {
      report = diffSnapshot(item.baseline);
    } catch (error) {
      warn('integrity', error);
      return next();
    }

    const summary = {
      target: item.target,
      note: item.note,
      targetRemoved: report.targetRemoved,
      added: report.added,
      removed: report.removed,
      changed: report.changed,
      truncated: item.baseline.truncated,
    };
    audit({
      at: new Date().toISOString(),
      party: 'dsh',
      tool,
      verdict: report.ok ? 'allow' : 'block',
      rule: 'integrity',
      reason: report.ok ? '邻近文件未变' : '邻近文件发生非预期变化',
      command: '',
      integrity: summary,
    });

    if (!report.ok) {
      const detail = JSON.stringify({ added: report.added, removed: report.removed, changed: report.changed });
      suspendAllowlist(allowlistFile, 'integrity-violation ' + detail);
      warn('integrity', new Error('邻近文件完整性校验失败，白名单已挂起：' + detail));
    }
    return next();
  });

  /* ────────────────────────── 对外服务 ────────────────────────── */

  const allowlistSummary = () => {
    try {
      const view = describeAllowlist(allowlistFile);
      return {
        enabled: allowlistEnabled,
        integrity: integrityEnabled,
        file: allowlistFile,
        suspended: view.suspended,
        entries: view.entries.length,
        valid: view.entries.filter((entry) => entry.valid).length,
        errors: view.errors,
      };
    } catch (error) {
      return { enabled: allowlistEnabled, integrity: integrityEnabled, file: allowlistFile, errors: [String(error)] };
    }
  };

  const service = {
    /** 引擎是否装载成功（false 时闸门惰性放行）。 */
    status: () => ({
      active: engine.active,
      mode,
      allowlist: allowlistSummary(),
      guardRoot,
      guardConfigPath: engine.guardConfigPath,
      auditPath,
      source: engine.source,
      reason: engine.reason,
      protectedRoots: (engine.rules?.protectedRoots ?? []).map((entry) => {
        const path = typeof entry === 'string' ? entry : entry.path;
        const depth = typeof entry === 'string' ? (engine.rules?.defaultDepth ?? 1) : (entry.depth ?? engine.rules?.defaultDepth ?? 1);
        // 文件系统层（哨兵）与命令层是两道独立闸门：这里顺手报一下哨兵在不在，
        // 免得"以为装了两层，其实只有一层"。
        let sentinel = false;
        try { sentinel = path ? existsSync(join(String(path), engine.sentinelName)) : false; } catch { /* ignore */ }
        return { path, depth, sentinel, sentinelName: engine.sentinelName };
      }),
      defaultDepth: engine.rules?.defaultDepth ?? null,
      tools: toolPatterns.map((pattern) => String(pattern)),
      stats: { ...stats },
    }),
    /** 纯判定，不执行、不审计 —— 给测试、别的插件、以及"先问一句会怎样"用。 */
    evaluate: (command, options = {}) => (engine.active
      ? engine.evaluate({ command, shell: options.shell, cwd: options.cwd, party: 'dsh' }, engine.rules)
      : { verdict: 'allow', matched: null, reason: 'engine-inactive', findings: [] }),
    rules: () => engine.rules,
    auditPath: () => auditPath,
    /** 删除白名单：AI 侧把要删的临时产物写进来，删一条消耗一条。 */
    allowlist: {
      file: () => allowlistFile,
      list: () => describeAllowlist(allowlistFile),
      add: (path, options = {}) => addEntry(allowlistFile, { path, ...options }),
      revoke: (path) => revokeEntry(allowlistFile, path),
      purge: () => purgeAllowlist(allowlistFile),
      suspend: (reason) => suspendAllowlist(allowlistFile, reason),
      resume: () => resumeAllowlist(allowlistFile),
    },
    /** 读审计尾部（排查"闸门到底生效没有"）。 */
    tail: (lines = 20) => {
      try {
        const text = readFileSync(auditPath, 'utf8').trimEnd();
        const all = text.length === 0 ? [] : text.split('\n');
        return all.slice(-Math.max(1, lines)).map((line) => { try { return JSON.parse(line); } catch { return { raw: line }; } });
      } catch { return []; }
    },
  };

  /** 等引擎装载完（测试、e2e、别的插件用它确定性地等）。 */
  service.ready = () => engineReady.then(() => service.status());

  try { ctx.provide('commandGuard', service); } catch (error) { warn('provide', error); }

  /** 引擎装载是一次性的：拿不到就保持惰性放行。 */
  const engineReady = loadEngine();

  // 引擎装载放在后台：拿不到引擎不影响装载，也不会卡住宿主启动。
  void engineReady.then((result) => {
    if (result.active) {
      const roots = (result.rules?.protectedRoots ?? []).length;
      try { ctx.logger?.info?.('command-guard: 已接管 tools/pre-execute（受保护范围 ' + roots + ' 条，审计 ' + auditPath + '）'); } catch { /* ignore */ }
    } else {
      warn('engine', result.reason);
    }
  });
}

/** 便于测试直接引用。 */
export const META = { MAX_COMMAND_CHARS, MAX_AUDIT_BYTES };
