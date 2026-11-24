/**
 * dsh-command-guard — 删除白名单（allowlist）。
 *
 * 解决的问题：受保护根往下 1 层是"防手滑"的红线，但 agent 的临时工具（`_ver.js`、
 * `_probe.mjs` 之类）正好长在这一层，删不掉就只会越堆越多。于是给一条**显式、可审计、
 * 会过期**的窄缝：先把目标写进清单，删除命令才放行。
 *
 * 设计要点（每一条都是为了"清单本身不能变成洞"）：
 *   - **只对 protected-depth 生效**：变量插值、通配符、卷根、哨兵目录等规则不被绕过；
 *   - **精确匹配**：命令里的每个绝对路径目标都必须逐字命中清单条目，不做前缀/正则匹配；
 *   - **一次只删一个**：一条命令里出现 2 个及以上绝对路径目标即拒绝（批删最容易误伤）；
 *   - **前后扫描**：删前给父目录做快照（名称/类型/大小/mtime + 小文件 sha256），删后比对，
 *     邻近文件有任何非预期增删改就判定违规；
 *   - **违规即挂起**：一旦检出非预期变化，整个白名单自动挂起，必须人工 `resume` 才能再用；
 *   - **一次性 + 过期**：默认用一次就消耗、24 小时过期，避免陈旧清单变成常驻后门；
 *   - **写入即校验**：根目录、系统目录、`.dsh`、哨兵目录、目录联接一律拒绝入单；
 *   - **每次放行都审计**：审计行带条目备注与完整性结论，事后能回答"凭什么放行、删掉了什么"。
 *
 * 文件位置默认 `<DSH_HOME>/command-guard/delete-allowlist.json`（DSH 侧，不落在共享引擎里）。
 *
 * @module dsh-command-guard/allowlist
 */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, win32 } from 'node:path';

export const ALLOWLIST_VERSION = 2;

/** 默认有效期与可用次数：窄缝要小。 */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_USES = 1;
export const MAX_ENTRIES = 200;
export const MAX_NOTE_CHARS = 200;

/** 只有这些规则允许被白名单放行（其余一律硬拦）。 */
export const BYPASSABLE_RULES = new Set(['protected-depth']);

/** 永远不允许出现在白名单里的子树（规范化小写后比对）。 */
export const DENY_SUBTREES = [
  'c:\\windows',
  'c:\\program files',
  'c:\\program files (x86)',
  'c:\\programdata',
  'c:\\users\\default',
  'd:\\zcodeprojecttt',
  'd:\\vms',
  'c:\\users\\27096\\.dsh',
];

/** 哨兵目录名：出现在目标路径里时拒绝。 */
export const SENTINEL_NAME = '!000-guard';

/** 邻近扫描上限：时间换安全，但不能把一次删除拖成分钟级。 */
export const SCAN_LIMITS = { maxSiblings: 400, maxHashedFiles: 40, maxHashBytes: 512 * 1024 };

const lower = (value) => String(value).replace(/\//g, '\\').toLowerCase();

/* ────────────────────────── 路径与条目校验 ────────────────────────── */

/** 把用户输入的路径规范化为绝对、无反斜杠歧义的 win32 路径。 */
export function normalizePath(raw) {
  if (typeof raw !== 'string' || raw.trim().length === 0) return { ok: false, error: '路径为空' };
  const text = raw.trim();
  if (/[*?]/.test(text)) return { ok: false, error: '不允许通配符' };
  if (/[%$]/.test(text)) return { ok: false, error: '不允许环境变量或插值' };
  if (!win32.isAbsolute(text)) return { ok: false, error: '必须是绝对路径' };
  if (text.split(/[\\/]/).some((segment) => segment === '..')) return { ok: false, error: '不允许 .. 片段' };
  const normalized = win32.normalize(text);
  return { ok: true, path: normalized };
}

/** 目标本身、或它的某个祖先，是否落在拒绝子树里。 */
export function inDenySubtree(normalizedPath) {
  const value = lower(normalizedPath).replace(/\\+$/, '');
  for (const deny of DENY_SUBTREES) {
    if (value === deny || value.startsWith(deny + '\\')) return deny;
  }
  return null;
}

export function isVolumeRoot(normalizedPath) {
  return /^[a-z]:\\?$/i.test(normalizedPath);
}

export function hasSentinel(normalizedPath) {
  return lower(normalizedPath).split('\\').includes(SENTINEL_NAME.toLowerCase());
}

/** 目录联接/符号链接：递归删除会穿透到真实目标，不允许进白名单。 */
export function isLinkLike(normalizedPath) {
  try {
    const stat = lstatSync(normalizedPath);
    if (stat.isSymbolicLink()) return true;
    return typeof stat.isReparsePoint === 'function' && stat.isReparsePoint();
  } catch {
    return false;
  }
}

/**
 * 校验一条待加入的条目。
 * @returns {{ok: true, entry: object} | {ok: false, errors: string[]}}
 */
export function validateEntry(input, { now = Date.now(), ttlMs = DEFAULT_TTL_MS, uses = DEFAULT_USES } = {}) {
  const errors = [];
  const normalized = normalizePath(input?.path);
  if (!normalized.ok) errors.push(normalized.error);
  const target = normalized.ok ? normalized.path : '';

  if (normalized.ok) {
    if (isVolumeRoot(target)) errors.push('不能是卷根');
    const deny = inDenySubtree(target);
    if (deny) errors.push('落在拒绝子树：' + deny);
    if (hasSentinel(target)) errors.push('目标位于/等于哨兵目录 ' + SENTINEL_NAME);
    if (isLinkLike(target)) errors.push('目标是目录联接/符号链接，递归删除会穿透');
  }

  const note = typeof input?.note === 'string' ? input.note.trim() : '';
  if (note.length === 0) errors.push('必须写 note（说明为什么要删）');
  if (note.length > MAX_NOTE_CHARS) errors.push('note 超过 ' + MAX_NOTE_CHARS + ' 字');

  const kind = input?.kind ?? 'any';
  if (!['file', 'dir', 'any'].includes(kind)) errors.push('kind 只能是 file/dir/any');

  const usesLeft = Number.isInteger(input?.usesLeft) ? input.usesLeft : uses;
  if (!Number.isInteger(usesLeft) || usesLeft < 1 || usesLeft > 50) errors.push('usesLeft 必须在 1..50');

  const expiresAt = typeof input?.expiresAt === 'string'
    ? Date.parse(input.expiresAt)
    : now + (Number.isFinite(input?.ttlHours) ? input.ttlHours * 3600 * 1000 : ttlMs);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) errors.push('过期时间必须在将来');

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    entry: {
      path: target,
      key: lower(target),
      kind,
      note,
      addedAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
      usesLeft,
    },
  };
}

/* ────────────────────────── 清单读写 ────────────────────────── */

export function loadAllowlist(file) {
  if (!existsSync(file)) return { ok: true, entries: [], suspended: null, errors: [] };
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8'));
    const entries = Array.isArray(raw?.entries) ? raw.entries.filter((entry) => typeof entry?.path === 'string') : [];
    const suspended = raw?.suspended && typeof raw.suspended === 'object' ? raw.suspended : null;
    return { ok: true, entries, suspended, errors: [] };
  } catch (error) {
    return { ok: false, entries: [], suspended: null, errors: ['清单解析失败：' + String(error?.message ?? error)] };
  }
}

/** 原子写清单（先写临时文件再 rename，避免半截 JSON）。 */
export function saveAllowlist(file, state) {
  mkdirSync(dirname(file), { recursive: true });
  const payload = {
    version: ALLOWLIST_VERSION,
    updatedAt: new Date().toISOString(),
    suspended: state.suspended ?? null,
    entries: state.entries.slice(0, MAX_ENTRIES),
  };
  const tmp = join(dirname(file), '.' + Date.now() + '-' + process.pid + '.tmp');
  writeFileSync(tmp, JSON.stringify(payload, null, 2) + '\n', 'utf8');
  renameSync(tmp, file);
  return payload;
}

export function addEntry(file, input, options = {}) {
  const checked = validateEntry(input, options);
  if (!checked.ok) return { ok: false, errors: checked.errors };
  const state = loadAllowlist(file);
  const entries = state.entries.filter((entry) => lower(entry.path) !== checked.entry.key);
  entries.unshift(checked.entry);
  if (entries.length > MAX_ENTRIES) return { ok: false, errors: ['清单条目超过上限 ' + MAX_ENTRIES] };
  saveAllowlist(file, { entries, suspended: state.suspended });
  return { ok: true, entry: checked.entry };
}

export function revokeEntry(file, rawPath) {
  const normalized = normalizePath(rawPath);
  if (!normalized.ok) return { ok: false, errors: [normalized.error] };
  const state = loadAllowlist(file);
  const before = state.entries.length;
  const entries = state.entries.filter((entry) => lower(entry.path) !== lower(normalized.path));
  saveAllowlist(file, { entries, suspended: state.suspended });
  return { ok: true, removed: before - entries.length };
}

/** 清掉过期与用尽的条目。 */
export function purge(file, now = Date.now()) {
  const state = loadAllowlist(file);
  const entries = state.entries.filter((entry) => {
    const expires = Date.parse(entry.expiresAt);
    const uses = Number.isInteger(entry.usesLeft) ? entry.usesLeft : 0;
    return (Number.isFinite(expires) ? expires > now : true) && uses > 0;
  });
  saveAllowlist(file, { entries, suspended: state.suspended });
  return { ok: true, kept: entries.length, dropped: state.entries.length - entries.length };
}

/** 违规后挂起：保留条目，但拒绝一切放行，直到人工 resume。 */
export function suspend(file, reason) {
  const state = loadAllowlist(file);
  const suspended = { at: new Date().toISOString(), reason: String(reason ?? 'integrity-violation') };
  saveAllowlist(file, { entries: state.entries, suspended });
  return { ok: true, suspended };
}

export function resume(file) {
  const state = loadAllowlist(file);
  const had = state.suspended;
  saveAllowlist(file, { entries: state.entries, suspended: null });
  return { ok: true, resumed: had !== null, previous: had };
}

/* ────────────────────────── 命令目标抽取 ────────────────────────── */

/**
 * 从命令文本里抽出"绝对路径目标"。保守实现：
 *   - 命令里出现 `$` `%` `*` `?` 一律视为不安全（与 var-in-destructive 同向）；
 *   - 只认带盘符的绝对路径（引号内或裸写）。
 */
export function extractTargets(command) {
  const text = String(command ?? '');
  if (text.trim().length === 0) return { ok: false, reason: '空命令', targets: [] };
  if (/[$%*?]/.test(text)) return { ok: false, reason: '命令含变量或通配符，白名单不适用', targets: [] };

  const found = new Set();
  const quoted = /'([^']+)'|"([^"]+)"/g;
  let match;
  while ((match = quoted.exec(text)) !== null) {
    const value = match[1] ?? match[2] ?? '';
    if (/^[a-zA-Z]:[\\/]/.test(value)) found.add(value);
  }
  const bare = /[a-zA-Z]:[\\/][^\s'"`,;|)&<>]+/g;
  while ((match = bare.exec(text)) !== null) found.add(match[0]);

  const targets = [];
  for (const value of found) {
    const normalized = normalizePath(value);
    if (normalized.ok) targets.push(normalized.path);
  }
  return { ok: targets.length > 0, reason: targets.length > 0 ? '' : '没抽到绝对路径目标', targets };
}

/* ────────────────────────── 邻近文件完整性 ────────────────────────── */

function sha256Of(file, size) {
  if (!Number.isFinite(size) || size > SCAN_LIMITS.maxHashBytes) return null;
  try {
    return createHash('sha256').update(readFileSync(file)).digest('hex');
  } catch {
    return null;
  }
}

function statOf(file) {
  try {
    const stat = lstatSync(file);
    return {
      type: stat.isDirectory() ? 'dir' : stat.isSymbolicLink() ? 'link' : 'file',
      size: stat.size,
      mtimeMs: Math.round(stat.mtimeMs),
    };
  } catch {
    return { type: 'missing', size: 0, mtimeMs: 0 };
  }
}

/**
 * 给目标所在目录做快照（只看**直接子项**，排除目标自己与自身管理文件）。
 * 时间换安全：小文件额外算 sha256，大文件只比大小与 mtime。
 * @param {string} target
 * @param {{exclude?: string[]}} [options] 自身文件（审计/清单）不参与比对
 */
export function snapshotNeighborhood(target, options = {}) {
  const parent = dirname(target);
  const targetName = lower(basename(target));
  const excluded = new Set((options.exclude ?? []).map((value) => lower(value)));
  const siblings = new Map();
  let hashed = 0;
  let listing = [];
  try {
    listing = readdirSync(parent, { withFileTypes: true }).slice(0, SCAN_LIMITS.maxSiblings);
  } catch {
    listing = [];
  }
  for (const entry of listing) {
    const key = lower(entry.name);
    if (key === targetName) continue;
    const full = join(parent, entry.name);
    if (excluded.has(lower(full))) continue;
    const info = statOf(full);
    if (info.type === 'file' && hashed < SCAN_LIMITS.maxHashedFiles) {
      info.hash = sha256Of(full, info.size);
      if (info.hash) hashed += 1;
    }
    siblings.set(key, info);
  }
  return {
    target,
    parent,
    at: Date.now(),
    targetExists: existsSync(target),
    targetStat: statOf(target),
    siblings,
    hashed,
    exclude: [...excluded],
    truncated: listing.length >= SCAN_LIMITS.maxSiblings,
  };
}

/**
 * 删后比对：目标必须消失；邻近条目只允许"消失的只有目标自己"。
 * @returns {{ok: boolean, targetRemoved: boolean, added: string[], removed: string[], changed: string[]}}
 */
export function diffSnapshot(baseline) {
  const current = snapshotNeighborhood(baseline.target, { exclude: baseline.exclude ?? [] });
  const added = [];
  const removed = [];
  const changed = [];

  for (const [key, info] of current.siblings) {
    const before = baseline.siblings.get(key);
    if (!before) { added.push(key); continue; }
    if (before.type !== info.type || before.size !== info.size || before.mtimeMs !== info.mtimeMs
      || (before.hash && info.hash && before.hash !== info.hash)) {
      changed.push(key);
    }
  }
  for (const key of baseline.siblings.keys()) {
    if (!current.siblings.has(key)) removed.push(key);
  }

  const targetRemoved = baseline.targetExists && !current.targetExists;
  const ok = added.length === 0 && removed.length === 0 && changed.length === 0;
  return { ok, targetRemoved, added, removed, changed, current };
}

/* ────────────────────────── 放行判定 ────────────────────────── */

/**
 * 判定一次放行。
 * @returns {{ok: true, entries: Array<{entry: object, target: string}>} | {ok: false, reason: string}}
 */
export function matchBypass(entries, command, verdict, { now = Date.now(), suspended = null } = {}) {
  if (suspended) return { ok: false, reason: '白名单已挂起（' + String(suspended.reason ?? '') + '），需人工 resume' };
  if (!BYPASSABLE_RULES.has(String(verdict?.matched ?? ''))) {
    return { ok: false, reason: '规则 ' + String(verdict?.matched ?? '?') + ' 不在可放行范围' };
  }
  const extracted = extractTargets(command);
  if (!extracted.ok) return { ok: false, reason: extracted.reason };
  if (extracted.targets.length > 1) {
    return { ok: false, reason: '一次只允许删一个目标（当前 ' + extracted.targets.length + ' 个），请逐条执行' };
  }

  const active = entries.filter((entry) => {
    const expires = Date.parse(entry.expiresAt);
    const uses = Number.isInteger(entry.usesLeft) ? entry.usesLeft : 0;
    return uses > 0 && (!Number.isFinite(expires) || expires > now);
  });
  const byKey = new Map(active.map((entry) => [lower(entry.path), entry]));

  const matched = [];
  for (const target of extracted.targets) {
    const entry = byKey.get(lower(target));
    if (!entry) return { ok: false, reason: '目标不在白名单：' + target };
    if (entry.kind === 'file' && existsSync(target) && !lstatSync(target).isFile()) {
      return { ok: false, reason: '条目声明为 file，但目标是目录：' + target };
    }
    if (entry.kind === 'dir' && existsSync(target) && !lstatSync(target).isDirectory()) {
      return { ok: false, reason: '条目声明为 dir，但目标是文件：' + target };
    }
    if (isLinkLike(target)) return { ok: false, reason: '目标是目录联接/符号链接：' + target };
    matched.push({ entry, target });
  }
  return { ok: true, entries: matched };
}

/** 消耗一次使用额度（放行成功后调用）。 */
export function consume(file, matched, now = Date.now()) {
  const keys = new Set(matched.map((item) => lower(item.entry.path)));
  const state = loadAllowlist(file);
  const entries = [];
  for (const entry of state.entries) {
    const key = lower(entry.path);
    if (!keys.has(key)) { entries.push(entry); continue; }
    const uses = (Number.isInteger(entry.usesLeft) ? entry.usesLeft : 1) - 1;
    if (uses > 0) entries.push({ ...entry, usesLeft: uses, lastUsedAt: new Date(now).toISOString() });
  }
  saveAllowlist(file, { entries, suspended: state.suspended });
  return entries.length;
}

/* ────────────────────────── 展示 ────────────────────────── */

export function describe(file, now = Date.now()) {
  const state = loadAllowlist(file);
  return {
    file,
    ok: state.ok,
    suspended: state.suspended,
    errors: state.errors,
    entries: state.entries.map((entry) => {
      const expires = Date.parse(entry.expiresAt);
      const expired = Number.isFinite(expires) ? expires <= now : false;
      const usesLeft = Number.isInteger(entry.usesLeft) ? entry.usesLeft : 0;
      return { ...entry, expired, valid: !expired && usesLeft > 0 };
    }),
  };
}

export function ensure(file) {
  if (existsSync(file)) return false;
  saveAllowlist(file, { entries: [], suspended: null });
  return true;
}

export const META = {
  ALLOWLIST_VERSION,
  DEFAULT_TTL_MS,
  DEFAULT_USES,
  MAX_ENTRIES,
  BYPASSABLE_RULES,
  DENY_SUBTREES,
  SENTINEL_NAME,
  SCAN_LIMITS,
};
