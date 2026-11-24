/**
 * 安装/卸载共用的档案读写工具。
 *
 * 关键事实（来自 dsh 源码 profile-boot）：`<profile>/cordis.yml` 是**每次启动
 * 重新生成**的产物（"Edit cordis.patch.yml, not this file"）。真正的输入是：
 *
 *   package.json 的 `dsh.profile.bundles`（按顺序叠加每个包的 dsh.bundle.patch）
 *   → `cordis.patch.yml`（本档案的用户层）
 *   → `$DSH_HOME/cordis.patch.yml`（机器级）+ `--patch` 覆盖层
 *
 * 所以安装 = 把包放进 `<profile>/node_modules/` + 把它追加进 bundles。
 * 不去碰 cordis.yml（下次启动会被重写，改了也没用）。
 *
 * @module dsh-command-guard/scripts/profile-io
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, cpSync, symlinkSync, lstatSync, readdirSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

export const PACKAGE_NAME = 'dsh-command-guard';

/** 兜底清单：读不到 package.json 的 files 字段时用这个。 */
export const SHIP_FILES = ['package.json', 'cordis.patch.yml', 'icon.svg', 'lib', 'skills', 'scripts', 'e2e', 'docs', 'README.md', 'LICENSE'];

/**
 * 该复制进 profile 的文件清单。
 *
 * 以 package.json 的 `files` 为准（单一事实来源），再补上 package.json 自己。
 * 之前这里是硬编码的，结果 `docs/`、`e2e/` 加进 files 之后装出来的副本少了它们，
 * README 里的图全裂 —— 复制清单和发布清单不该有两份。
 *
 * @param sourceDir - 包根目录。
 * @returns 相对包根的文件/目录名数组。
 */
export function shipFiles(sourceDir) {
  try {
    const manifest = JSON.parse(readFileSync(join(sourceDir, 'package.json'), 'utf8'));
    if (Array.isArray(manifest.files) && manifest.files.length > 0) {
      const list = manifest.files.filter((entry) => typeof entry === 'string' && !entry.includes('*'));
      if (!list.includes('package.json')) list.unshift('package.json');
      return list;
    }
  } catch { /* 落到兜底清单 */ }
  return SHIP_FILES;
}

export function parseArgv(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) { out._.push(token); continue; }
    const eq = token.indexOf('=');
    if (eq > 0) { out[token.slice(2, eq)] = token.slice(eq + 1); continue; }
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) { out[key] = next; i += 1; } else { out[key] = true; }
  }
  return out;
}

export function resolveHome(options = {}) {
  const fromFlag = typeof options.home === 'string' ? options.home : undefined;
  const fromEnv = process.env.DSH_HOME && process.env.DSH_HOME.trim().length > 0 ? process.env.DSH_HOME.trim() : undefined;
  return resolve(fromFlag ?? fromEnv ?? join(homedir(), '.dsh'));
}

export function resolveProfileName(options = {}) {
  const fromFlag = typeof options.profile === 'string' ? options.profile : undefined;
  const fromEnv = process.env.DSH_PROFILE && process.env.DSH_PROFILE.trim().length > 0 ? process.env.DSH_PROFILE.trim() : undefined;
  return fromFlag ?? fromEnv ?? 'desktop';
}

export function resolveProfileDir(options = {}) {
  return join(resolveHome(options), 'profiles', resolveProfileName(options));
}

export function timestamp() {
  const now = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

/** 读 JSON；文件不存在返回 undefined，解析失败抛错（宁可停下来也别写坏）。 */
export function readJson(file) {
  if (!existsSync(file)) return undefined;
  return JSON.parse(readFileSync(file, 'utf8'));
}

export function writeJson(file, value, backupSuffix) {
  if (backupSuffix) writeFileSync(file + '.bak-' + backupSuffix, readFileSync(file));
  writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

/**
 * 把包放进 profile 的 node_modules。默认建目录联接（pnpm 的 link 协议）。
 *
 * 默认必须是链接而不是复制：复制出来的目录没有依赖记录，DSH 更新时会按 lockfile
 * 把 node_modules 回收一遍，插件就静默消失了 —— 2026-10 的那次更新正是这样把
 * dsh-command-guard（本防线）连根拔掉的，之后才发生了误删未遂。
 *
 * @returns {{target:string, mode:'link'|'copy'}}
 */
export function placePackage(sourceDir, profileDir, options = {}) {
  const target = join(profileDir, 'node_modules', PACKAGE_NAME);
  mkdirSync(join(profileDir, 'node_modules'), { recursive: true });
  if (existsSync(target) || isLink(target)) {
    removeTree(target);
  }
  if (options.link !== false) {
    symlinkSync(sourceDir, target, 'junction');
    return { target, mode: 'link' };
  }
  for (const entry of shipFiles(sourceDir)) {
    const from = join(sourceDir, entry);
    if (!existsSync(from)) continue;
    cpSync(from, join(target, entry), { recursive: true });
  }
  return { target, mode: 'copy' };
}

export function isLink(path) {
  try { return lstatSync(path).isSymbolicLink(); } catch { return false; }
}

/** 把绝对路径转成 pnpm 认的 POSIX 形式。 */
export function toPosixPath(value) {
  return value.replace(/\\/g, '/');
}

/** 该写进 dependencies 的说明符。 */
export function linkSpecifier(sourceDir) {
  return 'link:' + toPosixPath(resolve(sourceDir));
}

/**
 * 把本包登记进 profile 的 `dependencies`（`link:<源目录>`，幂等）。
 * 没有依赖记录的包会被 pnpm 按 lockfile 回收 —— 这是"更新之后插件还在"的关键。
 */
export function addDependency(manifestPath, sourceDir, backupSuffix) {
  const manifest = readJson(manifestPath);
  if (!manifest) throw new Error('找不到 profile 的 package.json：' + manifestPath);
  const specifier = linkSpecifier(sourceDir);
  manifest.dependencies ??= {};
  if (manifest.dependencies[PACKAGE_NAME] === specifier) return { changed: false, specifier };
  manifest.dependencies[PACKAGE_NAME] = specifier;
  manifest.dependencies = Object.fromEntries(Object.entries(manifest.dependencies).sort(([a], [b]) => a.localeCompare(b)));
  writeJson(manifestPath, manifest, backupSuffix);
  return { changed: true, specifier };
}

/** 从 `dependencies` 里摘掉本包（幂等）。 */
export function removeDependency(manifestPath, backupSuffix) {
  const manifest = readJson(manifestPath);
  if (!manifest?.dependencies || !(PACKAGE_NAME in manifest.dependencies)) return { changed: false };
  delete manifest.dependencies[PACKAGE_NAME];
  writeJson(manifestPath, manifest, backupSuffix);
  return { changed: true };
}

/**
 * 在 profile 目录里跑一次 `pnpm install`，让 dependencies 的改动落进 pnpm-lock.yaml。
 * 只改 package.json 不跑 pnpm，lockfile 会过期；DSH 更新若用 --frozen-lockfile 会整体失败。
 */
export function runPnpmInstall(profileDir) {
  const args = ['install', '--reporter=append-only'];
  const command = process.platform === 'win32' ? 'cmd.exe' : 'pnpm';
  const argv = process.platform === 'win32' ? ['/d', '/s', '/c', 'pnpm ' + args.join(' ')] : args;
  const result = spawnSync(command, argv, { cwd: profileDir, encoding: 'utf8', timeout: 10 * 60 * 1000 });
  if (result.error) return { ok: false, output: String(result.error.message ?? result.error) };
  const output = ((result.stdout ?? '') + (result.stderr ?? '')).trim();
  return { ok: result.status === 0, output: output.split(/\r?\n/).slice(-6).join('\n') };
}

/**
 * 安全地删掉一棵目录树。
 *
 * `fs.rmSync(path, { recursive: true })` 在 Windows 上遇到目录联接（junction）会**穿透**
 * 它去删真正的目标 —— 也就是说用 `--link` 装过插件之后，删 profile 会把插件源码删掉。
 * （这不是理论风险：本项目的 e2e 跑手真的这样删过一次源码。）
 * 所以先递归把树里所有链接/联接单独 unlink 掉，再删剩下的实体目录。
 *
 * @param path - 要删的路径。
 * @returns 是否删掉了东西。
 */
export function removeTree(path) {
  if (!existsSync(path) && !isLink(path)) return false;
  if (isLink(path)) {
    unlinkSync(path); // 只摘链接本身，不碰目标
    return true;
  }
  let entries = [];
  try { entries = readdirSync(path, { withFileTypes: true }); } catch { /* 读不动就直接删 */ }
  for (const entry of entries) {
    const child = join(path, entry.name);
    if (isLink(child)) {
      try { unlinkSync(child); } catch { /* ignore */ }
    } else if (entry.isDirectory()) {
      removeTree(child);
    }
  }
  rmSync(path, { recursive: true, force: true });
  return true;
}

export function removePackage(profileDir) {
  const target = join(profileDir, 'node_modules', PACKAGE_NAME);
  if (!existsSync(target) && !isLink(target)) return false;
  removeTree(target);
  return true;
}

/** 把包名追加进 `dsh.profile.bundles`（幂等）。 */
export function addBundle(manifestPath, backupSuffix) {
  const manifest = readJson(manifestPath);
  if (!manifest) throw new Error('找不到 profile 的 package.json：' + manifestPath);
  manifest.dsh ??= {};
  manifest.dsh.profile ??= {};
  const bundles = Array.isArray(manifest.dsh.profile.bundles) ? manifest.dsh.profile.bundles : [];
  if (bundles.includes(PACKAGE_NAME)) return { changed: false, bundles };
  bundles.push(PACKAGE_NAME);
  manifest.dsh.profile.bundles = bundles;
  writeJson(manifestPath, manifest, backupSuffix);
  return { changed: true, bundles };
}

/** 从 `dsh.profile.bundles` 里摘掉包名（幂等）。 */
export function removeBundle(manifestPath, backupSuffix) {
  const manifest = readJson(manifestPath);
  if (!manifest) return { changed: false };
  const bundles = manifest.dsh?.profile?.bundles;
  if (!Array.isArray(bundles) || !bundles.includes(PACKAGE_NAME)) return { changed: false };
  manifest.dsh.profile.bundles = bundles.filter((name) => name !== PACKAGE_NAME);
  writeJson(manifestPath, manifest, backupSuffix);
  return { changed: true };
}