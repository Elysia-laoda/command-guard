#!/usr/bin/env node
/**
 * dsh-command-guard 一键安装（薄适配器：装进档案，重启生效）。
 *   node scripts/install.mjs [--profile desktop] [--home D:\dshhome] [--copy] [--no-pnpm] [--dry-run] [--json]
 *
 * 做四件事（都不碰会被重写的 cordis.yml）：
 *   1. 在 <profile>/node_modules/dsh-command-guard 建目录联接 → 本目录；
 *   2. 把包名追加进 dsh.profile.bundles；
 *   3. 在 dependencies 里写 link:<本目录>；
 *   4. 跑一次 pnpm install 落进 pnpm-lock.yaml。
 *
 * 3、4 步不能省：DSH 更新会按 lockfile 回收 node_modules，没有依赖记录的插件会被删掉。
 * 2026-10 的更新就是这样把本防线整个拔掉的 —— 闸门关着的时候才发生了那次误删未遂。
 */
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PACKAGE_NAME, addBundle, addDependency, parseArgv, placePackage, readJson,
  resolveHome, resolveProfileDir, resolveProfileName, runPnpmInstall, timestamp,
} from './profile-io.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const sourceDir = resolve(here, '..');

const options = parseArgv(process.argv.slice(2));
const home = resolveHome(options);
const profile = resolveProfileName(options);
const profileDir = resolveProfileDir(options);
const manifestPath = join(profileDir, 'package.json');
const dryRun = options['dry-run'] === true;
const asJson = options.json === true;
const useLink = options.copy !== true;
const runPnpm = options['no-pnpm'] !== true;

const report = { home, profile, profileDir, sourceDir, dryRun, steps: [], ok: false, warnings: [] };
if (!existsSync(profileDir) || !existsSync(manifestPath)) {
  process.stderr.write('档案不存在：' + profileDir + '\n');
  process.exit(1);
}
const manifest = readJson(manifestPath);
if (!manifest || !manifest.dsh) report.warnings.push('这个 package.json 里没有 dsh 段，可能不是 DSH 档案');
if (!useLink) report.warnings.push('--copy 是临时调试模式：复制出来的目录没有依赖记录，DSH 更新时会被 pnpm 回收');

if (dryRun) {
  report.steps.push({ action: 'place-package', target: join(profileDir, 'node_modules', PACKAGE_NAME), mode: useLink ? 'link' : 'copy' });
  report.steps.push({ action: 'add-bundle', manifest: manifestPath, bundle: PACKAGE_NAME });
  if (useLink) report.steps.push({ action: 'add-dependency', manifest: manifestPath, specifier: 'link:' + sourceDir.replace(/\\/g, '/') });
  report.ok = true;
} else {
  const suffix = timestamp();
  const placed = placePackage(sourceDir, profileDir, { link: useLink });
  report.steps.push({ action: 'place-package', target: placed.target, mode: placed.mode });

  const bundleResult = addBundle(manifestPath, suffix);
  report.steps.push({ action: 'add-bundle', manifest: manifestPath, changed: bundleResult.changed, backup: bundleResult.changed ? manifestPath + '.bak-' + suffix : null });

  if (useLink) {
    const depResult = addDependency(manifestPath, sourceDir, suffix);
    report.steps.push({ action: 'add-dependency', manifest: manifestPath, changed: depResult.changed, specifier: depResult.specifier });
    if (runPnpm) {
      const pnpmResult = runPnpmInstall(profileDir);
      report.steps.push({ action: 'pnpm-install', ok: pnpmResult.ok });
      if (!pnpmResult.ok) report.warnings.push('pnpm install 没跑成功，lockfile 可能是旧的；请手动在档案目录执行一次 pnpm install');
    } else {
      report.warnings.push('已跳过 pnpm install（--no-pnpm）：lockfile 没更新，DSH 更新时可能被回收');
    }
  }
  report.ok = true;
}

if (asJson) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  const lines = ['', '🛡  dsh-command-guard 安装' + (dryRun ? '（预演，未写入）' : '')];
  lines.push('   DSH_HOME : ' + report.home);
  lines.push('   档案     : ' + report.profile);
  for (const step of report.steps) {
    if (step.action === 'place-package') lines.push('   · 已' + (step.mode === 'link' ? '链接' : '复制') + '包 → ' + step.target);
    if (step.action === 'add-bundle') lines.push(step.changed === false ? '   · bundles 里已经有了，跳过' : '   · 已追加到 dsh.profile.bundles');
    if (step.action === 'add-dependency') lines.push(step.changed ? '   · 已写入 dependencies：' + step.specifier : '   · dependencies 里已经是 ' + step.specifier + '，跳过');
    if (step.action === 'pnpm-install') lines.push(step.ok ? '   · pnpm install 完成，lockfile 已更新' : '   · pnpm install 失败');
  }
  for (const warning of report.warnings) lines.push('   ⚠ ' + warning);
  if (report.ok && !dryRun) {
    lines.push('');
    lines.push('   策略引擎不复制：直接读 <guardRoot>/guard.json 与 src/policy.mjs（默认 D:\\ZCodeprojecttt\\command-guard）。');
    lines.push('   下一步：完全退出并重开 DSH。');
  }
  lines.push('');
  process.stdout.write(lines.join('\n'));
}
