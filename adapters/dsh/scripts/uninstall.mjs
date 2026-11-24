#!/usr/bin/env node
/**
 * dsh-command-guard 卸载：从 dsh.profile.bundles 摘掉 + 删包目录。
 *   node scripts/uninstall.mjs [--profile desktop] [--home D:\dshhome] [--dry-run]
 * 不碰策略引擎、不碰 guard.json、不碰审计日志。
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgv, removeBundle, removeDependency, removePackage, resolveHome, resolveProfileDir, runPnpmInstall, timestamp } from './profile-io.mjs';

const options = parseArgv(process.argv.slice(2));
const profileDir = resolveProfileDir(options);
const manifestPath = join(profileDir, 'package.json');
const dryRun = options['dry-run'] === true;
const steps = [];

if (!existsSync(manifestPath)) {
  process.stderr.write('找不到档案 package.json：' + manifestPath + '\n');
  process.exit(1);
}
if (dryRun) {
  steps.push('将摘除 bundles 里的 dsh-command-guard');
  steps.push('将摘除 dependencies 里的 link 依赖');
  steps.push('将删除 ' + join(profileDir, 'node_modules', 'dsh-command-guard'));
  steps.push('将跑一次 pnpm install 同步 lockfile');
} else {
  const suffix = timestamp();
  const result = removeBundle(manifestPath, suffix);
  steps.push(result.changed ? '已从 dsh.profile.bundles 摘除（原文件已备份）' : 'bundles 里本来就没有它');
  const dep = removeDependency(manifestPath, suffix);
  steps.push(dep.changed ? '已从 dependencies 摘除（原文件已备份）' : 'dependencies 里本来就没有它');
  steps.push(removePackage(profileDir) ? '已删除包目录' : '包目录不存在');
  if (dep.changed && options['no-pnpm'] !== true) {
    const pnpmResult = runPnpmInstall(profileDir);
    steps.push(pnpmResult.ok ? '已跑 pnpm install，lockfile 同步' : 'pnpm install 失败，请手动在档案目录执行一次');
  }
}
process.stdout.write('\n🛡  dsh-command-guard 卸载' + (dryRun ? '（预演）' : '') + '\n   ' + steps.join('\n   ') + '\n   （策略引擎与审计日志未动）\n\n');
void resolveHome;
