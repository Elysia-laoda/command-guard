#!/usr/bin/env node
/**
 * 端到端自测：临时档案 → 装驱动 + 装本包 → 真运行时跑一次 → 用真 waterfall 派发
 * tools/pre-execute，收集 [e2e] 结论。
 *
 *   node e2e/run.mjs
 *   node e2e/run.mjs --runtime D:/dshproject/_ref/dsh-runtime --home D:/dshproject/_e2ehome --keep
 *
 * 不需要 API key：断言在模型失败之前就完成了。
 * 注意：审计默认写 <guardRoot>/logs/audit.jsonl —— 也就是说 e2e 会往**真实流水**里
 * 追加几行（party=dsh），这是设计使然（一份流水看全）。
 */
import { existsSync, mkdirSync, cpSync, writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgv, removeTree } from '../scripts/profile-io.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');
const options = parseArgv(process.argv.slice(2));

const runtime = options.runtime ?? 'D:/dshproject/_ref/dsh-runtime';
const home = resolve(options.home ?? 'D:/dshproject/_e2ehome');
const profile = options.profile ?? 'cge2e';
const bin = join(runtime, 'node_modules/@deepseek-ai/dsh/lib/bin.js');
const profileDir = join(home, 'profiles', profile);

function fail(message) { process.stderr.write('e2e: ' + message + '\n'); process.exit(1); }
if (!existsSync(bin)) fail('运行时入口不存在：' + bin);

removeTree(join(home, 'profiles', profile));
const init = spawnSync(process.execPath, [bin, '--from-default-profile', 'headless', '--profile', profile, '--dump-config'], {
  env: { ...process.env, DSH_HOME: home }, encoding: 'utf8',
});
if (init.status !== 0) fail('初始化档案失败：' + (init.stderr || init.stdout));

const driverDir = join(profileDir, 'node_modules', 'cg-e2e-driver');
mkdirSync(driverDir, { recursive: true });
for (const file of ['package.json', 'cordis.patch.yml', 'index.js']) cpSync(join(here, 'cg-e2e-driver', file), join(driverDir, file));

const install = spawnSync(process.execPath, [join(packageRoot, 'scripts/install.mjs'), '--home', home, '--profile', profile, '--link', '--json'], { encoding: 'utf8' });
if (install.status !== 0) fail('安装失败：' + (install.stderr || install.stdout));

const manifestPath = join(profileDir, 'package.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.dsh.profile.bundles = manifest.dsh.profile.bundles.filter((entry) => entry !== 'dsh-command-guard' && entry !== 'cg-e2e-driver');
manifest.dsh.profile.bundles.push('cg-e2e-driver', 'dsh-command-guard');
writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

process.stdout.write('e2e: runtime=' + runtime + '\nhome=' + home + ' profile=' + profile + '\n\n');
let output = '';
try {
  const run = spawnSync(process.execPath, [bin, '--profile', profile, options.prompt ?? '说一句你好就行。'], {
    env: { ...process.env, DSH_HOME: home, COMMAND_GUARD_ROOT: options.guardRoot ?? process.env.COMMAND_GUARD_ROOT ?? '', CG_E2E_HOLD_MS: '8000' },
    encoding: 'utf8',
    timeout: Number(options.timeout ?? 60) * 1000,
  });
  output = (run.stdout ?? '') + (run.stderr ?? '');
} finally {
  if (!options.keep) removeTree(join(home, 'profiles', profile));
}

for (const line of output.split(/\r?\n/)) {
  if (line.includes('[e2e]') || line.includes('MISSING_CREDENTIAL') || line.includes('did not activate')) process.stdout.write(line + '\n');
}

const checks = [
  ['插件装载并暴露服务', /\[e2e\] commandGuard service found/],
  ['策略引擎装载成功', /PASS engine active=true/],
  ['两层自检（哨兵在位）', /PASS 文件系统层自检/],
  ['waterfall 拦下受保护根', /PASS waterfall 拦下受保护根 -> deny/],
  ['waterfall 放行无害命令', /PASS waterfall 放行无害命令 -> allow/],
  ['waterfall 拦下变量\+递归', /PASS waterfall 拦下变量\+递归 -> deny/],
  ['审计有记录', /PASS 审计行数=\d+/],
  ['审计同时含 block 与 allow', /PASS 审计同时含 block 与 allow/],
  ['全部检查跑完', /\[e2e\] DONE/],
];
process.stdout.write('\n');
let failed = 0;
for (const [label, pattern] of checks) {
  const ok = pattern.test(output);
  if (!ok) failed += 1;
  process.stdout.write((ok ? '  ✔ ' : '  ✖ ') + label + '\n');
}
process.stdout.write('\n' + (failed === 0 ? 'e2e: 全部通过' : 'e2e: ' + failed + ' 项未通过') + '\n');
process.exitCode = failed === 0 ? 0 : 1;
