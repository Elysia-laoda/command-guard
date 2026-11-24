#!/usr/bin/env node
/**
 * 删除白名单管理 CLI。
 *
 *   node scripts/allow.mjs add "D:\dshproject\_probe.mjs" --note "临时探查脚本"
 *   node scripts/allow.mjs add "D:\dshproject\_tmp" --note "临时目录" --kind dir --uses 2 --ttl-hours 6
 *   node scripts/allow.mjs list
 *   node scripts/allow.mjs revoke "D:\dshproject\_probe.mjs"
 *   node scripts/allow.mjs purge
 *   node scripts/allow.mjs resume
 *   node scripts/allow.mjs check "D:\dshproject\x.txt"
 *
 * 清单默认在 <DSH_HOME>/command-guard/delete-allowlist.json（可用 --file 覆盖）。
 */
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  addEntry,
  describe,
  purge,
  resume,
  revokeEntry,
  validateEntry,
} from '../lib/allowlist.js';

const args = process.argv.slice(2);
const fileFlag = args.indexOf('--file');
const fileValue = fileFlag >= 0 ? args[fileFlag + 1] : null;
const dshHome = process.env.DSH_HOME && process.env.DSH_HOME.trim().length > 0
  ? process.env.DSH_HOME.trim()
  : join(homedir(), '.dsh');
const file = fileValue || join(dshHome, 'command-guard', 'delete-allowlist.json');

const positional = [];
const options = {};
for (let i = 0; i < args.length; i += 1) {
  const token = args[i];
  if (token === '--file') { i += 1; continue; }
  if (token.startsWith('--')) {
    const key = token.slice(2);
    const value = args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : 'true';
    if (value !== 'true') i += 1;
    options[key] = value;
    continue;
  }
  positional.push(token);
}

const [command, target] = positional;

function fail(message) {
  console.error('✗ ' + message);
  process.exitCode = 1;
}

function printList(view) {
  console.log('清单：' + view.file);
  if (view.suspended) console.log('⚠ 已挂起：' + JSON.stringify(view.suspended));
  if (!view.entries.length) { console.log('（空）'); return; }
  for (const entry of view.entries) {
    const state = entry.valid ? '可用' : entry.expired ? '已过期' : '已用尽';
    console.log(`- [${state}] ${entry.path}`);
    console.log(`    kind=${entry.kind} usesLeft=${entry.usesLeft} expires=${entry.expiresAt}`);
    console.log(`    note=${entry.note}`);
  }
}

switch (command) {
  case 'add': {
    if (!target) { fail('用法：add "<绝对路径>" --note "<原因>" [--kind file|dir|any] [--uses 1] [--ttl-hours 24]'); break; }
    const result = addEntry(file, {
      path: target,
      note: options.note,
      kind: options.kind,
      usesLeft: options.uses ? Number(options.uses) : undefined,
      ttlHours: options['ttl-hours'] ? Number(options['ttl-hours']) : undefined,
    });
    if (!result.ok) { fail(result.errors.join('；')); break; }
    console.log('✓ 已加入：' + result.entry.path);
    console.log('  kind=' + result.entry.kind + ' usesLeft=' + result.entry.usesLeft + ' expires=' + result.entry.expiresAt);
    console.log('  提示：一次命令只能删一个目标；删前会扫描父目录，删后比对，有异常即挂起。');
    break;
  }
  case 'list': printList(describe(file)); break;
  case 'revoke': {
    if (!target) { fail('用法：revoke "<绝对路径>"'); break; }
    const result = revokeEntry(file, target);
    if (!result.ok) { fail(result.errors.join('；')); break; }
    console.log(result.removed > 0 ? '✓ 已移除' : '（清单里没有这条）');
    break;
  }
  case 'purge': {
    const result = purge(file);
    console.log('✓ 清理完成：保留 ' + result.kept + '，移除 ' + result.dropped);
    break;
  }
  case 'resume': {
    const result = resume(file);
    console.log(result.resumed ? '✓ 已解除挂起' : '（本来就没挂起）');
    break;
  }
  case 'check': {
    if (!target) { fail('用法：check "<绝对路径>"'); break; }
    const result = validateEntry({ path: target, note: options.note || 'check' });
    if (result.ok) console.log('✓ 可以作为白名单条目：' + result.entry.path);
    else fail(result.errors.join('；'));
    break;
  }
  default: {
    console.log('用法：');
    console.log('  allow.mjs add "<绝对路径>" --note "<原因>" [--kind file|dir|any] [--uses 1] [--ttl-hours 24]');
    console.log('  allow.mjs list | revoke "<路径>" | purge | resume | check "<路径>"');
    console.log('  --file "<清单路径>"  覆盖默认清单位置');
    console.log('默认清单：' + file);
  }
}
