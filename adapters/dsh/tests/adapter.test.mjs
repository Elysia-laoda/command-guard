/**
 * 适配器行为测试：用假 ctx 接住 tools/pre-execute，跑**真实的策略引擎**
 * （D:\ZCodeprojecttt\command-guard\src\policy.mjs + guard.json）。
 *   node --test tests/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply, commandOf } from '../lib/index.js';

const GUARD_ROOT = process.env.COMMAND_GUARD_ROOT || 'D:/ZCodeprojecttt/command-guard';
const HAS_ENGINE = existsSync(join(GUARD_ROOT, 'src', 'policy.mjs'));
const PROTECTED = 'D:\\ZCodeprojecttt';

async function makeHost({ guardRoot = GUARD_ROOT, mode, audit = true } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'cg-'));
  const auditFile = join(dir, 'audit.jsonl');
  const listeners = [];
  const provided = new Map();
  const warnings = [];
  const ctx = {
    logger: { warn: (message) => warnings.push(String(message)), info: () => {} },
    on: (event, handler) => { listeners.push({ event, handler }); return () => {}; },
    provide: (nameValue, service) => provided.set(nameValue, service),
    effect: () => {},
  };
  apply(ctx, { guardRoot, auditFile, mode, audit });
  const service = provided.get('commandGuard');
  const pre = listeners.find((entry) => entry.event === 'tools/pre-execute');
  assert.ok(service, 'ctx.commandGuard 已提供');
  assert.ok(pre, 'tools/pre-execute 已挂上');
  await service.ready();
  return { service, pre, auditFile, warnings };
}

async function runPre(pre, command, name = 'pwsh') {
  let nextCalled = false;
  const decision = await pre.handler({ name, arguments: { command } }, async () => { nextCalled = true; return { kind: 'allow' }; });
  return { decision, nextCalled };
}

test('commandOf 认常见字段与浅层嵌套', () => {
  assert.equal(commandOf({ command: 'rm -rf x' }), 'rm -rf x');
  assert.equal(commandOf({ code: 'echo hi' }), 'echo hi');
  assert.equal(commandOf({ nested: { script: 'Remove-Item x' } }), 'Remove-Item x');
  assert.equal(commandOf('plain'), 'plain');
  assert.equal(commandOf(undefined), '');
});

test('拿不到引擎：插件仍装载，闸门惰性放行（失败开放）', async () => {
  const host = await makeHost({ guardRoot: join(tmpdir(), 'nope-command-guard') });
  const status = host.service.status();
  assert.equal(status.active, false);
  assert.ok(String(status.reason).includes('找不到策略引擎'));
  const { decision, nextCalled } = await runPre(host.pre, 'Remove-Item -Recurse -Force D:\\anything');
  assert.equal(nextCalled, true, '引擎不在时必须放行');
  assert.equal(decision.kind, 'allow');
});

test('受保护范围：删根目录被拦、且给出规则与理由', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const status = host.service.status();
  assert.equal(status.active, true);
  const root = status.protectedRoots.find((entry) => entry.path.toLowerCase() === PROTECTED.toLowerCase());
  assert.ok(root, '受保护范围里应有 ' + PROTECTED);
  assert.equal(root.depth, 1);
  assert.equal(root.sentinel, true, '文件系统层自检：' + PROTECTED + ' 下应有 ' + root.sentinelName + ' 哨兵');

  const { decision } = await runPre(host.pre, "Remove-Item -Recurse -Force '" + PROTECTED + "'");
  assert.equal(decision.kind, 'deny');
  assert.ok(decision.reason.includes('protected-root'), decision.reason);
  assert.ok(decision.reason.includes('command-guard 拦下了这条命令'));

  const audit = (await readFile(host.auditFile, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(audit.length, 1);
  assert.equal(audit[0].party, 'dsh');
  assert.equal(audit[0].verdict, 'block');
  assert.equal(audit[0].rule, 'protected-root');
  assert.equal(audit[0].tool, 'pwsh');
});

test('深度语义：第 2 层以下不受保护，只 warn 放行', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const { decision, nextCalled } = await runPre(host.pre, "Remove-Item -Recurse -Force -ErrorAction Stop '" + PROTECTED + "\\_trash\\a\\b\\c.txt'");
  assert.equal(nextCalled, true, 'depth 之外的路径放行');
  assert.equal(decision.kind, 'allow');
  const audit = (await readFile(host.auditFile, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(audit[0].verdict, 'warn');
  assert.equal(audit[0].rule, 'recursive-absolute');
});

test('受保护树内递归但没上膛：拦下并提示加 -ErrorAction Stop', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const { decision, nextCalled } = await runPre(host.pre, "Remove-Item -Recurse '" + PROTECTED + "\\_trash\\a\\b\\c.txt'");
  assert.equal(nextCalled, false, '没上膛的递归删除不应放行');
  assert.equal(decision.kind, 'deny');
  assert.ok(decision.reason.includes('unarmed-recursive'), decision.reason);
});
test('变量 + 递归：跨 shell 展开无法核对的写法被拦', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const { decision } = await runPre(host.pre, 'rm -rf $TARGET_DIR');
  assert.equal(decision.kind, 'deny');
  assert.ok(decision.reason.includes('var-in-destructive'), decision.reason);
});

test('卷根与根目录目标：一拦到底', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const volume = await runPre(host.pre, "Remove-Item -Recurse -Force 'D:\\'");
  assert.equal(volume.decision.kind, 'deny');
  assert.ok(volume.decision.reason.includes('volume-root'), volume.decision.reason);
});

test('无害命令：放行且仍留审计（闸门生效的唯一证据）', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const { nextCalled } = await runPre(host.pre, 'Get-ChildItem ' + PROTECTED);
  assert.equal(nextCalled, true);
  const audit = (await readFile(host.auditFile, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(audit.length, 1);
  assert.equal(audit[0].verdict, 'allow');
  assert.equal(audit[0].rule, null);
});

test('advise 模式：判定仍是 block，但不拒绝执行（只记账）', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost({ mode: 'advise' });
  const { nextCalled } = await runPre(host.pre, "Remove-Item -Recurse -Force '" + PROTECTED + "'");
  assert.equal(nextCalled, true, 'advise 模式下不拦');
  const audit = (await readFile(host.auditFile, 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(audit[0].verdict, 'block');
  assert.equal(host.service.status().stats.block, 1);
  assert.equal(host.service.status().stats.denied, 0);
});

test('evaluate() 是纯判定：不执行、不写审计', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const verdict = host.service.evaluate("Remove-Item -Recurse -Force '" + PROTECTED + "'");
  assert.equal(verdict.verdict, 'block');
  assert.equal(verdict.matched, 'protected-root');
  let auditMissing = false;
  try { await readFile(host.auditFile, 'utf8'); } catch { auditMissing = true; }
  assert.equal(auditMissing, true, '纯判定不落盘');
});

test('空命令与非对象入参不炸', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const empty = await runPre(host.pre, '   ');
  assert.equal(empty.nextCalled, true);
  const weird = await preSafe(host.pre, { name: 'pwsh' });
  assert.equal(weird, true);
});

async function preSafe(pre, exec) {
  const decision = await pre.handler(exec, async () => ({ kind: 'allow' }));
  return decision.kind === 'allow';
}

test('非 shell 工具不入闸门、也不审计（run_code 只是"写着"命令，不是要执行）', { skip: !HAS_ENGINE }, async () => {
  const host = await makeHost();
  const verb = 'Remove' + '-Item';
  const program = "const cmd = \"" + verb + " -Recurse -Force '" + '$' + "TARGET' -ErrorAction Stop\";";
  const { nextCalled } = await runPre(host.pre, program, 'run_code');
  assert.equal(nextCalled, true, '非 shell 工具必须原样放行');
  assert.equal(host.service.status().stats.seen, 0, '它甚至不该进入统计');
  let audited = false;
  try { audited = (await readFile(host.auditFile, 'utf8')).trim().length > 0; } catch { audited = false; }
  assert.equal(audited, false, '非 shell 工具不该留下审计行');
  const tools = host.service.status().tools;
  assert.ok(Array.isArray(tools) && tools.length > 0, 'status 里要报出作用域');
});
