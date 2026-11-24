/**
 * 适配器级集成测试：用桩引擎驱动 pre-execute / post-execute，
 * 验证「白名单放行 → 删前快照 → 删后比对 → 违规挂起」整条链路。
 * 不读真实策略引擎，也不碰真实受保护路径。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply } from '../lib/index.js';
import { addEntry } from '../lib/allowlist.js';

const STUB_POLICY = [
  'export function evaluate() {',
  "  return { verdict: 'block', matched: 'protected-depth', reason: 'stub block', findings: [] };",
  '}',
  'export const DEFAULT_RULES = { protectedRoots: [], defaultDepth: 1 };',
].join('\n');

/**
 * @param {{auditInTargetDir?: boolean}} options
 *   auditInTargetDir=true 时把审计/清单与目标放同一目录，用来验证"自身文件不参与比对"。
 */
async function makeHost({ auditInTargetDir = false } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'cg-host-'));
  const guardRoot = join(root, 'engine');
  const dataDir = auditInTargetDir ? root : join(root, 'data');
  const metaDir = auditInTargetDir ? root : join(root, 'meta');
  await mkdir(join(guardRoot, 'src'), { recursive: true });
  await mkdir(dataDir, { recursive: true });
  await mkdir(metaDir, { recursive: true });
  await writeFile(join(guardRoot, 'src', 'policy.mjs'), STUB_POLICY);

  const auditFile = join(metaDir, 'audit.jsonl');
  const allowlistFile = join(metaDir, 'allow.json');
  const listeners = new Map();
  const provided = new Map();
  const ctx = {
    logger: { warn: () => {}, info: () => {} },
    on: (event, handler) => { listeners.set(event, handler); return () => {}; },
    provide: (name, service) => provided.set(name, service),
    effect: () => {},
  };
  apply(ctx, { guardRoot, allowlistFile, auditFile });
  const service = provided.get('commandGuard');
  await service.ready();
  return {
    root,
    dataDir,
    auditFile,
    allowlistFile,
    service,
    pre: listeners.get('tools/pre-execute'),
    post: listeners.get('tools/post-execute'),
    async auditRows() {
      try {
        const text = (await readFile(auditFile, 'utf8')).trim();
        return text.length === 0 ? [] : text.split('\n').map((line) => JSON.parse(line));
      } catch {
        return [];
      }
    },
  };
}

const removeCommand = (target) => 'Remove-Item -LiteralPath "' + target + '"';

test('白名单放行 → 删后比对通过 → 条目被消耗', async () => {
  const host = await makeHost();
  const target = join(host.dataDir, '_probe.mjs');
  await writeFile(target, 'probe\n');
  addEntry(host.allowlistFile, { path: target, note: '临时探查脚本' });

  let nextCalled = false;
  await host.pre({ name: 'pwsh', arguments: { command: removeCommand(target) } }, async () => {
    nextCalled = true;
    return { kind: 'allow' };
  });
  assert.equal(nextCalled, true, '白名单命中应放行');

  await host.post({ name: 'pwsh' }, { kind: 'allow' }, async () => ({ kind: 'allow' }));

  const rows = await host.auditRows();
  const allowed = rows.find((row) => row.rule === 'allowlist');
  assert.ok(allowed, '审计里应有 allowlist 放行记录');
  assert.equal(allowed.allowlist.note, '临时探查脚本');
  const integrity = rows.find((row) => row.rule === 'integrity');
  assert.ok(integrity, '应留下完整性记录');
  assert.equal(integrity.verdict, 'allow');
  assert.equal(host.service.allowlist.list().entries.length, 0, '单次条目应被消耗');
});

test('审计/清单与目标同目录时，自身文件不参与完整性比对', async () => {
  const host = await makeHost({ auditInTargetDir: true });
  const target = join(host.dataDir, '_probe.mjs');
  await writeFile(target, 'probe\n');
  addEntry(host.allowlistFile, { path: target, note: '同目录场景' });

  let nextCalled = false;
  await host.pre({ name: 'pwsh', arguments: { command: removeCommand(target) } }, async () => {
    nextCalled = true;
    return { kind: 'allow' };
  });
  assert.equal(nextCalled, true);
  await host.post({ name: 'pwsh' }, { kind: 'allow' }, async () => ({ kind: 'allow' }));

  const integrity = (await host.auditRows()).find((row) => row.rule === 'integrity');
  assert.ok(integrity, '应留下完整性记录');
  assert.equal(integrity.verdict, 'allow', '写审计本身不该被判成违反完整性');
});

test('删后邻近文件被改 → 判定违规、自动挂起、后续继续拦', async () => {
  const host = await makeHost();
  const target = join(host.dataDir, '_probe.mjs');
  const neighbor = join(host.dataDir, '_keep.txt');
  await writeFile(target, 'probe\n');
  await writeFile(neighbor, 'keep\n');
  addEntry(host.allowlistFile, { path: target, note: '临时探查脚本' });

  await host.pre({ name: 'pwsh', arguments: { command: removeCommand(target) } }, async () => ({ kind: 'allow' }));

  // 模拟"命令顺带改了旁边的文件"
  await writeFile(neighbor, 'keep CHANGED\n');
  await host.post({ name: 'pwsh' }, { kind: 'allow' }, async () => ({ kind: 'allow' }));

  const integrity = (await host.auditRows()).find((row) => row.rule === 'integrity');
  assert.equal(integrity.verdict, 'block');
  assert.ok(integrity.integrity.changed.includes('_keep.txt'));
  assert.ok(host.service.allowlist.list().suspended, '违规后应自动挂起');

  // 挂起后即便重新登记也不放行
  addEntry(host.allowlistFile, { path: target, note: 'again' });
  let passed = false;
  await host.pre({ name: 'pwsh', arguments: { command: removeCommand(target) } }, async () => {
    passed = true;
    return { kind: 'allow' };
  });
  assert.equal(passed, false, '挂起期间必须继续拦');
});
