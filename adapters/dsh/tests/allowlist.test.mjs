/**
 * 删除白名单的行为测试（纯逻辑 + 真实文件系统，不依赖策略引擎）。
 *   node --test tests/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  addEntry,
  consume,
  describe,
  diffSnapshot,
  extractTargets,
  loadAllowlist,
  matchBypass,
  normalizePath,
  resume,
  snapshotNeighborhood,
  suspend,
  validateEntry,
} from '../lib/allowlist.js';

const tmpFile = async () => join(await mkdtemp(join(tmpdir(), 'cg-allow-')), 'allow.json');
const blockDepth = { verdict: 'block', matched: 'protected-depth', reason: '目标落在受保护范围内' };

test('路径规范化：相对路径/通配符/变量/.. 全部拒绝', () => {
  assert.equal(normalizePath('relative\\x.js').ok, false);
  assert.equal(normalizePath('D:\\a\\*.js').ok, false);
  assert.equal(normalizePath('D:\\a\\%TEMP%.js').ok, false);
  assert.equal(normalizePath('D:\\a\\..\\b.js').ok, false);
  assert.equal(normalizePath('D:/dshproject/_x.js').path, 'D:\\dshproject\\_x.js');
});

test('条目校验：卷根/系统目录/.dsh/哨兵/无备注 都进不来', () => {
  assert.equal(validateEntry({ path: 'D:\\', note: 'x' }).ok, false);
  assert.equal(validateEntry({ path: 'C:\\Windows\\x.dll', note: 'x' }).ok, false);
  assert.equal(validateEntry({ path: 'C:\\Users\\27096\\.dsh\\x.json', note: 'x' }).ok, false);
  assert.equal(validateEntry({ path: 'D:\\dshproject\\!000-guard', note: 'x' }).ok, false);
  assert.equal(validateEntry({ path: 'D:\\dshproject\\_tmp', note: '' }).ok, false);
  const ok = validateEntry({ path: 'D:\\dshproject\\_probe.mjs', note: '临时探查脚本' });
  assert.equal(ok.ok, true);
  assert.equal(ok.entry.key, 'd:\\dshproject\\_probe.mjs');
});

test('目标抽取：只认绝对路径；含变量或通配符的命令不适用', () => {
  assert.deepEqual(extractTargets('Remove-Item -LiteralPath "D:\\dshproject\\_a.mjs"').targets, ['D:\\dshproject\\_a.mjs']);
  assert.equal(extractTargets('rm -rf $TARGET').ok, false);
  assert.equal(extractTargets('Remove-Item D:\\a\\*.mjs').ok, false);
  assert.equal(extractTargets('Get-ChildItem D:\\dshproject').targets.length, 1);
});

test('一次只能删一个目标：两个目标直接拒绝', async () => {
  const file = await tmpFile();
  addEntry(file, { path: 'D:\\dshproject\\_a.mjs', note: 'a' });
  addEntry(file, { path: 'D:\\dshproject\\_b.mjs', note: 'b' });
  const { entries } = loadAllowlist(file);
  const one = matchBypass(entries, 'Remove-Item "D:\\dshproject\\_a.mjs"', blockDepth);
  assert.equal(one.ok, true);
  const two = matchBypass(entries, 'Remove-Item "D:\\dshproject\\_a.mjs","D:\\dshproject\\_b.mjs"', blockDepth);
  assert.equal(two.ok, false);
  assert.match(two.reason, /一次只允许删一个目标/);
});

test('白名单只对 protected-depth 生效（变量/根目录等规则不被绕过）', async () => {
  const file = await tmpFile();
  addEntry(file, { path: 'D:\\dshproject\\_a.mjs', note: 'a' });
  const { entries } = loadAllowlist(file);
  const other = matchBypass(entries, 'Remove-Item "D:\\dshproject\\_a.mjs"', { verdict: 'block', matched: 'var-in-destructive' });
  assert.equal(other.ok, false);
  assert.match(other.reason, /不在可放行范围/);
});

test('未登记的邻近路径不放行', async () => {
  const file = await tmpFile();
  addEntry(file, { path: 'D:\\dshproject\\_a.mjs', note: 'a' });
  const { entries } = loadAllowlist(file);
  const result = matchBypass(entries, 'Remove-Item "D:\\dshproject\\_other.mjs"', blockDepth);
  assert.equal(result.ok, false);
  assert.match(result.reason, /不在白名单/);
});

test('用过一次就消耗；挂起后一律不放行，resume 恢复', async () => {
  const file = await tmpFile();
  addEntry(file, { path: 'D:\\dshproject\\_a.mjs', note: 'a', usesLeft: 1 });
  let state = loadAllowlist(file);
  const match = matchBypass(state.entries, 'Remove-Item "D:\\dshproject\\_a.mjs"', blockDepth);
  assert.equal(match.ok, true);
  consume(file, match.entries);
  state = loadAllowlist(file);
  assert.equal(state.entries.length, 0, '单次条目用尽后应移除');
  assert.equal(matchBypass([], 'Remove-Item "D:\\dshproject\\_a.mjs"', blockDepth).ok, false);

  addEntry(file, { path: 'D:\\dshproject\\_b.mjs', note: 'b' });
  suspend(file, 'integrity-violation');
  state = loadAllowlist(file);
  const blocked = matchBypass(state.entries, 'Remove-Item "D:\\dshproject\\_b.mjs"', blockDepth, { suspended: state.suspended });
  assert.equal(blocked.ok, false);
  assert.match(blocked.reason, /已挂起/);
  resume(file);
  state = loadAllowlist(file);
  const again = matchBypass(state.entries, 'Remove-Item "D:\\dshproject\\_b.mjs"', blockDepth, { suspended: state.suspended });
  assert.equal(again.ok, true);
});

test('邻近文件完整性：只允许目标消失，旁文件被改即违规', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cg-near-'));
  const target = join(dir, '_probe.mjs');
  const neighbor = join(dir, '_keep.mjs');
  await writeFile(target, 'probe\n');
  await writeFile(neighbor, 'keep\n');

  const baseline = snapshotNeighborhood(target);
  assert.ok(baseline.siblings.size >= 1, '应扫到邻近文件');

  await rm(target);
  const clean = diffSnapshot(baseline);
  assert.equal(clean.ok, true, JSON.stringify({ added: clean.added, removed: clean.removed, changed: clean.changed }));
  assert.equal(clean.targetRemoved, true);

  // 换成"目标还在、旁文件被改"的形状
  await writeFile(target, 'probe\n');
  const baseline2 = snapshotNeighborhood(target);
  await writeFile(neighbor, 'keep CHANGED\n');
  const dirty = diffSnapshot(baseline2);
  assert.equal(dirty.ok, false);
  assert.ok(dirty.changed.includes('_keep.mjs'), JSON.stringify(dirty.changed));
});

test('清单展示：valid/expired 标记正确', async () => {
  const file = await tmpFile();
  addEntry(file, { path: 'D:\\dshproject\\_a.mjs', note: 'a' });
  const rejected = addEntry(file, { path: 'D:\\dshproject\\_b.mjs', note: 'b', ttlHours: -1 });
  assert.equal(rejected.ok, false, '过去的时间不能入单');
  const view = describe(file);
  assert.equal(view.entries.length, 1);
  assert.equal(view.entries[0].valid, true);
});
