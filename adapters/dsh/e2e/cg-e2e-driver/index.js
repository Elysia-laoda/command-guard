/**
 * e2e 驱动：在真 cordis 容器里用**真 waterfall** 派发 tools/pre-execute，
 * 验证闸门确实挂在宿主执行工具的同一条路上。
 */
export const name = 'cg-e2e-driver';
export const inject = [];

function log(line) {
  process.stderr.write('[e2e] ' + line + '\n');
}

export function apply(ctx) {
  // 撑住回合，别让 headless 应用在断言跑完前退出（缺凭据时它退得很快）
  const holdMs = Number(process.env.CG_E2E_HOLD_MS || 8000);
  ctx.on('agent/pre-step', async (_payload, next) => {
    log('holding pre-step ' + holdMs + 'ms');
    await new Promise((resolve) => setTimeout(resolve, holdMs));
    return next();
  });

  ctx.inject(['commandGuard'], (inner) => {
    const guard = inner.commandGuard;
    log('commandGuard service found');
    void (async () => {
      try {
        const status = await guard.ready();
        log((status.active ? 'PASS' : 'FAIL') + ' engine active=' + status.active + ' mode=' + status.mode + ' roots=' + status.protectedRoots.length);
        const root = status.protectedRoots[0];
        log((root && root.sentinel ? 'PASS' : 'FAIL') + ' 文件系统层自检：' + (root ? root.path + ' 下 ' + root.sentinelName + '=' + root.sentinel : '无根'));

        const protectedPath = root ? root.path : 'D:\\__nope__';
        const blocked = await ctx.waterfall(ctx, 'tools/pre-execute', {
          name: 'pwsh',
          arguments: { command: "Remove-Item -Recurse -Force '" + protectedPath + "'" },
        }, async () => ({ kind: 'allow' }));
        log((blocked && blocked.kind === 'deny' ? 'PASS' : 'FAIL') + ' waterfall 拦下受保护根 -> ' + (blocked ? blocked.kind : 'null') + ' / ' + String(blocked && blocked.reason || '').slice(0, 50));

        const benign = await ctx.waterfall(ctx, 'tools/pre-execute', {
          name: 'pwsh',
          arguments: { command: 'Get-ChildItem .' },
        }, async () => ({ kind: 'allow' }));
        log((benign && benign.kind === 'allow' ? 'PASS' : 'FAIL') + ' waterfall 放行无害命令 -> ' + (benign ? benign.kind : 'null'));

        const variable = await ctx.waterfall(ctx, 'tools/pre-execute', {
          name: 'pwsh',
          arguments: { command: 'rm -rf $SOMETHING' },
        }, async () => ({ kind: 'allow' }));
        log((variable && variable.kind === 'deny' ? 'PASS' : 'FAIL') + ' waterfall 拦下变量+递归 -> ' + (variable ? variable.kind : 'null'));

        const lines = guard.tail(10);
        log((lines.length >= 3 ? 'PASS' : 'FAIL') + ' 审计行数=' + lines.length);
        log((lines.some((row) => row.verdict === 'block') && lines.some((row) => row.verdict === 'allow') ? 'PASS' : 'FAIL') + ' 审计同时含 block 与 allow');
        log('DONE');
      } catch (error) {
        log('FAIL driver threw: ' + String((error && error.stack) || error));
      }
    })();
  });
}
