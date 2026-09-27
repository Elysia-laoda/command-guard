/**
 * 引擎的契约测试。跑法：node src/cli.mjs selftest
 *
 * 保护力度的核心断言只有一条：**受保护范围只覆盖到 depth 指定的层数**，
 * 更深的目标必须放行 —— 这样"删错一项"只伤一项，不会带走整棵项目树。
 *
 * 注意：测试用自己的一份规则夹具（TEST_RULES），不依赖生产默认值 ——
 * 生产默认值是空的（受保护路径属于部署配置，写在 guard.json 里）。
 */

import { DEFAULT_RULES, evaluate, evaluateTargets } from "../src/policy.mjs";

/** 测试用的通用路径，不指向任何真实位置。 */
const WORKSPACE = "D:\\ws";

const TEST_RULES = {
  ...DEFAULT_RULES,
  protectedRoots: [{ path: WORKSPACE, depth: 1, note: "test fixture" }],
};

/** 把受保护根整体调到某个力度，用来验证"一个数字调力度"。 */
function withDepth(depth) {
  return {
    ...TEST_RULES,
    protectedRoots: TEST_RULES.protectedRoots.map((r) => ({ ...r, depth })),
  };
}

export function run() {
  /** [名称, 命令, 期望裁决, 期望规则] */
  const textCases = [
    ["工作区根", `Remove-Item '${WORKSPACE}' -Recurse -Force`, "block", "protected-root"],
    ["工作区第一层", `Remove-Item '${WORKSPACE}\\tools' -Recurse -Force`, "block", "protected-depth"],
    ["工作区第二层（刻意不拦）", `Remove-Item '${WORKSPACE}\\tools\\sub' -Recurse -Force`, "warn", "recursive-absolute"],
    ["工作区更深一层（刻意不拦）", `Remove-Item '${WORKSPACE}\\tools\\a\\b\\c' -Recurse -Force`, "warn", "recursive-absolute"],
    ["卷根", 'Remove-Item "E:\\" -Recurse -Force', "block", "volume-root"],
    ["表外路径的顶层目录（不拦）", "Remove-Item 'E:\\scratch' -Recurse -Force", "warn", "recursive-absolute"],
    ["含 .. 的路径", "Remove-Item 'D:\\work\\a\\..\\b' -Recurse", "block", "dotdot"],
    ["rm -rf /", "rm -rf /", "block", "root-target"],
    [
      "2026-09-15 误删原文（变量被 bash 吃掉）",
      'cd /d/ZCodeprojecttt\npowershell -NoProfile -Command "\n$new = \'x\'\nif (Test-Path \\"D:\\ZCodeprojecttt\\\\$new\\") { Remove-Item \\"D:\\ZCodeprojecttt\\\\$new\\" -Recurse -Force }"',
      "block",
      "var-in-destructive",
    ],
    ["普通删除（放行）", "Remove-Item 'D:\\work\\build' -ErrorAction SilentlyContinue", "allow", null],
    ["无关命令（放行）", "git status --short", "allow", null],
    ["空命令（放行）", "", "allow", null],
  ];

  const lines = [];
  let pass = 0;
  let total = 0;

  function check(name, gotVerdict, gotRule, wantVerdict, wantRule) {
    total += 1;
    const ok = gotVerdict === wantVerdict && (wantRule === null || gotRule === wantRule);
    if (ok) pass += 1;
    lines.push(
      `${ok ? "PASS" : "FAIL"}  ${name}  -> ${gotVerdict}/${gotRule ?? "-"}` +
        (ok ? "" : ` （期望 ${wantVerdict}/${wantRule ?? "-"}）`)
    );
  }

  for (const [name, command, wantVerdict, wantRule] of textCases) {
    const v = evaluate({ command }, TEST_RULES);
    check(name, v.verdict, v.matched, wantVerdict, wantRule);
  }

  // ---- 力度就是一个数字 ----
  const dial = [
    ["力度=0：第一层不再被拦", 0, `${WORKSPACE}\\tools`, "warn"],
    ["力度=1：第一层被拦", 1, `${WORKSPACE}\\tools`, "block"],
    ["力度=2：第二层被拦", 2, `${WORKSPACE}\\tools\\sub`, "block"],
    ["力度=3：第三层被拦", 3, `${WORKSPACE}\\tools\\a\\b`, "block"],
  ];
  for (const [name, depth, target, want] of dial) {
    const v = evaluate({ command: `Remove-Item '${target}' -Recurse -Force` }, withDepth(depth));
    check(name, v.verdict, v.matched, want, want === "block" ? v.matched : null);
  }

  // 力度=-1：整棵子树（不可再生数据用这个）
  const deep = evaluate(
    { command: `Remove-Item '${WORKSPACE}\\tools\\a\\b\\c' -Recurse -Force` },
    withDepth(-1)
  );
  check("力度=-1：任意深度都被拦", deep.verdict, deep.matched, "block", "protected-depth");

  // 条目自带的 depth 覆盖 defaultDepth
  const mixed = {
    ...TEST_RULES,
    defaultDepth: 1,
    protectedRoots: [{ path: WORKSPACE, depth: 0 }],
  };
  const m = evaluate({ command: `Remove-Item '${WORKSPACE}\\tools' -Recurse -Force` }, mixed);
  check("条目自带 depth=0 覆盖 defaultDepth", m.verdict, m.matched, "warn", null);

  // ---- 结构化核心：命令已解析过的调用方走这条 ----
  const structured = [
    ["结构化 · 工作区根", { verb: "Remove-Item", targets: [WORKSPACE], recursive: true }, "block"],
    ["结构化 · 第一层", { verb: "Remove-Item", targets: [`${WORKSPACE}\\tools`], recursive: true }, "block"],
    ["结构化 · 第二层", { verb: "Remove-Item", targets: [`${WORKSPACE}\\tools\\sub`], recursive: true }, "warn"],
    ["结构化 · 变量拼路径", { verb: "Remove-Item", targets: [`${WORKSPACE}\\x`], recursive: true, usesVariable: true }, "block"],
  ];
  for (const [name, input, want] of structured) {
    const v = evaluateTargets(input, TEST_RULES);
    check(name, v.verdict, v.matched, want, null);
  }

  return { pass, total, lines };
}
