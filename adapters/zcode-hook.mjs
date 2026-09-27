#!/usr/bin/env node
/**
 * 薄适配器：ZCode 的 PreToolUse 载荷 -> 引擎 -> ZCode 的决策格式。
 *
 * 这里**不应该有任何规则**。规则全在 ../src/policy.mjs；本文件只做字段搬运。
 * 换个宿主就换这一个文件，引擎一行不改 —— 这就是把策略与传送方式分开的全部意义。
 *
 * 这是"快递方"层的适配器之一。它的能力边界很清楚：
 *   - 只覆盖经过 ZCode 的 Bash 工具调用；
 *   - 换个 agent、或绕过工具层直接执行的命令，它看不到（那要靠乙方层的处置）。
 * 它不假设命令是谁写的，也不需要写命令的一方配合。
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_RULES, evaluate } from "../src/policy.mjs";
import { loadRules } from "../src/rules.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const AUDIT = process.env.COMMAND_GUARD_AUDIT || join(HERE, "..", "logs", "audit.jsonl");
try {
  mkdirSync(dirname(AUDIT), { recursive: true });
} catch {
  /* 写不进去就跳过审计，不影响判定 */
}

// 与 cli.mjs 读同一份 guard.json —— 否则"钩子用默认值、CLI 用配置"会不一致。
let RULES = DEFAULT_RULES;
try {
  RULES = loadRules({});
}
catch (err) {
  process.stderr.write(`[command-guard/zcode] 读 guard.json 失败，退回内置默认规则：${err.message}\n`);
}

function out(obj) {
  process.stdout.write(JSON.stringify(obj));
}

function log(msg) {
  process.stderr.write(`[command-guard/zcode] ${msg}\n`);
}

async function main() {
  let raw = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) raw += chunk;

  // 核对 ZCode 实际发来的字段名，而不是猜。设了 COMMAND_GUARD_DUMP 才写盘。
  if (process.env.COMMAND_GUARD_DUMP) {
    try {
      appendFileSync(process.env.COMMAND_GUARD_DUMP, `${JSON.stringify({ at: new Date().toISOString(), raw: raw.slice(0, 200000) })}\n`, "utf8");
    } catch (err) {
      log(`转储失败：${err.message}`);
    }
  }

  let input = {};
  try {
    input = raw.trim() ? JSON.parse(raw) : {};
  } catch (err) {
    log(`载荷不是合法 JSON：${err.message}（放行）`);
    return 0;
  }

  const event = input.hook_event_name || input.hookEventName;
  if (event && event !== "PreToolUse") return 0;

  const tool = input.tool_name ?? input.toolName ?? "";
  if (tool && tool !== "Bash" && tool !== "bash") return 0;

  const ti = input.tool_input ?? input.toolInput ?? {};
  const command = ti.command ?? ti.cmd ?? "";
  const verdict = evaluate({ command }, RULES);

  // 审计：每次被调用都留一行。这既是对"钩子到底有没有生效"的证据，
  // 也是事后复盘"当时那条命令长什么样"的唯一原始记录。
  try {
    appendFileSync(
      AUDIT,
      JSON.stringify({
        at: new Date().toISOString(),
        session: input.session_id ?? input.sessionId ?? null,
        verdict: verdict.verdict,
        rule: verdict.matched,
        command: String(command).slice(0, 2000),
      }) + "\n",
      "utf8"
    );
  } catch (err) {
    log(`审计写入失败：${err.message}`);
  }

  if (verdict.verdict === "allow") return 0;

  if (verdict.verdict === "block") {
    log(`拦截 [${verdict.matched}]`);
    out({ decision: "block", reason: `command-guard 拦下这条命令（规则 ${verdict.matched}）：${verdict.reason}` });
    return 0;
  }

  out({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      additionalContext: `command-guard 提示（规则 ${verdict.matched}）：${verdict.reason}`,
    },
  });
  return 0;
}

main().then(
  (code) => process.exit(typeof code === "number" ? code : 0),
  (err) => {
    // 失败开放：适配器崩了不能把整个 agent 卡死。引擎正确性由 cli.mjs selftest 保证。
    log(`出错，放行：${err.stack || err.message}`);
    process.exit(0);
  }
);
