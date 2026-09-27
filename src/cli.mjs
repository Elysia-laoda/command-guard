#!/usr/bin/env node
/**
 * command-guard CLI —— 通用入口。任何宿主、任何 agent、任何传送方式都能调它。
 *
 * 用法：
 *   node cli.mjs check [--raw] [--text] [--rules <file>]      # 检查，裁决输出到 stdout
 *   node cli.mjs run -- <命令...>                             # 检查后执行（就地替代"直接跑"）
 *   node cli.mjs describe                                     # 打印生效的规则
 *   node cli.mjs selftest                                     # 用真实事故命令跑全部规则
 *
 * check 的输入：
 *   默认  stdin 是 JSON 事件 {"command": "...", "shell"?: "...", "cwd"?: "...", "party"?: "..."}
 *   --raw stdin 是命令原文（给 shell 包装器用，省掉 JSON 转义）
 *
 * 退出码：
 *   0  放行（allow / warn）
 *   2  拦截（block）      —— 调用方只应把 2 当作"不要执行"
 *   3  用法/解析错误      —— 与拦截区分开：调用方可以自行决定失败开放还是失败关闭
 *
 * 这个文件不认识 ZCode、Claude Code、MCP 或 ssh；那些都是"快递方"，各有各的薄适配器。
 */

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_RULES, evaluate } from "./policy.mjs";
import { loadRules } from "./rules.mjs";
import { run as runPolicyTests } from "../tests/policy.test.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

async function readStdin() {
  let raw = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) raw += chunk;
  return raw;
}

function buildEvent(argv, raw) {
  if (argv.includes("--raw")) {
    return { command: raw, shell: readFlag(argv, "--shell") ?? undefined, cwd: readFlag(argv, "--cwd") ?? undefined };
  }
  const text = raw.trim();
  if (!text) return { command: "" };
  const parsed = JSON.parse(text);
  if (typeof parsed === "string") return { command: parsed };
  return parsed ?? { command: "" };
}

function readFlag(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
}

/**
 * JSON 一律转义成纯 ASCII 再输出。
 *
 * 理由：解码方式由**消费端**决定，生产端管不着。本机的 PowerShell 用 GBK 解码子进程的
 * stdout，含非 ASCII 字节的 JSON 会被解成乱码，连 JSON 结构都保不住（实测：
 * "从 JSON 转换失败 … unexpected character 'f'"）。\uXXXX 转义在语义上完全等价，
 * 解析后拿到的仍是原来的中文。
 */
function toAsciiJson(value, indent) {
  return JSON.stringify(value, null, indent).replace(/[\u007f-\uffff]/g, (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")
  );
}

function render(verdict, text) {
  if (text) {
    return `${verdict.verdict.toUpperCase()}  ${verdict.matched ?? "-"}\n${verdict.reason || "(无)"}\n`;
  }
  return toAsciiJson(verdict, 2) + "\n";
}

function exitCodeFor(verdict) {
  return verdict.verdict === "block" ? 2 : 0;
}

async function cmdCheck(argv) {
  let rules;
  let event;
  try {
    rules = loadRules({ file: readFlag(argv, "--rules"), depth: readFlag(argv, "--depth") });
    event = buildEvent(argv, await readStdin());
  } catch (err) {
    process.stderr.write(`[command-guard] 输入无法解析：${err.message}\n`);
    return 3;
  }
  const verdict = evaluate(event, rules);
  if (!argv.includes("--quiet")) {
    process.stdout.write(render(verdict, argv.includes("--text")));
  }
  return exitCodeFor(verdict);
}

async function cmdRun(argv) {
  const sep = argv.indexOf("--");
  const cmdline = sep >= 0 ? argv.slice(sep + 1) : [];
  if (!cmdline.length) {
    process.stderr.write("[command-guard] run 需要 `-- <命令...>`\n");
    return 3;
  }
  const rules = loadRules({ file: readFlag(argv, "--rules"), depth: readFlag(argv, "--depth") });
  // 用原始命令行文本做判定：这正是甲方写下的那串字符，也是唯一能核对的东西。
  const verdict = evaluate({ command: cmdline.join(" ") }, rules);
  if (verdict.verdict === "block") {
    process.stderr.write(`[command-guard] 已拦截，未执行。\n${verdict.reason}\n`);
    return 2;
  }
  if (verdict.verdict === "warn") {
    process.stderr.write(`[command-guard] 提示：${verdict.reason}\n`);
  }
  // 不经 shell：命令与参数按数组直接传给进程，避免二次解释。
  const child = spawn(cmdline[0], cmdline.slice(1), { stdio: "inherit", shell: false });
  return await new Promise((resolve) => {
    child.on("error", (err) => {
      process.stderr.write(`[command-guard] 无法启动 ${cmdline[0]}：${err.message}\n`);
      resolve(3);
    });
    child.on("exit", (code, signal) => resolve(signal ? 3 : code ?? 0));
  });
}

function cmdDescribe(argv) {
  const rules = loadRules({ file: readFlag(argv, "--rules"), depth: readFlag(argv, "--depth") });
  process.stdout.write(JSON.stringify(rules, null, 2) + "\n");
  return 0;
}

function selftest() {
  const { pass, total, lines } = runPolicyTests();
  process.stdout.write(lines.join("\n") + `\n\n${pass}/${total} 通过\n`);
  return pass === total ? 0 : 1;
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0] ?? "";
  if (cmd === "check") return cmdCheck(argv);
  if (cmd === "run") return cmdRun(argv);
  if (cmd === "describe") return cmdDescribe(argv);
  if (cmd === "selftest" || cmd === "--selftest") return selftest();
  process.stderr.write(
    [
      "command-guard —— 与 agent 无关的命令护栏",
      "",
      `  node ${join(HERE, "cli.mjs")} check [--raw] [--text] [--rules <file>] [--depth N]`,
      `  node ${join(HERE, "cli.mjs")} run -- <命令...>`,
      `  node ${join(HERE, "cli.mjs")} describe | selftest`,
      "",
      "  --depth N  一个数字调保护力度（覆盖规则文件里的值）：",
      "             0=只保护根自己  1=根+第一层  n=往下 n 层  -1=整棵子树",
      "退出码 0=放行 2=拦截 3=用法错误",
      "",
    ].join("\n")
  );
  return 3;
}

main().then(
  (code) => process.exit(typeof code === "number" ? code : 0),
  (err) => {
    process.stderr.write(`[command-guard] 致命错误：${err.stack || err.message}\n`);
    process.exit(3);
  }
);
