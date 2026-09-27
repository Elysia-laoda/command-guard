/**
 * 规则装配 —— 引擎与各适配器共用这一处，避免"钩子读到默认值、CLI 读到配置文件"这种不一致。
 *
 * 优先级：显式 --rules 文件 > 项目根目录的 guard.json > 代码内置 DEFAULT_RULES。
 * 配置里只认 roots[].path / roots[].depth（level、exclude 由 protect/guard.ps1 使用）。
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_RULES } from "./policy.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

/** guard.json 的默认位置：项目根（src/ 的上一级）。没有就返回 null。 */
export function guardConfigPath() {
  const p = join(HERE, "..", "guard.json");
  return existsSync(p) ? p : null;
}

export function loadRules({ file = null, depth = null } = {}) {
  let rules = DEFAULT_RULES;
  const source = file ?? guardConfigPath();
  if (source) {
    const raw = JSON.parse(readFileSync(source, "utf8"));
    if (Array.isArray(raw?.roots)) {
      // guard.json 的形状：roots[] 直接就是受保护根
      rules = { ...DEFAULT_RULES, protectedRoots: raw.roots };
    }
    else {
      rules = { ...DEFAULT_RULES, ...raw };
    }
  }
  if (depth !== null && depth !== undefined && `${depth}`.trim() !== "") {
    const d = Number(depth);
    if (!Number.isInteger(d)) throw new Error(`--depth 需要一个整数，收到：${depth}`);
    rules = {
      ...rules,
      defaultDepth: d,
      protectedRoots: (rules.protectedRoots ?? []).map((r) => ({
        ...(typeof r === "string" ? { path: r } : r),
        depth: d,
      })),
    };
  }
  return rules;
}
