/**
 * 策略引擎 —— 与任何 agent、任何宿主、任何传送方式无关的纯函数。
 *
 * 契约：吃一个"命令事件"，吐一个"裁决"。它不知道 ZCode、Claude Code、MCP 或 ssh 的存在，
 * 也不假设是谁写的这条命令。甲方（命令的作者）不需要配合，快递方（怎么送过来）也不影响判定。
 *
 * 输入 event:
 *   { command: string,            // 必填：待检查的原始命令文本（原样，不做展开）
 *     shell?: 'bash'|'powershell'|'cmd',   // 可选：影响路径字面量的解析
 *     cwd?: string,               // 可选：相对路径的基准
 *     party?: string }            // 可选：仅用于报告，不参与判定
 *
 * 输出 verdict:
 *   { verdict: 'allow'|'warn'|'block',
 *     matched: string|null,       // 命中的规则 id
 *     reason: string,             // 给人/给模型看的理由
 *     findings: [{ rule, severity, target, detail }] }
 *
 * 规则是数据，不是代码：默认规则见 DEFAULT_RULES，可用 rules JSON 覆盖。
 */

/** 默认规则。所有条目都对应真实事故或已知会毁数据的写法。 */
export const DEFAULT_RULES = {
  /**
   * 受保护范围。**力度就靠这里的 depth 一个数字调**：
   *   depth: 0   只保护它自己        —— D:\proj 不能被删，D:\proj\a 可以
   *   depth: 1   保护它自己 + 第一层   —— D:\proj 与 D:\proj\a 都不能被删，D:\proj\a\b 可以
   *   depth: n   同理，往下 n 层
   *   depth: -1  整棵子树             —— 不可再生的数据用这个
   * 不在表里的路径不受保护（卷根除外，见下）。
   *
   * 默认留空：受保护的具体路径属于**部署配置**，不写死在代码里。
   * 写进项目根目录的 guard.json（见 guard.json.example），cli 与各适配器都会读它。
   */
  protectedRoots: [],

  /** 上面没写 depth 的条目用这个默认值；命令行 --depth 也改它。 */
  defaultDepth: 1,

  /** 破坏性动词。顺序无关；命中任一即进入规则检查。 */
  destructiveVerbs: [
    { id: "Remove-Item", re: "\\bRemove-Item\\b" },
    { id: "ri", re: "(^|[\\s;&|(])ri\\s" },
    { id: "rm", re: "(^|[\\s;&|(])rm\\s" },
    { id: "rmdir", re: "\\brmdir\\b" },
    { id: "rd", re: "(^|[\\s;&|(])rd\\s" },
    { id: "del", re: "(^|[\\s;&|(])del\\s" },
    { id: "erase", re: "\\berase\\b" },
    { id: "Clear-RecycleBin", re: "\\bClear-RecycleBin\\b" },
    { id: "Format-Volume", re: "\\bFormat-Volume\\b" },
    { id: "git-clean", re: "\\bgit\\s+clean\\b[^\\n]*-[a-z]*f" },
  ],

  /** 递归/强制开关：出现它，命令的杀伤面就从"一个文件"变成"一整棵树"。 */
  recursiveOrForce: "-recurse\\b|-r\\b|-rf\\b|-fr\\b|-force\\b|/s\\b",

  /** 变量插值：跨 shell 传变量时，展开结果无法在命令文本里核对。 */
  variableInterpolation: "\\$[A-Za-z_(]|\\$\\{|%[A-Za-z_]+%",
};

function toRe(s) {
  return s instanceof RegExp ? s : new RegExp(s, "i");
}

function log() {}

/** 从命令行里挑出看起来像路径的片段：引号里的优先，其次裸 token。 */
export function extractPaths(command) {
  const out = [];
  const re = /'([^']*)'|"([^"]*)"|(?:^|[\s=;])([A-Za-z]:\\[^\s'"|;&]*|\/[^\s'"|;&]*|~[^\s'"|;&]*)/g;
  let m;
  while ((m = re.exec(command)) !== null) {
    const v = m[1] ?? m[2] ?? m[3];
    if (v) out.push(v);
  }
  return out;
}

export function normalizePath(p) {
  let s = String(p).trim();
  s = s.replace(/^["']|["']$/g, "").replace(/\\+$/, "");
  if (/^[A-Za-z]:\//.test(s)) s = s.replace(/\//g, "\\");
  return s;
}

/** 盘符路径的形状：卷根 / 第几层。非盘符路径返回 null。 */
export function pathShape(p) {
  const m = /^([A-Za-z]):(.*)$/.exec(p);
  if (!m) return null;
  const rest = m[2].replace(/^\\+/, "");
  if (rest === "") return { root: true, depth: 0, text: `${m[1]}:\\` };
  const segs = rest.split("\\").filter(Boolean);
  return { root: false, depth: segs.length, text: p };
}

/**
 * 目标是否落在受保护范围内。depth 的语义见 DEFAULT_RULES.protectedRoots 的注释。
 * 返回 null 表示不在任何受保护范围内；否则给出距根层数与那个根设定的上限。
 * 注意：距离超过上限时**继续看下一个根**，因为同一路径可能落在另一个更宽的范围里。
 */
export function protectedHit(p, protectedRoots, defaultDepth = 1) {
  const low = String(p).toLowerCase().replace(/\\+$/, "");
  for (const entry of protectedRoots) {
    const root = String(typeof entry === "string" ? entry : (entry?.path ?? ""));
    const limit = typeof entry === "string" ? defaultDepth : (entry?.depth ?? defaultDepth);
    const r = root.toLowerCase().replace(/\\+$/, "");
    if (!r) continue;
    if (low === r) return { root, depth: 0, limit };
    if (low.startsWith(r + "\\")) {
      const rest = low.slice(r.length + 1).replace(/\\+$/, "");
      const d = rest.split("\\").filter(Boolean).length;
      if (limit < 0 || d <= limit) return { root, depth: d, limit };
    }
  }
  return null;
}

const OK = { verdict: "allow", matched: null, reason: "", findings: [] };

function block(rule, target, detail) {
  return { verdict: "block", matched: rule, reason: detail, findings: [{ rule, severity: "block", target, detail }] };
}

/**
 * 结构化核心：已经知道动词、目标、开关时直接判定。
 * 任何已经解析过命令的适配器（PowerShell 的 cmdlet 包装、MCP 代理、CI 钩子）都该走这里，
 * 不必把命令重新拼成文本再解析一遍 —— 拼回去本身就会引入新的转义问题。
 */
export function evaluateTargets(input, rules = DEFAULT_RULES) {
  const verb = input?.verb ?? "(unknown)";
  const targets = Array.isArray(input?.targets) ? input.targets.filter((t) => typeof t === "string") : [];
  const recursive = Boolean(input?.recursive || input?.force);
  const usesVariable = Boolean(input?.usesVariable);

  // 规则 var-in-destructive：2026-09-15 那次误删的签名。
  // bash 双引号吃掉了 $new，路径塌缩成工作目录根，整棵树被递归删除。
  if (recursive && usesVariable) {
    const detail =
      `${verb} 带递归/强制开关，且路径里出现了变量。` +
      "跨 shell 传变量时展开结果无法在命令里核对，这正是 2026-09-15 工作区被整目录删除的形状。";
    return block("var-in-destructive", "(variable)", detail);
  }

  for (const raw of targets) {
    const p = normalizePath(raw);

    if (p.includes("..")) {
      return block("dotdot", p, `${verb} 的目标含 ".."（未规范化的相对路径）：${p}`);
    }

    // 根目录整体作为目标：/ 、~ 、\ —— "把整台机器交出去"的写法
    if (p === "/" || p === "~" || p === "\\") {
      return block("root-target", p, `${verb} 把 ${p} 作为删除目标。`);
    }

    const shape = pathShape(p);
    if (shape && shape.root) {
      return block("volume-root", shape.text, `${verb} 的目标是卷根：${shape.text}`);
    }

    // 受保护范围：命中即拦，深度上限在 protectedHit 里判定。
    // 更深的文件不在这里被拦 —— 那是故意的：让"删错一项"只伤到一项，而不是整棵项目树。
    const hit = protectedHit(p, rules.protectedRoots ?? [], rules.defaultDepth ?? 1);
    if (hit) {
      const scope = hit.limit < 0 ? "整棵子树" : hit.limit === 0 ? "它自己" : `它自己与往下 ${hit.limit} 层`;
      return block(
        hit.depth === 0 ? "protected-root" : "protected-depth",
        p,
        `${verb} 的目标落在受保护范围内：${hit.root}（该范围保护：${scope}；当前目标距根 ${hit.depth} 层）。` +
          "更深的文件不在保护范围内 —— 要调力度，改规则里的 depth 一个数字即可。"
      );
    }
  }

  // 放行但提示：绝对路径上的递归/强制删除，属于"删掉就回不来"的范畴。
  if (recursive && targets.length) {
    const detail =
      `${verb} 带递归/强制开关且目标是绝对路径。若这属于不可再生的数据，` +
      "改走回收站更稳妥：Remove-Safely（powershell-safe-delete 模块）。";
    return {
      verdict: "warn",
      matched: "recursive-absolute",
      reason: detail,
      findings: [{ rule: "recursive-absolute", severity: "warn", target: targets.join(" "), detail }],
    };
  }

  return OK;
}

/**
 * 文本前端：从命令原文抽出动词、目标、开关，再交给结构化核心。
 * 纯函数：同样的 event + rules 永远得到同样的 verdict。
 */
export function evaluate(event, rules = DEFAULT_RULES) {
  // 已经给了结构化目标的调用方可以直接走核心
  if (Array.isArray(event?.targets)) return evaluateTargets(event, rules);

  const command = typeof event?.command === "string" ? event.command : "";
  if (!command.trim()) return OK;

  const verb = rules.destructiveVerbs.find((d) => toRe(d.re).test(command));
  if (!verb) {
    // 没有已知破坏性动词，仍拦住把整个根交出去的最粗暴写法
    if (/\brm\s+-[a-z]*[rf][a-z]*\s+\/(\s|$)/.test(command)) {
      return block("root-target", "/", "rm 把 / 作为删除目标。");
    }
    return OK;
  }

  return evaluateTargets(
    {
      verb: verb.id,
      targets: extractPaths(command),
      recursive: toRe(rules.recursiveOrForce).test(command),
      usesVariable: toRe(rules.variableInterpolation).test(command),
    },
    rules
  );
}
