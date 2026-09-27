#!/usr/bin/env bash
# 薄适配器：任何"能把命令交出去"的地方都能用这一个。
#
# 用法：
#   guard.sh <命令> [参数...]        # 检查后执行；被拦下则不执行
#   guard.sh --check <命令> [参数...] # 只检查，不执行（退出码 0=放行 2=拦截）
#
# 它不关心命令是谁写的、从哪来的 —— 它是"先问引擎再交给乙方"的那个夹层。
# 引擎路径可以用 COMMAND_GUARD_HOME 覆盖，默认取本脚本上一级目录。

set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GUARD_HOME="${COMMAND_GUARD_HOME:-$(dirname -- "$HERE")}"
CLI="$GUARD_HOME/src/cli.mjs"
NODE_BIN="${COMMAND_GUARD_NODE:-node}"

check_only=0
if [ "${1:-}" = "--check" ]; then
  check_only=1
  shift
fi

if [ "$#" -eq 0 ]; then
  echo "用法: guard.sh [--check] <命令> [参数...]" >&2
  exit 3
fi

# 用原始命令行文本判定：这是甲方写下的那串字符，也是唯一能核对的东西。
verdict="$("$NODE_BIN" "$CLI" check --raw --text 2>/dev/null <<< "$*")"
rc=$?

if [ "$rc" -eq 2 ]; then
  echo "[command-guard] 已拦截，未执行。" >&2
  echo "$verdict" >&2
  exit 2
fi
if [ "$rc" -eq 3 ]; then
  echo "[command-guard] 检查本身失败（退出码 3）：$verdict" >&2
  exit 3
fi

[ "$check_only" -eq 1 ] && exit 0

case "$verdict" in
  WARN*) echo "[command-guard] 提示：$verdict" >&2 ;;
esac

exec "$@"
