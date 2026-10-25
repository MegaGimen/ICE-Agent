#!/bin/bash
# 用法: ice/serving/nc.sh <nemoclaw 参数>   例: nc.sh ice agent --session-key t1 --json -m "hi"
# nemoclaw 装在 nvm 的 node 下；dell 刚加进 docker 组，旧登录会话里要用 sg docker 才有权限。
# 参数经 NUL 分隔的临时文件传给 sg 内的自己，不做任何 shell 转义：sg -c 由 dash 解析，
# bash 的 printf %q 引号（$'...'）在 dash 下会语法错误，长消息/特殊字符必然踩到。
export NVM_DIR=$HOME/.nvm; . "$NVM_DIR/nvm.sh" >/dev/null; export PATH=$HOME/.local/bin:$PATH
export NEMOCLAW_DISABLE_TELEMETRY=1 NODE_NO_WARNINGS=1

if [ -z "${NC_ARGS_FILE:-}" ] && [ "$(id -u)" -ne 0 ] && ! id -nG | tr ' ' '\n' | grep -qx docker; then
  f="$(mktemp)"
  printf '%s\0' "$@" > "$f"
  NC_ARGS_FILE="$f" exec sg docker -c "$(readlink -f "$0")"
fi
if [ -n "${NC_ARGS_FILE:-}" ]; then
  mapfile -d '' -t ARGS < "$NC_ARGS_FILE"
  rm -f "$NC_ARGS_FILE"
  unset NC_ARGS_FILE
  set -- "${ARGS[@]}"
fi
exec nemoclaw "$@"
