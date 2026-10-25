#!/usr/bin/env bash
# 服务健康检查（plan.md §8）。
# 用法:
#   health_check.sh vllm [--wait]   检查主模型 :8000
#   health_check.sh kev  [--wait]   检查决策模型 :8010
#   health_check.sh all             两个都查一次
# --wait: 轮询直到就绪（vLLM 约 6 分钟），超时 600s。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

probe_vllm() {
  # vLLM 就绪后 /health 返回 200，/v1/models 列出模型
  curl -sf -m 5 "http://localhost:$VLLM_PORT/health" >/dev/null 2>&1
}
probe_kev() {
  # Kev 实现 TypeSafe：GET /v1/models 在模型加载完成后才可用（serve.py）
  curl -sf -m 5 "http://localhost:$KEV_PORT/v1/models" >/dev/null 2>&1
}

wait_for() {
  local name="$1" fn="$2" timeout="${3:-600}" t=0
  echo -n ">>> 等待 $name 就绪 "
  while ! "$fn"; do
    if [ "$t" -ge "$timeout" ]; then echo " 超时(${timeout}s)"; return 1; fi
    echo -n "."; sleep 5; t=$((t+5))
  done
  echo " OK (${t}s)"; return 0
}

check_one() {
  local name="$1" fn="$2" wait="$3"
  if [ "$wait" = "--wait" ]; then
    wait_for "$name" "$fn" 600
  elif "$fn"; then
    echo ">>> $name: OK"
  else
    echo ">>> $name: 未就绪 / 不可达"; return 1
  fi
}

target="${1:-all}"; wait="${2:-}"
case "$target" in
  vllm) check_one vLLM probe_vllm "$wait" ;;
  kev)  check_one Kev  probe_kev  "$wait" ;;
  all)  check_one vLLM probe_vllm ""; check_one Kev probe_kev "" ;;
  *) echo "用法: $0 {vllm|kev|all} [--wait]" >&2; exit 2 ;;
esac
