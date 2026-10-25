#!/usr/bin/env bash
# systemd ExecStartPost: block until the service answers, then post its status to Slack.
# Dependent units (After=) start only once this returns, so models come up strictly in order.
# 用法: wait_ready.sh {vllm|kev|embed} [timeout_s]
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"
svc="$1"; timeout="${2:-1200}"
case "$svc" in
  vllm)  url="http://localhost:$VLLM_PORT/health";  name="vLLM ($QWEN_MODEL)" ;;
  kev)   url="http://localhost:$KEV_PORT/v1/models"; name="Kev ($KEV_MODEL)" ;;
  embed) url="http://127.0.0.1:8020/health";         name="embedding service (bge-m3, CPU)" ;;
  *) echo "unknown service $svc" >&2; exit 2 ;;
esac
notify() { (cd "$HERE/../.." && "$ICE_ENVS/daemon-env/bin/python" -m ice.daemon.notify.status "$@") || true; }
t=0
until curl -sf -m 5 "$url" >/dev/null 2>&1; do
  if [ "$t" -ge "$timeout" ]; then
    notify "$svc" failed "$name not ready after ${timeout}s"
    exit 1
  fi
  sleep 5; t=$((t+5))
done
notify "$svc" ready "$name ready after ${t}s"
