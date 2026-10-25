#!/bin/bash
# 用法: ice/serving/nc.sh <nemoclaw 参数>   例: nc.sh ice agent --session-key t1 --json -m "hi"
# nemoclaw 装在 nvm 的 node 下；dell 刚加进 docker 组，旧登录会话里要用 sg docker 才有权限。
# 在 docker 组 + nvm 环境下跑 nemoclaw
export NVM_DIR=$HOME/.nvm; . $NVM_DIR/nvm.sh >/dev/null; export PATH=$HOME/.local/bin:$PATH
export NEMOCLAW_DISABLE_TELEMETRY=1 NODE_NO_WARNINGS=1
exec sg docker -c "$(printf '%q ' nemoclaw "$@")"
