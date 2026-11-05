# ICE deployment — RTX PRO 6000 Blackwell box (Clore n1.de, sm_120, 96GB)

> **This is not the machine recording runs on.** Dataset recording happens on the Salad box,
> `root@220.86.159.73:21530` (the address the tooling uses: see `ice/exercise/sync_bundles.sh` and
> `ice/exercise/push_repo.sh`). The Clore instance below was rented for the local models; its SSH
> host keys no longer match, and port 2534 on that node may belong to someone else now, so do not
> connect to it on the strength of this file. Everything below describes that machine, not the
> recording rig.

Deployed 2026-11-03. This box differs from the GB10 plan: **96GB dedicated VRAM**
(not 120GB unified), compute cap **sm_120**, driver 595.84/CUDA 13.2, Ubuntu 20.04
**Docker container (no systemd)**, 188GB RAM, 2.1TB disk.

## What runs
| Service | Port | Env | VRAM | Notes |
|---|---|---|---|---|
| vLLM Qwen3.6-35B-A3B-NVFP4 | 8000 | ice-envs/vllm-env (vllm 0.33.0, torch 2.14+cu130) | ~28.6GB | modelopt NVFP4, Marlin MoE, FlashInfer OFF (no nvcc) |
| Kev-27B decision model | 8010 | ice-envs/kev-env (torch 2.8+cu128, py3.13) | ~49GB | bf16, prefix-cache + CUDA-graphs OFF, states truncated |
| embedding bge-m3 (+ATT&CK KB 356) | 8020 | ice-envs/kev-env, CPU | 0 | lazy-loads kb/attack.jsonl |
| ICE host daemon | MCP 8083, dashboard 8088 | ice-envs/daemon-env (py3.12) | 0 | perception(osquery)+detect(Kev)+graph+case |

Both models co-resident at ~78GB / 96GB.

## Start / stop (no systemd — setsid launchers)
    cd /root/ICE
    bash ice/serving/run_ice_box.sh          # ordered: vLLM -> Kev -> embed -> daemon
    # individually:
    bash ice/serving/start_vllm_box.sh        # ~2min to /health
    bash ice/serving/start_kev_box.sh         # or --fallback for kev-9b
    bash ice/serving/start_embed_box.sh
    ICE_DASHBOARD_PORT=8088 bash ice/serving/start_daemon_box.sh --no-slack
    # replay demo (dry-run, injects labelled synthetic attacks):
    bash ice/serving/start_daemon_box.sh --replay cron_curl_pipe_sh,ssh_key_root_new,webshell_child_shell --no-slack
    # stop a model (frees VRAM cleanly):
    bash ice/serving/stop_vllm.sh ; fuser -k 8010/tcp ; pkill -f ice.kb.embed_service
    # smoke test:
    /root/ice-envs/daemon-env/bin/python ice/serving/smoke_test.py

Config overrides live in ice/serving/env.box.sh (GB10 original kept as *.gb10.bak).

## View the dashboard from your laptop
    ssh -L 8088:127.0.0.1:8088 -p 2534 root@n1.de.clorecloud.net
    # then open http://127.0.0.1:8088/   (read-only live threat graph; /api/graph is the JSON)

## Box-specific fixes applied (vs GB10 plan)
1. apt install build-essential  (Triton JIT needs a C compiler)
2. VLLM_USE_FLASHINFER_SAMPLER=0 + VLLM_ATTENTION_BACKEND=TRITON_ATTN  (no nvcc/CUDA toolkit in container; FlashInfer JIT cannot build). NVFP4 MoE runs on Marlin (no nvcc).
3. Kev base tokenizer+config: downloaded Qwen/Qwen3.8-27B json/tokenizer only (no weights) at rev 1d4bf0f2 — Kev loads its tokenizer from the base.
4. setsid launchers (container kills nohup children on ssh channel close).
5. osquery 5.12.1 installed (perception sensor).
6. MCP bearer token generated at deploy/local-secrets/mcp.token.
7. Dropped all unified-memory drop_caches logic (dedicated VRAM; also /proc not writable here).

## Verified working end-to-end
- smoke_test: Qwen tool-call PASS, Kev judge PASS (malicious vs normal).
- Live replay: Kev escalated all 3 malicious fixtures (verdict=malicious, persistence/privilege/actor_mismatch ~1.0), passed benign real host activity; case opened + correlation graph written; dashboard shows the incident.

## Known gaps (need extra infra, not GPU)
- Investigation agent + ICE Gate: driven by the NemoClaw/OpenClaw sandbox (nc.sh -> nemoclaw) over MCP; needs node CLI + OpenShell **docker** gateway (not in this container) + Slack tokens. Until then case.investigated returns "Agent returned no case" and ASK actions DENY (fail-closed). Detection/correlation/decision are unaffected.
- MCP TLS proxy (nginx 8443) / Slack ICE Gate: not configured (no tokens/bridge here).

---

# OpenClaw investigation agent (added 2026-11-03)

The investigate stage (`ice/daemon/investigate/agent.py`) shells out to an OpenClaw agent.
It is now installed and wired to the local vLLM.

## What was installed
- **node 24.22.2** at `/root/node24` (OpenClaw requires `>=24.22.1 <25 || >=26.12.1`; the box had node 16).
- **openclaw 2026.10.9** globally: `npm install -g --allow-scripts=@google/genai,esbuild,koffi,protobufjs,openclaw openclaw`
  (the allow-scripts list matters: openclaw's own postinstall sets up bundled plugins).
- Config/state in `/root/.openclaw` (`openclaw setup --baseline`).

## Provider: local vLLM (no cloud model)
`models.providers.vllm` in `/root/.openclaw/openclaw.json`:
baseUrl `http://127.0.0.1:8000/v1`, api `openai-completions`, apiKey `vllm-local` (vLLM enforces none),
timeoutSeconds 300, one model `nvidia/Qwen3.6-35B-A3B-NVFP4` (contextWindow 65536, maxTokens 8192).
Default model `agents.defaults.model.primary = vllm/nvidia/Qwen3.6-35B-A3B-NVFP4`.
`openclaw models list` shows it as `66k`, default. vLLM `--max-model-len` was raised 32768 -> 65536
because OpenClaw's system prompt + tool schemas alone are ~19k tokens (measured: promptTokens 18873).

## ICE host tools over MCP
`openclaw mcp add ice-host --url http://127.0.0.1:8083/mcp --transport streamable-http --header "Authorization=Bearer <mcp.token>" --timeout 120 --parallel`
`openclaw mcp probe` -> **ice-host: 4 tools**. A test turn called `ice-host__host_query` and ICE logged a
`tool` event in `~/ice-state/audit.jsonl`, so the agent really reaches ICE's host tools.

## Why --local instead of the OpenShell/Docker sandbox
This Clore container is **not privileged** (CapEff has no cap_sys_admin, no iptables, no /dev/fuse), so a
nested `dockerd` cannot run and `openclaw sandbox` (Docker-based isolation) is unavailable. `openclaw agent
--local` runs the agent embedded in-process instead, which needs no container.

## Two adaptations in ICE
1. `ice/serving/oc.sh` (new): maps the old NemoClaw argv `<sandbox> agent --session-key K --json -m MSG`
   onto `openclaw agent --local --session-key K --json -m MSG`. Wire it with `ICE_NC=/root/ICE/ice/serving/oc.sh`
   and `ICE_AGENT_USER=` (empty, so the root daemon does not sudo to a nonexistent `dell` user). Both are
   set in `ice/serving/env.box.sh`.
2. `ice/daemon/investigate/agent.py`: OpenClaw 2026.10 `agent --json` returns `{payloads, meta}` at the top
   level, while ICE expected `{"result": {...}}`; tool names moved from
   `agentMeta.terminalReceipt.successfulToolNames` to `meta.toolSummary.tools`. The parser now accepts both
   shapes. **This was the real cause of the earlier "Agent returned no case"** — not a missing model.

---

# Agent sandbox + unattended approvals (2026-11-03)

## Why not Docker / Podman / OpenShell on this box
Measured, not assumed:
- `CapEff 00000000a80425fb` — the default Docker cap set, **no CAP_SYS_ADMIN**.
- `unshare -Ur` and `unshare -Urm` both fail with **EPERM** (seccomp filter active), although
  `max_user_namespaces=717036` and `unprivileged_userns_clone=1`. So **rootless Podman is out too.**
- **No `/dev/kvm`** -> no virtualization. **No `/var/run/docker.sock`** -> cannot borrow a host daemon.

OpenClaw sandbox backends are `docker | podman | ssh | openshell | crabbox`. **OpenShell is only a
control plane**: its own docs require "a supported compute runtime on the gateway host for local
sandboxes" (Docker, Podman or virtualization) or a reachable remote OpenShell gateway on separate
infrastructure. Neither exists here, so OpenShell cannot sandbox anything on this box either.

## What is used instead: the `ssh` backend to a confined local user
`sshd` already listens on :22 in this container, and the ssh backend explicitly does not involve
Docker (`sandbox.docker.*` does not apply to it).

- unprivileged user **`iceagent`**, key `/root/.ssh/id_ed25519_sandbox`, host key pinned in
  `/root/.ssh/known_hosts_sandbox`, workspaces under `/home/iceagent/sandboxes`.
- `agents.defaults.sandbox = {mode:"all", backend:"ssh", scope:"session", workspaceAccess:"rw",
  ssh:{target:"iceagent@127.0.0.1:22", workspaceRoot:"/home/iceagent/sandboxes", ...}}`
- `openclaw sandbox explain` -> `runtime: sandboxed`, `backend: ssh`, fresh per-session workdir;
  `exec/read/write/edit/apply_patch` run inside the sandbox, chat channels denied,
  elevated exec `allowedByConfig: false`.

**Proved by running the agent** (session `sandbox-proof2`, tool `exec`):
```
id -un  -> iceagent
pwd     -> /home/iceagent/sandboxes/openclaw-ssh-workspace-<hash>/workspace
touch /root/PWNTEST2        -> Permission denied, exit=1
cat /root/.ssh/authorized_keys -> Permission denied
```
**Honest limit:** this is POSIX user isolation on the same kernel and the same filesystem namespace,
not container isolation. The agent cannot modify (or read) root-owned paths, but it is not a fresh
machine and world-readable files stay readable. For true isolation, point `ssh.target` at a separate
throwaway host, or use `backend: openshell` once a real OpenShell gateway is reachable.

## The part a sandbox does NOT cover
ICE's own `host_query` / `host_exec` MCP tools execute **inside the root ICE daemon**, not in the
agent sandbox. Sandboxing the agent therefore does not stop ICE from changing the real host; only the
safety gate, `ICE_CRITICAL_ASSETS` and `ICE_DRY_RUN` do.

## Unattended approvals (no Slack)
`ICE_AUTO_APPROVE=1` (new, `runtime._AutoApproveStore`): each ASK is approved the moment the gate
queues it, so propose -> ASK -> approve -> execute -> backward runs with no human. It does **not**
bypass policy: `ApprovalStore.decide()` still calls `approval_guard`, so critical-asset, out-of-scope
and kill-switched commands are still refused (refusals are logged, request left to expire).

Paired with `ICE_DRY_RUN=1` — gate verdicts and approvals happen as usual, **no command executes**.
Keep them together on a test box. With dry run off, auto-approve lets ICE run irreversible
containment as root; it has already proposed `rm -f /root/.ssh/authorized_keys`, which would end SSH
access to this machine. `ICE_CRITICAL_ASSETS` is now set to this box's real paths (the upstream
default lists a `/home/dell` GB10 layout that does not exist here) so that path is denied as a backstop.

## Finding: `critical_assets` alone does not deny (fixed)
`SafetyPolicy.deny_critical_assets` defaults to **False**, and `runtime.py` did not set it. Listing a
path in `ICE_CRITICAL_ASSETS` therefore only pushed the action onto the **ASK** path — it assumed a
human would refuse it. Observed live on this box: with `ICE_AUTO_APPROVE=1`, the proposal
`rm -f /root/.ssh/authorized_keys` was logged as

    AUTO-APPROVED (no human review) 'rm -f /root/.ssh/authorized_keys' on O-2392760

even though that exact path was in `ICE_CRITICAL_ASSETS`. Only `ICE_DRY_RUN=1` stopped it, and the
file was verified untouched.

`runtime.py` now sets `deny_critical_assets`, defaulting to **on whenever `ICE_AUTO_APPROVE=1`**
(override with `ICE_DENY_CRITICAL_ASSETS=0|1`): with no human behind ASK, a critical asset must be
refused outright rather than rubber-stamped. Legitimate containment that touches no critical asset
(e.g. `iptables -I INPUT -s <attacker-ip> -j DROP`) still passes.

Verified directly against the gate with the daemon's own config (`score_provider=None` to isolate the rule):

    rm -f /root/.ssh/authorized_keys      -> DENY  Critical asset is denied by policy
    rm -rf /root/ICE                      -> DENY  Critical asset is denied by policy
    systemctl stop vllm                   -> DENY  Critical asset is denied by policy
    iptables -I INPUT -s 45.9.1.2 -j DROP -> not a critical asset; in the running daemon this goes
                                             ASK -> AUTO-APPROVED and then `dry run: not executed`
                                             (audit `host_exec.executed`, `by: "AUTO"`, `dry_run: true`)

## Cost of the sandbox: investigation latency
Unsandboxed, an investigation turn took **29.2 s** (`agent case-d68d0d06: ok=True 29.2s`). With the
ssh backend every `exec`/file tool call round-trips over SSH with workspace sync, and a turn ran for
**6+ minutes** without finishing. OpenClaw also serialises its local state: a second `openclaw agent`
fails with "Another OpenClaw process is using your data", so manual test turns and daemon
investigations cannot overlap. If investigation latency matters more than confinement, set
`agents.defaults.sandbox.mode="off"` (agent then runs as root, unconfined) — or move the sandbox to a
separate host so the sync is not competing with the models for this box.

## Current posture on this box
    sandbox        : ssh backend -> iceagent@127.0.0.1, per-session workspace (agent confined, non-root)
    approvals      : ICE_AUTO_APPROVE=1  (no Slack, no human)
    execution      : ICE_DRY_RUN=1       (nothing runs on the host)
    critical assets: ICE_CRITICAL_ASSETS set for this box, denied outright (ICE_DENY_CRITICAL_ASSETS=1)
Going to production means: wire a real Slack approver, set ICE_AUTO_APPROVE=0, then ICE_DRY_RUN=0 last.
