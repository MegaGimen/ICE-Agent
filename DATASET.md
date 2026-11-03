# ICE trajectory dataset recorder

`ice/exercise/record.py` records one investigation **episode** at a time: a scoped-clean machine, an
armed attack, ICE's full forward flow, and the agent's complete turn-by-turn trajectory.

Actions are **executed for real** (`ICE_DRY_RUN=0`), because each agent step has to build on the real
consequences of the previous one — a dry-run trajectory would be counterfactual.

## Why "clean machine" here means scoped reset
This box cannot start a throwaway container or VM per episode: it is an unprivileged Docker container
(no `CAP_SYS_ADMIN`, `unshare` blocked by seccomp, no `/dev/kvm`, no docker socket). See DEPLOY_BOX.md.
So each episode restores a **snapshot of the mutable system state** instead:

    record.py snapshot        # once, on a box with no scenario residue

tars the paths an attack or a remediation can change — `/etc/passwd|shadow|group|gshadow`,
`sudoers(.d)`, `crontab`, `cron.d`, `cron.*`, `/var/spool/cron`, `/etc/systemd/system`,
`ld.so.preload`, `hosts.allow|deny`, `/root/.ssh`, `/home/iceagent/.ssh` — plus a manifest of
`/tmp` and `/var/tmp`. Docker bind mounts (`/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`) are
skipped automatically: tar cannot replace a bind mount.

Per episode, `reset()` then:
1. stops the daemon and any running agent,
2. extracts the baseline over `/` (`--overwrite`) and deletes `/tmp`,`/var/tmp` entries that are not
   in the manifest,
3. wipes `ICE_STATE_DIR` (baseline, snapshots, cases, graph, audit, error book),
4. deletes the OpenClaw agent store so the agent has no memory of earlier episodes, and
   `openclaw sandbox recreate --all`,
5. starts the daemon and waits `ICE_RECORD_WARMUP` seconds so ICE takes **T0 of the clean machine**
   before the attack lands — without this the attack is not a diff and nothing escalates.

`verify_clean()` then greps for the scenario's own markers; residue is recorded in `episode.json`
as `reset_residue` rather than silently ignored.

## Recording posture
`source ice/serving/record_env.sh`:

| variable | value | why |
|---|---|---|
| `ICE_RECORD_MODE` | 1 | Kev is **not** a safety-gate veto: `runtime.py` builds the gate with no score provider, so its score-based DENYs ("lacks a legitimate basis", "effects exceed the stated scope") cannot truncate a trajectory. Kev scores the finished episode instead. |
| `ICE_AUTO_APPROVE` | 1 | no human in the loop |
| `ICE_DRY_RUN` | 0 | execute for real |
| `ICE_FORCE_ESCALATE_FLAG` | `$ICE_STATE_DIR/FORCE_ESCALATE` | every change reaches investigation, but **only while the recorder has armed an attack** |
| `ICE_DENY_CRITICAL_ASSETS` | 1 | deterministic floor, see below |

**Why the flag file and not `ICE_FORCE_ESCALATE=1`:** forcing for the whole run spends each episode
investigating reset/warmup noise. OpenClaw serialises agent runs (a second one fails with "Another
OpenClaw process is using your data"), so the real attack would queue behind the noise. The recorder
touches the flag immediately before arming and removes it once the case is found.

**Why the critical-asset floor stays on:** it is static policy, not Kev's judgement and not a human
gate. Without it an episode can delete this rig's own SSH key (the agent has proposed
`rm -f /root/.ssh/authorized_keys`) or stop the models, which would end the data collection. It
denies `/root/ICE`, `/root/ice_models`, `/root/.ssh`, the model ports, etc. A DENY that does fire is
recorded in the audit, so the episode stays usable as a labelled datapoint.

## What an episode bundle contains
`$ICE_DATASET_DIR/<scenario>-<UTC>-<NNN>/`:

| file | contents |
|---|---|
| `ice-audit.jsonl` | ICE's **hash-chained** audit for the episode (`prev`/`hash` per record): every gate result with Kev's per-attribute scores and verdict, `case.open`, `graph.write`, `case.investigated`, `host_exec.verdict`, `host_exec.executed`, `backward`. Because the state dir is wiped per episode, this file is exactly one episode. |
| `case-*.json` | the case: assessment, ATT&CK ids, blast radius, confidence, triggers, the agent's reasoning |
| `agent-trajectory.json` | the agent's full trajectory from OpenClaw's store: `transcript_events` (every message and tool call/result, with `parentId` threading and timestamps) and `trajectory_runtime_events`, for the session whose key is `agent:main:<case_id>` |
| `episode.json` | scenario ground truth (ATT&CK ids, artifacts, attack commands), the posture, deterministic `grade`, `kev_score`, and event counts |

## Grading
- **Deterministic** (`grade()`, same rules as `ice.exercise.drill`): verdict must be
  malicious/uncertain, ATT&CK must intersect ground truth, blast radius must cover the artifacts.
- **Kev** (`kev_score()`): one `/v1/systemone` call over the finished trajectory asking
  `verdict_correct`, `techniques_correct`, `scope_complete` (noul) and `investigation_quality`
  (score). This is Kev's only role in recording — it never gated the episode.

## Running
    source ice/serving/record_env.sh
    python -u -m ice.exercise.record snapshot                  # once, on a clean box
    python -u -m ice.exercise.record run persistence --episodes 5

Use `-u`: the recorder prints progress, and without it Python buffers the log when it is not a tty.

## Known limits
- Only one scenario is implemented upstream (`persistence`: a uid-0 account + `/etc/cron.d` entry).
  `targets/SCENARIOS.md` describes two more (access expansion, outbound transfer) that are not in
  `ice/exercise/scenarios.py` yet.
- The scenario's `variant` uses `systemctl enable`; systemd is not PID 1 in this container, so the
  variant phase cannot run here. The `attack` phase works.
- `iptables` is absent in this container, so iptables-based containment fails. That failure is itself
  recorded in the trajectory.
- The ssh-sandboxed agent is slow (an unsandboxed turn took 29 s; sandboxed turns run minutes),
  which caps episode throughput. `agents.defaults.sandbox.mode="off"` trades confinement for speed.
- Scoped reset is not a fresh OS. Residue drift is possible across many episodes; `verify_clean()`
  flags scenario residue, and a periodic fresh-box control run is the way to quantify the rest.

## Verified: first recorded episode

`persistence-20261103T023712Z-001`, recorded end to end on the box:

    reset -> restore baseline, wipe ICE state + OpenClaw store, sandbox recreate,
             start daemon, 75s for T0 of the clean machine
    arm   -> useradd -g 0 ... butter ; chpasswd ; /etc/cron.d/persistevil        (all ok)
    ICE   -> cycle 4: 5 changes, 5 escalated
    agent -> case-b69db594 ok=True 62.0s tools=['tool_search','exec']   (sandboxed, as iceagent)
    ALERT -> assessment=malicious attck=['T1136.001','T1098.004','T1053.003']
    gate  -> AUTO-APPROVED (no human review) 'rm -f /etc/cron.d/persistevil'
    export-> grade=OK
    clean -> userdel butter ; rm -f /etc/cron.d/persistevil /tmp/atomic_art.log

Bundle:

| file | size |
|---|---|
| `agent-trajectory.json` | 486 KB — 115 transcript events + 117 trajectory runtime events |
| `case-b69db594.json` | 7 KB — `_ice` carries `t0`, `t1`, `actions`, `agent`, `knowledge`, `trigger_keys` |
| `ice-audit.jsonl` | 4.3 KB — 8 hash-chained events |
| `episode.json` | posture, ground truth, grade, Kev score, counts |

Deterministic grade, a clean hit:

    detected=true  verdict=malicious  confidence=0.95
    techniques=['T1053.003','T1136.001']   <- both ground-truth ids
    scope_missed=[]  miss=false

`blast_radius` was `['/etc/cron.d/persistevil','butter','/etc/passwd','/etc/shadow',
'/root/.ssh/authorized_keys']`, covering both ground-truth artifacts.

Timing: reset + T0 ≈ 2 min, detection ≈ 1 cycle (30 s), investigation 62 s, settle 60 s —
about 5 minutes per episode, so roughly 12 episodes an hour unattended.

### Kev scoring API note
This Kev build's `/v1/systemone` accepts only `noul` and `choice` questions; a `score` question is
rejected with `422 literal_error ... Input should be 'noul' / 'choice'`. The first episode therefore
recorded `kev_score: {"error": "HTTPError: HTTP Error 422"}` while its deterministic grade was fine.
`investigation_quality` is now a `choice` over ordered levels instead.
