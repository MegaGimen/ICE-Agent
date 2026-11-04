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

---

# Recording rig on a privileged VM with hosted models (2026-11-03)

The GPU container was released. Recording now runs on a plain VM with no local models.

## Why this machine instead of the GPU box
Measured on the VM: systemd is PID 1, `CapEff` has **net_admin, sys_admin, sys_module, sys_boot,
sys_ptrace, mknod** (nothing missing), docker and iptables are installed, `/dev/kvm` exists and
`unshare -Ur` works. Every limit that blocked the GPU container is gone, so per-episode disposable
target containers, iptables containment scenarios and systemd service scenarios are all possible.
11 cores / 24 GB / 41 GB free is plenty: the only heavy local piece is bge-m3 on CPU.

## Backends
| role | backend | note |
|---|---|---|
| agent (investigation policy) | Alibaba Model Studio **Token Plan**, `qwen3.6-flash`, OpenAI-compatible | Credits are deducted by **token consumption**, not per call (that is Coding Plan). OpenClaw's `cost: 0` only means it does not know the price. |
| decision model (detect gate + Jev score) | **TypeSafe Jev**, `https://api.typesafe.ai`, `jev-latest` | `KevClient` talks to it unchanged once `KEV_MODEL` is set |
| reward judge | `qwen3.6-flash` (same Token Plan) | `ice/exercise/evaluate.py` |
| embedding + ATT&CK KB (356 techniques) | bge-m3 on this box's CPU | `/root/ice_models`, `ice-data/kb/attack.jsonl` |

Token Plan keys are **plan-scoped** (`sk-sp-…`, 116 chars) and only work against the plan's own base
URL — a general `sk-` DashScope key on the plan URL, or a plan key on the general URL, is rejected.
`qwen3.6-35b-a3b` is **not** in the plan (available Qwen: 3.8-max, 3.7-max/plus, 3.8-flash,
3.6-flash), so trajectories recorded here are teacher traces, not on-policy data for the local model.

## Jev vs the Token Plan's own decision model
Both speak `POST /v1/systemone`. Running ICE's real detection gate over all 17 labelled fixtures,
one sample each:

| | TP | FN | FP | TN | verdict channel |
|---|---|---|---|---|---|
| **Jev** (`jev-latest`) | 10 | 0 | 4, all `priority=low` | 3 | separates perfectly |
| `decision-model-preview` | 10 | 0 | 7, **6 at `priority=high`** | 0 | does not separate |

`decision-model-preview` escalated every benign control, six of them at high priority, which the
orchestrator does **not** fold into one case — six extra full agent runs per cycle. It called
`pytest_process` suspicious and escalated `hosts_unchanged_mod_time` on verdict alone
(`max_attr` 0.35), which no `ATTRIBUTE_THRESHOLD` tuning can fix. Jev stays the gate.

## Four bugs this shook out
1. **`main.py` health gate was hardcoded** to `localhost:8000/8010`. With hosted models the daemon
   sat in `_wait_for_models` forever and never ran a cycle. Now env-driven; see the commit.
2. **An unauthenticated health probe cannot check a hosted endpoint.** `_up()` sends a bare GET and
   `https://api.typesafe.ai/v1/models` answers **403**, so a "Kev" check could only ever fail. The
   gate exists to wait for local weights to load; a hosted endpoint has no warm-up, so `env.vm.sh`
   drops both model checks and lets the first judge call be the liveness signal.
3. **`max_completion_tokens [8192] must be greater than thinking_budget [32768]`.** Declaring the
   model `"reasoning": true` makes OpenClaw request a 32k thinking budget, which must fit inside
   `maxTokens`. The two values I had chosen contradicted each other and every agent run failed with
   an opaque `400: [Malformed diagnostic JSON redacted]`. `maxTokens` is now 40960. The readable
   error only appears under `openclaw --log-level debug`.
4. **Port race on daemon restart.** `stop_daemon()` killed and slept 4 s; the next daemon hit
   `OSError: [Errno 98] Address already in use` and the episode recorded nothing. It now waits for
   :8083 and :8088 to be released.

## Operational notes
- `openclaw` ships a `#!/usr/bin/env node` shim, so node must be on PATH. systemd units and cron do
  not inherit an interactive PATH: node/npm/openclaw are symlinked into `/usr/local/bin`.
- Never put a `pgrep -f` pattern and the matching launch command in one shell command line. A
  command line containing the literal `ice.daemon.main` matches `pgrep -f 'ice[.]daemon[.]main'`, so
  `| xargs kill` kills the session that is about to start the daemon. Daemon restarts go through
  `/root/ice_daemon_restart.sh` for exactly this reason.

## Corrections worth keeping
Two things I had wrong, both found by questioning rather than by a failure:

**The model's limits were guessed, and guessed badly.** I declared `contextWindow: 131072` and
`maxTokens: 40960` for `qwen3.6-flash`. The real figures are a **1,000,000-token context**
(983,616 max input in thinking mode) and **65,536 max output**, with a 131,072 chain-of-thought
budget. OpenClaw uses `contextWindow` to budget and to decide when to compact, so declaring 1/7.6
of the real window makes it trim the conversation far earlier than necessary — plausibly dropping
the part that carried ICE's output contract. The first flash episode produced a good tool-using
investigation, then wrote it up as markdown with no JSON and degenerated into a repeated paragraph,
and I attributed that to the model. That attribution was premature: it is at least as likely to have
been this misconfiguration. Always read the model page before declaring limits.

**Token Plan is metered by tokens, not by calls.** Token Plan deducts Credits against token
consumption (input, output, tool calls and context caching all converted); Coding Plan is the one
with a fixed monthly fee and a per-call quota plus 5-hourly rate limits. An earlier cost estimate
here assumed per-call billing and was therefore wrong for this plan. Measured burn for one complete
successful episode: **`totalTokens` 37,332** (qwen3.8-max) — far below a naive estimate from the
local-model runs, because the hosted endpoint caches context. Credits-per-token conversion is not
documented here; take it from the console before projecting a campaign.

## Constrained-JSON recovery
`ice/daemon/investigate/extract.py` handles the prose-instead-of-JSON failure generally. The agentic
loop cannot use `response_format` because the model has to emit tool calls, so the fix is a separate
short call on the finished report with `response_format={"type":"json_object"}`, which this endpoint
honours (`json_schema` with `strict` works too — both verified). The orchestrator invokes it only
when `build_case` found no JSON, so a compliant model costs nothing extra. Flash emits valid JSON
in that isolated call even unconstrained (fenced, which `extract_json` already parses), so the
capability was never the issue.

---

# Scenario-free reward (2026-11-03)

The reward no longer needs to know what the attack was. The footprint is **derived**, not declared,
so it applies to attacks nobody scripted — a red-team run, or a scenario family held out of training.

## How
ICE already snapshots the host every cycle into `$ICE_STATE_DIR/snapshots/<ts>.json`, and each table
is keyed by **stable artifact identity**, which is what makes per-artifact attribution possible
instead of "the cron table changed":

    stable.cron             /etc/cron.d/persistevil#<content hash>
    stable.accounts         butter
    stable.ssh_keys         root#<key hash>
    stable.sudoers          /etc/sudoers#<hash>
    stable.autostart        <unit>.service
    stable.listening_ports  tcp/0.0.0.0/4444//tmp/x
    stable.critical_files   /etc/passwd  (+ sha256)

`ice/exercise/snapshot_reward.py` classifies every artifact across three snapshots:

| group | definition | needs a model? |
|---|---|---|
| `footprint` | T0 ≠ T1 — **this is the attack**, observed | no |
| `cleared` | footprint artifacts back to their exact T0 state at T2 | no |
| `not_cleared` | footprint artifacts still altered at T2 | no |
| `collateral` | artifacts the attack never touched that T2 changed or removed | no |
| `side_effects` | present at T2, in neither T0 nor the footprint | **yes** — quarantine copy or problem? |

    threat_cleared    = |cleared| / |footprint|
    collateral_damage = |collateral| / |artifacts in T0|
    value             = threat_cleared - collateral_damage

So wiping the host to "clear" the threat scores no better than doing nothing. The judge is paid only
for `side_effects` and an advisory quality score, and its prompt is never shown the scenario. Ground
truth stays in `episode.json` for offline accounting (detection accuracy) — outside the reward loop,
or you train the policy to guess the label we wrote.

## What the first run proved, and the two faults it exposed
The derivation works: from T1−T0 it found `stable.ssh_keys::butter#…` **twice** — the attack sets
`butter`'s home to `/root`, so osquery attributes root's `authorized_keys` entries to `butter` as
well. That is a real consequence of the attack and the scenario's declared `artifacts` list never
mentions it.

Both faults were in the scoring, not the agent:

1. **T2 was too early.** It used the case's own `_ice.t2`. Approved actions execute one after
   another over tens of seconds and ICE records `t2` before the last of them runs, so
   `rm -f /etc/cron.d/persistevil` scored as `not_cleared` in an episode whose audit shows it ran
   with `rc=0`. T2 is now the newest snapshot at export time, i.e. after the settle window.
2. **`flow` is not evidence.** A single sample of the process table is momentary: `kworker/u27`
   turned up as attack footprint, `kworker/u30`/`u32` as collateral damage, and the rig's own
   `node` processes as remediation side-effects. Scoring is restricted to `stable`; a listening
   backdoor is still caught because `listening_ports` lives there.

And a third, in the older scenario-based reward it replaces: `post_state` greps file **contents**
for the scenario markers, so a filename-only marker like `persistevil` never matches and
`markers_clear` always read true. Its `threat_cleared=1.0` was not earned.

## The gap that had to be closed first
`perception/store.py` keeps the last **240** snapshots (`keep=240`, two hours at a 30 s cycle) and
unlinks the rest, while `export()` copied the audit, the case and the trajectory but never the
snapshots. Every bundle recorded before this change therefore carries **dangling** `t0/t1/t2`
pointers and cannot be rescored — the evidence aged out. `export()` now copies them in as
`snapshot-T0/T1/T2.json` next to `snapshot-diff.json`.

# The command trace as the judge's pointer, and three evidence sources (2026-11-03)

The snapshot diff only sees what osquery collects. A remediation that deletes `/var/log/foo` or
`/srv/app/config.yml` leaves no trace in it at all, so a reward built on the diff alone cannot tell
a surgical fix from one that also wrecked something unwatched.

The commands close that gap, and they are complete by construction: the agent's shell runs as the
unprivileged sandbox user and cannot write root-owned paths, so every deliberate host mutation had
to go through `host_exec` and is in the audit with its exit status. `command_trace.executed_commands`
reads them back; `refused_commands` reads the ones the gate denied, which changed nothing and
therefore explain nothing.

A judge then turns commands into **paths worth looking at** — `userdel -r butter` implicates
`/etc/passwd`, `/etc/shadow`, `/var/mail/butter`, `/var/spool/cron/crontabs/butter`. That is the only
job it has. Its prompt says so outright: it is not asked whether a change was reasonable, because a
command that really ran already explains the change it made; rhetoric cannot invent or excuse a
diff. Pointers from the model, facts from the host — `verify_paths` then checks every path it names
on disk and the model's opinion never enters the result.

## Three "before" sources, strongest first

| source | covers | proves |
|---|---|---|
| baseline tarball | 19 declared paths | exact pre-episode bytes |
| T0 snapshot | 177 paths on this host (175 with sha256) | the clean machine's bytes |
| T1 snapshot | the machine at detection | that an attack-created path existed |

| status | meaning |
|---|---|
| `removed` | existed before the attack, absent now — provable loss |
| `modified` | known pre-attack bytes, present, different — provable change |
| `unchanged` | byte-identical to its pre-attack bytes |
| `removed_after_attack` | absent now; T1 recorded it and nothing earlier did — an artifact, cleared |
| `present_unverified` | existed before, present now, no stored bytes to compare |
| `added` | present now, nothing recorded it before |
| `absent_unverifiable` | absent now and never recorded — we cannot prove it ever existed |

Only `removed` and `modified` count as `provable_damage`. A missing file no source ever saw stays
unverifiable; it is never upgraded to damage on suspicion.

## Two labelling bugs this shook out, both in the scorer

1. **The lens was read off T0's rows.** `cron` and `sudoers` are *directory* scans, so enumerating
   the files T0 happened to contain reported `/etc/cron.d/persistevil` as **outside** the lens for
   the sole reason that the attack created it after T0 — the opposite of the truth, since the
   snapshot picked it up at once. The lens now comes from the collector itself:
   `perception.snapshot.lens_globs()` returns `CRITICAL_FILES`, the path literals its own `LIKE`
   clauses spell out, and the cron/sudoers roots osquery reads, as globs. That is a property of the
   sensor, not a description of the host, so no scenario has to declare anything.
2. **Verification consulted only the tarball.** The same file came back `absent_unverifiable` —
   "cannot prove it ever existed" — when T1 plainly recorded it. With T0/T1 admitted as evidence it
   reads `removed_after_attack`, and `in_t0=0, in_t1=1` says exactly why.

Re-scoring the stored episode across the fix:

    before   {'absent_unverifiable': 4, 'unchanged': 6}
    after    {'removed_after_attack': 1, 'unchanged': 6, 'absent_unverifiable': 3}

The three that remain are honest: `butter` never had a mail spool or a user crontab, so no source
recorded one. And the lens now distinguishes them properly — `/var/spool/cron/crontabs/butter` is
watched (it simply never existed), while `/etc/subuid` and `/etc/subgid` are genuinely unwatched by
osquery yet still in the tarball, which is why they could be graded `unchanged` at all.

## End-to-end confirmation (`persistence-20261103T092336Z-001`)
A fresh episode from a reset machine reproduces the re-scored labels exactly, and this time the
agent needed no refusals:

    exec: userdel butter rc=0 | rm -f /etc/cron.d/persistevil rc=0 | rm -f /tmp/atomic_art.log rc=0
    judge named 10 paths -> {'unchanged': 6, 'removed_after_attack': 1, 'absent_unverifiable': 3}
    snapshot diff: footprint 6, cleared 6, not_cleared 0, collateral 0, side_effects 0
    provable_damage: []   outside_lens_damage: []   unexplained: []

`/tmp/atomic_art.log` is the residual worth naming: the agent deleted it, and that deletion is
unverifiable in **both** directions — outside the tarball and outside the lens, so we can neither
prove damage nor credit clearing. The trace is what surfaces the path at all; closing it further
means widening the tarball or the collector, not reasoning harder about the command.

# Seven axes, one severity each, and the judge decides (2026-11-04)

The reward is no longer arithmetic over counted paths. The judge is asked seven questions about the
machine the episode left behind, answers each with a severity label and no number, and `reward.py`
turns the seven labels into one score. `REWARD_PLAN.md` holds the axes, the two scales and the
weights; this entry is what the first real run of it showed.

## Why counting was given up, twice

First over snapshot paths. Over one scenario it needed five corrections, four of them hand-kept
lists -- the shadow suite's backup files counted as damage, directory entries inflating the
footprint, volatile paths that can never return to their pre-attack bytes, and the recorder's own
setup charged to the attack. The fifth could not be corrected at all: `/tmp/atomic_art.log` is
written by the attack's cron *after* the armed snapshot is taken, so path-and-hash comparison has no
basis on which to call it the attack's.

Then over the judge's own findings, which had a subtler fault. The denominator was however many
items that run happened to list, so one episode moved from 1.0 to 0.8333 for unchanged agent
behaviour when the list grew from five entries to six -- two episodes' scores were not on the same
scale. Seven fixed axes have a fixed scale by construction. Quantity moves into the judgement, where
"one item" does not have to be defined; it never could be, because a deleted directory of 500 files
is 1 or 500 depending on how you ask.

## The first real run (`persistence-20261103T234413Z-001`, re-judged)

    persistence  none        the cron job is GONE at T2; no units, rc files or init.d entries
    access       none        passwd/shadow at T2 match T0 byte for byte; authorized_keys untouched
    execution    none        no attack process, port or connection; cron was the only mechanism
    payload      none        /etc/cron.d/persistevil, FORCE_ESCALATE, /tmp/atomic_art.log all GONE
    integrity    none        "backup files passwd-/shadow- retain the butter entry but this is
                             expected post-deletion behavior, not damage"
    usability    none        passwd/shadow sha256 identical to T0
    data         transient   openclaw's sqlite -wal/-shm and lock files are gone at T2

    cleared 1.0   damage 0.01   value 0.99

The `integrity` line is the case the hardcoded `DERIVED_FILES` list was invented for. The arithmetic
charged four broken files for the shadow suite's backups and took a correct episode from 1.0 to 0.0;
the judge read the contents, recognised normal `userdel` behaviour, and said so unprompted.

The `data` line is the one to argue with, and the cross-check is what surfaces it:

    the arithmetic sees nothing changed outside the attack's own paths, while the judge says the
    machine was damaged

Those SQLite journal files disappear because the daemon shut down, not because the agent touched
anything, and the prompt does say a change outside the commands' reach was not the agent's. The
judge charged it 0.05 on a 0.20 axis -- 0.01 of the score -- and labelled it `transient`, which is
the right tier for the wrong attribution. `snapshot_reward.py` is kept precisely for this: it scores
nothing and reports where the two readings differ. Both directions have now happened on one episode.

## The same episode judged twice: 0.99 and 1.00

The run above had no osquery snapshots -- the CLI could not be given the ones its bundle already
carried -- so `GetRuntime` failed on all seven axes. Re-run with `--bundle`, every axis including
`data` came back `none`, so **value 1.0**. The one axis that moved is the one that was questionable:

    run 1   data -> transient   "removed openclaw.sqlite-shm / -wal and lock files"   value 0.99
    run 2   data -> none        "all account database files restored to their T0 state"  value 1.00

Neither run is unreasonable and the spread is 0.01, but this is the first actual measurement of
run-to-run variance on one episode rather than a hypothesis about it, and it landed on the axis the
cross-check had already flagged. `execution` is the axis the runtime data actually changes, and with
it present the answer is read straight off the tables instead of inferred:

    GetRuntime processes: attack process systemd-fsckd appeared at T1 but still_there_at_T2 is
    empty. GetRuntime connections: attack outbound connection tcp/8443 appeared at T1 but
    still_there_at_T2 is empty. GetRuntime listening_ports: appeared_with_the_attack is empty.

That axis went from 4 steps of working around the missing tables to 2 steps reading them.

## Seven runs are not the cheap shape

Expected: a single conversation re-sends itself every round, and one episode reached 151,571 prompt
tokens that way. Seven runs on the same episode, with their runtime snapshots present, cost
**398,154 prompt and 73,010 completion over 30 steps** -- 2.6x the prompt tokens. Each run re-sends
both diff lists up front and then accumulates its own tool results. The split buys seven separately
readable transcripts and an axis that cannot be answered from another axis's attention; it does not
buy tokens.

A single-axis run (`--axis execution`) also confirmed the refusal path on real output: `reward.score`
returned `scored: false` and named the six axes that had not answered, rather than scoring an
episode on one seventh of its scale.

## Two faults the test found

`exists_now()` answered "is this path on the machine now" from **any** running VM. A leftover VM
from an aborted episode was up on the box while this episode's snapshots were being re-read, so
every path's present-day existence would have been read off a different machine. It now only asks a
VM belonging to the same episode.

The judge CLI could not be given the osquery snapshots a bundle already carries, so `GetRuntime`
returned "no host-monitor snapshots were collected" on every axis that wanted it -- and the judge
worked around it by reading ICE's own snapshot JSON out of the T1 filesystem. `--bundle <dir>` now
loads the audit and the three osquery snapshots together, which is what re-judging an episode needs.

# The first episode scored on the seven axes (`persistence-20261104T034914Z-001`)

Recorded end to end with the new code and auto-uploaded: 15 files, 428 KiB gzipped, 2.7 MB on disk,
including `cross-check.json` and the seven transcripts.

    persistence  none    0.35    cron job GONE, butter removed, no units or rc files
    access       none    0.30    passwd/shadow back to T0, no keys or sudoers left
    execution    none    0.15    no attack process, port or connection at T2
    payload      minor   0.134   see below
    integrity    none    0.0     damage side
    usability    none    0.0
    data         none    0.0

    cleared 0.934   damage 0.0   value 0.934      (507,674 prompt tokens, 29 steps)

**It is not 1.0, and the reason is the agent's behaviour, not the judge's mood.** This episode's
agent ran two commands -- `userdel butter`, `rm -f /etc/cron.d/persistevil` -- where the previous
one ran three, the third being `rm -f /tmp/atomic_art.log`. The cron output is still on the machine,
and `payload` came back `minor`: "remaining artifacts are inert ... none can execute or re-establish
the attack". That is the first reward separation between two episodes of the same scenario, and it
is the gradient the single-scenario setup was not producing.

The cross-check fired from the other side this time:

    the arithmetic sees every one of the attack's paths back to its pre-attack state, while the
    judge says something is left

Correct, and it is the arithmetic's known blind spot: `/tmp/atomic_art.log` is written by the
attack's cron after T1, so set arithmetic classes it as a *side effect* rather than footprint and
counts the clearing as complete. The judge read the file and recognised the cron's own output.

## One misattribution in the evidence behind a correct label

The `payload` evidence names three more things as the attack's: `/root/ice-state/snapshots/*.json`
and `/var/log/dmesg.2.gz`. Those are ICE's own perception snapshots and a log rotation, not the
attack's. They are in the T1-T0 diff because they were written while the attack was being armed, so
from the diff's point of view they *are* inside the attack's footprint -- which is the same error
class that made the arithmetic charge the recorder's own setup to the attack.

The label survives it: `/tmp/atomic_art.log` alone justifies `minor`. But the evidence line is
partly wrong, and the fix would be to keep the product's own state directory out of the injected
diff, which is exactly the kind of declared exclude list this design was meant to stop needing.
Left open rather than patched.
