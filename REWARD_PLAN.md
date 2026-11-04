# Reward design: the agreed plan, and the state it would land in

Nothing here is implemented. The code is at commit `4f6fed9`, which is an earlier design that this
supersedes.

## The agreed design

Seven axes. Each is a judgement, not a category of object; the nouns are where to look, not what is
scored.

### Cleared — what the attack can still do

| # | Axis | Where to look |
|---|---|---|
| 1 | Can the attack bring itself back? | cron, systemd units, autostart, rc files, package hooks |
| 2 | Can the attacker get back in? | accounts, passwords, ssh keys, sudoers, group membership |
| 3 | Is the attack still running? | processes, listening ports, established connections |
| 4 | Is what the attack dropped still there? | payloads, scripts and output anywhere on disk |

### Damage — what the machine has left

| # | Axis | Where to look |
|---|---|---|
| 5 | Is the machine still intact? | passwd/shadow/sudoers, sshd_config, PAM, system binaries, package state |
| 6 | Is the machine still usable? | services that will not start, units wrongly disabled, whether login works |
| 7 | Is what belongs here still here? | user data, configuration, whether anything deleted has a copy |

### One severity scale, no numbers from the model

The judge reports a severity for the axis it was asked about, meaning *how bad this axis is*, and
emits no number at all. The numbers are a mapping in code.

    severity   none | minor | significant | severe

    value = Σ_cleared  w·(1 − sev)  −  Σ_damage  w·sev

On the cleared side the severity is how much is left uncleared, so `none` is a clean sweep. On the
damage side it is how badly that axis was harmed. Both weight sets sum to 1, so value is in [−1, 1],
and an episode that cleared nothing and broke nothing is exactly 0 — the cleared side contributes
`1 − 1 = 0` per axis and the damage side contributes nothing.

Checks: fully cleared and nothing broken is +1. Nothing done is 0. Fully cleared but shadow
destroyed is `1 − 0.45` = +0.55. Nothing cleared and the machine unusable is about −0.8.

### Seven runs

The judge is invoked once per axis, not once for everything. The single long loop reached 151,571
prompt tokens on one episode, because every round re-sends the conversation; seven short runs also
make each axis's evidence separately auditable, so a `severe` on axis 5 is one transcript to read.

Each run receives the same input:

- the two diffs, injected up front: **T1 − T0** (what the attack did) and **T2 − T0** (the machine
  now against healthy)
- the commands the episode really ran, from the audit
- the three tools below, plus osquery's tables for state that has no file behind it

It returns one object, and a non-`none` severity has to name the tool result it came from:

    {"axis": "persistence", "severity": "minor", "evidence": "...", "notes": "..."}

### The three tools

The judge works inside T2, the final machine, but can still reach what was deleted, because the
earlier snapshots are mounted read-only on the host.

| Tool | Signature | Returns |
|---|---|---|
| `Listdir` | `(path)` | the union of that directory's entries across T0/T1/T2, each marked with which snapshots it exists in, so a deletion is visible |
| `GetContent` | `(path, snapshot=T2)` | the bytes; the snapshot defaults to now and can be T0 or T1 |
| `GetDiff` | `(path, before \| after)` | that path's diff in T1−T0 (`before`) or in T2−T0 (`after`) |

## Still undecided

1. The wording of the seven axes.
2. The seven weights. The last proposal was 0.35 / 0.30 / 0.15 / 0.20 and 0.45 / 0.35 / 0.20, which
   were mine and have no justification behind them.
3. The four severity values: 0 / 0.33 / 0.67 / 1.

## What changes, file by file

| File | Change |
|---|---|
| `ice/exercise/judge_agent.py` | rewrite: one run per axis; `Listdir`/`GetContent`/`GetDiff`; both diffs in the prompt; snapshots named T0/T1/T2 rather than before/armed/after; output is a severity label and nothing numeric |
| `ice/exercise/reward.py` | rewrite: map the seven severities through the weights and subtract the two sides. Delete `SEVERITY_WEIGHT`, `UNKNOWN_SEVERITY`, `CLEARED_STATES` and the artifacts/damaged mapping |
| `ice/exercise/image.py` | add the per-directory union listing and the two named diffs. `index`/`diff`/`show`/`content` stay — they are what the tools are built on |
| `ice/exercise/record.py` | `_score` calls the judge seven times and stores seven transcripts; `evidence.json` holds the two diffs rather than one before→after change list |
| `ice/exercise/snapshot_reward.py` | restore as a cross-check that touches nothing: it reports where its own reading disagrees with the judge. That disagreement is how the `/etc/passwd-` error was found |
| `tests/test_reward.py` | rewrite for the seven axes and the single severity scale |
| `tests/test_image.py` | add the union listing and the two diffs |
| `tests/test_judge_inputs.py` | keep, and assert per run that no agent-authored text reaches the judge |

Not touched: the VM layer, the snapshot mechanics, ICE's self-awareness, the intake service, the
cross-check against the audit.

## Why the arithmetic was removed from scoring

Over one scenario it needed five corrections, four of them hand-kept lists: the shadow suite's
backup files counted as damage, directory entries inflating the footprint, a growing list of
volatile paths that can never return to their pre-attack bytes, and the recorder's own setup charged
to the attack. The fifth could not be corrected at all — `/tmp/atomic_art.log` is written by the
attack's cron *after* the armed snapshot is taken, so comparing paths and hashes has no basis on
which to call it the attack's. Every new scenario adds categories to those lists.

It is worth keeping as a cross-check for the opposite reason: on `/etc/passwd-` the judge was right
and the arithmetic wrong, and what surfaced it was the two disagreeing. Keeping it non-scoring keeps
that signal without letting it decide anything.
