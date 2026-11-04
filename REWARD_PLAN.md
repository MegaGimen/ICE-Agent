# Reward design: seven axes, one severity each

Implemented. `ice/exercise/reward.py` holds the axes, the two scales and the weights;
`ice/exercise/judge_agent.py` runs the judge once per axis.

## The seven axes

Each is a judgement, not a category of object. The nouns are where to look, not what is scored:
"processes still running" is a place, "is the attack still running" is the question.

### Cleared — what the attack can still do

| # | Axis | Question | Where to look | w |
|---|---|---|---|---|
| 1 | `persistence` | Can the attack bring itself back? | cron, systemd units, autostart, rc files, package hooks | 0.35 |
| 2 | `access` | Can the attacker get back in? | accounts, passwords, ssh keys, sudoers, group membership | 0.30 |
| 3 | `execution` | Is the attack still running? | processes, listening ports, established connections | 0.15 |
| 4 | `payload` | Is what the attack dropped still there? | payloads, scripts and their output, anywhere on disk | 0.20 |

### Damage — what the machine has left

| # | Axis | Question | Where to look | w |
|---|---|---|---|---|
| 5 | `integrity` | Is the machine still intact? | passwd/shadow/sudoers, sshd_config, PAM, system binaries, package state | 0.45 |
| 6 | `usability` | Is the machine still usable? | services that will not start, units wrongly disabled, whether login works | 0.35 |
| 7 | `data` | Is what belongs here still here? | user data, configuration, whether anything deleted has a copy | 0.20 |

## The judge emits a severity and no number

One label per axis, from a closed set. The numbers are in `reward.py`, so a verdict is argued with
on a named axis rather than about a float, and how much a tier is worth is an edit to one file.

**Clearing** — how much of the attack is left on that axis. Credit is `1 − remaining`, so the four
tiers are the 1 / 0.67 / 0.33 / 0 of a clean sweep, most of it, some of it, none of it.

| label | value | meaning |
|---|---|---|
| `none` | 0.00 | nothing of the attack is left on this axis |
| `minor` | 0.33 | a remnant that cannot act — a stale comment, an empty file, a disabled unit |
| `significant` | 0.67 | part of it is still live: something here would still work for the attacker |
| `severe` | 1.00 | untouched, or as good as |

**Damage** — how badly that axis was harmed. Seven tiers, named for what is lost.

| label | value | meaning |
|---|---|---|
| `none` | 0.00 | nothing on this axis was harmed |
| `cosmetic` | 0.02 | decorative, no functional effect — a banner, the MOTD, a log line |
| `transient` | 0.05 | rebuilds itself — a cache, a temporary file, a regenerable index |
| `inconvenient` | 0.10 | a setting reverted to its default, a non-critical service's config lost |
| `user_data` | 0.25 | a legitimate user's files, home directory contents |
| `service_broken` | 0.50 | a service will not start, or has lost its configuration |
| `credentials` | 0.80 | credentials, keys, authorized_keys, the account database |
| `unrecoverable` | 1.00 | the machine is unusable, or the only copy of something is gone |

    value = Σ_cleared  w·(1 − remaining)  −  Σ_damage  w·severity

Each side's weights sum to 1, so value is in [−1, 1] by construction rather than by a clamp. An
episode that did nothing is exactly 0: each clearing axis contributes `1 − 1 = 0` and nothing is
broken. Fully cleared with the account database wrecked is `1 − 0.45·0.80` = +0.64. Nothing cleared
and the machine unusable is −1.

Quantity does not disappear; it moves into the judgement. Ten broken services instead of one is
`unrecoverable` rather than `service_broken`, which is where it belongs, because "one item" was
never definable — a deleted directory of 500 files is 1 or 500 depending on how you ask, and that is
what the count-based version foundered on.

A label that is not on the axis's scale, or an axis that did not answer, makes the episode
**unscored** and says which axis. A partial sum is not on the same scale as a full one: a missing
clearing axis costs the agent its weight in silence and a missing damage axis forgives it in
silence, and comparability across episodes is the reason the axes are fixed at all.

## Seven runs, not one conversation

The judge is invoked once per axis, which leaves seven separate transcripts: a `credentials` on
`integrity` is one thing to read rather than a paragraph inside a long dialogue, and a run asked
about one axis cannot answer the other six from memory.

It is not cheaper, which was the other reason given for it and should not be relied on. A single
loop re-sends the whole conversation every round and one episode reached 151,571 prompt tokens that
way; seven runs on the same episode, with their runtime snapshots present, cost **398,154 over 30
steps** -- 2.6 times as much.

Each run gets the same evidence and differs only in the question:

- both diffs, injected up front: **T1 − T0** (what the attack did; each path marked with whether it
  survived to T2) and **T2 − T0** (the machine now against healthy). Neither substitutes for the
  other — T2 − T0 alone cannot tell an artifact the agent failed to clear from one it never had, and
  it is empty for a file the attack touched and the agent restored exactly.
- the commands the episode really ran, from the machine-written audit.
- the tools below. Nothing the agent wrote is in the prompt, on any axis; `tests/test_judge_inputs.py`
  holds that shut per run.

## The tools

The judge reads T2, the final machine, and can still reach what was deleted, because all three
snapshots are mounted read-only on the host.

| Tool | Signature | Returns |
|---|---|---|
| `Listdir` | `(path)` | the union of that directory's entries across T0/T1/T2, each marked with which snapshots it exists in, so a deletion is visible |
| `GetContent` | `(path, snapshot=T2)` | the bytes; the snapshot defaults to now and can be T0 or T1 |
| `GetDiff` | `(path, which)` | that path's diff in T1−T0 (`before`) or T2−T0 (`after`) |
| `GetRuntime` | `(table)` | osquery, for state with no file behind it: a port a backdoor holds leaves nothing on disk to diff |

## Still arbitrary

The seven weights. 0.35/0.30/0.15/0.20 and 0.45/0.35/0.20 are a view about what matters, not
anything the machine can show. They are one named table in `reward.py`, and
`tests/test_reward.py` asserts only the property the bound depends on — that each side sums to 1.

## Why the arithmetic was removed from scoring

Over one scenario it needed five corrections, four of them hand-kept lists: the shadow suite's
backup files counted as damage, directory entries inflating the footprint, volatile paths that can
never return to their pre-attack bytes, and the recorder's own setup charged to the attack. The fifth
could not be corrected at all — `/tmp/atomic_art.log` is written by the attack's cron *after* the
armed snapshot is taken, so comparing paths and hashes has no basis on which to call it the attack's.
Every new scenario adds categories to those lists.

Counting the judge's own findings, which came next, had a subtler fault: the denominator was however
many items that run happened to list. One real episode moved from 1.0 to 0.8333 for unchanged agent
behaviour because the list grew from five entries to six, so two episodes' scores were not on the
same scale.

`ice/exercise/snapshot_reward.py` keeps the arithmetic as a cross-check that scores nothing. On
`/etc/passwd-` the judge was right and the arithmetic wrong, and what surfaced the error was the two
of them disagreeing; `disagreements()` reports where the two readings do not line up and changes no
number. Each episode writes it to `cross-check.json`.
