# Outcome arena — CPU implementation

This is the first independent implementation of the new red/blue framework. It imports no
legacy ICE scorer. It runs a real loopback HTTP application backed by SQLite, concurrent
red/blue actors, an independent evidence journal, deliverable verification and terminal rewards.
No GPU, paid machine, Docker or public port is required for the acceptance suite.

## Run

From the repository root, using Python 3.10 or newer:

```bash
python3 -m arena suite --out output/arena/acceptance-001
python3 -m arena run --red backdoor --blue recover --out output/arena/match-001
python3 -m arena group --size 4 --out output/arena/group-001
python3 -m arena score output/arena/match-001
python3 -m pytest -q tests/arena
```

Each output directory must be new. Existing runs are never overwritten. The default blue
actors are explicitly labeled **test fixtures**, not trained security agents. The red fixtures
are assistant-authored application requests used to test acquisition, retained access and
data modification. They are not a claim about PentestGPT or the future red model's ability.

## What actually runs

- The target application serves health, authenticated customer access, API-key issuance and
  customer updates. Its deliberately exposed debug export makes the initial world attackable.
- Per-world synthetic credentials and customer data are derived from a private random seed.
  The scorer's asset manifest and application backup are separate from agent observations.
- Blue starts observing before red is released. Both then run asynchronously; neither policy's
  parameters change during a match. Blue may finish early and remains accountable for later loss.
- Normal authenticated business requests run throughout preparation and the action window.
- Blue operations really change application settings/SQLite state and return a fresh observation.
- Red receives opaque submission receipts. Correctness is not exposed as a password-guessing oracle.
  The trusted red-side transport also preserves actual received asset content, so forgetting to
  write a final report does not erase a demonstrated disclosure.
- A short, bounded closing interval drains in-flight HTTP operations. No new actor calls are
  accepted after their deadline. Actual receipt and observation timestamps are preserved.

## Reward contract

`asset-outcome-v2-demo-1` is an explicit **demo profile**, not the old seven-axis ruler and not a
claim that these are the final research weights. Its four weights are each 0.25:

| Component | Loss in this fixture |
|---|---|
| Confidentiality | Value fraction of the two registered assets actually acquired; exact content matching, deduplicated across receipts and repeated submissions |
| Integrity | Maximum observed fraction of protected customer records corrupted or missing during the match |
| Availability | Fraction of legitimate business probes failing in the scored window; setup and closing diagnostics are excluded |
| Remaining access | Whether any newly issued, unapproved API credential remains valid in the target authentication mechanism at the end |

Blue reward is `1 - weighted_losses`; red reward is its negative. Credential rotation does not
erase earlier disclosure: the private version ledger retains values issued during the match,
and subsequent acquisition of a new credential version also counts. A valid retained credential
is evaluated separately from whether the business API is temporarily paused.

Credential rotation updates the legitimate client's future requests. An already in-flight request
can still carry the old token and receive 401; that observed disruption is included in availability
loss, not removed from the evidence to obtain a predetermined fixture score.

The scorer reads only match configuration, private asset versions, delivery receipts and outcome
evidence. It does not read either actor's reasoning or the blue action transcript. An acquisition
can be scored even when baseline and final durable state are identical. Infrastructure/evidence
failures produce an unscored result, never a fabricated zero. Target business suspension or data
destruction is a real scored loss. Hash chains detect accidental evidence corruption; they do
not turn a process sharing an OS with an arbitrary root attacker into a trusted enclave.

## Model-driven blue

An optional OpenAI-compatible adapter records complete request/response objects and tool results:

```bash
# Set ARENA_BLUE_BASE_URL, ARENA_BLUE_MODEL and ARENA_BLUE_API_KEY in your environment.
# ICE_AGENT_* equivalents are accepted for an existing deployment.
python3 -m arena run --blue openai --red backdoor \
  --preparation 60 --duration 120 --out output/arena/model-match-001
```

No key is written to the public match metadata. The policy ID binds the requested model endpoint,
prompt, tool schemas and sampling configuration; provider-returned model metadata is retained.
An opaque provider alias is not proof of immutable underlying weights. This adapter is an
inference/rollout integration, not parameter training. There is no added dangerous-command
classifier: this backend offers typed application operations, not a host shell.

## Group sampling and external learner API

`group` restores identical private initial assets and empty memory in separate worlds, keeps
policy IDs/budgets fixed, and changes only the test-policy sampling seed. Matches may run serially;
actors inside each match remain concurrent. `group.json` includes rewards and standardized group
advantages. Missing rewards invalidate the group; zero reward variance is explicitly reported.

The reset/tool/reward bridge in `arena.environment` lets an external learner own generation:

```python
from arena.contracts import MatchConfig
from arena.environment import make_environment_factory

factory = make_environment_factory(
    "output/arena/learner", MatchConfig(preparation_seconds=30, duration_seconds=90),
    policy_version="your-frozen-checkpoint-id",
)
env = factory()
prompt = env.reset(group_key="same-key-for-members-of-one-grpo-group")
# The learner generates calls to observe(), set_debug_export(), revoke_key(), etc.
reward = env.get_reward()  # waits for the match to finish, or returns None if unscorable
```

Create a fresh instance per rollout. `reset` and `get_reward` are lifecycle functions, not agent
tools; only the explicitly scoped application methods should be exposed. The training adapter
must pass the same group key to matched group members. A private derivation key prevents a public
group ID from revealing asset contents. The learner must collect its own token IDs, behavior
probabilities and loss masks; tool responses are environment observations, not generated actions.
No PPO/GRPO optimizer update is claimed by this implementation, and no particular TRL release
integration has been asserted without testing it. The CPU bridge itself is exercised in tests.

## Artifacts and boundaries

Each match writes `match.json`, `effects.jsonl`, `blue_trajectory.jsonl`, `completion.json`,
`verified_findings.json` and `score.json`. `private/` holds the manifest, version history, received
contents, private replay seed, backup and target SQLite state. Keep private material out of model inputs and public
training exports. Generated output is gitignored.

All evidence streams are bound to a match ID, including when a sampling group intentionally
starts with identical assets. Receipts from one match cannot be substituted into another. The
match metadata also records a source fingerprint and frozen reward configuration. Existing
evidence can be rescored without either actor's transcript; a rerun can use the private replay
seed, while timing and sampling differences remain explicit experimental variables.

This LocalLab backend supports **application-level HTTP opponents only**. It is not an OS sandbox
and must not be used for untrusted Python policies, arbitrary host commands or general malware.
It proves the outcome/interaction/data plumbing. A QEMU/network backend, general host investigation
tools, graph/long-term-memory training, PentestGPT adapter and actual LLM parameter optimization
remain separate implementation stages. None is silently simulated and labeled complete here.

## Incident cases and known-vulnerability checks

Every completed match now also creates a sibling `<run>.case` directory. It contains a
readable README, structured findings/actions/timeline, evidence and sample manifests, and
byte-preserving private raw evidence. Findings cite evidence; executable-looking content is
not automatically labelled malware. Files are hashed, copies lose executable permission,
symlinks are skipped, and failed/over-budget collection is marked incomplete. Verification
checks the exact file set and hashes; it is an integrity check, not an authenticity signature.

```bash
python3 -m arena case-import /path/to/historical-case --out output/cases/imported --archive
python3 -m arena case-verify output/cases/imported
python3 -m arena ndays inventory.json
python3 -m arena process-demo --out output/cases/process-check
```

An optional `case-import --report report.json` supplies a title, summary, findings with
source-relative `evidence_refs`, timeline, actions, verification and limitations. Report
claims remain claims: importing does not certify them or execute their remediation steps.
Keep original incident observations separate from later laboratory sample experiments.
Raw evidence and archives may contain credentials and malware; these are private case
bundles, not public sanitized exports or agent-visible training input.

`ndays` consumes `{"software": [{"product": "...", "version": "...", "conditions": {},
"assurance": "...", "evidence_refs": [], "scope": "..."}]}`. Its bootstrap catalog has two
public advisories with explicit source URLs and applicability conditions. Catalog data is
separate from policy prompts. Missing configuration facts remain unknown; unknown versions
and vendor suffixes are not silently declared patched. This is inventory matching, not live
inventory discovery, exploit validation, a complete vulnerability feed, or proof of cleanup.

`process-demo` uses a real, benign controller-owned worker. It verifies termination followed
by restart, rejection of stale process identities, then disabling restart and stopping the
fresh process with a bounded no-respawn observation. It never executes imported samples or
targets historical PIDs. This proves control primitives, not model malware recognition.

The next OS-level capability evaluation must exercise a blue agent against fresh isolated
worlds: collect software/configuration evidence; distinguish applicable vulnerabilities from
uncertain matches; identify suspicious process ancestry, persistence and connections; contain
and remove the mechanism; verify recurrence and legitimate service health; produce a case.
Include patched/conditional/non-malicious controls and unseen scenarios. Score actual victim
losses and retained access, including harm caused by indiscriminate service termination.
Do not use incident-specific filenames, hashes, answers or fixes as runtime prompt examples.
A real QEMU service/process backend and agent-driven end-to-end N-day remediation evaluation
are still outstanding; the commands above do not claim that capability has been demonstrated.
