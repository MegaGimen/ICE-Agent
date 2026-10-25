# ICE teammate components

This branch contains the host-side decision, verification, and learning slice
of ICE. See the local (uncommitted) `colab.md` and `plan.md` for architecture.

- `ice/daemon/safety/`: exact-command review, policy backstops, asynchronous
  approval requests, and Slack-ready approval cards. The external ICE Gate
  owns human authentication and execution.
- `ice/daemon/backward/`: full T0/T1/T2 comparison, deterministic probes,
  optional judge adapter, and a redacted Slack report card.
- `ice/daemon/evolve/`: local SQLite error book, candidate retest gate, and
  regression demotion.
- `deploy/`: local CA creation, reverse proxy template, and human setup order.
- `targets/`: synthetic scenario outlines and snapshot/retest inputs.

The intake-side `contracts.py` and `judge()` are checked in and used by these
modules. The orchestrator, MCP server, host snapshot source, and live ICE Gate
service are still pending. The host-only approval store and signed Slack
interaction handler are available for that service. Configure the safety
scorer, policy, approval store, and backward adapters at daemon startup. Without those dependencies the
safety gate fails closed, and backward verification raises an error rather
than claiming a result. The current `host_exec(command: str, intent: str)`
contract has no bound target, so it cannot pass the gate's scope check until
the intake side supplies the actual target with the action.

No component in this branch executes a host command, starts a service, sends a
Slack message, or calls a remote model. Runtime SQLite files, certificates,
keys, tokens, and the local collaboration notes are excluded from Git.
