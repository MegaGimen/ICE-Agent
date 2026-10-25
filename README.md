# ICE teammate components

This branch contains the host-side decision, verification, and learning slice
of ICE. See the local (uncommitted) `colab.md` and `plan.md` for architecture.

- `ice/daemon/safety/`: exact-command review, policy backstops, asynchronous
  approval requests, and Slack-ready approval cards. The external ICE Gate
  owns human authentication and execution.
- `ice/daemon/backward/`: full T0/T1/T2 comparison, deterministic probes,
  optional judge adapter, and a redacted report payload.
- `ice/daemon/evolve/`: local SQLite error book and candidate retest gate.
- `deploy/`: local CA creation, reverse proxy template, and human setup order.

The intake-side `contracts.py`, `judge()`, orchestrator, MCP server, and host
snapshot source are not checked into this branch yet. Configure the safety
scorer and backward adapters when their interfaces are frozen. Without those
dependencies the safety gate fails closed, and backward verification raises
an error rather than claiming a result.

No component in this branch executes a host command, starts a service, sends a
Slack message, or calls a remote model. Runtime SQLite files, certificates,
keys, tokens, and the local collaboration notes are excluded from Git.
