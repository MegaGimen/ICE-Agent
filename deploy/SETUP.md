# Human setup sequence

These steps are prepared from the local ICE plan. They have not been performed on
the GB10. Confirm the current private IP and the daemon's loopback MCP port
before applying the reverse proxy template.

1. On the GB10, run `nemoclaw host probe`. Confirm the offline bundle hash and
   model cache layout described in `plan.md` §8.2; keep the bundle and models
   outside this repository.
2. Before onboarding, run `bash deploy/create-local-ca.sh <private-MCP-IP>` on
   the GB10. The script creates an IP SAN server certificate and a local CA in
   ignored `deploy/local-secrets/`. Review the printed certificate verification.
3. Confirm local vLLM on port 8000 and Kev on port 8010 with the intake owner.
   Set `NEMOCLAW_CORPORATE_CA_BUNDLE` to the absolute `ca.crt` path and
   `NEMOCLAW_DISABLE_TELEMETRY=1`. Supply Slack tokens only through environment
   variables or a local secret store. Run `nemoclaw onboard` interactively and
   choose **Local vLLM (already running)**.
4. Start the host MCP daemon on loopback. Fill in the nginx template with the
   verified private IP and paths, install it on the host, and verify HTTPS with
   the local CA. The MCP server must validate `ICE_MCP_TOKEN` itself.
5. Add the MCP endpoint with the trusted private host flag from `plan.md` §9.
   Inspect `nemoclaw ice mcp status --json`; proceed only when
   `trustedPrivateTarget.state` is `match`. Use a verified LAN IP if the private
   bridge IP is unreachable from the sandbox.
6. Test agent wakeup and a read-only tool call. Create a separate **ICE Gate**
   Slack app for approval callbacks. Bind each approval to the exact request ID,
   command, target, authorized Slack user, and expiry in the host-side service.
   Agent messages never count as approval.

No live service, SSH tunnel, security setting, Slack app, or host process has
been changed by these repository artifacts.
