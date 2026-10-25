"""Link-test MCP server (plan §9 step 4-6). Not the ICE MCP server.

Exposes one read-only `ping` tool over Streamable HTTP on 127.0.0.1:8083/mcp so the
sandbox -> nginx (HTTPS, private IP) -> host path and `trustedPrivateTarget == match`
can be verified before the real mcp_server.py exists. Replace it with the real server
on the same port; nginx and the NemoClaw registration stay unchanged.

Run:  ICE_MCP_TOKEN=... ~/ice-envs/daemon-env/bin/python deploy/mcp_link_test.py
"""
import hmac
import os
import platform
import time

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

TOKEN = os.environ["ICE_MCP_TOKEN"]
# nginx forwards Host without the port ($host); accept both forms for each private IP.
PRIVATE_IPS = os.environ.get("ICE_MCP_PRIVATE_IPS", "172.18.0.1,172.17.0.1").split(",")
ALLOWED_HOSTS = [h for ip in PRIVATE_IPS for h in (ip, f"{ip}:8443")] + ["127.0.0.1", "127.0.0.1:8083"]

server = MCPServer("ice-link-test")


@server.tool()
def ping(message: str = "") -> dict:
    """Read-only link check: echoes the message with host identity and time."""
    return {"pong": message, "host": platform.node(), "arch": platform.machine(), "ts": time.time()}


class BearerAuth:
    """Reject any request without `Authorization: Bearer $ICE_MCP_TOKEN`."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            auth = dict(scope["headers"]).get(b"authorization", b"").decode()
            if not hmac.compare_digest(auth, f"Bearer {TOKEN}"):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)


app = BearerAuth(server.streamable_http_app(
    streamable_http_path="/mcp",
    transport_security=TransportSecuritySettings(allowed_hosts=ALLOWED_HOSTS),
))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8083, log_level="info")
