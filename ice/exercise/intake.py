"""An upload endpoint for recorded bundles.

The recording box is a rented instance whose disk goes with it, so bundles have to leave it. It
pushes each one here as it finishes, which also means a bundle can be reviewed or re-judged from
this machine without the box existing.

    python -m ice.exercise.intake                 # serve on 0.0.0.0:8137, token from ~/.ice-intake-token
    curl -sS -H "X-Ice-Token: $TOKEN" --data-binary @ep.tar.gz \\
         "http://<host>:8137/upload?episode=persistence-20261103T234413Z-001"

It listens on a public address, so uploads carry a token and the archive is unpacked defensively:
names are checked against the recorder's own episode pattern, and every member of the tar has to be
a plain file resolving inside that episode's directory. An upload endpoint that trusts paths out of
a tarball is how you hand someone the filesystem.
"""
from __future__ import annotations

import hmac
import io
import json
import os
import re
import tarfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATASET = Path(os.environ.get("ICE_LOCAL_DATASET",
                              Path(__file__).resolve().parents[2] / "dataset"))
TOKEN_FILE = Path(os.environ.get("ICE_INTAKE_TOKEN_FILE",
                                 Path.home() / ".ice-intake-token"))
PORT = int(os.environ.get("ICE_INTAKE_PORT", "8137"))
MAX_BYTES = int(os.environ.get("ICE_INTAKE_MAX_BYTES", str(64 * 1024 * 1024)))
EPISODE = re.compile(r"^[a-z0-9_]+-\d{8}T\d{6}Z-\d{3}$")


def token() -> str:
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    value = os.urandom(24).hex()
    TOKEN_FILE.write_text(value + "\n")
    TOKEN_FILE.chmod(0o600)
    return value


def unpack(blob: bytes, episode: str) -> dict:
    """Extract one bundle, trusting nothing in the archive about where its files go."""
    dest = DATASET / episode
    dest.mkdir(parents=True, exist_ok=True)
    written, skipped = [], []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf.getmembers():
            name = Path(m.name).name              # the archive's directory structure is not used
            target = (dest / name).resolve()
            if not m.isfile() or not name or name.startswith("."):
                skipped.append(m.name)
                continue
            if not str(target).startswith(str(dest.resolve()) + os.sep):
                skipped.append(m.name)            # .. or an absolute path
                continue
            src = tf.extractfile(m)
            if src is None:
                skipped.append(m.name)
                continue
            target.write_bytes(src.read())
            written.append(name)
    return {"episode": episode, "written": sorted(written), "skipped": skipped,
            "bytes": len(blob), "at": time.time()}


class Handler(BaseHTTPRequestHandler):
    server_version = "ice-intake"

    def _reply(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args) -> None:
        print(f"  {self.address_string()} {fmt % args}", flush=True)

    def do_GET(self) -> None:                      # a liveness check the box can use before pushing
        if self.path.rstrip("/") in ("", "/health"):
            have = sorted(p.name for p in DATASET.glob("*/") if (p / "episode.json").exists())
            return self._reply(200, {"ok": True, "bundles": len(have), "dataset": str(DATASET)})
        self._reply(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self.path.startswith("/upload"):
            return self._reply(404, {"error": "not found"})
        if not hmac.compare_digest(self.headers.get("X-Ice-Token", ""), token()):
            return self._reply(401, {"error": "bad or missing X-Ice-Token"})
        episode = ""
        if "?" in self.path:
            for part in self.path.split("?", 1)[1].split("&"):
                k, _, v = part.partition("=")
                if k == "episode":
                    episode = v
        if not EPISODE.match(episode):
            return self._reply(400, {"error": f"episode name {episode!r} is not an episode name"})
        size = int(self.headers.get("Content-Length") or 0)
        if size <= 0 or size > MAX_BYTES:
            return self._reply(413, {"error": f"length {size} outside 1..{MAX_BYTES}"})
        try:
            result = unpack(self.rfile.read(size), episode)
        except (tarfile.TarError, OSError) as e:
            return self._reply(400, {"error": f"{type(e).__name__}: {e}"})
        print(f">>> {episode}: {len(result['written'])} files, {size / 1024:.0f} KiB"
              + (f", skipped {result['skipped']}" if result["skipped"] else ""), flush=True)
        self._reply(200, result)


def main() -> None:
    DATASET.mkdir(parents=True, exist_ok=True)
    value = token()
    print(f">>> dataset {DATASET}")
    print(f">>> token   {TOKEN_FILE} ({value[:8]}…)")
    print(f">>> listening on 0.0.0.0:{PORT}  (POST /upload?episode=<name>, GET /health)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
