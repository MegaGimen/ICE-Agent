"""Local embedding + vector search service (plan.md §7.3: bge-m3) for the knowledge base and
the experience base. Runs in kev-env (torch + transformers already installed) on CPU, so it
takes no GPU memory away from vLLM and Kev.

  CUDA_VISIBLE_DEVICES= ~/ice-envs/kev-env/bin/python -m ice.kb.embed_service

Collections are JSON-lines files {id, text, payload} in ICE_KB_DIR (default ~/ice-data/kb);
embeddings are cached next to them as <name>.npy and rebuilt when the file changes.
HTTP on 127.0.0.1:8020:
  GET  /health
  POST /search {"collection", "text", "k"}      -> {"results": [{"id", "score", "payload"}]}
  POST /upsert {"collection", "items": [...]}  -> appends/replaces items, re-embeds them
bge-m3 dense vectors are the normalized [CLS] state of the last layer.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

KB_DIR = Path(os.environ.get("ICE_KB_DIR", Path.home() / "ice-data" / "kb"))
MODEL = os.environ.get("ICE_EMBED_MODEL", "BAAI/bge-m3")
PORT = int(os.environ.get("ICE_EMBED_PORT", "8020"))
torch.set_num_threads(int(os.environ.get("ICE_EMBED_THREADS", "8")))


class Embedder:
    def __init__(self):
        self.tok = AutoTokenizer.from_pretrained(MODEL)
        self.model = AutoModel.from_pretrained(MODEL, torch_dtype=torch.float32).eval()
        self.lock = threading.Lock()

    def encode(self, texts: List[str], batch: int = 16) -> np.ndarray:
        vecs = []
        with self.lock, torch.inference_mode():
            for i in range(0, len(texts), batch):
                t = self.tok(texts[i:i + batch], padding=True, truncation=True, max_length=512, return_tensors="pt")
                cls = self.model(**t).last_hidden_state[:, 0]
                vecs.append(torch.nn.functional.normalize(cls, dim=-1).numpy())
        return np.concatenate(vecs) if vecs else np.zeros((0, 1024), dtype=np.float32)


class Collection:
    def __init__(self, name: str, emb: Embedder):
        self.name, self.emb = name, emb
        self.path = KB_DIR / f"{name}.jsonl"
        self.items: List[Dict] = []
        self.vecs = np.zeros((0, 1024), dtype=np.float32)
        self.load()

    def _digest(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()[:16] if self.path.exists() else "empty"

    def load(self) -> None:
        self.items = [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()] if self.path.exists() else []
        cache, meta = KB_DIR / f"{self.name}.npy", KB_DIR / f"{self.name}.npy.json"
        digest = self._digest()
        if cache.exists() and meta.exists() and json.loads(meta.read_text()).get("digest") == digest:
            self.vecs = np.load(cache)
        else:
            self.vecs = self.emb.encode([it["text"] for it in self.items])
            if self.items:
                np.save(cache, self.vecs)
                meta.write_text(json.dumps({"digest": digest, "n": len(self.items)}))

    def search(self, text: str, k: int) -> List[Dict]:
        if not self.items:
            return []
        q = self.emb.encode([text])[0]
        scores = self.vecs @ q
        top = np.argsort(-scores)[:k]
        return [{"id": self.items[i]["id"], "score": round(float(scores[i]), 4), "payload": self.items[i].get("payload")}
                for i in top]

    def upsert(self, items: List[Dict]) -> int:
        by_id = {it["id"]: it for it in self.items}
        for it in items:
            by_id[str(it["id"])] = {"id": str(it["id"]), "text": str(it["text"]), "payload": it.get("payload")}
        KB_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(it, ensure_ascii=False) + "\n" for it in by_id.values()))
        tmp.replace(self.path)
        self.load()
        return len(self.items)


def main() -> None:
    emb = Embedder()
    cols: Dict[str, Collection] = {}
    lock = threading.Lock()

    def col(name: str) -> Collection:
        if not name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("bad collection name")
        with lock:
            if name not in cols:
                cols[name] = Collection(name, emb)
            return cols[name]

    for p in sorted(KB_DIR.glob("*.jsonl")):
        c = col(p.stem)
        print(f"collection {c.name}: {len(c.items)} items", flush=True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, obj) -> None:
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"ok": True, "model": MODEL, "collections": {n: len(c.items) for n, c in cols.items()}})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))).decode())
                if self.path == "/search":
                    self._send(200, {"results": col(body["collection"]).search(str(body["text"]), int(body.get("k", 3)))})
                elif self.path == "/upsert":
                    self._send(200, {"count": col(body["collection"]).upsert(list(body["items"]))})
                else:
                    self._send(404, {"error": "not found"})
            except Exception as e:  # noqa: BLE001
                self._send(400, {"error": f"{type(e).__name__}: {e}"})

    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print(f"embed service on http://127.0.0.1:{PORT} ({MODEL}, CPU)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
