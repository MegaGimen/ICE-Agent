"""Read-only visualization dashboard for ICE (correlation graph + knowledge/experience + cases).

Runs inside the daemon process (so it shares the single-writer Kùzu connection via rt.graph, which is
lock-guarded) on a thread. Serves an HTML page that polls the JSON APIs and draws the graph with
vis-network (loaded from a CDN in the viewer's browser). Expose with `ngrok http <port>`.

APIs: /api/graph  /api/cases  /api/experience  /api/stats   Page: /
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

log = logging.getLogger("ice.dashboard")

PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><title>ICE — live threat graph</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/vis-network.min.js"></script>
<style>
:root{--bg:#0b0f17;--panel:#121826;--line:#1f2a3c;--fg:#e6edf6;--mut:#8aa0bd;--mal:#ff5c6c;--unc:#ffb020;--ben:#39d98a}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);height:100vh;display:flex;flex-direction:column}
header{padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header b{font-size:16px}header .s{color:var(--mut)}
#wrap{flex:1;display:flex;min-height:0}
#net{flex:1;min-width:0}
aside{width:380px;max-width:42vw;background:var(--panel);border-left:1px solid var(--line);overflow:auto;padding:12px}
h3{margin:14px 0 6px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
.case{padding:8px;border:1px solid var(--line);border-radius:8px;margin-bottom:6px}
.pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;font-weight:700}
.mal{background:rgba(255,92,108,.18);color:var(--mal)}.unc{background:rgba(255,176,32,.18);color:var(--unc)}.ben{background:rgba(57,217,138,.16);color:var(--ben)}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mut);word-break:break-all}
.tech{display:inline-block;background:#1b2740;color:#9cc2ff;border-radius:6px;padding:1px 7px;margin:2px 3px 0 0;font-size:12px}
.note{border-left:3px solid var(--unc);padding:4px 8px;margin:4px 0;color:#d7c7a0;font-size:12.5px}
.legend span{margin-right:12px}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle}
</style></head><body>
<header><b>🧊 ICE</b><span class="s">local AI security · live correlation graph</span>
<span id="stat" class="s"></span>
<span class="legend s" style="margin-left:auto">
<span><i class="dot" style="background:#ff5c6c"></i>Incident</span>
<span><i class="dot" style="background:#9cc2ff"></i>Technique</span>
<span><i class="dot" style="background:#ffb020"></i>IP</span>
<span><i class="dot" style="background:#39d98a"></i>Account</span>
<span><i class="dot" style="background:#c08cff"></i>File/Key/URL</span></span></header>
<div id="wrap"><div id="net"></div>
<aside>
<h3>Recent cases</h3><div id="cases"></div>
<h3>ATT&amp;CK techniques seen</h3><div id="tech"></div>
<h3>Knowledge base</h3><div id="kb" class="s"></div>
<h3>Experience (learned / to learn)</h3><div id="exp"></div>
</aside></div>
<script>
const COLOR={Incident:'#ff5c6c',Technique:'#9cc2ff',Host:'#5a6b86',IP:'#ffb020',Account:'#39d98a',Process:'#6fa8ff',Unit:'#c08cff',File:'#c08cff',URL:'#c08cff',Hash:'#c08cff',Domain:'#ffd56b'};
const ASS={malicious:'mal',uncertain:'unc',benign:'ben'};
let net,nodes,edges;
function draw(g){
  const vn=g.nodes.map(n=>({id:n.id,label:n.label,title:n.title,group:n.group,
    color:{background:(n.group=='Incident'&&n.assessment=='benign')?'#39d98a':(n.group=='Incident'&&n.assessment=='uncertain')?'#ffb020':COLOR[n.group]||'#888',border:'#0b0f17'},
    shape:n.group=='Incident'?'hexagon':n.group=='Technique'?'box':'dot',
    size:n.group=='Incident'?22:14,font:{color:'#e6edf6',size:12}}));
  const ve=g.edges.map(e=>({from:e.from,to:e.to,arrows:'to',color:{color:'#2b3a52',opacity:.8},font:{color:'#5f7498',size:9},label:e.label}));
  const data={nodes:new vis.DataSet(vn),edges:new vis.DataSet(ve)};
  const opts={physics:{stabilization:true,barnesHut:{gravitationalConstant:-9000,springLength:130}},interaction:{hover:true,tooltipDelay:120}};
  if(!net){net=new vis.Network(document.getElementById('net'),data,opts);}else{net.setData(data);}
  document.getElementById('stat').textContent='· '+g.nodes.length+' nodes / '+g.edges.length+' edges · '+JSON.stringify(g.stats).replace(/[{}"]/g,'');
}
async function refresh(){
  try{
    const g=await (await fetch('api/graph')).json(); draw(g);
    const cs=await (await fetch('api/cases')).json();
    document.getElementById('cases').innerHTML=cs.map(c=>`<div class="case"><span class="pill ${ASS[c.assessment]||'unc'}">${c.assessment||'?'}</span> <b>${c.case_id}</b> <span class="s">${(c.conf*100||0).toFixed(0)}%</span><br><span class="mono">${(c.attck||[]).join(' ')||'—'}</span><br><div class="s" style="margin-top:3px">${(c.reason||'').slice(0,180)}</div></div>`).join('')||'<span class="s">none</span>';
    const t=[...new Set(cs.flatMap(c=>c.attck||[]))]; document.getElementById('tech').innerHTML=t.map(x=>`<span class="tech">${x}</span>`).join('')||'<span class="s">none</span>';
    const e=await (await fetch('api/experience')).json();
    document.getElementById('kb').innerHTML=`ATT&CK技库: <b>${e.kb_attack}</b> 条 · 经验库: <b>${e.experience}</b> 条`;
    document.getElementById('exp').innerHTML=(e.active_notes||[]).map(n=>`<div class="note">${n.slice(0,220)}</div>`).join('')
      +`<div class="s" style="margin-top:6px">错题(待转为经验): <b>${e.misses}</b> 条 · 已入库经验: <b>${e.active}</b> 条</div>`;
  }catch(err){document.getElementById('stat').textContent='· refresh error';}
}
refresh(); setInterval(refresh,8000);
</script></body></html>"""


class _Dash(BaseHTTPRequestHandler):
    rt = None

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any):
        self._send(200, json.dumps(obj, default=str).encode(), "application/json")

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        rt = _Dash.rt
        try:
            if path == "/":
                self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            elif path == "/api/graph":
                self._json(rt.graph.export() if rt.graph else {"nodes": [], "edges": [], "stats": {}})
            elif path == "/api/cases":
                self._json(_cases(rt))
            elif path == "/api/experience":
                self._json(_experience(rt))
            elif path == "/api/stats":
                self._json(rt.graph.stats() if rt.graph else {})
            else:
                self._send(404, b"not found", "text/plain")
        except Exception as e:  # noqa: BLE001
            self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")


def _cases(rt, n: int = 12):
    import glob, os
    out = []
    for p in sorted(glob.glob(str(rt.conf.state_dir / "cases" / "case-*.json")), key=os.path.getmtime, reverse=True)[:n]:
        try:
            d = json.loads(open(p).read())
        except Exception:  # noqa: BLE001
            continue
        out.append({"case_id": d["case_id"], "assessment": d.get("_ice", {}).get("assessment"),
                    "conf": d.get("confidence", 0), "attck": d.get("attck", []), "reason": d.get("reason", "")})
    return out


def _experience(rt):
    misses = active = 0
    notes = []
    try:
        c = sqlite3.connect(f"file:{rt.conf.state_dir / 'errorbook.sqlite3'}?mode=ro", uri=True)
        misses = c.execute("SELECT count(*) FROM misses").fetchone()[0]
        active = c.execute("SELECT count(*) FROM candidates WHERE status='active'").fetchone()[0]
        notes = [r[0] for r in c.execute("SELECT note FROM candidates WHERE status='active' LIMIT 10")]
        c.close()
    except Exception:  # noqa: BLE001
        pass
    kb_attack = exp = 0
    try:
        h = json.load(urllib.request.urlopen("http://127.0.0.1:8020/health", timeout=3))
        kb_attack = h.get("collections", {}).get("attack", 0)
        exp = h.get("collections", {}).get("experience", 0)
    except Exception:  # noqa: BLE001
        pass
    return {"misses": misses, "active": active, "active_notes": notes, "kb_attack": kb_attack, "experience": exp}


def start(rt, host: str = "127.0.0.1", port: int = 8088) -> None:
    _Dash.rt = rt
    srv = ThreadingHTTPServer((host, port), _Dash)
    threading.Thread(target=srv.serve_forever, name="dashboard", daemon=True).start()
    log.info("dashboard on http://%s:%s", host, port)
