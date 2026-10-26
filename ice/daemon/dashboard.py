"""Read-only visualization dashboard for ICE: correlation graph + knowledge base + experience +
a live agent execution log (from the host audit trail). Runs in the daemon process (shares the
lock-guarded Kùzu connection) on a thread; expose with `ngrok tcp 8088` (open http://<endpoint>).

APIs: /api/graph /api/cases /api/experience /api/stats /api/audit /api/kb   Page: /
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

log = logging.getLogger("ice.dashboard")

KB_DIR = Path(os.environ.get("ICE_KB_DIR", "/home/dell/ice-data/kb"))

PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><title>ICE — live threat graph</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/vis-network.min.js"></script>
<style>
:root{--bg:#0b0f17;--panel:#121826;--line:#1f2a3c;--fg:#e6edf6;--mut:#8aa0bd;--mal:#ff5c6c;--unc:#ffb020;--ben:#39d98a}
*{box-sizing:border-box}body{margin:0;font:13.5px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);height:100vh;display:flex;flex-direction:column}
header{padding:9px 16px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header b{font-size:16px}.s{color:var(--mut)}
#top{flex:1;display:flex;min-height:0}
#net{flex:1;min-width:0}
aside{width:360px;max-width:40vw;background:var(--panel);border-left:1px solid var(--line);overflow:auto;padding:12px}
#bottom{height:30vh;display:flex;border-top:1px solid var(--line);min-height:0}
#logwrap{flex:1;overflow:auto;padding:10px 12px;background:#0a0e16}
#kbwrap{width:42%;overflow:auto;padding:10px 12px;background:var(--panel);border-left:1px solid var(--line)}
h3{margin:12px 0 6px;font-size:11.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}
h3:first-child{margin-top:0}
.case{padding:7px;border:1px solid var(--line);border-radius:8px;margin-bottom:6px}
.pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;font-weight:700}
.mal{background:rgba(255,92,108,.18);color:var(--mal)}.unc{background:rgba(255,176,32,.18);color:var(--unc)}.ben{background:rgba(57,217,138,.16);color:var(--ben)}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mut);word-break:break-all}
.tech{display:inline-block;background:#1b2740;color:#9cc2ff;border-radius:6px;padding:1px 7px;margin:2px 3px 0 0;font-size:12px}
.note{border-left:3px solid var(--unc);padding:4px 8px;margin:4px 0;color:#d7c7a0;font-size:12.5px}
.legend span{margin-right:12px}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle}
.row{font-family:ui-monospace,Menlo,monospace;font-size:12px;padding:2px 0;border-bottom:1px solid #121a28;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .t{color:#5f7498;margin-right:8px}
.ev-tool{color:#9cc2ff}.ev-gate{color:#ffd56b}.ev-exec{color:#ff8a5c}.ev-verdict{color:#ff5c6c}.ev-appr{color:#39d98a}.ev-back{color:#c08cff}.ev-floor{color:#ffb020}
.kbitem{padding:3px 0;border-bottom:1px solid #141d2c;font-size:12.5px}.kbitem b{color:#9cc2ff}
input#kbq{width:100%;padding:5px 8px;background:#0a0e16;border:1px solid var(--line);color:var(--fg);border-radius:6px;margin-bottom:6px}
</style></head><body>
<header><b>🧊 ICE</b><span class="s">local AI security · live correlation graph + agent log</span>
<span id="stat" class="s"></span>
<span class="legend s" style="margin-left:auto">
<span><i class="dot" style="background:#ff5c6c"></i>Incident</span>
<span><i class="dot" style="background:#9cc2ff"></i>Technique</span>
<span><i class="dot" style="background:#ffb020"></i>IP</span>
<span><i class="dot" style="background:#39d98a"></i>Account</span>
<span><i class="dot" style="background:#c08cff"></i>File/Key/URL</span></span></header>
<div id="top"><div id="net"></div>
<aside>
<h3>Recent cases</h3><div id="cases"></div>
<h3>ATT&amp;CK seen in cases</h3><div id="tech"></div>
<h3>Experience (learned / to learn)</h3><div id="exp"></div>
</aside></div>
<div id="bottom">
<div id="logwrap"><h3 style="margin-bottom:8px">🛰 Agent execution log (live)</h3><div id="log"></div></div>
<div id="kbwrap"><h3>Knowledge base — ATT&amp;CK (<span id="kbn">0</span>)</h3>
<input id="kbq" placeholder="filter techniques… (e.g. cron, ssh, persistence)" oninput="renderKB()"><div id="kb"></div></div>
</div>
<script>
const COLOR={Incident:'#ff5c6c',Technique:'#9cc2ff',Host:'#5a6b86',IP:'#ffb020',Account:'#39d98a',Process:'#6fa8ff',Unit:'#c08cff',File:'#c08cff',URL:'#c08cff',Hash:'#c08cff',Domain:'#ffd56b'};
const ASS={malicious:'mal',uncertain:'unc',benign:'ben'};
let net,kbData=[];
function draw(g){
  const vn=g.nodes.map(n=>({id:n.id,label:n.label,title:n.title,group:n.group,
    color:{background:(n.group=='Incident'&&n.assessment=='benign')?'#39d98a':(n.group=='Incident'&&n.assessment=='uncertain')?'#ffb020':COLOR[n.group]||'#888',border:'#0b0f17'},
    shape:n.group=='Incident'?'hexagon':n.group=='Technique'?'box':'dot',
    size:n.group=='Incident'?22:14,font:{color:'#e6edf6',size:12}}));
  const ve=g.edges.map(e=>({from:e.from,to:e.to,arrows:'to',color:{color:'#2b3a52',opacity:.8},font:{color:'#5f7498',size:9},label:e.label}));
  const data={nodes:new vis.DataSet(vn),edges:new vis.DataSet(ve)};
  if(!net){net=new vis.Network(document.getElementById('net'),data,{physics:{stabilization:true,barnesHut:{gravitationalConstant:-9000,springLength:130}},interaction:{hover:true,tooltipDelay:120}});}
  else{net.setData(data);}
  document.getElementById('stat').textContent='· '+g.nodes.length+' nodes / '+g.edges.length+' edges';
}
const CLS={tool:'ev-tool',gate:'ev-gate','host_exec.verdict':'ev-verdict','host_exec.executed':'ev-exec',approval:'ev-appr',backward:'ev-back',gate_floor:'ev-floor'};
function renderKB(){
  const q=(document.getElementById('kbq').value||'').toLowerCase();
  const rows=kbData.filter(k=>!q||(k.id+' '+k.name+' '+(k.tactics||[]).join(' ')).toLowerCase().includes(q)).slice(0,120);
  document.getElementById('kb').innerHTML=rows.map(k=>`<div class="kbitem"><b>${k.id}</b> ${k.name} <span class="s">${(k.tactics||[]).join(', ')}</span></div>`).join('');
}
async function refresh(){
  try{
    draw(await (await fetch('api/graph')).json());
    const cs=await (await fetch('api/cases')).json();
    document.getElementById('cases').innerHTML=cs.map(c=>`<div class="case"><span class="pill ${ASS[c.assessment]||'unc'}">${c.assessment||'?'}</span> <b>${c.case_id}</b> <span class="s">${(c.conf*100||0).toFixed(0)}%</span><br><span class="mono">${(c.attck||[]).join(' ')||'—'}</span><br><div class="s" style="margin-top:3px">${(c.reason||'').slice(0,160)}</div></div>`).join('')||'<span class="s">none</span>';
    document.getElementById('tech').innerHTML=[...new Set(cs.flatMap(c=>c.attck||[]))].map(x=>`<span class="tech">${x}</span>`).join('')||'<span class="s">none</span>';
    const e=await (await fetch('api/experience')).json();
    document.getElementById('exp').innerHTML=(e.active_notes||[]).map(n=>`<div class="note">${n.slice(0,220)}</div>`).join('')
      +`<div class="s" style="margin-top:6px">错题(待转为经验): <b>${e.misses}</b> · 已入库经验: <b>${e.active}</b> · 经验向量库: <b>${e.experience}</b></div>`;
    const au=await (await fetch('api/audit')).json();
    document.getElementById('log').innerHTML=au.map(a=>`<div class="row"><span class="t">${a.ts}</span><span class="${CLS[a.event]||'s'}">${a.text}</span></div>`).join('');
    const lw=document.getElementById('logwrap'); lw.scrollTop=lw.scrollHeight;
    const kb=await (await fetch('api/kb')).json(); kbData=kb.attack||[]; document.getElementById('kbn').textContent=kbData.length; renderKB();
  }catch(err){document.getElementById('stat').textContent='· refresh error';}
}
refresh(); setInterval(refresh,6000);
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
            elif path == "/api/audit":
                self._json(_audit(rt))
            elif path == "/api/kb":
                self._json(_kb())
            elif path == "/api/stats":
                self._json(rt.graph.stats() if rt.graph else {})
            else:
                self._send(404, b"not found", "text/plain")
        except Exception as e:  # noqa: BLE001
            self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")


def _cases(rt, n: int = 12):
    import glob
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
    notes: List[str] = []
    try:
        c = sqlite3.connect(f"file:{rt.conf.state_dir / 'errorbook.sqlite3'}?mode=ro", uri=True)
        misses = c.execute("SELECT count(*) FROM misses").fetchone()[0]
        active = c.execute("SELECT count(*) FROM candidates WHERE status='active'").fetchone()[0]
        notes = [r[0] for r in c.execute("SELECT note FROM candidates WHERE status='active' LIMIT 10")]
        c.close()
    except Exception:  # noqa: BLE001
        pass
    exp = 0
    try:
        h = json.load(urllib.request.urlopen("http://127.0.0.1:8020/health", timeout=3))
        exp = h.get("collections", {}).get("experience", 0)
    except Exception:  # noqa: BLE001
        pass
    return {"misses": misses, "active": active, "active_notes": notes, "experience": exp}


def _clip(v: Any, n: int) -> str:
    s = str(v)
    return s if len(s) <= n else s[: n - 1] + "…"


def _audit(rt, n: int = 140) -> List[Dict[str, str]]:
    """Recent audit events rendered as a human-readable agent/daemon execution log."""
    path = rt.conf.state_dir / "audit.jsonl"
    try:
        with open(path, "rb") as f:
            f.seek(max(0, path.stat().st_size - 400_000))
            lines = f.read().decode(errors="replace").splitlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            r = json.loads(ln)
        except json.JSONDecodeError:
            continue
        ev = r.get("event", "")
        ts = (r.get("ts", "") or "")[11:19]
        case = (r.get("case") or r.get("case_id") or "")
        c = f"[{case[-8:]}] " if case else ""
        if ev == "tool":
            tool = r.get("tool", "")
            icon = "🔍" if tool == "host_query" else "🕸" if tool == "graph_query" else "💬"
            text = f"{icon} {c}{tool}: {_clip(r.get('query') or r.get('request_id') or '', 110)}"
        elif ev == "gate":
            text = f"🚦 {c}gate: {r.get('escalated')}/{r.get('entries')} escalated → investigate"
        elif ev == "case.open":
            text = f"📂 {c}case opened ({r.get('escalations')} signals)"
        elif ev == "case.investigated":
            text = f"🧠 {c}verdict: {r.get('assessment')} · {','.join(r.get('attck') or []) or '—'} · actions {len(r.get('actions') or [])}"
        elif ev == "gate_floor":
            text = f"⚖ {c}gate floor: Kev malicious on {r.get('table')} → held UNCERTAIN"
        elif ev == "host_exec.verdict":
            v = r.get("verdict") or {}
            text = f"🔒 {c}safety gate {v.get('decision')}: {_clip(r.get('command'), 90)}"
        elif ev == "host_exec.executed":
            rc = (r.get("result") or {}).get("returncode")
            text = f"⚡ {c}EXECUTED ({r.get('by')}, rc={rc}): {_clip(r.get('command'), 80)}"
        elif ev == "approval":
            text = f"{'✅' if r.get('approved') else '❌'} {c}human {'approved' if r.get('approved') else 'denied'} by {r.get('user')}"
        elif ev in ("approval.expired",):
            text = f"⏳ {c}approval expired: {_clip(r.get('command',''), 70)}"
        elif ev == "backward":
            text = f"🔁 {c}backward: {r.get('verdict')} score={r.get('score'):.2f} missed={r.get('missed_by_forward')}" if isinstance(r.get('score'), (int, float)) else f"🔁 {c}backward: {r.get('verdict')}"
        elif ev == "graph.write":
            text = f"🕸 {c}graph +{r.get('objects')} objects / {r.get('techniques')} techniques · related {r.get('related')}"
        elif ev == "evolve.misses_recorded":
            text = f"📓 {c}error book +{r.get('count')} misses"
        elif ev == "kill_switch":
            text = f"🛑 kill switch {'ON' if r.get('on') else 'off'}"
        else:
            continue
        out.append({"ts": ts, "event": ev, "text": text})
    return out


def _kb() -> Dict[str, Any]:
    attack = []
    try:
        for ln in (KB_DIR / "attack.jsonl").read_text().splitlines():
            if not ln.strip():
                continue
            p = json.loads(ln).get("payload", {})
            attack.append({"id": p.get("id"), "name": p.get("name"), "tactics": p.get("tactics", [])})
    except Exception:  # noqa: BLE001
        pass
    attack.sort(key=lambda x: x.get("id") or "")
    return {"attack": attack}


def start(rt, host: str = "127.0.0.1", port: int = 8088) -> None:
    _Dash.rt = rt
    srv = ThreadingHTTPServer((host, port), _Dash)
    threading.Thread(target=srv.serve_forever, name="dashboard", daemon=True).start()
    log.info("dashboard on http://%s:%s", host, port)
