"""A small read-only web view of the ICE/ART recording pipeline.

Three things, all read-only:
  * batch status      -- where the 423-ART run is, and its scored/empty/skip tally (from the box)
  * live trajectory   -- the episode in progress and the tail of its recorder log (from the box)
  * bundles           -- every finished bundle on this host, with its reward broken out by axis

It serves itself under /ICE (nginx strips that prefix before it reaches here, so routes are rooted
at /). Bundles are read from this host's dataset directory; batch/live state is pulled from the box
over ssh and cached for a few seconds so a page refresh does not open an ssh connection every time.

    python -m ice.exercise.webstatus            # 127.0.0.1:8139, behind nginx location /ICE/
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("ICE_WEB_PORT", "8139"))
DATASET = Path(os.environ.get("ICE_WEB_DATASET", "/home/ICE-Agent/dataset"))
BOX = os.environ.get("ICE_BOX", "root@220.86.159.73")
BOX_PORT = os.environ.get("ICE_BOX_PORT", "21530")
BATCH_LOG = os.environ.get("ICE_BATCH_LOG", "/root/ice-logs/art_batch.log")
BATCH_TOTAL = 423

_cache: dict = {}
_lock = threading.Lock()


def _cached(key: str, ttl: float, fn):
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _lock:
        _cache[key] = (now, val)
    return val


def _ssh(script: str, timeout: int = 25) -> str:
    """Run a shell script on the box by piping it to `bash -s` over stdin -- so the script can use
    normal quoting instead of fighting argv escaping through ssh."""
    try:
        p = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
             "-o", "StrictHostKeyChecking=no", "-p", BOX_PORT, BOX, "bash -s"],
            input=script, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception as e:                        # noqa: BLE001
        return f"__ERR__ {type(e).__name__}: {e}"


def box_state() -> dict:
    """Batch position/tally and the in-progress episode's log tail, in one ssh round-trip."""
    def fetch() -> dict:
        script = f"""L={BATCH_LOG}
pgrep -f "art_batch.sh /root" >/dev/null && echo "RUN=1" || echo "RUN=0"
echo "STOP=$(cat /root/art-batch.STOP 2>/dev/null)"
echo "DONE=$(grep -c ' done  ' "$L" 2>/dev/null)"
echo "EMPTY=$(grep -c 'empty arm' "$L" 2>/dev/null)"
echo "SKIP=$(grep -c 'scored bundle exists' "$L" 2>/dev/null)"
echo "POS=$(grep -E '^#####' "$L" 2>/dev/null | tail -1)"
echo "END=$(grep 'BATCH END' "$L" 2>/dev/null | tail -1)"
pref=$(grep -E '^#####' "$L" 2>/dev/null | tail -1 | grep -oE 'art_[a-z0-9_]+' | head -1)
echo "PREF=$pref"
echo "__T1__"; tail -14 /root/ice-logs/$pref.t1.log 2>/dev/null
echo "__ARM__"; tail -6 /root/ice-logs/$pref.arm.log 2>/dev/null
"""
        out = _ssh(script, timeout=25)
        st: dict = {"ok": not out.startswith("__ERR__"), "raw_error": out if out.startswith("__ERR__") else ""}
        t1 = arm = ""
        section = None
        for line in out.splitlines():
            if line == "__T1__":
                section = "t1"; continue
            if line == "__ARM__":
                section = "arm"; continue
            if section == "t1":
                t1 += line + "\n"; continue
            if section == "arm":
                arm += line + "\n"; continue
            if "=" in line:
                k, _, v = line.partition("=")
                st[k.lower()] = v
        st["running"] = st.get("run") == "1"
        st["stopped"] = bool((st.get("stop") or "").strip())
        st["finished"] = bool((st.get("end") or "").strip())
        for k in ("done", "empty", "skip"):
            try:
                st[k] = int(st.get(k) or 0)
            except ValueError:
                st[k] = 0
        pos = st.get("pos") or ""
        st["index"] = 0
        import re
        m = re.search(r"\[(\d+)/(\d+)\]", pos)
        if m:
            st["index"] = int(m.group(1)); st["total"] = int(m.group(2))
        else:
            st["total"] = BATCH_TOTAL
        st["t1_tail"] = t1.strip()
        st["arm_tail"] = arm.strip()
        st["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return st
    return _cached("box", 6.0, fetch)


def _summary(ep: dict, name: str) -> dict:
    r = ep.get("reward") or {}
    g = ep.get("grade") or {}
    tech = guid = ""
    # art_<tech lower,.→_>_<guid8>-<ts>-NNN
    base = name.split("-", 1)[0] if "-" in name else name
    if base.startswith("art_"):
        parts = base[4:].rsplit("_", 1)
        tech = parts[0].upper().replace("_", ".") if parts else ""
        guid = parts[1] if len(parts) > 1 else ""
    return {
        "name": name,
        "technique": tech, "guid": guid,
        "posture": ep.get("posture") or ("benign" if r.get("benign") else "attack"),
        "scored": bool(r.get("scored")),
        "aborted": ep.get("aborted") or "",
        "value": r.get("value"),
        "cleared": r.get("cleared"), "damage": r.get("damage"),
        "worst_cleared": r.get("worst_cleared"), "worst_damage": r.get("worst_damage"),
        "grade_miss": g.get("miss"), "detected": g.get("detected"), "verdict": g.get("verdict"),
        "recorded_at": ep.get("recorded_at") or "",
        "scenario": ep.get("scenario") or "",
    }


def bundles() -> list:
    def fetch() -> list:
        out = []
        if not DATASET.is_dir():
            return out
        for d in DATASET.iterdir():
            f = d / "episode.json"
            if not f.is_file():
                continue
            try:
                ep = json.loads(f.read_text())
            except Exception:                     # noqa: BLE001
                continue
            out.append(_summary(ep, d.name))
        out.sort(key=lambda b: str(b.get("recorded_at") or b["name"]), reverse=True)
        return out
    return _cached("bundles", 12.0, fetch)


def bundle_detail(name: str) -> dict:
    # name is a bundle dir name; refuse anything with a path separator
    if "/" in name or ".." in name or not name:
        return {"error": "bad name"}
    d = DATASET / name
    f = d / "episode.json"
    if not f.is_file():
        return {"error": "not found"}
    ep = json.loads(f.read_text())
    out = {"name": name, "summary": _summary(ep, name),
           "reward": ep.get("reward") or {}, "grade": ep.get("grade") or {},
           "counts": ep.get("counts") or {}, "posture": ep.get("posture"),
           "scenario": ep.get("scenario"), "decision_model": ep.get("decision_model"),
           "recorded_at": ep.get("recorded_at"), "armed_at": ep.get("armed_at"),
           "probe": ep.get("probe") or {}, "aborted": ep.get("aborted") or ""}
    # trajectory, trimmed for the browser
    tf = d / "agent-trajectory.json"
    traj = []
    if tf.is_file():
        try:
            t = json.loads(tf.read_text())
            for e in (t.get("transcript_events") or [])[:600]:
                if isinstance(e, dict):
                    ev = {k: (v if not isinstance(v, str) else v[:4000]) for k, v in e.items()}
                    traj.append(ev)
        except Exception:                         # noqa: BLE001
            pass
    out["trajectory"] = traj
    out["files"] = sorted(p.name for p in d.iterdir() if p.is_file())
    return out


HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><base href="/ICE/">
<title>ICE / ART recorder</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--line:#2a313c;--fg:#d6deeb;--mut:#8b98a9;--accent:#5bc0eb;
 --good:#4caf7d;--bad:#e06c75;--warn:#e0b050}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
 font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:12px 18px;border-bottom:1px solid var(--line);display:flex;gap:18px;align-items:center;flex-wrap:wrap;position:sticky;top:0;background:var(--bg);z-index:5}
h1{font-size:15px;margin:0;letter-spacing:.5px}h1 b{color:var(--accent)}
.pill{padding:2px 9px;border-radius:999px;border:1px solid var(--line);font-size:12px}
.pill.run{color:var(--good);border-color:var(--good)}.pill.stop{color:var(--bad);border-color:var(--bad)}
.bar{flex:1;min-width:160px;height:8px;background:var(--panel);border-radius:4px;overflow:hidden}
.bar>i{display:block;height:100%;background:var(--accent)}
.wrap{display:grid;grid-template-columns:minmax(300px,1fr) minmax(0,2fr);gap:14px;padding:14px}
@media(max-width:860px){.wrap{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;min-width:0}
.panel h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin:0 0 10px}
.muted{color:var(--mut)}.mono{white-space:pre-wrap;word-break:break-word}
.tail{background:#0b0e13;border:1px solid var(--line);border-radius:6px;padding:8px;max-height:230px;overflow:auto;font-size:12px;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:5px 7px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--panel)}
tbody tr{cursor:pointer}tbody tr:hover{background:#1c2430}tbody tr.sel{background:#223}
.val{font-weight:700}.sc{color:var(--good)}.em{color:var(--mut)}
.scroll{max-height:70vh;overflow:auto}
.big{font-size:30px;font-weight:700}
.axis{border:1px solid var(--line);border-radius:6px;padding:9px;margin:8px 0;background:#0b0e13}
.axis .top{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tag{font-size:11px;padding:1px 7px;border-radius:4px;border:1px solid var(--line)}
.tag.cleared{color:var(--accent);border-color:var(--accent)}.tag.damage{color:var(--warn);border-color:var(--warn)}
.sev-none{color:var(--good)}.sev-minor{color:var(--warn)}.sev-significant{color:#e08a50}.sev-severe,.sev-unrecoverable,.sev-credentials{color:var(--bad)}
.meter{height:6px;background:#0b0e13;border:1px solid var(--line);border-radius:4px;overflow:hidden;margin:4px 0}
.meter>i{display:block;height:100%}.meter>i.c{background:var(--accent)}.meter>i.d{background:var(--warn)}
details{margin-top:6px}summary{cursor:pointer;color:var(--mut);font-size:12px}
.k{color:var(--mut)}.filters{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}
.filters button{background:#0b0e13;color:var(--fg);border:1px solid var(--line);border-radius:5px;padding:3px 9px;cursor:pointer;font:inherit;font-size:12px}
.filters button.on{border-color:var(--accent);color:var(--accent)}
.ev{border-bottom:1px solid var(--line);padding:6px 0}.ev .role{color:var(--accent);font-size:11px;text-transform:uppercase}
.err{color:var(--bad)}
</style></head><body>
<header>
 <h1><b>ICE</b> · ART recorder</h1>
 <span id="state" class="pill">…</span>
 <span id="pos" class="muted"></span>
 <div class="bar"><i id="pbar" style="width:0"></i></div>
 <span id="tally" class="muted"></span>
 <span id="upd" class="muted" style="font-size:11px"></span>
</header>
<div class="wrap">
 <div style="display:flex;flex-direction:column;gap:14px;min-width:0">
  <div class="panel">
   <h2>Live episode</h2>
   <div id="live"><span class="muted">loading…</span></div>
  </div>
  <div class="panel">
   <h2>Bundles (<span id="bcount">0</span>)</h2>
   <div class="filters">
    <button data-f="all" class="on">all</button>
    <button data-f="scored">scored</button>
    <button data-f="empty">empty</button>
   </div>
   <div class="scroll"><table><thead><tr><th>technique</th><th>posture</th><th>value</th><th>when</th></tr></thead>
   <tbody id="btab"></tbody></table></div>
  </div>
 </div>
 <div class="panel" id="detail"><h2>Detail</h2><div class="muted">Select a bundle to see its reward breakdown and the agent's trajectory.</div></div>
</div>
<script>
const $=s=>document.querySelector(s), E=(t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e};
const esc=s=>(s==null?'':String(s)).replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));
let BUNDLES=[], FILTER='all', SEL=null;

async function j(u){const r=await fetch(u);if(!r.ok)throw new Error(r.status);return r.json();}

async function status(){
 try{const s=await j('api/status');
  const st=$('#state');
  if(s.stopped){st.className='pill stop';st.textContent='STOPPED';}
  else if(s.finished){st.className='pill';st.textContent='FINISHED';}
  else if(s.running){st.className='pill run';st.textContent='RUNNING';}
  else{st.className='pill stop';st.textContent='NOT RUNNING';}
  $('#pos').textContent=s.index?`[${s.index}/${s.total}]`:'';
  $('#pbar').style.width=(s.index/(s.total||423)*100)+'%';
  $('#tally').textContent=`scored ${s.done} · empty ${s.empty} · skip ${s.skip}`;
  $('#upd').textContent='box '+(s.ok?('@'+(s.updated||'')):'UNREACHABLE');
  const live=$('#live');live.innerHTML='';
  live.append(E('div','',`<span class="k">now:</span> ${esc((s.pos||'').replace(/^#+\s*/,''))||'—'}`));
  if(s.stop)live.append(E('div','err','STOP: '+esc(s.stop)));
  if(s.arm_tail){live.append(E('div','k','arm:'));const a=E('div','tail');a.textContent=s.arm_tail;live.append(a);}
  if(s.t1_tail){live.append(E('div','k','recorder:'));const t=E('div','tail');t.textContent=s.t1_tail;live.append(t);}
 }catch(e){$('#state').textContent='api error';}
}

async function loadBundles(){
 try{BUNDLES=await j('api/bundles');$('#bcount').textContent=BUNDLES.length;renderTable();}catch(e){}
}
function renderTable(){
 const tb=$('#btab');tb.innerHTML='';
 BUNDLES.filter(b=>FILTER==='all'||(FILTER==='scored'&&b.scored)||(FILTER==='empty'&&!b.scored))
  .forEach(b=>{const tr=E('tr');if(SEL===b.name)tr.className='sel';
   const v=b.scored?`<span class="val sc">${(+b.value).toFixed(3)}</span>`:'<span class="em">—</span>';
   tr.innerHTML=`<td>${esc(b.technique)}<div class="muted" style="font-size:10px">${esc(b.guid)}</div></td>
    <td>${esc(b.posture)}</td><td>${v}</td><td class="muted">${esc((b.recorded_at||'').replace('T',' ').replace('Z',''))}</td>`;
   tr.onclick=()=>{SEL=b.name;renderTable();detail(b.name);};tb.append(tr);});
}
$('.filters').onclick=e=>{if(e.target.dataset.f){FILTER=e.target.dataset.f;
 document.querySelectorAll('.filters button').forEach(x=>x.classList.toggle('on',x.dataset.f===FILTER));renderTable();}};

function meter(frac,cls){return `<div class="meter"><i class="${cls}" style="width:${Math.max(0,Math.min(1,frac||0))*100}%"></i></div>`;}
async function detail(name){
 const d=$('#detail');d.innerHTML='<h2>Detail</h2><div class="muted">loading…</div>';
 let x;try{x=await j('api/bundle?name='+encodeURIComponent(name));}catch(e){d.innerHTML='<h2>Detail</h2><div class="err">load failed</div>';return;}
 if(x.error){d.innerHTML='<h2>Detail</h2><div class="err">'+esc(x.error)+'</div>';return;}
 const r=x.reward||{}, g=x.grade||{}, s=x.summary||{};
 let h=`<h2>Detail</h2><div style="font-size:13px;margin-bottom:4px">${esc(s.technique)} <span class="muted">${esc(s.guid)}</span></div>`;
 h+=`<div class="muted" style="font-size:11px;margin-bottom:8px">${esc(name)}</div>`;
 if(r.scored){
  h+=`<div style="display:flex;gap:18px;align-items:flex-end;margin-bottom:8px">
   <div><div class="k">value</div><div class="big">${(+r.value).toFixed(3)}</div></div>
   <div style="flex:1"><div class="k">cleared ${(+r.cleared||0).toFixed(2)} <span class="muted">(worst: ${esc(r.worst_cleared||'—')})</span></div>${meter(r.cleared,'c')}
   <div class="k">damage ${(+r.damage||0).toFixed(2)} <span class="muted">(worst: ${esc(r.worst_damage||'—')})</span></div>${meter(r.damage,'d')}</div></div>`;
  h+=`<div class="muted" style="font-size:11px">posture ${esc(s.posture)} · judge ${esc((r.judge||{}).model||'?')} · ${(r.judge||{}).steps||'?'} steps · changed paths ${r.changed_paths_total??'?'} (attack ${r.attack_paths_total??'?'})</div>`;
 }else{
  h+=`<div class="big em">unscored</div><div class="muted">${esc(x.aborted||'no score')}</div>`;
 }
 // grade
 h+=`<details open><summary>grade</summary><div class="mono" style="font-size:12px">detected: ${g.detected} · verdict: ${esc(g.verdict)} · miss: ${g.miss}`;
 if(g.scope_missed&&g.scope_missed.length)h+=`<br>scope missed: <span class="err">${esc((g.scope_missed||[]).join(', '))}</span>`;
 if(g.reasons&&g.reasons.length)h+='<br>'+esc(g.reasons.join('; '));
 h+=`</div></details>`;
 // axes
 (r.axes||[]).forEach(a=>{
  const sev=esc(a.severity||''), cls=a.side==='damage'?'damage':'cleared';
  h+=`<div class="axis"><div class="top"><b>${esc(a.axis)}</b><span class="tag ${cls}">${esc(a.side)}</span>
   <span class="sev-${sev}">${sev}</span><span class="muted">w=${a.weight} · factor=${a.factor} · →${(+a.contribution).toFixed(3)}</span>
   ${a.counts_towards_score===false?'<span class="muted">(not counted)</span>':''}</div>`;
  if(a.criterion)h+=`<details><summary>criterion</summary><div class="mono">${esc(a.criterion)}</div></details>`;
  if(a.evidence)h+=`<details><summary>evidence</summary><div class="mono">${esc(a.evidence)}</div></details>`;
  if(a.notes)h+=`<details><summary>notes</summary><div class="mono">${esc(a.notes)}</div></details>`;
  h+=`</div>`;
 });
 // trajectory
 if((x.trajectory||[]).length){
  h+=`<details><summary>agent trajectory (${x.trajectory.length} events)</summary><div class="scroll" style="max-height:340px">`;
  x.trajectory.forEach(e=>{const role=e.role||e.type||e.event||'';
   let txt=e.content||e.text||e.message||'';
   if(typeof txt!=='string')txt=JSON.stringify(txt);
   if(e.tool||e.name)txt=(e.tool||e.name)+(e.arguments?(' '+JSON.stringify(e.arguments)):'')+(txt?('\n'+txt):'');
   h+=`<div class="ev"><div class="role">${esc(role)}</div><div class="mono">${esc((txt||'').slice(0,2000))}</div></div>`;});
  h+=`</div></details>`;
 }
 h+=`<details><summary>files (${(x.files||[]).length})</summary><div class="mono">${esc((x.files||[]).join('  '))}</div></details>`;
 d.innerHTML=h;
}

status();loadBundles();
setInterval(status,5000);
setInterval(loadBundles,20000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):   # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode(), "application/json; charset=utf-8")

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        try:
            if path in ("/", "/index.html"):
                self._send(200, HTML.encode(), "text/html; charset=utf-8")
            elif path == "/api/status":
                self._json(box_state())
            elif path == "/api/bundles":
                self._json(bundles())
            elif path == "/api/bundle":
                q = parse_qs(u.query)
                self._json(bundle_detail((q.get("name") or [""])[0]))
            elif path in ("/healthz", "/api/health"):
                self._json({"ok": True})
            else:
                self._send(404, b"not found", "text/plain")
        except BrokenPipeError:
            pass
        except Exception as e:                    # noqa: BLE001
            try:
                self._json({"error": f"{type(e).__name__}: {e}"}, 500)
            except Exception:                     # noqa: BLE001
                pass

    do_HEAD = do_GET


def main() -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f">>> ICE web view on 127.0.0.1:{PORT}  dataset={DATASET}  box={BOX}:{BOX_PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
