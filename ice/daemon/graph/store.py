"""Correlation graph (plan.md §11): Palantir-style objects + links, on embedded Kùzu.

Correlation and display only — it never decides anything (Kev, probes and hard rules do).
The only write path is case creation (`record_case`, pure code); the agent gets read-only
`graph_query`. Objects are deduplicated by natural key (IP address, file path, account
name, ...), so one IP seen in several cases is one node linked to each of them.

Schema (STIX naming):
  nodes  Host, Incident (= a case; CASE is a Cypher keyword), Technique, IP, File, Account, Process,
         Unit (systemd), Domain, URL, Hash
  edges  (Incident)-[INVOLVES]->(IP|File|Account|Process|Unit|Domain|URL|Hash)
         (Incident)-[MAPS_TO]->(Technique)   (Incident)-[ON_HOST]->(Host)
         (Process)-[CONNECTED_TO]->(IP)  (Process)-[SPAWNED]->(Process)
  edge properties: first_seen, last_seen, source (which ICE observed it), confidence
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import kuzu

OBJECT_TABLES = ("IP", "File", "Account", "Process", "Unit", "Domain", "URL", "Hash")
_EDGE_PROPS = "first_seen INT64, last_seen INT64, source STRING, confidence DOUBLE"
_SCHEMA = [
    "CREATE NODE TABLE IF NOT EXISTS Host(name STRING, PRIMARY KEY(name))",
    "CREATE NODE TABLE IF NOT EXISTS Incident(case_id STRING, assessment STRING, status STRING, confidence DOUBLE, "
    "summary STRING, created STRING, PRIMARY KEY(case_id))",
    "CREATE NODE TABLE IF NOT EXISTS Technique(id STRING, PRIMARY KEY(id))",
    *[f"CREATE NODE TABLE IF NOT EXISTS {t}(key STRING, PRIMARY KEY(key))" for t in OBJECT_TABLES],
    "CREATE REL TABLE IF NOT EXISTS INVOLVES(" + ", ".join(f"FROM Incident TO {t}" for t in OBJECT_TABLES)
    + f", {_EDGE_PROPS})",
    f"CREATE REL TABLE IF NOT EXISTS MAPS_TO(FROM Incident TO Technique, {_EDGE_PROPS})",
    f"CREATE REL TABLE IF NOT EXISTS ON_HOST(FROM Incident TO Host, {_EDGE_PROPS})",
    f"CREATE REL TABLE IF NOT EXISTS CONNECTED_TO(FROM Process TO IP, {_EDGE_PROPS})",
    f"CREATE REL TABLE IF NOT EXISTS SPAWNED(FROM Process TO Process, {_EDGE_PROPS})",
]
_WRITE = re.compile(r"\b(create|merge|set|delete|detach|drop|alter|copy|load|install|attach|export|import|"
                    r"checkpoint|begin|commit|rollback)\b", re.I)
_SHA = re.compile(r"^[0-9a-fA-F]{32,128}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


_UNIT = re.compile(r"^[A-Za-z0-9@._:-]+\.(service|timer|socket|path|mount|target)$")


def classify(item: str, accounts: Optional[set] = None) -> Optional[Tuple[str, str]]:
    """Map a bare identifier to (node table, natural key). A bare word is an Account only when it
    names a real account on the host (`accounts`); otherwise words like 'curl' would become users."""
    v = (item or "").strip()
    if not v:
        return None
    try:
        return "IP", str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return "URL", v
    if v.startswith("/"):
        return "File", v.split("#", 1)[0]
    if _SHA.match(v):
        return "Hash", v.lower()
    if _UNIT.match(v):
        return "Unit", v
    if _DOMAIN.match(v):
        return "Domain", v.lower()
    if accounts is not None and v in accounts:
        return "Account", v
    return None


class Graph:
    def __init__(self, path: Path, source: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.source = source
        self._db = kuzu.Database(str(self.path))
        self._conn = kuzu.Connection(self._db)
        self._lock = threading.Lock()      # a Kùzu connection is not thread-safe
        with self._lock:
            for stmt in _SCHEMA:
                self._conn.execute(stmt)

    # -- low level ---------------------------------------------------------------
    def _rows(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        with self._lock:
            res = self._conn.execute(cypher, params or {})
            cols = res.get_column_names()
            out = []
            while res.has_next():
                out.append(dict(zip(cols, res.get_next())))
            return out

    def _merge_node(self, table: str, key: str) -> None:
        field = {"Host": "name", "Incident": "case_id", "Technique": "id"}.get(table, "key")
        self._rows(f"MERGE (n:{table} {{{field}: $k}})", {"k": key})

    def _link(self, rel: str, a: Tuple[str, str, str], b: Tuple[str, str, str], confidence: float,
              source: Optional[str] = None) -> None:
        """a/b = (table, key field, key). Upsert the edge, keeping first_seen and bumping last_seen."""
        now = int(time.time())
        self._rows(
            f"MATCH (x:{a[0]} {{{a[1]}: $ka}}), (y:{b[0]} {{{b[1]}: $kb}}) "
            f"MERGE (x)-[r:{rel}]->(y) "
            "ON CREATE SET r.first_seen = $now, r.last_seen = $now, r.source = $src, r.confidence = $c "
            "ON MATCH SET r.last_seen = $now, r.confidence = CASE WHEN $c > r.confidence THEN $c ELSE r.confidence END",
            {"ka": a[2], "kb": b[2], "now": now, "src": source or self.source, "c": float(confidence)})

    # -- write path (case creation only) ----------------------------------------------
    def record_case(self, case: Any, assessment: Optional[str], accounts: Optional[set] = None,
                    source: Optional[str] = None) -> Dict[str, int]:
        """Upsert a case, its host, techniques, and every object it names (IOCs, blast radius,
        trigger provenance). Returns counts for the audit log. `source` overrides the edge source
        (e.g. "replay:<host>" for synthetic replays, "<other ICE host>" for shared intel)."""
        d = case.to_dict() if hasattr(case, "to_dict") else dict(case)
        cid = d["case_id"]
        conf = float(d.get("confidence") or 0.0)
        self._merge_node("Incident", cid)
        self._rows("MATCH (c:Incident {case_id: $id}) SET c.assessment = $a, c.status = $s, c.confidence = $c, "
                   "c.summary = $sum, c.created = $cr",
                   {"id": cid, "a": assessment or "unknown", "s": d.get("status", ""), "c": conf,
                    "sum": (d.get("reason") or "")[:300], "cr": d.get("created", "")})
        n = {"objects": 0, "techniques": 0}
        for host in d.get("hosts") or []:
            self._merge_node("Host", host)
            self._link("ON_HOST", ("Incident", "case_id", cid), ("Host", "name", host), conf, source)
        for t in d.get("attck") or []:
            self._merge_node("Technique", t)
            self._link("MAPS_TO", ("Incident", "case_id", cid), ("Technique", "id", t), conf, source)
            n["techniques"] += 1
        objects = set()
        for item in list(d.get("ioc") or []) + list(d.get("blast_radius") or []):
            c = classify(str(item), accounts)
            if c:
                objects.add(c)
        for trig in d.get("triggers") or []:
            prov = trig.get("provenance") or {}
            if trig.get("src_ip"):
                c = classify(trig["src_ip"])
                if c:
                    objects.add(c)
            if prov.get("user"):
                objects.add(("Account", prov["user"]))
            who = prov.get("who")
            if who and who.startswith("/"):
                proc = f"{who}@{prov.get('user') or '?'}"
                objects.add(("Process", proc))
                if trig.get("src_ip"):
                    ip = classify(trig["src_ip"])
                    if ip and ip[0] == "IP":
                        self._merge_node("Process", proc)
                        self._merge_node("IP", ip[1])
                        self._link("CONNECTED_TO", ("Process", "key", proc), ("IP", "key", ip[1]), conf, source)
                parent = prov.get("parent")
                if parent and parent.startswith("/"):
                    pp = f"{parent}@?"
                    self._merge_node("Process", pp)
                    self._merge_node("Process", proc)
                    self._link("SPAWNED", ("Process", "key", pp), ("Process", "key", proc), conf, source)
        for table, key in objects:
            self._merge_node(table, key)
            self._link("INVOLVES", ("Incident", "case_id", cid), (table, "key", key), conf, source)
            n["objects"] += 1
        return n

    # -- read path ---------------------------------------------------------------------
    def query(self, cypher: str) -> List[Dict[str, Any]]:
        """Read-only Cypher for the agent's graph_query tool."""
        q = (cypher or "").strip().rstrip(";")
        if not q or ";" in q or _WRITE.search(q):
            raise ValueError("graph_query is read-only: one MATCH/RETURN statement, no writes")
        return [{k: _plain(v) for k, v in row.items()} for row in self._rows(q)]

    def related_cases(self, case: Any, include_replay: bool = False) -> List[Dict[str, Any]]:
        """Earlier cases sharing any object with this one — 'this IP was seen in case-012'.
        Synthetic replay cases are left out of real correlation unless asked for."""
        d = case.to_dict() if hasattr(case, "to_dict") else dict(case)
        out = []
        where = "" if include_replay else " AND NOT r.source STARTS WITH 'replay'"
        for table in OBJECT_TABLES:
            out += self._rows(
                f"MATCH (c:Incident {{case_id: $id}})-[:INVOLVES]->(o:{table})<-[r:INVOLVES]-(p:Incident) "
                "WHERE p.case_id <> $id" + where + " "
                "RETURN p.case_id AS case_id, p.assessment AS assessment, p.created AS created, "
                f"'{table}' AS kind, o.key AS object, r.source AS source ORDER BY p.created",
                {"id": d["case_id"]})
        return out

    def lookup(self, items: List[str], accounts: Optional[set] = None,
               include_replay: bool = False) -> List[Dict[str, Any]]:
        """Past cases involving any of these identifiers (used before an investigation starts)."""
        out = []
        where = "" if include_replay else " WHERE NOT r.source STARTS WITH 'replay'"
        for item in dict.fromkeys(items):
            c = classify(item, accounts)
            if not c:
                continue
            out += self._rows(
                f"MATCH (p:Incident)-[r:INVOLVES]->(o:{c[0]} {{key: $k}})" + where + " "
                "RETURN p.case_id AS case_id, p.assessment AS assessment, p.created AS created, p.summary AS summary, "
                f"'{c[0]}' AS kind, o.key AS object, r.source AS source ORDER BY p.created",
                {"k": c[1]})
        return out

    def export(self, limit: int = 600) -> Dict[str, Any]:
        """Nodes + edges for the dashboard visualization (read-only)."""
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        def node(group: str, key: str, label: str = "", title: str = "", extra: Optional[dict] = None) -> str:
            nid = f"{group}:{key}"
            if nid not in nodes:
                nodes[nid] = {"id": nid, "group": group, "label": (label or key)[:40], "title": title or f"{group}: {key}", **(extra or {})}
            return nid

        for r in self._rows("MATCH (i:Incident) RETURN i.case_id AS c, i.assessment AS a, i.summary AS s LIMIT $n", {"n": limit}):
            node("Incident", r["c"], label=r["c"], title=f"{r['c']} [{r.get('a')}]: {(r.get('s') or '')[:160]}",
                 extra={"assessment": r.get("a")})
        for r in self._rows("MATCH (t:Technique) RETURN t.id AS id LIMIT $n", {"n": limit}):
            node("Technique", r["id"])
        for r in self._rows("MATCH (h:Host) RETURN h.name AS n LIMIT $n", {"n": limit}):
            node("Host", r["n"])
        for tbl in OBJECT_TABLES:
            for r in self._rows(f"MATCH (i:Incident)-[e:INVOLVES]->(o:{tbl}) RETURN i.case_id AS c, o.key AS k LIMIT $n", {"n": limit}):
                node("Incident", r["c"], label=r["c"]); node(tbl, r["k"])
                edges.append({"from": f"Incident:{r['c']}", "to": f"{tbl}:{r['k']}", "label": "involves"})
        for r in self._rows("MATCH (i:Incident)-[:MAPS_TO]->(t:Technique) RETURN i.case_id AS c, t.id AS id LIMIT $n", {"n": limit}):
            edges.append({"from": f"Incident:{r['c']}", "to": f"Technique:{r['id']}", "label": "maps_to"})
        for r in self._rows("MATCH (i:Incident)-[:ON_HOST]->(h:Host) RETURN i.case_id AS c, h.name AS n LIMIT $n", {"n": limit}):
            edges.append({"from": f"Incident:{r['c']}", "to": f"Host:{r['n']}", "label": "on_host"})
        for r in self._rows("MATCH (p:Process)-[:CONNECTED_TO]->(ip:IP) RETURN p.key AS p, ip.key AS ip LIMIT $n", {"n": limit}):
            edges.append({"from": f"Process:{r['p']}", "to": f"IP:{r['ip']}", "label": "connected_to"})
        for r in self._rows("MATCH (a:Process)-[:SPAWNED]->(b:Process) RETURN a.key AS a, b.key AS b LIMIT $n", {"n": limit}):
            edges.append({"from": f"Process:{r['a']}", "to": f"Process:{r['b']}", "label": "spawned"})
        return {"nodes": list(nodes.values()), "edges": edges, "stats": self.stats()}

    def stats(self) -> Dict[str, int]:
        return {t: self._rows(f"MATCH (n:{t}) RETURN count(n) AS n")[0]["n"]
                for t in ("Incident", "Technique", "Host", *OBJECT_TABLES)}


def _plain(v: Any) -> Any:
    """Kùzu returns node/rel values as dicts with internal ids; keep only user properties."""
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if not k.startswith("_")}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v
