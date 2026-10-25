"""Deterministic orchestrator (plan.md §3, §6.1).

The daemon owns the control flow: perceive -> gate -> investigate -> safety gate -> execute ->
audit -> backward. The LLM is free only inside the investigation step (and in writing the
human explanation for an ASK); it never decides what runs next.

One case per cycle: every entry the gate escalates in a cycle goes to the same case, so steps
of one chain (download, chmod, cron, connection) are investigated together.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ice.daemon import kb
from ice.daemon.backward.verify import BackwardVerifier, configure_backward, judge_quality_provider
from ice.daemon.contracts import Case, CaseStatus, ChangeEntry, GateDecision, new_id
from ice.daemon.detect.gate import GateResult, evaluate_many
from ice.daemon.evolve.error_book import ErrorBook
from ice.daemon.investigate import agent, prompts
from ice.daemon.investigate.case import build_case, extract_json
from ice.daemon.mcp_server import IceTools
from ice.daemon.perception import snapshot as snap_mod
from ice.daemon.perception.diff import diff
from ice.daemon.perception.logs import AuthLogWatcher
from ice.daemon.perception.store import Baseline, SnapshotStore
from ice.daemon.runtime import PendingAction, Runtime

log = logging.getLogger("ice.orchestrator")

_SHELL = re.compile(r"[;&|<>`$\\\n\r]")   # same class the safety gate treats as shell syntax


class _SkipErrorBook(Exception):
    pass


class CaseStore:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()

    def save(self, case: Case, **extra: Any) -> None:
        path = self.dir / f"{case.case_id}.json"
        with self._lock:
            old = json.loads(path.read_text()) if path.exists() else {}
            data = {**old.get("_ice", {}), **extra}
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({**case.to_dict(), "_ice": data}, ensure_ascii=False, indent=1, default=str))
            tmp.chmod(0o600)
            tmp.replace(path)

    def load(self, case_id: str) -> Optional[Dict[str, Any]]:
        path = self.dir / f"{case_id}.json"
        return json.loads(path.read_text()) if path.exists() else None

    def case(self, case_id: str) -> Optional[Case]:
        d = self.load(case_id)
        return Case.from_dict(d) if d else None

    def meta(self, case_id: str) -> Dict[str, Any]:
        d = self.load(case_id) or {}
        return d.get("_ice", {})

    def all(self) -> List[Dict[str, Any]]:
        return [json.loads(p.read_text()) for p in sorted(self.dir.glob("case-*.json"))]


class Notifier:
    """Slack output; the base class only logs (used until the Slack channel is configured)."""

    def case_alert(self, case: Case, assessment: Optional[str], results: List[GateResult],
                   related: Optional[List[Dict[str, Any]]] = None) -> None:
        log.info("ALERT %s assessment=%s attck=%s related=%d", case.case_id, assessment, case.attck, len(related or []))

    def action_update(self, case: Case, command: str, decision: str, detail: str) -> None:
        log.info("ACTION %s %s %s: %s", case.case_id, decision, command, detail)

    def approval_request(self, p: PendingAction) -> None:
        log.info("ASK %s for %s: %s", p.request_id, p.case_id, p.command)

    def backward_report(self, case: Case, report: Any) -> None:
        log.info("BACKWARD %s %s", case.case_id, getattr(report, "outcome", report))

    def mark_expired(self, request_id: str) -> None:
        log.info("EXPIRED %s", request_id)


class Orchestrator:
    def __init__(self, rt: Runtime, notifier: Optional[Notifier] = None):
        self.rt = rt
        sd = rt.conf.state_dir
        self.store = SnapshotStore(sd / "snapshots")
        self.baseline = Baseline(sd / "baseline.json")
        self.authlog = AuthLogWatcher(self.baseline)
        self.cases = CaseStore(sd / "cases")
        self.tools = IceTools(rt)
        self.notifier = notifier or Notifier()
        self.cycles = 0
        self._prev: Optional[snap_mod.Snapshot] = self.store.latest()
        # First run ever: learn normal flow combinations for `warmup_cycles` before reporting them.
        # After a restart the baseline exists, so changes made while ICE was down are still reported.
        self._first_run = not self.baseline.size()
        self._case_lock = threading.Lock()          # one agent investigation at a time
        self._injected: List[ChangeEntry] = []
        self._bg: List[threading.Thread] = []      # approval follow-ups and backward runs
        self._inject_lock = threading.Lock()
        self.verifier = BackwardVerifier(snapshot_provider=self._backward_snapshot,
                                         quality_judge=judge_quality_provider,
                                         observation_provider=self._backward_observations)
        configure_backward(self.verifier)
        rt.on_explain.append(self._on_explain)

    def _spawn(self, target: Callable, *args: Any) -> None:
        t = threading.Thread(target=target, args=args, daemon=True)
        self._bg = [x for x in self._bg if x.is_alive()] + [t]
        t.start()

    def join_background(self, timeout: float = 600) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            live = [t for t in self._bg if t.is_alive()]
            if not live:
                return
            for t in live:
                t.join(max(0.0, deadline - time.time()))

    # -- perception + gate ----------------------------------------------------
    def inject(self, entries: List[ChangeEntry], min_cycle: int = 2) -> None:
        """Replay synthetic change entries (testing without touching the host).

        They enter no earlier than cycle `min_cycle`, after real snapshots exist, so the case has a
        genuine T0 — as in real operation, where the snapshot before the first alert is T0.
        """
        for e in entries:
            e.replay = True   # synthetic: excluded from real correlation and from the error book
        with self._inject_lock:
            self._injected.extend(entries)
            self._inject_min_cycle = max(getattr(self, "_inject_min_cycle", 0), min_cycle)

    @property
    def injection_pending(self) -> bool:
        with self._inject_lock:
            return bool(self._injected)

    def sweep_expired(self) -> None:
        """An ASK nobody answered within the approval TTL is not executed; close out its case."""
        ttl = self.rt.approvals.policy.request_ttl_seconds if self.rt.approvals else 600
        now = time.time()
        for p in list(self.rt.pending.items.values()):
            if p.status != "pending" or now - p.created < ttl:
                continue
            self.rt.pending.update(p.request_id, status="expired")
            self.rt.audit.write("approval.expired", request_id=p.request_id, case=p.case_id, command=p.command)
            self.notifier.mark_expired(p.request_id)
            case = self.cases.case(p.case_id) if p.case_id else None
            if case:
                case.add_timeline(f"approval expired, not executed: {p.command}")
                self.cases.save(case)
                self.notifier.action_update(case, p.command, "EXPIRED", "no decision within the approval window")
                if not [x for x in self.rt.pending.items.values() if x.case_id == case.case_id and x.status == "pending"]:
                    self.finish(case.case_id)

    def _learn_own_traffic(self, snap: snap_mod.Snapshot) -> None:
        """The daemon's own connections (Slack API, Socket Mode) are known by pid, which an attacker
        cannot borrow: add them to the baseline before diffing so they are never reported."""
        me = str(os.getpid())
        own = [k for k, m in snap.meta.get("connections", {}).items() if str(m.get("pid")) == me]
        if own:
            self.baseline.add("connections", own, snap.ts)

    def cycle(self) -> Optional[str]:
        self.sweep_expired()
        snap = snap_mod.collect()
        self.store.save(snap)
        learning = self._first_run and self.cycles < self.rt.conf.warmup_cycles
        self._learn_own_traffic(snap)
        entries = diff(self._prev, snap, self.baseline, learning=learning)
        entries += self.authlog.poll()
        with self._inject_lock:
            if self.cycles >= getattr(self, "_inject_min_cycle", 0):
                injected, self._injected = self._injected, []
            else:
                injected = []
        entries += injected
        self._prev = snap
        self.cycles += 1
        if snap.errors:
            log.warning("snapshot errors: %s", snap.errors)
        if not entries:
            return None
        results = evaluate_many(entries)
        escalated = [r for r in results if r.escalate]
        self.rt.audit.write("gate", cycle=self.cycles, entries=len(entries), escalated=len(escalated),
                            results=[{"entry": r.entry.entry_id, "table": r.entry.table, "value": r.entry.value[:200],
                                      "priority": r.priority, "reasons": r.reasons} for r in results])
        log.info("cycle %d: %d changes, %d escalated", self.cycles, len(entries), len(escalated))
        if not escalated:
            return None
        return self.run_case(escalated, t1=snap)

    # -- investigation ----------------------------------------------------------
    def run_case(self, escalated: List[GateResult], t1: snap_mod.Snapshot) -> str:
        case_id = new_id("case")
        with self._case_lock:
            self.rt.set_current_case(case_id)
            try:
                return self._investigate_and_respond(case_id, escalated, t1)
            finally:
                self.rt.set_current_case(None)

    def _investigate_and_respond(self, case_id: str, escalated: List[GateResult], t1: snap_mod.Snapshot) -> str:
        host = self.rt.conf.hostname
        escalated = sorted(escalated, key=lambda r: r.priority != "high")
        t0 = self.store.before(t1.ts)
        replay = any(getattr(r.entry, "replay", False) for r in escalated)
        meta = {"t0": t0.ts if t0 else None, "t1": t1.ts, "replay": replay,
                "trigger_keys": [{"table": r.entry.table, "key": r.entry.field} for r in escalated]}
        graph = getattr(self.rt, "graph", None)
        accounts = set(t1.rows("accounts")) if "accounts" not in t1.errors else None
        prior: List[Dict[str, Any]] = []
        if graph is not None:
            items = []
            for r in escalated:
                e = r.entry
                items += [x for x in (e.src_ip, e.provenance.user, e.provenance.who, e.field.split("#", 1)[0]) if x]
                items += [v for v in e.untrusted.values() if isinstance(v, str) and len(v) < 300 and v.startswith("/")]
            try:
                prior = graph.lookup(items, accounts, include_replay=replay)
            except Exception:  # noqa: BLE001
                log.exception("graph lookup failed")
        experience = [f"- {p['kind']} {p['object']} appeared in {p['case_id']} ({p['assessment']}, {p['created']}): "
                      f"{(p.get('summary') or '')[:200]}" for p in prior[:10]]
        # Retrieval before investigating (plan §3.2): technique notes + lessons from the error book.
        query = " ".join(f"{r.entry.value} {' '.join(str(v)[:200] for v in r.entry.untrusted.values())}"
                         for r in escalated[:5])
        knowledge = kb.technique_notes(query)
        experience += kb.experience_notes(query)
        msg = prompts.wake_message(case_id, host, [r.to_dict() for r in escalated], knowledge=knowledge or None,
                                   experience=experience or None, graph_available=graph is not None)
        meta["knowledge"] = [n.split(" ", 2)[1] for n in knowledge]
        self.rt.audit.write("case.open", case=case_id, escalations=len(escalated))
        reply = agent.wake(case_id, msg)
        case, assessment = build_case(case_id, host, reply.text, [r.entry.to_dict() for r in escalated])
        if not reply.ok:
            case.add_timeline(f"agent error: {reply.error}")
        bad = [{"command": a.command, "problem": "uses shell syntax"} for a in case.proposed_actions if _SHELL.search(a.command)]
        if bad and assessment != "benign":
            revised = agent.wake(case_id, prompts.revise_actions_message(bad))
            obj = extract_json(revised.text)
            if obj and isinstance(obj.get("proposed_actions"), list):
                case2, _ = build_case(case_id, host, revised.text, case.triggers, created=case.created)
                kept, dropped = [], []
                for a in case2.proposed_actions:
                    # A revision that strips the arguments (bare `ls`, `rm`) and parks them in `targets`
                    # would hand a meaningless command to approval: drop it instead.
                    if _SHELL.search(a.command) or (len(a.command.split()) == 1 and a.targets):
                        dropped.append(a.command)
                    else:
                        kept.append(a)
                case.proposed_actions = kept
                case.add_timeline("proposed actions revised to shell-free commands"
                                  + (f"; dropped unusable: {dropped}" if dropped else ""))
            else:
                case.proposed_actions = [a for a in case.proposed_actions if not _SHELL.search(a.command)]
                case.add_timeline("revision failed; actions with shell syntax dropped")
            if not case.proposed_actions and case.status is CaseStatus.PROPOSED:
                case.status = CaseStatus.INVESTIGATING
        related: List[Dict[str, Any]] = []
        if graph is not None:
            try:
                written = graph.record_case(case, assessment, accounts,
                                            source=f"replay:{host}" if replay else None)
                related = graph.related_cases(case, include_replay=replay)
                self.rt.audit.write("graph.write", case=case_id, **written, related=len(related))
            except Exception:  # noqa: BLE001
                log.exception("graph write failed")
        self.cases.save(case, **meta, assessment=assessment, related=related,
                        agent={"seconds": reply.seconds, "tools": reply.tools,
                               "tokens_in": reply.tokens_in, "error": reply.error})
        self.rt.audit.write("case.investigated", case=case_id, assessment=assessment, status=case.status.value,
                            attck=case.attck, actions=[a.command for a in case.proposed_actions])
        self.notifier.case_alert(case, assessment, escalated, related)
        if case.status is CaseStatus.PROPOSED:
            self._respond(case)
        return case_id

    # -- response ---------------------------------------------------------------
    def _respond(self, case: Case) -> None:
        case.status = CaseStatus.MITIGATING
        outcomes = []
        for action in case.proposed_actions:
            r = self.tools.host_exec(action.command, action.intent)
            decision = (r.content or {}).get("decision", "DENY")
            outcomes.append({"action_id": action.action_id, "command": action.command, "decision": decision,
                             "request_id": r.request_id, "error": r.error})
            case.add_timeline(f"safety gate {decision}: {action.command}")
            if decision == "ASK":
                agent.wake(case.case_id, prompts.explain_request_message(
                    r.request_id, action.command, action.intent, (r.content or {}).get("reason", "")))
                p = self.rt.pending.get(r.request_id)
                if p and not p.explanation:   # the agent did not call explain_for_human: fall back to its intent
                    self.rt.pending.update(r.request_id, explanation=action.intent)
                    p = self.rt.pending.get(r.request_id)
                    self.notifier.approval_request(p)
                self.notifier.action_update(case, action.command, "ASK", "waiting for human approval in ICE Gate")
            elif decision == "AUTO":
                res = ((r.content or {}).get("result") or {}).get("data") or {}
                self.notifier.action_update(case, action.command, "AUTO",
                                            "dry run (replay): not executed" if self.rt.dry_run
                                            else f"exit {res.get('returncode')}")
            else:
                self.notifier.action_update(case, action.command, "DENY", r.error or "denied")
        self.cases.save(case, actions=outcomes)
        if not any(o["decision"] == "ASK" for o in outcomes):
            self.finish(case.case_id)

    def _on_explain(self, p: PendingAction) -> None:
        self.notifier.approval_request(p)

    def on_approval(self, request_id: str, approved: bool, user_id: str) -> None:
        """Called by the ICE Gate service after ApprovalStore.decide() accepted the click."""
        p = self.rt.pending.get(request_id)
        if p is None:
            return
        result = None
        if approved:
            from ice.daemon import executor
            # Re-check hard stops right before running (kill switch, scope may have changed since approval).
            if not self.rt.gate.current_policy_allows(p.command, self.rt.conf.hostname):
                self.rt.pending.update(request_id, status="blocked")
                self.rt.audit.write("host_exec.blocked_after_approval", case=p.case_id, command=p.command)
                return
            res = executor.dry(p.command) if self.rt.dry_run else executor.run(p.command)
            result = res.to_dict()
            self.rt.audit.write("host_exec.executed", case=p.case_id, command=p.command, result=result,
                                by=f"approval:{user_id}", request_id=request_id, dry_run=self.rt.dry_run)
        self.rt.pending.update(request_id, status="executed" if approved else "denied", result=result)
        self.rt.audit.write("approval", request_id=request_id, approved=approved, user=user_id, case=p.case_id)
        case = self.cases.case(p.case_id) if p.case_id else None
        if case:
            case.add_timeline(f"human {'approved' if approved else 'denied'}: {p.command}")
            self.cases.save(case)
            self.notifier.action_update(case, p.command, "APPROVED" if approved else "DENIED",
                                        ("dry run (replay): not executed" if self.rt.dry_run else
                                         f"exit {result.get('returncode')}") if result else "not run")
            self._spawn(agent.wake, case.case_id, prompts.result_message(request_id, p.command, approved, result))
            if not [x for x in self.rt.pending.items.values() if x.case_id == case.case_id and x.status == "pending"]:
                self._spawn(self.finish, case.case_id)

    # -- backward -----------------------------------------------------------------
    @staticmethod
    def _backward_view(s: snap_mod.Snapshot, flow_keys: Dict[str, set[str]]) -> Dict[str, Any]:
        # Compare flow by normalized key presence, not volatile cmdline/cwd/name
        # fields. The candidate set includes every combination new during the
        # case, including those the forward gate did not list as triggers.
        if s.errors:
            raise ValueError(f"Incomplete backward snapshot: {sorted(s.errors)}")
        flow = {
            table: {key: True for key in rows if key in flow_keys.get(table, set())}
            for table, rows in s.data.get("flow", {}).items()
        }
        return {"stable": s.data.get("stable", {}), "flow": flow}

    def _case_flow_keys(self, case_id: str) -> Dict[str, set[str]]:
        # T2-only flows belong to later activity and are handled by the next
        # forward cycle; only combinations present at detection can be tied to
        # this case's cleanup. Do not limit these to reported trigger keys.
        m = self.cases.meta(case_id)
        t1 = self.store.load(m["t1"]) if m.get("t1") else None
        if t1 is None or t1.errors:
            raise ValueError("T1 flow snapshot is unavailable or incomplete")
        t0_ts = m.get("t0")
        t0 = self.store.load(t0_ts) if t0_ts else None
        if t0 is not None and t0.errors:
            raise ValueError("T0 flow snapshot is incomplete")
        process_meta = t1.meta.get("processes", {})
        own_pids = {str(os.getpid())}
        for _ in range(len(process_meta)):
            children = {str(meta.get("pid")) for meta in process_meta.values()
                        if str(meta.get("ppid")) in own_pids}
            if children <= own_pids:
                break
            own_pids.update(children)

        candidates: Dict[str, set[str]] = {}
        for table, rows in t1.data.get("flow", {}).items():
            seen = self.baseline.seen.get(table, {})
            selected = set()
            for key in rows:
                if t0 is not None and key in t0.data.get("flow", {}).get(table, {}):
                    continue
                first_seen = seen.get(key)
                if t0_ts is not None and first_seen is not None and first_seen < t0_ts:
                    continue  # known before this case: normal reappearance/churn
                meta = t1.meta.get(table, {}).get(key, {})
                if str(meta.get("pid")) in own_pids:
                    continue
                raw = meta.get("_row") or {}
                name = str(raw.get("name") or "")
                exe = str(raw.get("path") or "")
                if table == "processes" and (name.startswith("kworker/") or
                                              str(raw.get("parent_name") or "") == "kthreadd" or
                                              "openshell-sandbox" in (exe or name).lower()):
                    continue
                if table == "connections":
                    if "|public:*" in key:  # trusted-egress bucket from perception
                        continue
                    internal_mcp = (str(raw.get("remote_port")) == "8443"
                                    and str(meta.get("remote_address")) in {"172.18.0.1", "172.17.0.1"}
                                    and ("openshell" in exe.lower() or "nemoclaw" in exe.lower()
                                         or "openshell" in name.lower() or "nemoclaw" in name.lower()))
                    if internal_mcp:
                        continue
                selected.add(key)
            candidates[table] = selected
        return candidates

    def _backward_snapshot(self, case: Any, phase: str) -> Dict[str, Any]:
        case_id = case.case_id if hasattr(case, "case_id") else case["case_id"]
        m = self.cases.meta(case_id)
        flow_keys = self._case_flow_keys(case_id)
        if phase == "T2":
            if m.get("t2"):
                s = self.store.load(m["t2"])
            else:
                s = snap_mod.collect()
                self._backward_view(s, flow_keys)  # never store an incomplete T2 as a successful cleanup view
                self.store.save(s)
                self.cases.save(self.cases.case(case_id), t2=s.ts)
        else:
            ts = m.get("t0") if phase == "T0" else m.get("t1")
            if phase == "T0" and not ts:
                # No snapshot predates the case (first run): T1 is the closest reference. Backward then
                # cannot tell attack residue already present at T1 from the baseline; the report says so.
                ts = m.get("t1")
                self.cases.save(self.cases.case(case_id), t0_fallback="T1")
            s = self.store.load(ts) if ts else None
            if s is None:
                return {}
        return self._backward_view(s, flow_keys)

    def _backward_observations(self, case: Any) -> List[Dict[str, Any]]:
        case_id = case.case_id if hasattr(case, "case_id") else case["case_id"]
        t2 = self.cases.meta(case_id).get("t2")
        flow_keys = self._case_flow_keys(case_id)
        return [self._backward_view(s, flow_keys) for s in self.store.since(t2)[:12]] if t2 else []

    def _followup_backward(self, case_id: str, delay: float) -> None:
        # --once still gets a later observation. A running daemon may also have
        # saved regular cycle snapshots during the wait.
        threading.Event().wait(delay)
        case = self.cases.case(case_id)
        if case is None:
            return
        try:
            observation = snap_mod.collect()
            self._backward_view(observation, self._case_flow_keys(case_id))
            self.store.save(observation)
        except Exception as e:  # noqa: BLE001
            log.exception("backward observation failed for %s", case_id)
            self.rt.audit.write("backward.observation_error", case=case_id, error=str(e))
            self.cases.save(case, backward_followup_scheduled=False)
            return
        self.cases.save(case, backward_followup_done=True)
        self.finish(case_id)

    def finish(self, case_id: str) -> None:
        case = self.cases.case(case_id)
        if case is None:
            return
        case.status = CaseStatus.VERIFYING
        self.cases.save(case)
        try:
            report = self.verifier.verify(case)
        except Exception as e:  # noqa: BLE001
            log.exception("backward failed for %s", case_id)
            self.rt.audit.write("backward.error", case=case_id, error=str(e))
            return
        res = report.result
        meta = self.cases.meta(case_id)
        awaiting_observation = report.observation_pending
        if awaiting_observation and not meta.get("backward_followup_done") and not meta.get("backward_followup_scheduled"):
            delay = max(30.0, min(120.0, 2 * self.rt.conf.snapshot_interval_s))
            self.cases.save(case, backward_followup_scheduled=True)
            self._spawn(self._followup_backward, case_id, delay)
        case.status = CaseStatus.RESOLVED if res.verdict.value == "cleared" and not awaiting_observation else CaseStatus.VERIFYING
        case.add_timeline(f"backward: {report.outcome} score={report.overall_score:.2f}")
        self.cases.save(case, backward=res.to_dict(), backward_outcome=report.outcome)
        self.rt.audit.write("backward", case=case_id, verdict=res.verdict.value, score=res.total_score,
                            missed_by_forward=len(res.missed_by_forward))
        try:
            if self.cases.meta(case_id).get("replay"):
                # Synthetic replay: nothing happened on the host, so a "miss" is an artifact, not a lesson.
                raise _SkipErrorBook
            book = ErrorBook(self.rt.conf.state_dir / "errorbook.sqlite3")
            try:
                recorded = book.record_backward_misses(res)
            finally:
                book.close()
            if recorded:
                self.rt.audit.write("evolve.misses_recorded", case=case_id, count=len(recorded))
        except _SkipErrorBook:
            pass
        except Exception as e:  # noqa: BLE001 — reporting must continue if the local error book fails
            log.exception("error book write failed for %s", case_id)
            self.rt.audit.write("evolve.error", case=case_id, error=str(e))
        self.notifier.backward_report(case, report)
        if self.cases.meta(case_id).get("t0_fallback"):
            self.notifier.action_update(case, "backward verification", "NOTE",
                                        "No snapshot predates this case (first run), so T1 served as the baseline: "
                                        "the cleanup score is low-confidence.")

    # -- main loop -------------------------------------------------------------------
    def run_forever(self, stop: Optional[threading.Event] = None) -> None:
        stop = stop or threading.Event()
        interval = self.rt.conf.snapshot_interval_s
        log.info("orchestrator started: interval %.0fs, warmup %d cycles", interval, self.rt.conf.warmup_cycles)
        while not stop.is_set():
            t = time.time()
            try:
                self.cycle()
            except Exception:  # noqa: BLE001 — one bad cycle must not stop monitoring
                log.exception("cycle failed")
            stop.wait(max(1.0, interval - (time.time() - t)))
