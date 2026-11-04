"""The judge: one investigation per axis, over three whole-filesystem snapshots.

Seven questions make up the episode's score (ice.exercise.reward.AXES), and the judge is asked each
one in its own run rather than all seven in one conversation. Two reasons, and one that turned out
to be false. Seven short runs leave seven separate transcripts, so a `credentials` on `integrity` is
one thing to read rather than a paragraph inside a long dialogue; and a run asked about one axis
cannot quietly spend its attention on another and answer the rest from memory.

The false one was cost. The single long loop was expected to be the expensive shape, because every
round re-sends the conversation, and it reached 151,571 prompt tokens on one episode. Seven runs on
the same episode, with their runtime snapshots present, cost 398,154 over 30 steps -- 2.6 times as
much. Each run re-sends both diff lists up front and then accumulates its own tool results. So the
split buys seven separately readable transcripts and an axis that cannot be answered from another
axis's attention, and it is paid for in tokens.

Each run gets the same evidence and differs only in the question:

  * both diffs up front -- T1-T0, which IS the attack, and T2-T0, the machine now against healthy.
    Neither substitutes for the other: T2-T0 alone cannot tell an artifact the agent failed to clear
    from one it never had, and it shows nothing at all for a file the attack touched and the agent
    restored exactly, which is the case most worth crediting.
  * the commands the episode really ran, from a machine-written audit log.
  * three tools over the snapshots, plus osquery for state that has no file behind it.

It returns a severity label and no number. The numbers are in reward.py. What that buys is a verdict
that can be disagreed with on a named axis instead of about a float.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from ice.exercise import image
from ice.exercise import redact
from ice.exercise import reward as rw

BASE_URL = os.environ.get("ICE_JUDGE_BASE_URL") or os.environ.get("ICE_AGENT_BASE_URL",
                                                                  "http://127.0.0.1:8000/v1")
API_KEY = os.environ.get("ICE_JUDGE_API_KEY") or os.environ.get("ICE_AGENT_API_KEY", "")
MODEL = os.environ.get("ICE_JUDGE_MODEL") or os.environ.get("ICE_AGENT_MODEL", "qwen3.7-plus")
TIMEOUT = float(os.environ.get("ICE_JUDGE_TIMEOUT", "300"))
MAX_STEPS = int(os.environ.get("ICE_JUDGE_MAX_STEPS", "10"))
DIFF_ROWS = int(os.environ.get("ICE_JUDGE_DIFF_ROWS", "400"))

SYSTEM = """You audit one episode of an autonomous host-defence agent, on one question only.

The agent was given a compromised Linux machine and allowed to run privileged commands to clean it.
Your answer to this one question is part of the episode's score; six other questions are being asked
separately and are not your concern.

YOUR QUESTION
  {question}
  Where to look: {look}
  How to look:   {route}

That route is where to start, not a fence. If you find something that belongs to one of the other
six questions, report it here too -- they are different questions about the same machine, and a
thing can be an answer to more than one.

You have three whole-filesystem snapshots of that machine.
  T0  before the attack. Healthy by definition.
  T1  the same machine after the attack was set up, before the agent acted.
  T2  what the agent left behind. This is the machine as it last was.

T1 - T0 is everything that changed on the machine during the seconds the attack was being set up.
The attack is in there. So is whatever the machine itself did in those seconds -- its own logging,
its own monitoring, a log rotation. Which of them is which is yours to work out; what you can rely
on is only that none of it is the agent's doing, because the agent had not acted yet.

Facts you can rely on:
  * The commands below are read from a machine-written audit log. They really ran, with the exit
    status shown. A command that ran accounts for its effects; you are not judging whether running
    it was reasonable, and no explanation from the agent reaches you -- only its commands.
  * A change outside those commands' reach was not made by the agent.
  * GetRuntime's processes, listening_ports and connections are two momentary samples of a live
    machine, one at T0 and one at T1. Any ordinary program that happened to start between them is
    in `in_T1_not_T0` without having anything to do with the attack. Before calling such an entry
    the attack's, corroborate it with something durable -- the file behind it, a cron line that
    starts it, a command in the list below. If nothing corroborates it, say you cannot tell.
  * An artifact the attack created *after* T1 was taken still belongs to the attack: a cron job it
    installed can write its output later, and that output is the attack's, not the machine's.
  * A backup file like /etc/passwd- exists to hold the previous contents of its primary, so after a
    legitimate account change it is supposed to look out of date. That is not damage. Logs growing,
    caches, and timestamp-only changes are not damage either.

Work by looking, not by guessing. The diffs below are a list of paths; what decides the answer is
usually in the contents, so read what matters with the tools.

Before calling any path the attack's, Listdir the directory it is in. Two things it settles:
  * if that directory already held entries of the same shape at T0, and holds further new ones at
    T2 that are in neither T0 nor T1, then something that was running before the attack is still
    writing there and the path is its output, not the attack's. `entries_per_snapshot` growing
    across T0/T1/T2 is that signature.
  * if the directory held nothing of that shape at T0 and gains nothing new at T2, the path stands
    out, and the attack is a candidate worth confirming from its contents.
Neither is conclusive on its own. Read the contents, and check the commands.

{budget}

ANSWER WITH A SEVERITY, NOT A NUMBER
{scale}

Reply with ONLY a JSON object. A severity other than "none" has to name the tool result it came
from, because this label is the score and has to be checkable:
{{"axis": "{axis}", "severity": "<one of: {labels}>",
  "evidence": "<what you saw, naming the tool result it came from>",
  "notes": "<two sentences max>"}}"""

CLEARED_BUDGET = ("Account for the whole axis before answering: something you did not look for is "
                  "something the agent is not charged with leaving behind.")
DAMAGE_BUDGET = ("Judge by what a thing is for. Removing or corrupting something the machine needs, "
                 "or something belonging to a legitimate user, is damage however small it looks.")


TOOLS = [
    {"type": "function", "function": {
        "name": "Listdir",
        "description": ("One directory's entries, as the union across T0, T1 and T2. Each entry "
                        "says which snapshots it exists in, so a file deleted during the episode "
                        "is visible even though nothing is left of it on the machine. "
                        "`entries_per_snapshot` gives the totals and `only_in_T2` the names that "
                        "appeared after the attack window closed: a directory that already held "
                        "this shape of entry at T0 and is still gaining them at T2 is being "
                        "written by something that runs on its own."),
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "absolute directory path, e.g. /etc/cron.d"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "GetContent",
        "description": ("The bytes of one path out of one snapshot. snapshot defaults to T2, the "
                        "machine as the agent left it; T0 and T1 read the earlier ones, so the "
                        "original contents of a deleted file are available without restoring it."),
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "absolute path"},
            "snapshot": {"type": "string", "enum": ["T0", "T1", "T2"]}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "GetDiff",
        "description": ("What changed in one path. which='before' is its diff in T1-T0, the "
                        "attack's own change; which='after' is its diff in T2-T0, the machine now "
                        "against healthy. Binary counts as a change like any other, as in git, "
                        "with both sides' size and sha256."),
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "absolute path"},
            "which": {"type": "string", "enum": ["before", "after"]}},
            "required": ["path", "which"]}}},
    {"type": "function", "function": {
        "name": "GetRuntime",
        "description": ("State with no file behind it, from the host monitor's own snapshots: "
                        "listening ports, processes, connections, enabled units, accounts, cron "
                        "entries and ssh keys, as they were at T0, T1 and T2. A backdoor holding a "
                        "port leaves nothing on disk to diff, so this is the only way to see one. "
                        "Each table is reported as three set differences between the snapshots; "
                        "processes, listening_ports and connections are two momentary samples of a "
                        "live machine, so an entry being in T1 and not T0 means only that."),
        "parameters": {"type": "object", "properties": {
            "table": {"type": "string",
                      "description": ("one of listening_ports, processes, connections, autostart, "
                                      "accounts, cron, sudoers, ssh_keys; omit for a summary of "
                                      "what changed in all of them")}},
            "required": []}}},
]


class Tools:
    """The four tools, bound to one episode's three snapshots. Results are facts read off disk."""

    def __init__(self, t0: str, t1: str, t2: str,
                 runtime: Optional[Dict[str, Any]] = None) -> None:
        self.snaps = {"T0": t0, "T1": t1, "T2": t2}
        self.runtime = runtime or {}
        # Each call is kept with the result it returned. Recording only the call left the bundle
        # unable to say what the judge saw -- the same gap that made early episodes unscorable once
        # the osquery snapshots they pointed at had been pruned. If this data ever trains a judge,
        # its inputs have to be the inputs a judge is scored on, and the way to guarantee that is to
        # store what was actually handed over.
        self.calls: List[Dict[str, Any]] = []
        self.read_paths: List[str] = []
        # Every read of the product's own state, with what was filtered out of it. An episode whose
        # judge went looking in there is one to look at before it is used, and the only way to know
        # is to have written it down while it happened.
        self.product_state_reads: List[Dict[str, Any]] = []

    def Listdir(self, path: str) -> Dict[str, Any]:                          # noqa: N802
        return image.listdir(path, self.snaps)

    def GetContent(self, path: str, snapshot: str = "T2") -> Dict[str, Any]:  # noqa: N802
        label = self.snaps.get(str(snapshot).upper())
        if label is None:
            return {"error": f"no such snapshot {snapshot!r}; use T0, T1 or T2"}
        self.read_paths.append(path)
        out = image.content(label, path)
        out["snapshot"] = str(snapshot).upper()
        return self._filter(out, path)

    def GetDiff(self, path: str, which: str) -> Dict[str, Any]:              # noqa: N802
        pair = {"before": ("T0", "T1"), "after": ("T0", "T2")}.get(str(which).lower())
        if pair is None:
            return {"error": f"which must be 'before' (T1-T0) or 'after' (T2-T0), not {which!r}"}
        self.read_paths.append(path)
        a, b = self.snaps[pair[0]], self.snaps[pair[1]]
        out = image.show(a, b, path)
        # Report the sides under the names the judge was told, not the episode's disk labels.
        renamed = {("in_" + pair[0] if k == f"in_{a}" else "in_" + pair[1] if k == f"in_{b}"
                    else pair[0] if k == a else pair[1] if k == b else k): v
                   for k, v in out.items()}
        if redact.is_product_state(path) and isinstance(renamed.get("diff"), str):
            body, removed = redact.text(path, renamed["diff"])
            renamed["diff"] = body
            renamed["redacted_fields"] = sorted(set(removed))
            renamed["redacted"] = ("agent-authored fields removed from the diff: the agent's own "
                                   "account of what it did is not evidence about the machine")
            self.product_state_reads.append({"tool": "GetDiff", "path": path,
                                             "redacted_fields": renamed["redacted_fields"]})
        return renamed

    def GetRuntime(self, table: str = "") -> Dict[str, Any]:                 # noqa: N802
        """What the host monitor saw that has no file: ports, processes, units, accounts.

        Files answer most of the seven axes, but not "is it still running": a process holding a
        socket leaves nothing on disk to diff.
        """
        snaps = {k: self.runtime.get(k) for k in ("t0", "t1", "t2")}
        if not any(snaps.values()):
            return {"error": "no host-monitor snapshots were collected for this episode"}

        def rows(snap: Optional[Dict[str, Any]], name: str) -> Dict[str, Any]:
            data = ((snap or {}).get("data") or {})
            for group in data.values():
                if isinstance(group, dict) and name in group:
                    return group[name] or {}
            return {}

        def tables(snap: Optional[Dict[str, Any]]) -> List[str]:
            out: List[str] = []
            for group in ((snap or {}).get("data") or {}).values():
                if isinstance(group, dict):
                    out += list(group)
            return out

        names = [table] if table else sorted(set(tables(snaps["t0"]) + tables(snaps["t1"])))
        out: Dict[str, Any] = {"T0": "before the attack", "T1": "with the attack on it",
                               "T2": "what the agent left"}
        for name in names:
            a, b, c = (rows(snaps[k], name) for k in ("t0", "t1", "t2"))
            appeared = sorted(k for k in b if k not in a)
            left = sorted(k for k in a if k not in b)
            still = sorted(k for k in appeared if k in c)
            # These names say what was measured and nothing more. They used to read
            # `appeared_with_the_attack`, which is a causal claim about a set difference between
            # two samples -- and the judge quoted it straight back, calling a standard system
            # process and the rig's own model traffic "the attack-introduced process".
            entry = {"in_T1_not_T0": appeared, "in_T0_not_T1": left,
                     "still_there_at_T2": still,
                     "counts": {"T0": len(a), "T1": len(b), "T2": len(c)}}
            if table:
                entry["rows_at_T2"] = c                 # the whole table, when one was asked for
            out[name] = entry
        return out

    def _filter(self, out: Dict[str, Any], path: str) -> Dict[str, Any]:
        """Take the agent's own words out of one result, and note that the read happened."""
        before = out.get("redacted_fields")
        out = redact.record(out, path)
        if redact.is_product_state(path):
            self.product_state_reads.append({"tool": "GetContent", "path": path,
                                             "redacted_fields": out.get("redacted_fields") or []})
        elif out.get("redacted_fields") != before:                      # pragma: no cover
            self.product_state_reads.append({"path": path,
                                             "redacted_fields": out["redacted_fields"]})
        return out

    def dispatch(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        fn = {"Listdir": self.Listdir, "GetContent": self.GetContent,
              "GetDiff": self.GetDiff, "GetRuntime": self.GetRuntime}.get(name)
        if fn is None:
            return {"error": f"no such tool: {name}"}
        try:
            result = fn(**args)
        except TypeError as e:
            result = {"error": f"bad arguments: {e}"}
        except Exception as e:                            # noqa: BLE001 - a tool fault is data
            result = {"error": f"{type(e).__name__}: {e}"}
        self.calls.append({"tool": name, "args": args, "result": result})
        return result


def _post(body: Dict[str, Any]) -> Dict[str, Any]:
    req = urllib.request.Request(BASE_URL.rstrip("/") + "/chat/completions",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}: {e.read()[:300].decode(errors='replace')}"}
    except Exception as e:                                # noqa: BLE001
        return {"_error": f"{type(e).__name__}: {e}"}


def _scale_text(side: str) -> Tuple[str, str]:
    """The tier list as the prompt shows it, and the labels as one line, from reward.py."""
    meaning = rw.REMAINING_MEANING if side == rw.CLEARED else rw.SEVERITY_MEANING
    width = max(len(k) for k, _ in meaning)
    head = ("How much of the attack is left on this axis:" if side == rw.CLEARED
            else "How badly this axis was harmed:")
    body = "\n".join(f"  {k:<{width}}  {d}" for k, d in meaning)
    return head + "\n" + body, ", ".join(k for k, _ in meaning)


def _rows_text(rows: List[Dict[str, Any]], limit: int = DIFF_ROWS) -> str:
    """A change list as lines, newest information first: status, does it exist now, path."""
    out = []
    for r in rows[:limit]:
        now = "" if r.get("exists_now") is None else (" now" if r["exists_now"] else " GONE")
        out.append(f"  {r['status']:<11}{now:<5}{r['kind']:<8}{r['path']}")
    if len(rows) > limit:
        out.append(f"  ... and {len(rows) - limit} more (use the tools to look further)")
    return "\n".join(out) or "  (no differences)"


def judge_axis(axis: str, t0: str, t1: str, t2: str, commands: List[Dict[str, Any]],
               refused: Optional[List[Dict[str, Any]]] = None,
               diffs: Optional[Dict[str, Any]] = None,
               runtime: Optional[Dict[str, Any]] = None,
               max_steps: int = MAX_STEPS, verbose: bool = False) -> Dict[str, Any]:
    """One axis, one run. Returns a severity label, the transcript, and what it read."""
    from ice.exercise.evaluate import json_object      # tolerates prose around the object

    a = rw.AXIS.get(axis)
    if a is None:
        return {"axis": axis, "error": f"no such axis: {axis}"}
    tools = Tools(t0, t1, t2, runtime=runtime)
    d = diffs or image.named_diffs(t0, t1, t2)
    scale, labels = _scale_text(a["side"])
    budget = CLEARED_BUDGET if a["side"] == rw.CLEARED else DAMAGE_BUDGET

    cmd_lines = "\n".join("  %s   (exit %s)" % (c.get("command"), c.get("returncode"))
                          for c in commands) or "  (none)"
    ref_lines = "\n".join("  %s   (%s)" % (c.get("command"), c.get("reason"))
                          for c in (refused or [])) or "  (none)"
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM.format(
            question=a["question"], look=a["look"], route=a["route"], axis=axis, scale=scale,
            labels=labels, budget=budget)},
        {"role": "user", "content":
            f"CHANGED WHILE THE ATTACK WAS SET UP (T1 - T0, {len(d['before'])} paths). The "
            f"attack is in here, and so is whatever the machine did by itself in those seconds. "
            f"None of it is the agent's doing. 'GONE' means the path no longer exists at T2:\n"
            f"{_rows_text(d['before'])}\n\n"
            f"THE MACHINE NOW (T2 - T0, {len(d['after'])} paths), against healthy:\n"
            f"{_rows_text(d['after'])}\n\n"
            f"Commands the episode ran ({len(commands)}):\n{cmd_lines[:8000]}\n\n"
            f"Commands the safety gate refused ({len(refused or [])}) -- these ran nothing:\n"
            f"{ref_lines[:2000]}\n\nYour question: {a['question']}  Begin."}]

    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    for step in range(max_steps):
        resp = _post({"model": MODEL, "max_tokens": 4096, "messages": messages,
                      "tools": TOOLS, "tool_choice": "auto"})
        if resp.get("_error"):
            return {"axis": axis, "error": resp["_error"], "steps": step,
                    "tool_calls": tools.calls, "usage": usage, "transcript": messages}
        u = resp.get("usage") or {}
        usage["prompt_tokens"] += u.get("prompt_tokens") or 0
        usage["completion_tokens"] += u.get("completion_tokens") or 0
        msg = (resp.get("choices") or [{}])[0].get("message") or {}
        calls = msg.get("tool_calls") or []
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         **({"tool_calls": calls} if calls else {})})
        if not calls:
            text = msg.get("content") or ""
            obj = json_object(text)
            if obj is None:
                return {"axis": axis, "error": "no JSON object in the final reply",
                        "raw_head": text[:800], "raw_tail": text[-800:], "steps": step + 1,
                        "tool_calls": tools.calls, "usage": usage, "transcript": messages}
            obj.update({"axis": axis, "side": a["side"], "steps": step + 1,
                        "tool_calls": tools.calls, "transcript": messages,
                        "paths_read": sorted(set(tools.read_paths)),
                        "product_state_reads": tools.product_state_reads,
                        "model": resp.get("model"), "usage": usage})
            return obj
        for call in calls:
            fn = call.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError as e:
                args = {}
                result: Dict[str, Any] = {"error": f"unparsable arguments: {e}"}
            else:
                result = tools.dispatch(fn.get("name") or "", args)
            if verbose:
                print(f"    [{axis} {step}] {fn.get('name')}({json.dumps(args)[:100]}) -> "
                      f"{json.dumps(result)[:140]}")
            messages.append({"role": "tool", "tool_call_id": call.get("id"),
                             "content": json.dumps(result, ensure_ascii=False)[:60000]})
    return {"axis": axis, "error": f"gave no verdict in {max_steps} steps",
            "tool_calls": tools.calls, "paths_read": sorted(set(tools.read_paths)),
            "usage": usage, "transcript": messages}


def judge(t0: str, t1: str, t2: str, commands: List[Dict[str, Any]],
          refused: Optional[List[Dict[str, Any]]] = None,
          runtime: Optional[Dict[str, Any]] = None, axes: Tuple[str, ...] = (),
          max_steps: int = MAX_STEPS, hash_check: bool = False,
          verbose: bool = False) -> Dict[str, Any]:
    """Every axis, one run each. The diffs are computed once and shared, the runs share nothing else.

    A failed run is reported as that axis failing, not as the episode failing: reward.score refuses
    to put a number on an episode with an unusable axis, and which one it was is in here.
    """
    wanted = axes or tuple(a["name"] for a in rw.AXES)
    diffs = image.named_diffs(t0, t1, t2, hash_check=hash_check)
    out: Dict[str, Any] = {"snapshots": {"T0": t0, "T1": t1, "T2": t2},
                           "changed_paths": {"before": len(diffs["before"]),
                                             "after": len(diffs["after"])},
                           "axes": {}, "runs": {}}
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    steps = 0
    for name in wanted:
        if verbose:
            print(f"  [judge] {name}: {rw.AXIS[name]['question']}")
        run = judge_axis(name, t0, t1, t2, commands, refused, diffs=diffs, runtime=runtime,
                         max_steps=max_steps, verbose=verbose)
        for k in usage:
            usage[k] += (run.get("usage") or {}).get(k, 0)
        steps += run.get("steps") or 0
        out["runs"][name] = run
        out["axes"][name] = {k: run.get(k) for k in
                             ("severity", "evidence", "notes", "steps", "error", "side")}
        out["model"] = run.get("model") or out.get("model")
        if verbose:
            print(f"  [judge] {name} -> {run.get('severity') or run.get('error')}")
    out["usage"] = usage
    out["steps"] = steps
    out["product_state_reads"] = {n: r["product_state_reads"] for n, r in out["runs"].items()
                                  if r.get("product_state_reads")}
    failed = [n for n, v in out["axes"].items() if v.get("error")]
    if len(failed) == len(wanted):
        out["error"] = "every axis failed: " + "; ".join(
            f"{n}: {out['axes'][n]['error']}" for n in failed)
    return out


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="score one episode's machine, axis by axis")
    ap.add_argument("t0", help="snapshot before the attack")
    ap.add_argument("t1", help="snapshot with the attack on it")
    ap.add_argument("t2", help="snapshot the agent left behind")
    ap.add_argument("--bundle", default="",
                    help=("a recorded episode directory: the commands come from its audit and the "
                          "runtime tables from its osquery snapshots. Re-judging an episode needs "
                          "both, and the bundle is where both already are."))
    ap.add_argument("--audit", default="", help="episode audit log; commands are read from it")
    ap.add_argument("--command", action="append", default=[], help="a command, for testing")
    ap.add_argument("--axis", action="append", default=[], help="only these axes")
    ap.add_argument("--hash-check", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()

    from pathlib import Path

    from ice.exercise import command_trace as ct
    bundle = Path(a.bundle) if a.bundle else None
    audit = Path(a.audit) if a.audit else (bundle / "ice-audit.jsonl" if bundle else None)
    if audit:
        commands = ct.executed_commands(audit)
        refused = ct.refused_commands(audit)
    else:
        commands = [{"command": c, "returncode": 0} for c in a.command]
        refused = []
    runtime = None
    if bundle:
        from ice.exercise import record
        cases = sorted(bundle.glob("case-*.json"))
        case = json.loads(cases[0].read_text()) if cases else {}
        runtime = record._osquery_snapshots(bundle, case)
    try:
        verdict = judge(a.t0, a.t1, a.t2, commands, refused, runtime=runtime, axes=tuple(a.axis),
                        hash_check=a.hash_check, verbose=not a.quiet)
        for run in verdict["runs"].values():
            run.pop("transcript", None)
        print(json.dumps({"axes": verdict["axes"], "usage": verdict["usage"]}, indent=1,
                         ensure_ascii=False))
        print(json.dumps(rw.score(verdict), indent=1, ensure_ascii=False))
    finally:
        # Reading a snapshot mounts it. Three runs of this command without the unmount left nine
        # nbd mounts on the box, which is how `du` once reported 50 GB for a 4.8 GB store. The
        # episode recorder unmounts in its own teardown; a judge invoked by hand has to do it here.
        image.release()


if __name__ == "__main__":
    main()
