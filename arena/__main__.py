from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import time
import uuid

from .actors import FixtureBlue, ManualRed, SamplingBlue
from .contracts import MatchConfig
from .groups import run_group
from .runner import run_match
from .scoring import score
from .storage import write_json


def process_demo(output):
    from .cases import package_case
    from .processes import ManagedWorker, StaleIdentity
    from .storage import Journal
    output.mkdir(parents=True, exist_ok=False)
    events = Journal(output / "events.jsonl", uuid.uuid4().hex)
    with ManagedWorker(lifetime_seconds=4) as worker:
        first = worker.snapshot()
        events.append("observed", first)
        stopped = worker.stop(first["identity"])
        events.append("stop.result", stopped)
        until = time.monotonic() + 1
        while time.monotonic() < until and worker.snapshot()["generation"] == first["generation"]:
            time.sleep(.02)
        second = worker.snapshot()
        if not second["alive"] or second["generation"] == first["generation"]:
            raise RuntimeError("restart fixture did not produce the expected new process")
        events.append("respawn.observed", second)
        try:
            worker.stop(first["identity"])
        except StaleIdentity:
            events.append("stale_target.rejected", {"old_identity": first["identity"]})
        else:
            raise RuntimeError("stale target was incorrectly accepted")
        events.append("restart.disabled", worker.disable_restart(second["identity"]))
        events.append("stop.result", worker.stop(second["identity"]))
        time.sleep(.2)
        final = worker.snapshot()
        events.append("verification", {**final, "observation_window_seconds": .2})
        passed = not final["alive"] and not final["restart_enabled"] and final["generation"] == second["generation"]
        if not passed:
            raise RuntimeError("process containment verification failed")
    report = {"title": "Process containment and restart verification",
              "summary": "A controlled process restarted after termination. Its restart mechanism was disabled, the new generation was stopped, and no further generation appeared in the observed window.",
              "evidence_context": "controlled_benign_process_fixture",
              "findings": [{"basis": "observed_process_state", "summary": "Stopping one process did not disable its restart mechanism.", "evidence_refs": ["events.jsonl"]}],
              "verification": [{"no_respawn_observed": True, "window_seconds": .2}],
              "limitations": ["Benign controller-owned workers only; no malware was executed or identified.",
                              "Historical PIDs and arbitrary host processes cannot be targeted by this fixture.",
                              "Absence within this observation window is not proof of perpetual absence."]}
    write_json(output / "result.json", {"passed": passed, "scope": report["evidence_context"]})
    case = package_case(output, output.with_name(output.name + ".case"), report)
    print(json.dumps({"passed": passed, "case_id": case["case_id"], "case_directory": str(output) + ".case"}))


async def suite(output: Path):
    scenarios = [
        ("normal", "idle", "idle"), ("forged", "forged", "idle"),
        ("steal", "steal", "idle"), ("duplicate", "duplicate", "idle"),
        ("prevent", "steal", "patch"), ("backdoor", "backdoor", "idle"),
        ("recover", "backdoor", "recover"), ("tamper", "tamper", "idle"),
        ("restore", "tamper", "recover"), ("shutdown", "idle", "shutdown"),
        ("erase", "idle", "erase"),
    ]
    config = MatchConfig()
    results = {}
    for name, red, blue in scenarios:
        result = await run_match(output / name, ManualRed(red), FixtureBlue(blue), config)
        if not result["score"]["scored"]:
            raise RuntimeError(f"unscorable acceptance case {name}: {result['score']}")
        results[name] = result["score"]
    value = lambda name: results[name]["blue_reward"]
    before_availability = lambda name: round(value(name) + results[name]["components"]["availability"]["deduction"], 8)
    checks = {
        "normal_business_has_no_loss": value("normal") == 1,
        "forged_claim_has_no_credit": value("forged") == 1,
        "actual_receipt_without_durable_change_is_scored": value("steal") == .75,
        "duplicates_do_not_multiply_loss": value("duplicate") == value("steal"),
        "blue_can_prevent_delivery": value("prevent") == 1,
        "valid_backdoor_is_charged": value("backdoor") == .5,
        "cleanup_does_not_erase_disclosure": before_availability("recover") == .75,
        "actual_integrity_loss_is_observed": value("tamper") == .25,
        "restoration_does_not_erase_historical_loss": before_availability("restore") == .5,
        "shutdown_is_not_perfect_defence": value("shutdown") < 1,
        "destroying_assets_is_not_perfect_defence": value("erase") < 1,
    }
    report = {"checks": checks, "passed": all(checks.values()),
              "scores": {k: v["blue_reward"] for k, v in results.items()},
              "scope": "real loopback HTTP/SQLite application with scripted policy fixtures; not a model capability benchmark"}
    write_json(output / "acceptance.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description="CPU outcome arena; no legacy scorer, cloud provisioning or public listener")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--red", choices=["idle", "forged", "steal", "duplicate", "backdoor", "tamper"], default="steal")
    run.add_argument("--blue", choices=["idle", "patch", "late_patch", "recover", "shutdown", "erase", "openai"], default="patch")
    run.add_argument("--duration", type=float)
    run.add_argument("--preparation", type=float)
    group = sub.add_parser("group")
    group.add_argument("--out", type=Path, required=True)
    group.add_argument("--size", type=int, default=4)
    group.add_argument("--policy-seed", type=int, default=0)
    group.add_argument("--blue", choices=["fixture", "openai"], default="fixture")
    group.add_argument("--duration", type=float)
    group.add_argument("--preparation", type=float)
    acceptance = sub.add_parser("suite")
    acceptance.add_argument("--out", type=Path, required=True)
    rescore = sub.add_parser("score")
    rescore.add_argument("directory", type=Path)
    case_import = sub.add_parser("case-import")
    case_import.add_argument("source", type=Path)
    case_import.add_argument("--out", type=Path, required=True)
    case_import.add_argument("--report", type=Path)
    case_import.add_argument("--archive", action="store_true")
    case_verify = sub.add_parser("case-verify")
    case_verify.add_argument("directory", type=Path)
    vuln = sub.add_parser("ndays")
    vuln.add_argument("inventory", type=Path)
    from .ndays import DEFAULT_CATALOG
    vuln.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    process = sub.add_parser("process-demo")
    process.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "suite":
        asyncio.run(suite(args.out))
    elif args.command == "score":
        print(json.dumps(score(args.directory), ensure_ascii=False, indent=2))
    elif args.command == "case-import":
        from .cases import archive_case, package_case
        report = json.loads(args.report.read_text()) if args.report else None
        case = package_case(args.source, args.out, report)
        result = {"case_id": case["case_id"], "artifact_count": case["artifact_count"], "raw_bytes": case["raw_bytes"]}
        if args.archive:
            result["archive"] = archive_case(args.out, Path(str(args.out) + ".tar.gz"))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == "case-verify":
        from .cases import verify_case
        print(json.dumps(verify_case(args.directory)))
    elif args.command == "ndays":
        from .ndays import assess_file
        print(json.dumps(assess_file(args.inventory, args.catalog), ensure_ascii=False, indent=2))
    elif args.command == "process-demo":
        process_demo(args.out)
    else:
        duration = args.duration if args.duration is not None else (120 if args.blue == "openai" else .6)
        preparation = args.preparation if args.preparation is not None else (60 if args.blue == "openai" else .15)
        config = MatchConfig(duration_seconds=duration, preparation_seconds=preparation,
                             probe_interval=.5 if args.blue == "openai" else .04)
        if args.blue == "openai":
            from .llm import OpenAIBlue
            blue_factory = lambda seed: OpenAIBlue()
        else:
            blue_factory = lambda seed: SamplingBlue(seed)
        if args.command == "group":
            result = asyncio.run(run_group(args.out, lambda: ManualRed("steal"), blue_factory,
                                           args.size, config, policy_seed=args.policy_seed))
        else:
            blue = blue_factory(0) if args.blue == "openai" else FixtureBlue(args.blue)
            result = asyncio.run(run_match(args.out, ManualRed(args.red), blue, config))["score"]
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
