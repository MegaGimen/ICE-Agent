from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .actors import FixtureBlue, ManualRed, SamplingBlue
from .contracts import MatchConfig
from .groups import run_group
from .runner import run_match
from .scoring import score
from .storage import write_json


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
    args = parser.parse_args()
    if args.command == "suite":
        asyncio.run(suite(args.out))
    elif args.command == "score":
        print(json.dumps(score(args.directory), ensure_ascii=False, indent=2))
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
