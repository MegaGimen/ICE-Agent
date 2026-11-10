from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import secrets
import time
import uuid

from .actors import BlueContext, RedContext, http_call
from .contracts import ArenaClosed, BudgetExceeded, MatchConfig, digest
from .lab import LabWorld
from .scoring import Deliveries, score
from .storage import Journal, write_json


async def run_match(output: Path, red, blue, config: MatchConfig | None = None,
                    *, world_secret: bytes | None = None, group_id: str | None = None):
    config = config or MatchConfig()
    config.validate()
    world_secret = world_secret or secrets.token_bytes(32)
    if len(world_secret) < 32:
        raise ValueError("world secret must contain at least 32 bytes")
    output = Path(output)
    if output.with_name(output.name + ".case").exists():
        raise FileExistsError("case output already exists")
    output.mkdir(parents=True, exist_ok=False)
    (output / "private").mkdir(mode=0o700)
    write_json(output / "private/world_seed.json", {"secret_hex": world_secret.hex()}, private=True)
    match_id = uuid.uuid4().hex
    evidence = Journal(output / "effects.jsonl", match_id)
    trace = Journal(output / "blue_trajectory.jsonl", match_id)
    sink = Deliveries(output / "private/deliveries.jsonl", config.submission_budget, config.submission_max_bytes, match_id)
    sink.journal.path.touch(mode=0o600)
    world = None
    tasks = []
    errors = []
    status = "initializing"
    try:
        world = LabWorld(output, world_secret, evidence)
        source_root = Path(__file__).parent
        implementation_id = hashlib.sha256(b"".join(
            p.name.encode() + b"\0" + p.read_bytes() for p in sorted(source_root.glob("*.py")))).hexdigest()
        spec = {"schema": "arena.match.v1", "match_id": match_id, "group_id": group_id,
                "implementation_id": implementation_id,
                "scenario_version": world.manifest["scenario_version"], "config": config.to_dict(),
                "initial_state_id": world.initial_state_id,
                "red_policy_id": red.policy_id, "blue_policy_id": blue.policy_id,
                "backend": "local-http-sqlite", "network": "loopback-only",
                "memory_initial_state": "empty", "parameter_updates_in_match": False}
        write_json(output / "match.json", spec)
        evidence.append("match.spec", {"digest": digest(spec)})
        blue_ctx = BlueContext(world, config, trace)
        red_ctx = RedContext(world.url, sink, config)
        trace.append("input", {"brief": blue_ctx.public_brief(), "policy_id": blue.policy_id})

        async def probe(phase="running"):
            try:
                result = await asyncio.to_thread(http_call, world.url + "/api/customer", "GET", None,
                                                 world.primary, config.request_timeout)
                good = result["status"] == 200 and result["body"].get("customer") is not None
                evidence.append("business.probe", {"business_ok": good, "status": result["status"], "phase": phase})
                return good
            except Exception as error:
                # Loss of this local fixture's controller transport is not a fabricated win.
                errors.append(f"probe infrastructure: {type(error).__name__}: {error}")
                evidence.append("collector.error", {"stage": "business probe", "error": str(error)})
                return False

        healthy_baseline = await probe("baseline")
        if errors or not healthy_baseline or world.observation()["integrity_loss"]:
            raise RuntimeError("baseline probe failed")
        start = time.monotonic()
        deadline = start + config.preparation_seconds + config.duration_seconds
        red_ctx.deadline = blue_ctx.deadline = deadline

        async def workload():
            while time.monotonic() < deadline:
                await probe()
                await asyncio.sleep(config.probe_interval)

        async def actor(role, policy, context):
            evidence.append("actor.started", {"role": role, "policy_id": policy.policy_id})
            try:
                await policy.run(context)
                reason = "returned"
            except (ArenaClosed, BudgetExceeded) as error:
                reason = str(error)  # a valid budget-limited trajectory, not missing reward
            except asyncio.CancelledError:
                evidence.append("actor.finished", {"role": role, "reason": "deadline"})
                raise
            except Exception as error:
                reason = f"{type(error).__name__}: {error}"
                errors.append(f"{role} infrastructure/runner error: {reason}")
            evidence.append("actor.finished", {"role": role, "reason": reason})

        status = "blue_preparation"
        evidence.append("match.phase", {"phase": status})
        blue_task = asyncio.create_task(actor("blue", blue, blue_ctx))
        probe_task = asyncio.create_task(workload())
        tasks.extend([blue_task, probe_task])
        await asyncio.sleep(config.preparation_seconds)
        if not blue_ctx.observing.is_set():
            errors.append("blue did not establish an observation before attack window")
        status = "live"
        evidence.append("match.phase", {"phase": status})
        red_task = asyncio.create_task(actor("red", red, red_ctx))
        tasks.append(red_task)
        await asyncio.sleep(max(0, deadline - time.monotonic()))
        evidence.append("match.phase", {"phase": "closing"})
        # No new calls pass the contexts' deadline. Drain short in-flight HTTP actions
        # before sealing evidence; receipt and sample timestamps remain explicit.
        _, pending = await asyncio.wait(tasks, timeout=config.request_timeout + .1)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        sink.seal()
        await probe("closing")
        world.seal()
        status = "sealed"
    except Exception as error:
        errors.append(f"controller error: {type(error).__name__}: {error}")
        status = "failed"
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        sink.seal()
        if world is not None:
            errors.extend(world.errors)
            world.close()
        write_json(output / "completion.json", {"status": status, "evidence_complete": not errors and status == "sealed",
                                                  "errors": errors})
    if not (output / "match.json").exists():
        raise RuntimeError("match setup failed: " + "; ".join(errors))
    result = score(output)
    write_json(output / "score.json", result)
    from .cases import package_match
    packaged = package_match(output)
    return {"directory": str(output), "match": json.loads((output / "match.json").read_text()), "score": result,
            "case_id": packaged["case_id"], "case_directory": str(output.with_name(output.name + ".case"))}
