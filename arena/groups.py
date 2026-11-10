from __future__ import annotations

import math
from pathlib import Path
import secrets
import uuid

from .runner import run_match
from .storage import write_json


def advantages(rewards):
    if not rewards or any(r is None or not math.isfinite(r) for r in rewards):
        raise ValueError("an advantage group needs complete finite rewards")
    mean = sum(rewards) / len(rewards)
    variance = sum((r - mean) ** 2 for r in rewards) / len(rewards)
    if variance < 1e-12:
        return [0.0] * len(rewards)
    std = math.sqrt(variance)
    return [(r - mean) / std for r in rewards]


async def run_group(output: Path, red_factory, blue_factory, size, config, *, policy_seed=0):
    """Fresh worlds with identical private initial assets and frozen policies.

    Produces rollout rewards/group advantages, not an optimizer update. A model
    trainer must additionally obtain correct token masks/probabilities from its sampler.
    """
    if size < 2:
        raise ValueError("a relative-advantage group needs at least two matches")
    output = Path(output)
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    group_id = uuid.uuid4().hex
    secret = secrets.token_bytes(32)
    results = []
    expected = None
    for i in range(size):
        result = await run_match(output / f"match-{i:03d}", red_factory(), blue_factory(policy_seed + i),
                                 config, world_secret=secret, group_id=group_id)
        m = result["match"]
        identity = (m["red_policy_id"], m["blue_policy_id"], m["initial_state_id"],
                    m["implementation_id"], m["config"])
        if expected is not None and identity != expected:
            raise ValueError("policy, initial state or budget changed inside a group")
        expected = identity
        results.append(result)
    rewards = [r["score"]["blue_reward"] for r in results]
    complete = all(r is not None for r in rewards)
    group_advantages = advantages(rewards) if complete else None
    manifest = {"schema": "arena.group.v1", "group_id": group_id,
                "matches": [r["match"]["match_id"] for r in results],
                "blue_rewards": rewards, "blue_advantages": group_advantages,
                "complete_reward_group": complete,
                "zero_variance": complete and not any(group_advantages),
                "optimizer_update_performed": False,
                "token_training_ready": False,
                "training_note": "Environment rollout/advantage interface only. Bind a trainable policy sampler with token IDs, behavior probabilities and masks before GRPO optimization."}
    write_json(output / "group.json", manifest)
    return manifest
