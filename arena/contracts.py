from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class RewardProfile:
    """Explicit demo values, not the legacy ruler or final research weights."""

    version: str = "asset-outcome-v2-demo-1"
    weights: dict[str, float] = field(default_factory=lambda: {
        "confidentiality": .25, "integrity": .25,
        "availability": .25, "remaining_access": .25,
    })

    def validate(self):
        required = {"confidentiality", "integrity", "availability", "remaining_access"}
        if set(self.weights) != required:
            raise ValueError("reward axes must be declared explicitly")
        if any(not math.isfinite(v) or v < 0 for v in self.weights.values()):
            raise ValueError("weights must be finite and nonnegative")
        if not math.isclose(sum(self.weights.values()), 1.0, abs_tol=1e-9):
            raise ValueError("weights must sum to one")


@dataclass(frozen=True)
class MatchConfig:
    preparation_seconds: float = .15
    duration_seconds: float = .6
    probe_interval: float = .04
    blue_action_budget: int = 80
    red_request_budget: int = 60
    submission_budget: int = 12
    submission_max_bytes: int = 32_768
    request_timeout: float = 2.0
    profile: RewardProfile = field(default_factory=RewardProfile)

    def validate(self):
        for name in ("duration_seconds", "probe_interval", "request_timeout"):
            if not math.isfinite(getattr(self, name)) or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if not math.isfinite(self.preparation_seconds) or self.preparation_seconds < 0:
            raise ValueError("preparation_seconds must be nonnegative")
        if self.probe_interval > self.duration_seconds:
            raise ValueError("probe_interval must not exceed match duration")
        for name in ("blue_action_budget", "red_request_budget", "submission_budget", "submission_max_bytes"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        self.profile.validate()

    def to_dict(self):
        return asdict(self)


class ArenaClosed(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass
