"""Environment bridge for an external multi-turn learner.

The learner owns model generation, token masks and policy probabilities. This module owns
the real application and concurrently running red fixture. No optimizer is implemented here.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import threading
import time
import uuid

from .actors import ManualRed
from .contracts import ArenaClosed, canonical
from .runner import run_match


class _DrivenBlue:
    def __init__(self, version):
        self.policy_id = "external-learner:" + version
        self.ready = threading.Event()
        self.context = None
        self.loop = None
        self.initial = None

    async def run(self, ctx):
        self.context = ctx
        self.loop = asyncio.get_running_loop()
        self.initial = await ctx.call("observe")
        self.ready.set()
        await asyncio.sleep(max(0, ctx.deadline - time.monotonic()))


class ArenaEnvironment:
    """Reset/tool/reward API; only the public operation methods are agent tools.

    `reset` and `get_reward` are lifecycle methods, never agent tools. A training
    adapter must provide a shared group_key for comparable GRPO group members.
    """

    def __init__(self, output, config, red_factory, policy_version, master_secret):
        self._output, self._config = Path(output), config
        self._red_factory, self._version = red_factory, policy_version
        self._master_secret = master_secret
        self._thread = None
        self._result = None
        self._error = None
        self._blue = None

    def reset(self, *, group_key, **kwargs) -> str:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("finish the previous match before resetting this environment")
        if not isinstance(group_key, str) or not group_key:
            raise ValueError("reset requires a nonempty shared group_key")
        self._result = self._error = None
        self._blue = _DrivenBlue(self._version)
        # A public group key does not reveal protected content: the derivation key is private.
        world_secret = hmac.new(self._master_secret, canonical(group_key), hashlib.sha256).digest()
        folder = self._output / uuid.uuid4().hex

        def run():
            try:
                self._result = asyncio.run(run_match(folder, self._red_factory(), self._blue,
                                                     self._config, world_secret=world_secret,
                                                     group_id=group_key))
            except Exception as error:
                self._error = error
            finally:
                self._blue.ready.set()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        if not self._blue.ready.wait(10):
            raise TimeoutError("arena did not initialize")
        if self._error:
            raise RuntimeError("arena setup failed") from self._error
        if self._blue.context is None:
            raise RuntimeError("arena did not provide an observation")
        return json.dumps({"brief": self._blue.context.public_brief(), "observation": self._blue.initial})

    def _call(self, name, **args):
        if self._blue is None or self._blue.loop is None or self._blue.loop.is_closed():
            raise ArenaClosed("no active arena")
        if time.monotonic() >= self._blue.context.deadline:
            raise ArenaClosed("match action window ended")
        future = asyncio.run_coroutine_threadsafe(self._blue.context.call(name, **args), self._blue.loop)
        return future.result(timeout=self._config.request_timeout + 2)

    def observe(self) -> dict:
        """Read current application state and recent request outcomes."""
        return self._call("observe")

    def set_debug_export(self, enabled: bool) -> dict:
        """Change the application debug export setting.

        Args:
            enabled: Whether anonymous debug export is enabled.
        """
        return self._call("set_debug_export", enabled=enabled)

    def revoke_key(self, key_id: str) -> dict:
        """Revoke an application API credential.

        Args:
            key_id: Observed identifier of the credential to revoke.
        """
        return self._call("revoke_key", key_id=key_id)

    def rotate_service_token(self) -> dict:
        """Rotate the primary credential and update the legitimate client configuration."""
        return self._call("rotate_service_token")

    def restore_customer(self) -> dict:
        """Restore the customer record from the existing application backup."""
        return self._call("restore_customer")

    def set_service_enabled(self, enabled: bool) -> dict:
        """Pause or resume business availability.

        Args:
            enabled: Whether the business service accepts requests.
        """
        return self._call("set_service_enabled", enabled=enabled)

    def delete_customer(self) -> dict:
        """Delete the live customer record; legitimate customer requests will fail."""
        return self._call("delete_customer")

    def get_reward(self) -> float | None:
        if self._thread is None:
            raise RuntimeError("reset must be called first")
        self._thread.join(timeout=self._config.preparation_seconds + self._config.duration_seconds
                          + self._config.request_timeout + 10)
        if self._thread.is_alive():
            raise TimeoutError("arena did not finish within its bounded lifecycle")
        if self._error:
            raise RuntimeError("arena failed") from self._error
        return self._result["score"]["blue_reward"]


def make_environment_factory(output, config, policy_version, red_factory=None, master_secret=None):
    """Capture one private derivation key for all replicas of a training job."""
    master_secret = master_secret or secrets.token_bytes(32)
    if len(master_secret) < 32:
        raise ValueError("master_secret must contain at least 32 bytes")
    red_factory = red_factory or (lambda: ManualRed("steal"))
    return lambda: ArenaEnvironment(output, config, red_factory, policy_version, master_secret)
