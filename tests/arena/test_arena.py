import asyncio
import json
from pathlib import Path

import pytest

from arena.actors import FixtureBlue, ManualRed, SamplingBlue
from arena.contracts import ArenaClosed, MatchConfig, RewardProfile
from arena.groups import advantages, run_group
from arena.runner import run_match
from arena.scoring import Deliveries, score
from arena.storage import read_journal


CONFIG = MatchConfig(preparation_seconds=.04, duration_seconds=.3, probe_interval=.025)


def play(tmp_path, red="idle", blue="idle"):
    return asyncio.run(run_match(tmp_path / "match", ManualRed(red, delay=.01),
                                 FixtureBlue(blue, delay=.14), CONFIG))


@pytest.mark.parametrize("red,blue,expected", [
    ("idle", "idle", 1), ("forged", "idle", 1), ("steal", "idle", .75),
    ("duplicate", "idle", .75), ("steal", "patch", 1),
    ("backdoor", "idle", .5), ("backdoor", "recover", .75),
    ("tamper", "idle", .25), ("tamper", "recover", .5),
])
def test_outcomes_are_verified_and_not_actor_narratives(tmp_path, red, blue, expected):
    result = play(tmp_path, red, blue)
    assert result["score"]["scored"], result
    measured_availability_cost = result["score"]["components"]["availability"]["deduction"]
    if blue != "recover":
        assert measured_availability_cost == 0
    # Rotation updates the legitimate client's next request, but a request already
    # in flight may still carry the revoked credential. That real 401 must count.
    expected_score = round(expected - measured_availability_cost, 8)
    assert result["score"]["blue_reward"] == expected_score
    assert result["score"]["red_reward"] == -expected_score
    if blue == "recover":
        probes = [r for r in read_journal(Path(result['directory']) / 'effects.jsonl')
                  if r['kind'] == 'business.probe' and r['data']['phase'] == 'running']
        failed = [r['data']['status'] for r in probes if not r['data']['business_ok']]
        assert failed in ([], [401])


def test_receipt_survives_no_durable_attack_change(tmp_path):
    result = play(tmp_path, "steal")
    events = read_journal(Path(result["directory"]) / "effects.jsonl")
    before = next(r["data"] for r in events if r["kind"] == "world.baseline")
    after = next(r["data"] for r in events if r["kind"] == "world.final")
    assert all(after[k] == v for k, v in before.items())
    assert result["score"]["components"]["confidentiality"]["loss"] == 1


@pytest.mark.parametrize("blue", ["erase", "shutdown"])
def test_defender_cannot_win_by_destroying_business(tmp_path, blue):
    result = play(tmp_path, "idle", blue)
    assert result["score"]["blue_reward"] < 1
    assert result["score"]["components"]["availability"]["loss"] > 0


def test_live_opponent_observes_blue_changes_and_blue_starts_first(tmp_path):
    class Red:
        policy_id = "interleaving-test"
        statuses = []

        async def run(self, ctx):
            self.statuses.append((await ctx.request("/debug/export"))["status"])
            await asyncio.sleep(.17)
            self.statuses.append((await ctx.request("/debug/export"))["status"])

    red = Red()
    result = asyncio.run(run_match(tmp_path / "match", red, FixtureBlue("late_patch", .12), CONFIG))
    assert red.statuses == [200, 404]
    events = read_journal(Path(result["directory"]) / "effects.jsonl")
    roles = [r["data"]["role"] for r in events if r["kind"] == "actor.started"]
    assert roles == ["blue", "red"]


def test_no_red_report_is_needed_for_independently_captured_receipt(tmp_path):
    class Red:
        policy_id = "read-without-report"

        async def run(self, ctx):
            await ctx.request("/debug/export")

    result = asyncio.run(run_match(tmp_path / "match", Red(), FixtureBlue(), CONFIG))
    assert result["score"]["blue_reward"] == .75
    assert result["score"]["acquired_assets"] == ["customer_record", "service_credential"]


def test_controller_failure_is_unscorable_not_an_attacker_win(tmp_path):
    class Broken:
        policy_id = "broken-runner"

        async def run(self, ctx):
            raise RuntimeError("collector client broke")

    result = asyncio.run(run_match(tmp_path / "match", Broken(), FixtureBlue(), CONFIG))
    assert not result["score"]["scored"]
    assert result["score"]["blue_reward"] is None


def test_evidence_corruption_is_detected(tmp_path):
    result = play(tmp_path)
    path = Path(result["directory"]) / "effects.jsonl"
    rows = path.read_text().splitlines()
    row = json.loads(rows[-1]);row["data"]["integrity_loss"] = 1
    rows[-1] = json.dumps(row);path.write_text("\n".join(rows) + "\n")
    assert not score(path.parent)["scored"]


def test_delivery_receipts_do_not_reveal_correctness_and_close_at_end(tmp_path):
    sink = Deliveries(tmp_path / "receipts.jsonl", budget=3, max_bytes=1000)
    a = sink.submit("credential", "correct-or-not")
    b = sink.submit("missing", "invented")
    assert set(a) == set(b) == {"receipt", "accepted"}
    assert a["accepted"] and b["accepted"]
    sink.seal()
    with pytest.raises(ArenaClosed):sink.submit("credential", "late")


def test_group_restores_same_world_and_keeps_policy_fixed(tmp_path):
    result = asyncio.run(run_group(tmp_path / "group", lambda: ManualRed("steal", .01),
                                    SamplingBlue, 4, CONFIG))
    specs = [json.loads(p.read_text()) for p in (tmp_path / "group").glob("match-*/match.json")]
    assert len({s["initial_state_id"] for s in specs}) == 1
    assert len({s["match_id"] for s in specs}) == 4
    assert len({s["blue_policy_id"] for s in specs}) == 1
    assert result["complete_reward_group"]
    assert not result["optimizer_update_performed"]
    assert not result["token_training_ready"]
    assert abs(sum(result["blue_advantages"])) < 1e-6


def test_previous_world_secret_is_not_accepted_in_new_world(tmp_path):
    first = asyncio.run(run_match(tmp_path / "first", ManualRed("idle"), FixtureBlue(), CONFIG))
    old = json.loads((Path(first["directory"]) / "private/asset_manifest.json").read_text())["assets"][0]["value"]

    class Red:
        policy_id = "stale-secret-test"

        async def run(self, ctx):
            await ctx.submit("service_credential", old)

    second = asyncio.run(run_match(tmp_path / "second", Red(), FixtureBlue(), CONFIG))
    assert second["match"]["initial_state_id"] != first["match"]["initial_state_id"]
    assert second["score"]["acquired_assets"] == []


def test_zero_variance_and_missing_rewards_are_explicit():
    assert advantages([.8, .8, .8]) == [0, 0, 0]
    with pytest.raises(ValueError):advantages([.8, None])
    with pytest.raises(ValueError):RewardProfile(weights={"confidentiality": 1}).validate()


def test_private_truth_never_reaches_blue_input(tmp_path):
    result = play(tmp_path, "backdoor", "recover")
    folder = Path(result["directory"])
    secret = json.loads((folder / "private/asset_manifest.json").read_text())["assets"][0]["value"]
    assert secret not in (folder / "blue_trajectory.jsonl").read_text()


def test_scorer_does_not_require_policy_trajectory(tmp_path):
    result = play(tmp_path, "steal")
    folder = Path(result["directory"])
    (folder / "blue_trajectory.jsonl").unlink()
    assert score(folder)["blue_reward"] == .75


def test_changed_reward_config_is_not_silently_accepted(tmp_path):
    result = play(tmp_path)
    folder = Path(result["directory"])
    spec = json.loads((folder / "match.json").read_text())
    spec["config"]["profile"]["version"] = "silently-relabelled"
    (folder / "match.json").write_text(json.dumps(spec))
    assert not score(folder)["scored"]


def test_external_learner_drives_real_tools_and_receives_terminal_reward(tmp_path):
    from arena.environment import make_environment_factory
    config = MatchConfig(preparation_seconds=.15, duration_seconds=.25, probe_interval=.025)
    factory = make_environment_factory(tmp_path / "external", config, "checkpoint-0")
    env = factory()
    prompt = json.loads(env.reset(group_key="group-a"))
    assert "observation" in prompt and "private" not in prompt
    env.set_debug_export(False)
    assert env.observe()["debug_export_enabled"] is False
    assert env.get_reward() == 1
    with pytest.raises(ArenaClosed):env.set_debug_export(True)


def test_external_group_replicas_share_world_but_not_state(tmp_path):
    from arena.environment import make_environment_factory
    factory = make_environment_factory(tmp_path / "external", CONFIG, "checkpoint-0")
    one, two = factory(), factory()
    one.reset(group_key="same-group")
    one.set_service_enabled(False)
    assert one.get_reward() < 1
    two.reset(group_key="same-group")
    assert two.observe()["service_enabled"] is True
    two.get_reward()
    specs = [json.loads(p.read_text()) for p in (tmp_path / "external").glob('*/match.json')]
    assert len({s['initial_state_id'] for s in specs}) == 1


def test_stealing_a_rotated_credential_still_counts(tmp_path):
    class Blue:
        policy_id = "rotate-without-closing-exposure"

        async def run(self, ctx):
            await ctx.call("observe")
            await ctx.call("rotate_service_token")

    result = asyncio.run(run_match(tmp_path / "match", ManualRed("steal", .01), Blue(), CONFIG))
    assert result["score"]["scored"]
    assert result["score"]["acquired_assets"] == ["customer_record", "service_credential"]
    cost = result["score"]["components"]["availability"]["deduction"]
    assert result["score"]["blue_reward"] == round(.75 - cost, 8)


def test_chat_adapter_executes_tools_and_records_exact_messages(tmp_path):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    from arena.llm import OpenAIBlue

    requests = []

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append(body)
            if len(requests) == 1:
                message = {'role': 'assistant', 'content': None, 'tool_calls': [
                    {'id': 'call-1', 'type': 'function', 'function': {
                        'name': 'set_debug_export', 'arguments': '{"enabled":false}'}}]}
            else:
                assert body['messages'][-1]['role'] == 'tool'
                message = {'role': 'assistant', 'content': 'The returned state confirms export is disabled.'}
            response = json.dumps({'model': 'fixture-model', 'choices': [{'message': message}]}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(response)))
            self.end_headers();self.wfile.write(response)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    worker.start()
    try:
        policy = OpenAIBlue(f'http://127.0.0.1:{server.server_port}/v1', 'fixture-model', 'key-do-not-log')
        result = asyncio.run(run_match(tmp_path / 'match', ManualRed('steal'), policy,
                                       MatchConfig(preparation_seconds=.2, duration_seconds=.25, probe_interval=.025)))
        assert result['score']['scored'] and result['score']['blue_reward'] == 1
        trace = (Path(result['directory']) / 'blue_trajectory.jsonl').read_text()
        assert 'key-do-not-log' not in trace
        events = read_journal(Path(result['directory']) / 'blue_trajectory.jsonl')
        inputs = [r['data'] for r in events if r['kind'] == 'model.input']
        assert inputs[1]['messages'] == requests[1]['messages']
        assert len(requests) == 2
    finally:
        server.shutdown();server.server_close();worker.join(timeout=2)


def test_invalid_red_input_cannot_turn_a_match_into_missing_reward(tmp_path):
    class Red:
        policy_id = 'invalid-inputs'

        async def run(self, ctx):
            assert not (await ctx.submit('service_credential', float('nan')))['accepted']
            assert (await ctx.request('https://not-a-target.invalid/'))['status'] == 400
            assert (await ctx.request('/health', method='UNSUPPORTED'))['status'] == 400
            assert (await ctx.request('/health', token='not-ascii-凭据'))['status'] == 400
            assert (await ctx.request('/health', token='bad\r\nheader'))['status'] == 400
            assert (await ctx.request('/bad path'))['status'] == 400

    result = asyncio.run(run_match(tmp_path / 'match', Red(), FixtureBlue(), CONFIG))
    assert result['score']['scored'] and result['score']['blue_reward'] == 1


def test_evidence_does_not_mutate_with_callers_objects(tmp_path):
    from arena.storage import Journal
    journal = Journal(tmp_path / 'evidence.jsonl')
    payload = {'messages': [{'content': 'original'}]}
    journal.append('model.input', payload)
    payload['messages'].append({'content': 'later'})
    assert journal.rows[0]['data']['messages'] == [{'content': 'original'}]
    assert read_journal(journal.path) == journal.rows


def test_deliveries_cannot_be_swapped_between_identical_group_worlds(tmp_path):
    import shutil
    secret = b'x' * 32
    first = asyncio.run(run_match(tmp_path / 'first', ManualRed('steal', .01), FixtureBlue(), CONFIG,
                                  world_secret=secret))
    replay_secret = bytes.fromhex(json.loads((tmp_path / 'first/private/world_seed.json').read_text())['secret_hex'])
    second = asyncio.run(run_match(tmp_path / 'second', ManualRed('idle'), FixtureBlue(), CONFIG,
                                   world_secret=replay_secret))
    assert first['match']['initial_state_id'] == second['match']['initial_state_id']
    assert second['score']['blue_reward'] == 1
    shutil.copyfile(tmp_path / 'first/private/deliveries.jsonl', tmp_path / 'second/private/deliveries.jsonl')
    assert not score(tmp_path / 'second')['scored']


def test_broken_initial_world_is_not_scored_as_actor_damage(tmp_path, monkeypatch):
    import arena.runner as runner
    from arena.lab import LabWorld

    class BrokenBaseline(LabWorld):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.blue_action('delete_customer', {})

    monkeypatch.setattr(runner, 'LabWorld', BrokenBaseline)
    result = asyncio.run(runner.run_match(tmp_path / 'match', ManualRed('idle'), FixtureBlue(), CONFIG))
    assert not result['score']['scored']
    assert result['score']['blue_reward'] is None
