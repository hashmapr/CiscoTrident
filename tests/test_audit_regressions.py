"""Regression tests for the audit findings.

Covers: evidence-based snapshot selection (not device count), single-source
facts never being called "derived", AI batching/truncation/question-number
reconciliation, entity-resolution ambiguity, and Engine B config filename
sanitisation.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from trident.config import Settings
from trident.models import AnswerStatus, DeviceInfo, NetworkModel
from trident.parsers.snapshot import select_snapshot
from trident.reasoning.ai_client import AIClient, AIClientError, build_digest
from trident.verification.consensus import ConsensusEngine
from trident.verification.validators import AnswerBuilder

# ---------------------------------------------------------------------------
# Snapshot selection: evidence, not device count
# ---------------------------------------------------------------------------

SNAP_RESOLVED = (
    "<NETWORK><DEVICES>"
    "<DEVICE><ENGINE><NAME>R1</NAME><LINE>hostname R1</LINE></ENGINE></DEVICE>"
    "<DEVICE><ENGINE><NAME>SW1</NAME><LINE>hostname SW1</LINE></ENGINE></DEVICE>"
    "</DEVICES></NETWORK>"
)
SNAP_TEMPLATED = (
    "<NETWORK><DEVICES>"
    "<DEVICE><ENGINE><NAME>[[pr3-rt_Display_name]]</NAME>"
    "<LINE>hostname Router</LINE></ENGINE></DEVICE>"
    "<DEVICE><ENGINE><NAME>[[pr3-0-sw_Display_name]]</NAME></ENGINE></DEVICE>"
    "<DEVICE><ENGINE><NAME>[[pr3-0-pc_Display_name]]</NAME></ENGINE></DEVICE>"
    "</DEVICES></NETWORK>"
)


def test_template_snapshot_is_demoted_even_when_larger():
    """3 templated devices vs 2 resolved: device count must NOT decide."""
    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{SNAP_RESOLVED}</PACKETTRACER5>"
        f"<PACKETTRACER5>{SNAP_TEMPLATED}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.snapshot_id == "block0"
    assert sel.reason == "template-demoted"
    assert not sel.abstained
    assert "[[pr3-rt_Display_name]]" not in (sel.xml_text or "")


def test_two_differing_resolved_snapshots_abstain():
    other = (
        "<NETWORK><DEVICES>"
        "<DEVICE><ENGINE><NAME>R9</NAME><LINE>hostname R9</LINE></ENGINE></DEVICE>"
        "</DEVICES></NETWORK>"
    )
    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{SNAP_RESOLVED}</PACKETTRACER5>"
        f"<PACKETTRACER5>{other}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.abstained is True
    assert sel.snapshot_id == "abstain"
    assert "abstaining" in " ".join(sel.notes)


def test_single_resolved_snapshot_is_selected():
    xml = f"<ROOT><PACKETTRACER5>{SNAP_RESOLVED}</PACKETTRACER5></ROOT>"
    sel = select_snapshot(xml)
    assert sel.snapshot_id == "block0"
    assert sel.reason == "single"


def test_reference_wrapper_block_never_selected():
    xml = (
        "<ROOT>"
        f"<COMPARISONS><PACKETTRACER5>{SNAP_TEMPLATED}</PACKETTRACER5></COMPARISONS>"
        f"<PACKETTRACER5>{SNAP_RESOLVED}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.snapshot_id == "block1"
    assert "COMPARISONS" in " ".join(sel.notes)


# --- majority agreement between snapshots ---------------------------------

def _net(device_names: list[str], ip: str = "10.0.0.1") -> str:
    devices = "".join(
        f"<DEVICE><ENGINE><NAME>{n}</NAME><RUNNINGCONFIG>"
        f"<LINE>hostname {n}</LINE>"
        f"<LINE>interface GigabitEthernet0/0</LINE>"
        f"<LINE>ip address {ip} 255.255.255.0</LINE>"
        "</RUNNINGCONFIG></ENGINE></DEVICE>"
        for n in device_names
    )
    return f"<NETWORK><DEVICES>{devices}</DEVICES></NETWORK>"


def test_majority_agreement_selects_consistent_snapshot():
    """0 and 1 are the same network; 2 is a later state. Not selected by size."""
    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{_net(['R1','SW1'])}</PACKETTRACER5>"
        f"<PACKETTRACER5>{_net(['R1','SW1'])}</PACKETTRACER5>"
        f"<PACKETTRACER5>{_net(['R1','SW1'], '172.16.0.1')}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.snapshot_id == "block0"
    assert sel.reason == "majority-agreement"
    assert not sel.abstained
    assert "172.16.0.1" not in (sel.xml_text or "")


def test_no_majority_still_abstains():
    """Three snapshots all different: no evidence which is intended."""
    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{_net(['A'], '10.0.0.1')}</PACKETTRACER5>"
        f"<PACKETTRACER5>{_net(['B'], '10.0.0.2')}</PACKETTRACER5>"
        f"<PACKETTRACER5>{_net(['C'], '10.0.0.3')}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    assert sel.abstained is True
    assert sel.snapshot_id == "abstain"


def test_volatile_memory_addresses_do_not_break_majority():
    """Two snapshots differing only in MEM_ADDR are the same network."""
    base = _net(["R1", "SW1"])
    other = base.replace(
        "<DEVICES>",
        "<DEVICES><VOLATILE_DEVICE><MEM_ADDR>123456</MEM_ADDR>"
        "<DEV_ADDR>7890</DEV_ADDR></VOLATILE_DEVICE>",
    )
    third = _net(["R1", "SW1"], "192.168.55.1")
    xml = (
        "<ROOT>"
        f"<PACKETTRACER5>{base}</PACKETTRACER5>"
        f"<PACKETTRACER5>{other}</PACKETTRACER5>"
        f"<PACKETTRACER5>{third}</PACKETTRACER5>"
        "</ROOT>"
    )
    sel = select_snapshot(xml)
    # VOLATILE_DEVICE has no <NAME>, so it contributes no fingerprint part
    assert sel.reason == "majority-agreement"
    assert sel.snapshot_id == "block0"


# --- hostname questions ----------------------------------------------------

def test_hostname_question_resolves_three_engine_value():
    from conftest import build_model, obs

    from trident.models import ParsedQuestion, QuestionKind, QuestionOption

    model = build_model(
        [
            obs("device", "R1", "hostname", "edge-router-1", e)
            for e in ("engine_a", "engine_b", "engine_c")
        ]
    )
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    question = ParsedQuestion(
        question_number=1,
        original="hostname?",
        stem="What is the hostname of R1?",
        kind=QuestionKind.SINGLE_SELECT,
        options=[QuestionOption(letter="A", text="edge-router-1")],
    )
    result = builder.build(question, None)
    assert result.status is AnswerStatus.VERIFIED
    assert result.selected_options == ["A"]
    assert result.consensus.agree == 3



# ---------------------------------------------------------------------------
# Single-source evidence must not be labelled "derived"
# ---------------------------------------------------------------------------

def _model_with_gateway() -> NetworkModel:
    model = NetworkModel(
        devices={"PC-A": DeviceInfo(id="PC-A", name="PC-A", hostname="PC-A")},
        snapshot_id="block0",
    )
    model.settings.default_gateways["PC-A"] = "192.168.1.254"
    return model


def test_single_source_gateway_is_incomplete_not_derived():
    from trident.reasoning.ai_client import QueryPlan, QueryStep

    model = _model_with_gateway()
    builder = AnswerBuilder(model, ConsensusEngine(model, Settings()))
    plan = QueryPlan(
        question_number=1,
        steps=[QueryStep(op="default_gateway", device="PC-A", reason="gateway")],
    )
    from trident.models import ParsedQuestion, QuestionKind, QuestionOption

    question = ParsedQuestion(
        question_number=1,
        original="gateway?",
        stem="What is the default gateway of PC-A?",
        kind=QuestionKind.SINGLE_SELECT,
        options=[QuestionOption(letter="A", text="192.168.1.254")],
    )
    result = builder.build(question, plan)
    # A single-source switch setting must never be presented as verified.
    assert result.status is AnswerStatus.INCOMPLETE
    assert result.status is not AnswerStatus.VERIFIED_DERIVED
    assert result.consensus.agree < result.consensus.required


# ---------------------------------------------------------------------------
# AI batching
# ---------------------------------------------------------------------------

def _questions(n: int) -> list[dict]:
    return [{"question_number": i, "text": f"question {i}", "options": [], "kind": "FACTUAL"}
            for i in range(1, n + 1)]


def _fake_provider(monkeypatch, calls: list[int], batch_size_seen=None):
    class FakeResponse:
        status_code = 200

        def __init__(self, content):
            self._content = content

        def json(self):
            return {
                "choices": [
                    {"message": {"content": self._content}, "finish_reason": "stop"}
                ]
            }

    async def fake_post(self, url, headers=None, json=None):
        payload = json["messages"][1]["content"]
        nums = [
            int(n)
            for n in __import__("re").findall(r'"question_number":\s*(\d+)', payload)
        ]
        calls.append(len(nums))
        if batch_size_seen is not None:
            batch_size_seen.append(len(nums))
        plans = [{"question_number": n, "kind": "FACTUAL", "steps": []} for n in nums]
        import json as _json

        return FakeResponse(_json.dumps({"plans": plans}))

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


def test_ai_batches_large_question_sets(monkeypatch):
    calls: list[int] = []
    _fake_provider(monkeypatch, calls)
    client = AIClient(Settings(ai_api_key="k", ai_model="m", ai_batch_size=12))
    plans = asyncio.run(client.plan_questions({}, _questions(65)))
    assert len(plans) == 65
    assert sum(calls) == 65
    assert len(calls) == 6  # 12*5 + 5
    assert all(c <= 12 for c in calls)


def test_ai_batch_sizes_10_25_65_100(monkeypatch):
    for total, expected_calls in ((10, 1), (25, 3), (65, 6), (100, 9)):
        calls: list[int] = []
        _fake_provider(monkeypatch, calls)
        client = AIClient(Settings(ai_api_key="k", ai_model="m", ai_batch_size=12))
        plans = asyncio.run(client.plan_questions({}, _questions(total)))
        assert len(plans) == total, f"{total}: dropped questions"
        assert [p.question_number for p in plans] == list(range(1, total + 1))
        assert len(calls) == expected_calls


def test_ai_ignores_plans_for_questions_not_asked(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {"plans": [
                                    {"question_number": 1, "steps": []},
                                    {"question_number": 999, "steps": []},
                                ]}
                            )
                        },
                        "finish_reason": "stop",
                    }
                ]
            }

    async def fake_post(self, *_a, **_k):
        return FakeResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = AIClient(Settings(ai_api_key="k", ai_model="m"))
    plans = asyncio.run(client.plan_questions({}, _questions(1)))
    assert [p.question_number for p in plans] == [1]


def test_ai_truncated_response_is_an_error(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": '{"plans": [{"question_num'}, "finish_reason": "length"}]}

    async def fake_post(self, *_a, **_k):
        return FakeResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = AIClient(Settings(ai_api_key="k", ai_model="m"))
    with pytest.raises(AIClientError) as excinfo:
        asyncio.run(client.plan_questions({}, _questions(3)))
    assert "truncated" in str(excinfo.value).lower()


def test_ai_partial_batch_failure_keeps_other_batches(monkeypatch):
    state = {"n": 0}

    class Ok:
        status_code = 200

        def json(self):
            return {
                "choices": [
                    {
                        "message": {"content": json.dumps({"plans": [
                            {"question_number": 13, "steps": []}]})},
                        "finish_reason": "stop",
                    }
                ]
            }

    class Bad:
        status_code = 500
        text = "server error"

        def json(self):
            return {}

    async def fake_post(self, url, headers=None, json=None):
        state["n"] += 1
        return Ok() if state["n"] == 2 else Bad()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = AIClient(Settings(ai_api_key="k", ai_model="m", ai_batch_size=12))
    plans = asyncio.run(client.plan_questions({}, _questions(24)))
    assert client.last_batch_errors, "batch errors must be recorded"
    assert [p.question_number for p in plans] == [13]


# ---------------------------------------------------------------------------
# Digest redaction
# ---------------------------------------------------------------------------

def test_digest_never_includes_raw_config_or_secrets():
    model = NetworkModel(
        devices={
            "R1": DeviceInfo(
                id="R1",
                name="R1",
                hostname="R1",
                configuration=["enable secret 5 $1$SECRET", "username admin secret 5 $1$X"],
            )
        }
    )
    blob = json.dumps(build_digest(model))
    assert "$1$SECRET" not in blob
    assert "enable secret" not in blob


# ---------------------------------------------------------------------------
# Engine B config filename sanitisation
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Engine A must use RUNNINGCONFIG, not RUNNINGCONFIG + STARTUPCONFIG
# ---------------------------------------------------------------------------


def test_engine_a_config_uses_running_not_startup():
    """Startup config is the saved old state; merging it corrupts interfaces."""
    from trident.parsers.pka_xml import _walk_xml

    engine = (
        "<ENGINE><NAME>R1</NAME>"
        "<RUNNINGCONFIG>"
        "<LINE>hostname RunningName</LINE>"
        "<LINE>interface GigabitEthernet0/0</LINE>"
        "<LINE>ip address 10.0.0.1 255.255.255.0</LINE>"
        "</RUNNINGCONFIG>"
        "<STARTUPCONFIG>"
        "<LINE>hostname StartupName</LINE>"
        "<LINE>interface GigabitEthernet0/0</LINE>"
        "<LINE>ip address 172.16.0.1 255.255.255.0</LINE>"
        "</STARTUPCONFIG>"
        "</ENGINE>"
    )
    walk = _walk_xml(f"<ROOT><DEVICE>{engine}</DEVICE></ROOT>")
    lines = walk["configs"]["R1"]
    joined = "\n".join(lines)

    assert "hostname RunningName" in joined
    assert "10.0.0.1" in joined
    # startup values must not leak in
    assert "StartupName" not in joined
    assert "172.16.0.1" not in joined


def test_engine_a_falls_back_to_startup_when_no_running_config():
    from trident.parsers.pka_xml import _walk_xml

    engine = (
        "<ENGINE><NAME>SW1</NAME>"
        "<STARTUPCONFIG><LINE>hostname OnlyStartup</LINE></STARTUPCONFIG>"
        "</ENGINE>"
    )
    walk = _walk_xml(f"<ROOT><DEVICE>{engine}</DEVICE></ROOT>")
    assert walk["configs"]["SW1"] == ["hostname OnlyStartup"]


def test_engine_b_slug_matches_pkt_core_filenames():
    """pkt-core sanitises device names into .cfg filenames; matching must survive."""
    from trident.parsers.pkt_core import _slug

    assert _slug("Hub Switch 1 (Our Trusty Sidekick)") == "Hub_Switch_1__Our_Trusty_Sidekick"
    assert _slug("R1") == "R1"
    assert _slug("[[pr3-rt_Display_name]]") == "pr3_rt_Display_name"
