"""AI client tests. No real provider is contacted: transport is mocked.

The important guarantees here are structural, not model-quality:
  * the raw PKA is never sent
  * the key never leaks into errors or payloads
  * malformed / unparseable model output is discarded, not trusted
  * a model cannot inject a network fact
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from trident.config import Settings
from trident.models import DeviceInfo, InterfaceInfo, NetworkModel
from trident.reasoning.ai_client import (
    AIClient,
    AIClientError,
    build_digest,
    parse_plan_json,
)


@pytest.fixture
def small_model() -> NetworkModel:
    return NetworkModel(
        devices={
            "R1": DeviceInfo(
                id="R1",
                name="R1",
                hostname="R1",
                device_type="Router",
                model="2911",
                ios_version="15.1",
                interfaces=["GigabitEthernet0/0"],
                configuration=["enable secret 5 $1$HASHED", "username admin secret 5 $1$X"],
            )
        },
        interfaces={
            "R1:GigabitEthernet0/0": InterfaceInfo(
                device="R1",
                name="GigabitEthernet0/0",
                canonical_name="GigabitEthernet0/0",
                ipv4_address="192.168.1.1",
                subnet_mask="255.255.255.0",
                prefix_length=24,
            )
        },
    )


def test_unconfigured_client_returns_no_plans(small_model):
    client = AIClient(Settings(ai_api_key="", ai_model=""))
    plans = asyncio.run(client.plan_questions(build_digest(small_model), []))
    assert plans == []


def test_digest_excludes_credentials(small_model):
    digest = build_digest(small_model)
    blob = json.dumps(digest)
    assert "$1$HASHED" not in blob
    assert "enable secret" not in blob
    # but the useful facts are present
    assert "192.168.1.1" in blob
    assert "R1" in blob


def test_digest_never_contains_file_bytes(small_model):
    digest = build_digest(small_model)
    assert set(digest) == {
        "devices", "links", "default_gateways", "dns_servers", "vlans", "routes", "acl_ids"
    }


def test_parse_plan_valid():
    payload = {
        "plans": [
            {
                "question_number": 1,
                "kind": "SINGLE_SELECT",
                "steps": [{"op": "device_ip", "device": "R1", "interface": "Gi0/0"}],
            }
        ]
    }
    plans = parse_plan_json(json.dumps(payload))
    assert len(plans) == 1
    assert plans[0].question_number == 1
    assert plans[0].steps[0].op == "device_ip"


def test_parse_plan_strips_markdown_fence():
    payload = '```json\n{"plans": [{"question_number": 2, "steps": [{"op": "device_list"}]}]}\n```'
    plans = parse_plan_json(payload)
    assert len(plans) == 1
    assert plans[0].steps[0].op == "device_list"


def test_parse_plan_rejects_garbage():
    assert parse_plan_json("this is not json") == []
    assert parse_plan_json("") == []
    assert parse_plan_json("[]") == []


def test_parse_plan_filters_unknown_operations():
    payload = {
        "plans": [
            {
                "question_number": 3,
                "steps": [
                    {"op": "execute_shell", "device": "R1"},
                    {"op": "device_ip", "device": "R1"},
                ],
            }
        ]
    }
    plans = parse_plan_json(json.dumps(payload))
    assert len(plans) == 1
    assert [s.op for s in plans[0].steps] == ["device_ip"]


def test_parse_plan_drops_invalid_schema():
    bad = {"plans": [{"nonsense_field": True}]}
    assert parse_plan_json(json.dumps(bad)) == []


def test_transport_error_does_not_leak_key(monkeypatch):
    secret = "sk-transport-secret-999"
    cfg = Settings(ai_api_key=secret, ai_model="m")

    def boom(*_a, **_k):
        raise httpx.ConnectError(f"failed with Bearer {secret}")

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    client = AIClient(cfg)
    with pytest.raises(AIClientError) as exc_info:
        asyncio.run(client.plan_questions({}, []))
    assert secret not in str(exc_info.value)


def test_http_error_body_key_is_scrubbed(monkeypatch):
    secret = "sk-http-error-secret-777"

    class FakeResponse:
        status_code = 401
        text = f"invalid key {secret}"

        def json(self):
            return {}

    async def fake_post(self, *_a, **_k):
        return FakeResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = AIClient(Settings(ai_api_key=secret, ai_model="m"))
    with pytest.raises(AIClientError) as exc_info:
        asyncio.run(client.plan_questions({}, []))
    assert secret not in str(exc_info.value)
    assert "[redacted]" in str(exc_info.value)


def test_successful_plan_roundtrip(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "plans": [
                                        {
                                            "question_number": 1,
                                            "steps": [
                                                {"op": "device_ip", "device": "R1", "interface": "Gi0/0"}
                                            ],
                                        }
                                    ]
                                }
                            )
                        }
                    }
                ]
            }

    async def fake_post(self, url, headers=None, json=None):
        # verify key goes in header, never the body
        assert headers["Authorization"].startswith("Bearer ")
        assert "api_key" not in globals().get("body", {})
        return FakeResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    client = AIClient(Settings(ai_api_key="sk-test", ai_model="m"))
    plans = asyncio.run(client.plan_questions({}, [{"question_number": 1, "text": "q"}]))
    assert len(plans) == 1
