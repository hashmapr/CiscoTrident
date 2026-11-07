"""OpenAI-compatible AI client for *interpretation only*.

Hard boundaries enforced here:

* The API key is read from settings and placed in an Authorization header. It is
  never logged, never returned, never included in an exception message.
* The raw PKA file is never sent. Only a compact, redacted network digest plus the
  question text leaves the machine.
* The model returns a *query plan* validated by Pydantic. The model never returns
  a network fact that TRIDENT accepts directly — every fact in a final answer must
  come from the deterministic engine.
"""

from __future__ import annotations

import json
import re

import httpx
from pydantic import BaseModel, Field, ValidationError

from ..config import Settings

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------

class QueryStep(BaseModel):
    """One deterministic operation the model wants executed."""

    op: str = Field(
        description=(
            "Operation name. One of: device_ip, interface_info, default_gateway, dns_servers, "
            "ios_version, vlan_of_interface, vlan_members, subnet_network, subnet_broadcast, "
            "same_subnet, connected_devices, topology_path, route_lookup, acl_lookup, "
            "switchport_mode, device_interfaces, device_list, unknown"
        )
    )
    device: str | None = None
    interface: str | None = None
    peer: str | None = None
    ip: str | None = None
    other_ip: str | None = None
    mask: str | None = None
    vlan_id: int | None = None
    acl_id: str | None = None
    destination: str | None = None
    reason: str = ""


class QueryPlan(BaseModel):
    """The model's interpretation of one question."""

    question_number: int
    kind: str = "FACTUAL"
    steps: list[QueryStep] = Field(default_factory=list)
    comparison: str | None = Field(
        default=None,
        description="Optional expected value the model *believes* it remembers, used only for conflict detection",
    )
    claim_is_true: bool | None = Field(
        default=None, description="For true/false questions, the model's reading of the claim direction"
    )
    notes: str = ""


class PlanEnvelope(BaseModel):
    plans: list[QueryPlan] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a network-question interpreter for a deterministic analysis tool.

You do NOT answer questions. You convert each question into a list of deterministic
lookup operations that the tool will execute against a verified network model.

Rules:
- Never invent device names, interface names, IP addresses, VLANs or routes.
- Only use operations from the allowed list.
- If you cannot map a question to operations, return a single step with op="unknown".
- Do not state the answer. Do not include prose answers.
- For multiple-choice questions, map the question to the fact being asked; the tool
  performs option matching itself.
- Output ONLY JSON matching the schema. No markdown, no commentary.

Allowed operations and their required fields:
  device_ip                device, optional interface
  interface_info           device, interface
  default_gateway          device
  dns_servers              device
  ios_version              device
  vlan_of_interface        device, interface
  vlan_members             vlan_id
  subnet_network           ip, mask
  subnet_broadcast         ip, mask
  same_subnet              ip, other_ip, mask
  connected_devices        device
  topology_path            device, peer
  route_lookup             destination
  acl_lookup               acl_id
  switchport_mode          device, interface
  device_interfaces        device
  device_list              (no fields)
  unknown                  (no fields)
"""


def build_user_prompt(digest: dict, questions: list[dict]) -> str:
    payload = {
        "network_digest": digest,
        "questions": questions,
    }
    return (
        "Interpret every question below into lookup operations.\n"
        "Return JSON: {\"plans\": [{\"question_number\": int, \"kind\": str, \"steps\": [...]}]}\n\n"
        + json.dumps(payload, ensure_ascii=False)
    )


def build_digest(model, max_devices: int = 60) -> dict:
    """A minimal, redacted network digest. Never includes credentials or full configs."""
    devices = []
    for name in sorted(model.devices)[:max_devices]:
        dev = model.devices[name]
        ifaces = []
        for canon in dev.interfaces[:40]:
            iface = model.interfaces.get(f"{name}:{canon}")
            if iface is None:
                continue
            ifaces.append(
                {
                    "name": iface.canonical_name,
                    **({"ipv4": iface.ipv4_address} if iface.ipv4_address else {}),
                    **({"mask": iface.subnet_mask} if iface.subnet_mask else {}),
                    **({"vlan": iface.vlan_assignments} if iface.vlan_assignments else {}),
                    **({"mode": iface.access_mode} if iface.access_mode else {}),
                }
            )
        devices.append(
            {
                "name": name,
                **({"type": dev.device_type} if dev.device_type else {}),
                **({"model": dev.model} if dev.model else {}),
                **({"ios": dev.ios_version} if dev.ios_version else {}),
                "interfaces": ifaces,
            }
        )

    digest = {
        "devices": devices,
        "links": [
            {
                "a": l.device_a,
                "a_if": l.interface_a,
                "b": l.device_b,
                "b_if": l.interface_b,
            }
            for l in model.links[:120]
        ],
        "default_gateways": model.settings.default_gateways,
        "dns_servers": model.settings.dns_servers,
        "vlans": [{"id": v.vlan_id, "name": v.name} for v in model.vlans[:60]],
        "routes": [
            {
                "type": r.route_type,
                "destination": r.destination,
                **({"next_hop": r.next_hop} if r.next_hop else {}),
                **({"interface": r.outgoing_interface} if r.outgoing_interface else {}),
            }
            for r in model.routes[:60]
        ],
        "acl_ids": sorted({a.acl_id for a in model.acls})[:40],
    }
    return digest


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class AIClientError(RuntimeError):
    """Raised for provider/transport failures. Never contains the API key."""


class AIClient:
    def __init__(self, cfg: Settings) -> None:
        self.cfg = cfg

    @property
    def configured(self) -> bool:
        return self.cfg.ai_configured

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.cfg.ai_api_key}",
            "Content-Type": "application/json",
        }

    async def plan_questions(self, digest: dict, questions: list[dict]) -> list[QueryPlan]:
        """Ask the model for a query plan. Returns [] when unconfigured or unusable."""
        if not self.configured:
            return []

        url = self.cfg.ai_base_url.rstrip("/") + "/chat/completions"
        body = {
            "model": self.cfg.ai_model,
            "temperature": self.cfg.ai_temperature,
            "max_tokens": self.cfg.ai_max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(digest, questions)},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=self.cfg.ai_timeout) as client:
                response = await client.post(url, headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            # Deliberately do not echo headers/url with secrets.
            raise AIClientError(f"network error contacting AI provider: {type(exc).__name__}") from None

        if response.status_code >= 400:
            # Provider errors can echo the key in some proxies; scrub defensively.
            detail = _scrub(response.text[:300], self.cfg.ai_api_key)
            raise AIClientError(f"AI provider returned HTTP {response.status_code}: {detail}")

        try:
            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError, TypeError):
            raise AIClientError("AI provider returned an unexpected response shape") from None

        return parse_plan_json(content)


def _scrub(text: str, secret: str) -> str:
    if secret:
        text = text.replace(secret, "[redacted]")
    return text


def parse_plan_json(content: str) -> list[QueryPlan]:
    """Validate the model's JSON. Rejects anything that is not a proper plan."""
    text = (content or "").strip()
    if not text:
        return []
    # tolerate accidental fences
    fence = re.match(r"^```(?:json)?\s*(.*?)```$", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()

    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return []

    if isinstance(raw, list):
        raw = {"plans": raw}
    if not isinstance(raw, dict):
        return []

    try:
        envelope = PlanEnvelope.model_validate(raw)
    except ValidationError:
        return []

    # Filter out steps that reference operations we cannot execute.
    allowed = {
        "device_ip", "interface_info", "default_gateway", "dns_servers", "ios_version",
        "vlan_of_interface", "vlan_members", "subnet_network", "subnet_broadcast",
        "same_subnet", "connected_devices", "topology_path", "route_lookup",
        "acl_lookup", "switchport_mode", "device_interfaces", "device_list", "unknown",
    }
    cleaned: list[QueryPlan] = []
    for plan in envelope.plans:
        plan.steps = [s for s in plan.steps if s.op in allowed]
        cleaned.append(plan)
    return cleaned
