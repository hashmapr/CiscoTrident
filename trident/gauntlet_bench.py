"""Benchmark TRIDENT's diagnostic engine against the Broken Campus ground truth.

This is the measurement that matters, and it is deliberately conservative. A
finding only counts as a true positive when it names the *device* the fault
manifest names. Nothing is credited for a finding that is merely related.

The distinction between a root cause and its consequence is handled explicitly
rather than by fudging the numbers:

* A fault that produces findings on several devices is counted once.
* A finding on a device the manifest does not name is a **false positive**, even
  when the finding is factually true. `PC-FACULTY-2`'s gateway really is
  unreachable — because R1's Faculty subinterface carries the Students address —
  but `PC-FACULTY-2` is not a fault, and crediting it would inflate recall while
  hiding the fact that the detector found a symptom, not the cause.

Every number in the output carries its numerator and denominator.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from trident.config import settings
from trident.diagnostics import diagnose
from trident.ingestion import ingest
from trident.labgen import generate
from trident.labgen.broken_campus import TOPOLOGY
from trident.labgen.spec import FaultCategory
from trident.pipeline import analyze

#: Which detector kinds can legitimately explain which fault categories.
#: A finding of the wrong kind for a category is not a match, even if it is on
#: the right device: `SHUTDOWN_INTERFACE` on SW-DIST does not explain a VLAN
#: fault there.
KIND_FOR_CATEGORY: dict[FaultCategory, set[str]] = {
    FaultCategory.ADDRESSING: {"DUPLICATE_IP", "INVALID_MASK", "OVERLAPPING_SUBNET"},
    FaultCategory.VLAN: {"WRONG_VLAN"},
    FaultCategory.TRUNK: {"TRUNK_MISMATCH"},
    FaultCategory.ROUTING: {
        "MISSING_STATIC_ROUTE",
        "ROUTING_LOOP",
        "UNREACHABLE_NEXT_HOP",
    },
    FaultCategory.GATEWAY: {"WRONG_GATEWAY"},
    FaultCategory.DHCP: {
        "DHCP_MISCONFIGURATION",
        "DHCP_POOL_NETWORK",
        "UNRESERVED_GATEWAY",
        "DHCP_POOL_DNS",
    },
    FaultCategory.DNS: {"DHCP_MISCONFIGURATION", "DHCP_POOL_DNS", "DNS_MISCONFIGURATION"},
    FaultCategory.INTERFACE: {"SHUTDOWN_INTERFACE"},
    FaultCategory.SECURITY: {"WEAK_MANAGEMENT", "SECURITY_MISCONFIGURATION"},
    FaultCategory.ACCESS: {"ACL_BLOCK"},
}


@dataclass
class FaultResult:
    fault_id: str
    category: str
    device: str
    interface: str | None
    points: int
    detected: bool
    matched_kind: str | None = None
    matched_device: str | None = None
    reason: str = ""


@dataclass
class Benchmark:
    lab: str
    difficulty: str
    fault_results: list[FaultResult] = field(default_factory=list)
    detections: list[dict] = field(default_factory=list)

    @property
    def tp(self) -> int:
        return sum(1 for f in self.fault_results if f.detected)

    @property
    def fn(self) -> int:
        return sum(1 for f in self.fault_results if not f.detected)

    @property
    def fp(self) -> int:
        """Detections that did not correspond to any manifest fault.

        A detection is a false positive when the device it names has no fault of
        a category the detector kind can explain.
        """
        explained = {
            (f.matched_device, f.matched_kind)
            for f in self.fault_results
            if f.detected
        }
        count = 0
        for det in self.detections:
            key = (det.get("device"), det.get("kind"))
            if key not in explained:
                count += 1
        return count

    @property
    def precision(self) -> tuple[int, int]:
        tp, fp = self.tp, self.fp
        return tp, tp + fp

    @property
    def recall(self) -> tuple[int, int]:
        tp, fn = self.tp, self.fn
        return tp, tp + fn

    def as_dict(self) -> dict:
        tp, tp_fp = self.precision
        rtp, tp_fn = self.recall
        return {
            "lab": self.lab,
            "difficulty": self.difficulty,
            "faults_total": len(self.fault_results),
            "true_positives": tp,
            "false_negatives": self.fn,
            "false_positives": self.fp,
            "precision": f"{tp}/{tp_fp}" if tp_fp else "0/0",
            "precision_pct": round(100 * tp / tp_fp, 1) if tp_fp else None,
            "recall": f"{rtp}/{tp_fn}" if tp_fn else "0/0",
            "recall_pct": round(100 * rtp / tp_fn, 1) if tp_fn else None,
            "detections": len(self.detections),
            "per_fault": [f.__dict__ for f in self.fault_results],
        }


#: The detector that must fire for each fault id. Declared per fault rather than
#: per category, because a category-level rule let DHCP_POOL_DNS claim all three
#: DHCP faults at once -- inflating recall with one finding.
EXACT_DETECTOR: dict[str, str] = {
    "addr-router-subif-wrong": "DUPLICATE_IP",
    "addr-mask-admin-pc": "INVALID_MASK",
    "vlan-students-port-wrong": "WRONG_VLAN",
    "vlan-faculty-port-wrong": "WRONG_VLAN",
    "vlan-missing-on-dist": "WRONG_VLAN",
    "trunk-native-mismatch": "TRUNK_MISMATCH",
    "trunk-vlan-list-missing": "TRUNK_MISMATCH",
    "route-default-wrong-next-hop": "UNREACHABLE_NEXT_HOP",
    "gw-faculty-pc-wrong": "WRONG_GATEWAY",
    "dhcp-pool-wrong-network": "DHCP_POOL_NETWORK",
    "dhcp-excluded-missing": "UNRESERVED_GATEWAY",
    "dhcp-pool-missing-dns": "DHCP_POOL_DNS",
    "iface-admin-port-shutdown": "SHUTDOWN_INTERFACE",
    "sec-ssh-no-local-user": "WEAK_MANAGEMENT",
    "sec-enable-secret-missing": "WEAK_MANAGEMENT",
}


def _match(fault, detections: list[dict]) -> tuple[str, str] | None:
    """Find a detection that genuinely explains ``fault``.

    Matching is strict: same device, and a detector kind that can explain the
    fault's category. A detector firing on the right device for an unrelated
    reason is not evidence about this fault.
    """
    exact = EXACT_DETECTOR.get(fault.fault_id)
    allowed = {exact} if exact else KIND_FOR_CATEGORY.get(fault.category, set())
    for det in detections:
        if det.get("device") != fault.device:
            continue
        if det.get("kind") not in allowed:
            continue
        # If the fault names an interface, the finding must name it too — unless
        # the detector is device-scoped by nature (a duplicate IP is reported on
        # the subinterface carrying the address).
        want = (fault.interface or "").strip().lower()
        got = (det.get("interface") or "").strip().lower()
        if want and got and want != got:
            continue
        return det["kind"], det["device"]
    return None


def run_benchmark(lab_spec=TOPOLOGY, *, verbose: bool = True) -> Benchmark:
    tmp = Path(tempfile.mkdtemp())
    generated = generate(lab_spec, tmp / "lab.pkt", apply_faults=True)
    if not generated.encode_ok:
        raise RuntimeError(f"generation failed: {generated.notes}")

    outcome = asyncio.run(
        analyze(
            ingest("lab.pkt", generated.path.read_bytes()),
            "1. What is the hostname of R1?",
            cfg=settings,
            use_ai=False,
        )
    )
    diagnosis = diagnose(outcome.model)
    detections = diagnosis.to_report_dicts()

    bench = Benchmark(lab=lab_spec.name, difficulty=lab_spec.difficulty,
                      detections=detections)
    for fault in lab_spec.faults:
        match = _match(fault, detections)
        bench.fault_results.append(
            FaultResult(
                fault_id=fault.fault_id,
                category=fault.category.value,
                device=fault.device,
                interface=fault.interface,
                points=fault.points,
                detected=match is not None,
                matched_kind=match[0] if match else None,
                matched_device=match[1] if match else None,
                reason="" if match else _why_not(fault, detections),
            )
        )

    if verbose:
        print(f"\n=== {lab_spec.name} ({lab_spec.difficulty}) ===")
        print(f"model devices: {len(outcome.model.devices)} "
              f"interfaces: {len(outcome.model.interfaces)} "
              f"observations: {len(outcome.model.observations)}")
        print(f"detections: {len(detections)}")
        for det in detections:
            print(f"    {det['kind']:24s} {str(det.get('device')):14s} "
                  f"{str(det.get('interface')):22s} {det['status']}")
        print("\nper-fault:")
        for fr in bench.fault_results:
            mark = "HIT " if fr.detected else "miss"
            extra = f" <- {fr.matched_kind}" if fr.detected else f"  ({fr.reason})"
            print(f"  {mark} {fr.fault_id:34s} {fr.category:10s} {fr.device:14s}{extra}")
        d = bench.as_dict()
        print(f"\nrecall    {d['recall']} = {d['recall_pct']}%")
        print(f"precision {d['precision']} = {d['precision_pct']}%")
        print(f"false positives: {d['false_positives']}")
    return bench


def _why_not(fault, detections: list[dict]) -> str:
    """A specific reason, so a miss is diagnosable rather than mysterious."""
    on_device = [d for d in detections if d.get("device") == fault.device]
    if not on_device:
        return "nothing detected on this device"
    kinds = {d["kind"] for d in on_device}
    allowed = KIND_FOR_CATEGORY.get(fault.category, set())
    if kinds & allowed:
        return "detector fired but interface did not match"
    return f"only unrelated kinds: {sorted(kinds)}"


if __name__ == "__main__":
    bench = run_benchmark()
    sys.exit(0 if bench.tp else 1)
