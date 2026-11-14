"""A graduated practice gauntlet: six labs from easy to insane.

Every lab is built from the **15 faults that were independently verified
observable in Packet Tracer 9.0.1** (see `tests/test_labgen_live.py`). That is a
deliberate constraint: a gauntlet whose hard labs contain faults nobody has ever
seen in the simulator is a difficulty ramp made of guesses.

What changes between difficulties is not the fault vocabulary but three real
things:

* **how many faults** are present (4 → 16),
* **which faults** — easy labs use only unambiguous, single-command faults;
  hard labs add ones that require correlating two outputs,
* **point weighting** — the same fault is worth more when it is one of four than
  when it is one of sixteen.

Points are rescaled to exactly 100 per lab by :func:`rebalance`, so a score is
comparable across difficulties without any percentage arithmetic at the call
site.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from .broken_campus import TOPOLOGY as _BASE
from .spec import FaultSpec, TopologySpec

#: Difficulty order, easiest first.
DIFFICULTIES = ("easy", "basic", "intermediate", "advanced", "expert", "insane")

#: Faults in increasing order of how much work they take to find.
#:
#: * ``TRIVIAL`` — one `show` command shows it outright (a shut port, a missing
#:   enable secret).
#: * ``EASY`` — one command, but you must know what to compare against.
#: * ``MEDIUM`` — two facts must be related (a port's VLAN vs the subnet of the
#:   host on it).
#: * ``HARD`` — needs a consequence traced back to its cause.
TRIVIAL = (
    "iface-admin-port-shutdown",
    "sec-enable-secret-missing",
)
EASY = (
    "addr-mask-admin-pc",
    "gw-faculty-pc-wrong",
    "sec-ssh-no-local-user",
    "dhcp-excluded-missing",
)
MEDIUM = (
    "vlan-students-port-wrong",
    "vlan-faculty-port-wrong",
    "vlan-missing-on-dist",
    "dhcp-pool-wrong-network",
    "dhcp-pool-missing-dns",
)
HARD = (
    "trunk-native-mismatch",
    "trunk-vlan-list-missing",
    "route-default-wrong-next-hop",
    "addr-router-subif-wrong",
)

#: Which fault ids each difficulty contains, in increasing order.
LAB_FAULTS: dict[str, tuple[str, ...]] = {
    "easy": TRIVIAL + EASY[:2],
    "basic": TRIVIAL + EASY,
    "intermediate": TRIVIAL + EASY + MEDIUM[:2],
    "advanced": TRIVIAL + EASY + MEDIUM,
    "expert": TRIVIAL + EASY + MEDIUM + HARD[:2],
    "insane": TRIVIAL + EASY + MEDIUM + HARD,
}


def rebalance(faults: list[FaultSpec]) -> list[FaultSpec]:
    """Rescale a fault set so the points total exactly 100.

    Largest-remainder, so the weights stay proportional and the total is exact.
    Hand-writing 100-point splits for six labs invites a 99 or a 101, and
    `TopologySpec.validate()` would then refuse to build the lab at all.
    """
    total = sum(f.points for f in faults)
    if not faults:
        return []
    if total == 100:
        return list(faults)

    scaled = [f.points * 100 / total for f in faults]
    floors = [int(value) for value in scaled]
    remainder = 100 - sum(floors)
    # Hand out the leftover points to the largest fractional parts.
    order = sorted(
        range(len(faults)), key=lambda i: (scaled[i] - floors[i]), reverse=True
    )
    for i in order[:remainder]:
        floors[i] += 1
    # A fault worth 0 points cannot be scored; nudge from the largest.
    for i, points in enumerate(floors):
        if points == 0:
            richest = max(range(len(floors)), key=lambda j: floors[j])
            if floors[richest] > 1:
                floors[richest] -= 1
                floors[i] = 1
    return [dataclasses.replace(f, points=points) for f, points in zip(faults, floors)]


def lab_for(difficulty: str) -> TopologySpec:
    """Build one gauntlet lab. Raises ``KeyError`` on an unknown difficulty."""
    if difficulty not in LAB_FAULTS:
        raise KeyError(
            f"unknown difficulty {difficulty!r}; choose from {', '.join(DIFFICULTIES)}"
        )
    wanted = LAB_FAULTS[difficulty]
    by_id = {f.fault_id: f for f in _BASE.faults}
    missing = [f for f in wanted if f not in by_id]
    if missing:
        raise RuntimeError(f"gauntlet references unknown faults: {missing}")

    selected = [by_id[fault_id] for fault_id in wanted]
    rebalanced = rebalance(selected)
    return dataclasses.replace(
        _BASE,
        name=f"gauntlet-{difficulty}",
        title=f"Gauntlet — {difficulty.title()}",
        faults=rebalanced,
        difficulty=_DIFFICULTY_WORD[difficulty],
    )


#: ``TopologySpec.difficulty`` only accepts three words; map onto them.
_DIFFICULTY_WORD = {
    "easy": "beginner",
    "basic": "beginner",
    "intermediate": "intermediate",
    "advanced": "intermediate",
    "expert": "advanced",
    "insane": "advanced",
}


def all_labs() -> dict[str, TopologySpec]:
    return {name: lab_for(name) for name in DIFFICULTIES}


@dataclass(frozen=True)
class LabProbe:
    """How a fault in a given lab is observed on a real device."""

    fault_id: str
    device: str
    command: str
    expect_present: bool


def probes_for(difficulty: str) -> list[LabProbe]:
    """The read-only probe for every fault in a lab.

    Only commands that Packet Tracer 9.0.1 actually answers are used, and
    end-host faults are excluded because a PC rejects ``enterCommand`` on that
    build. That is a documented limitation, not an oversight.
    """
    lab = lab_for(difficulty)
    probes: list[LabProbe] = []
    for fault in lab.faults:
        probe = _PROBE_TABLE.get(fault.fault_id)
        if probe is None:
            # ENDHOST faults have no CLI probe on PT 9.0.1.
            continue
        device, command, expect_present = probe
        probes.append(LabProbe(fault.fault_id, device, command, expect_present))
    return probes


#: (device, read-only command, expect the fault text to be PRESENT).
#: Verified against a live simulator for the base lab.
_PROBE_TABLE: dict[str, tuple[str, str, bool]] = {
    "iface-admin-port-shutdown": ("SW-DIST", "show interfaces status", True),
    "sec-enable-secret-missing": ("SW-ACCESS", "show running-config", False),
    "addr-mask-admin-pc": ("PC-ADMIN-1", "ipconfig", True),
    "gw-faculty-pc-wrong": ("PC-FACULTY-1", "ipconfig", True),
    "sec-ssh-no-local-user": ("R1", "show running-config", False),
    "dhcp-excluded-missing": ("R1", "show running-config", False),
    "vlan-students-port-wrong": ("SW-ACCESS", "show vlan brief", True),
    "vlan-faculty-port-wrong": ("SW-ACCESS", "show vlan brief", True),
    "vlan-missing-on-dist": ("SW-DIST", "show vlan brief", False),
    "dhcp-pool-wrong-network": ("R1", "show running-config", True),
    "dhcp-pool-missing-dns": ("R1", "show running-config", False),
    "trunk-native-mismatch": ("SW-ACCESS", "show interfaces trunk", True),
    "trunk-vlan-list-missing": ("SW-DIST", "show interfaces trunk", False),
    "route-default-wrong-next-hop": ("R1", "show running-config", True),
    "addr-router-subif-wrong": ("R1", "show running-config", True),
}


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------


@dataclass
class Metrics:
    """Detection quality for one lab. Every rate carries its numerator."""

    lab: str
    difficulty: str
    faults: int
    true_positives: int
    false_positives: int
    false_negatives: int
    unsupported: int = 0

    @property
    def precision(self) -> tuple[int, int]:
        denominator = self.true_positives + self.false_positives
        return self.true_positives, denominator

    @property
    def recall(self) -> tuple[int, int]:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives, denominator

    @property
    def precision_pct(self) -> float | None:
        num, den = self.precision
        return round(100 * num / den, 1) if den else None

    @property
    def recall_pct(self) -> float | None:
        num, den = self.recall
        return round(100 * num / den, 1) if den else None

    def row(self) -> str:
        """A markdown row. A rate without its fraction is never printed alone."""
        p_num, p_den = self.precision
        r_num, r_den = self.recall
        p = f"{self.precision_pct}% ({p_num}/{p_den})" if p_den else "n/a (0/0)"
        r = f"{self.recall_pct}% ({r_num}/{r_den})" if r_den else "n/a (0/0)"
        return (
            f"| {self.lab} | {self.faults} | {self.true_positives} | "
            f"{self.false_positives} | {self.false_negatives} | {p} | {r} |"
        )


def score_findings(
    lab: TopologySpec, claimed_fault_ids: set[str]
) -> Metrics:
    """Score a set of claimed fault ids against a lab's manifest.

    This is the offline harness: it measures the *matcher*, not the detectors.
    It is used to prove the scoring arithmetic, while the real detection numbers
    come from :mod:`trident.gauntlet_bench`, which runs the actual engine.
    """
    real = {f.fault_id for f in lab.faults}
    tp = len(claimed_fault_ids & real)
    fp = len(claimed_fault_ids - real)
    fn = len(real - claimed_fault_ids)
    return Metrics(lab.name, lab.difficulty, len(real), tp, fp, fn)
