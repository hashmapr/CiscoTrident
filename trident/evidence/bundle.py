"""In-memory collection of CLI records grouped by device.

A bundle never merges two devices. Records whose device could not be determined
are held apart under :meth:`EvidenceBundle.unattributed` and are never returned
by a per-device query.
"""

from __future__ import annotations

from .types import CliRecord, EvidenceKind


class EvidenceBundle:
    """Holds records for one or more devices, keyed strictly by device name."""

    def __init__(self) -> None:
        self._by_device: dict[str, list[CliRecord]] = {}
        self._unattributed: list[CliRecord] = []

    # -- insertion ---------------------------------------------------------

    def add(self, record: CliRecord) -> None:
        if record.device is None:
            self._unattributed.append(record)
            return
        self._by_device.setdefault(record.device, []).append(record)

    # -- queries -----------------------------------------------------------

    def for_device(self, device: str) -> tuple[CliRecord, ...]:
        return tuple(self._by_device.get(device, ()))

    def by_kind(self, kind: EvidenceKind) -> tuple[CliRecord, ...]:
        out: list[CliRecord] = []
        for records in self._by_device.values():
            out.extend(record for record in records if record.kind is kind)
        out.extend(record for record in self._unattributed if record.kind is kind)
        return tuple(out)

    def unattributed(self) -> tuple[CliRecord, ...]:
        """Records whose device could not be determined. Never merged into one."""
        return tuple(self._unattributed)

    def devices(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_device))

    # -- typed views -------------------------------------------------------

    def _latest(self, device: str, kind: EvidenceKind) -> CliRecord | None:
        candidates = [r for r in self._by_device.get(device, ()) if r.kind is kind]
        if not candidates:
            return None
        return candidates[-1]

    def runtime_interfaces(self, device: str) -> dict[str, dict]:
        """Interface rows from the most recent ``show ip interface brief``."""
        record = self._latest(device, EvidenceKind.IP_INTERFACE_BRIEF)
        if record is None or not isinstance(record.parsed, dict):
            return {}
        return dict(record.parsed)

    def runtime_routes(self, device: str) -> list[dict]:
        """Route rows from the most recent ``show ip route``."""
        record = self._latest(device, EvidenceKind.IP_ROUTE)
        if record is None or not isinstance(record.parsed, list):
            return []
        return list(record.parsed)

    def static_config(self, device: str) -> list[str]:
        """Lines of the most recent ``show running-config`` for ``device``."""
        record = self._latest(device, EvidenceKind.RUNNING_CONFIG)
        if record is None or not isinstance(record.parsed, dict):
            return []
        lines = record.parsed.get("lines", [])
        return list(lines) if isinstance(lines, list) else []
