"""Parser adapter contract.

An adapter is the *only* way TRIDENT obtains facts. Each adapter must:

* report its own availability honestly (``probe``)
* return raw observations with provenance, never a pre-verified answer
* never raise on bad input — return a report with state=ERROR instead
* never modify the input file
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..models import Observation, ParserReport, ParserState


@dataclass
class AdapterResult:
    """What an adapter produces: observations + its own honest report."""

    engine_id: str
    report: ParserReport
    observations: list[Observation] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    #: Raw IOS configs per device name, as this engine saw them.
    configs: dict[str, list[str]] = field(default_factory=dict)
    #: Raw links as (device_a, iface_a, device_b, iface_b, media) tuples.
    links: list[tuple[str, str, str, str, str | None]] = field(default_factory=list)
    #: End-host facts this engine exposes directly (gateway, DNS, IP).
    end_hosts: dict[str, dict] = field(default_factory=dict)
    #: True when this engine's container decode is the shared public algorithm.
    crypto_shared: bool = True
    #: Free-form engine-specific payload for debugging / export.
    raw: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.report.state is ParserState.OK


class ParserAdapter(abc.ABC):
    """Base class for the three engine adapters."""

    engine_id: str = "unnamed"
    display_name: str = "Unnamed engine"
    capabilities: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __init__(self, cfg: Settings) -> None:
        self.cfg = cfg

    # -- availability -----------------------------------------------------
    @abc.abstractmethod
    def probe(self) -> tuple[bool, str]:
        """Return (available, message). Must never raise."""

    # -- execution --------------------------------------------------------
    @abc.abstractmethod
    def _extract(self, file_path: Path, workdir: Path) -> AdapterResult:
        """Do the real work. May raise; the base class converts to ERROR."""

    def run(self, file_path: Path, workdir: Path) -> AdapterResult:
        """Template method: probe, time the extraction, capture failures."""
        started = time.monotonic()
        available, message = self.probe()
        if not available:
            return AdapterResult(
                engine_id=self.engine_id,
                report=ParserReport(
                    engine=self.engine_id,
                    state=ParserState.UNAVAILABLE,
                    message=message,
                    duration_ms=0,
                    capabilities=list(self.capabilities),
                    limitations=list(self.limitations),
                ),
            )

        try:
            result = self._extract(file_path, workdir)
        except TimeoutError:
            elapsed = int((time.monotonic() - started) * 1000)
            return AdapterResult(
                engine_id=self.engine_id,
                report=ParserReport(
                    engine=self.engine_id,
                    state=ParserState.TIMEOUT,
                    message=f"parser exceeded {self.cfg.parser_timeout:.0f}s",
                    duration_ms=elapsed,
                    capabilities=list(self.capabilities),
                    limitations=list(self.limitations),
                ),
            )
        except Exception as exc:  # noqa: BLE001 - adapters must not crash the request
            elapsed = int((time.monotonic() - started) * 1000)
            return AdapterResult(
                engine_id=self.engine_id,
                report=ParserReport(
                    engine=self.engine_id,
                    state=ParserState.ERROR,
                    message=f"{type(exc).__name__}: {exc}",
                    duration_ms=elapsed,
                    capabilities=list(self.capabilities),
                    limitations=list(self.limitations),
                ),
            )

        elapsed = int((time.monotonic() - started) * 1000)
        result.report.duration_ms = elapsed
        if not result.report.capabilities:
            result.report.capabilities = list(self.capabilities)
        if not result.report.limitations:
            result.report.limitations = list(self.limitations)
        return result
