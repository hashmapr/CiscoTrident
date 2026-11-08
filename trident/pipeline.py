"""End-to-end analysis pipeline.

PKA FILE -> ingestion -> three adapters -> normalisation -> consensus -> AI plans
-> deterministic validation -> results

The file is parsed once per analysis. All questions reuse the same model.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .config import Settings
from .config import settings as default_settings
from .ingestion import IngestedFile, make_workspace
from .models import (
    AnalysisResponse,
    AnswerResult,
    NetworkModel,
    ParsedQuestion,
    ParserReport,
    ParserState,
)
from .normalization.devices import Normalizer
from .parsers.base import AdapterResult, ParserAdapter
from .parsers.pka_xml import EngineAAdapter
from .parsers.pkt_core import EngineBAdapter
from .parsers.pt_convert import EngineCAdapter
from .reasoning.ai_client import AIClient, AIClientError, QueryPlan, build_digest
from .reasoning.questions import parse_questions
from .verification.consensus import ConsensusEngine
from .verification.validators import AnswerBuilder

VERSION = "1.0.0"


def build_adapters(cfg: Settings) -> list[ParserAdapter]:
    return [EngineAAdapter(cfg), EngineBAdapter(cfg), EngineCAdapter(cfg)]


@dataclass
class AnalysisOutcome:
    response: AnalysisResponse
    model: NetworkModel
    adapter_results: list[AdapterResult] = field(default_factory=list)


async def _run_adapters(
    adapters: list[ParserAdapter], file_path, workdir, cfg: Settings
) -> list[AdapterResult]:
    """Run adapters concurrently but isolate failures per adapter."""

    async def one(adapter: ParserAdapter) -> AdapterResult:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, adapter.run, file_path, workdir),
                timeout=cfg.parser_timeout + 5,
            )
        except TimeoutError:
            return AdapterResult(
                engine_id=adapter.engine_id,
                report=ParserReport(
                    engine=adapter.engine_id,
                    state=ParserState.TIMEOUT,
                    message=f"adapter exceeded {cfg.parser_timeout:.0f}s",
                ),
            )

    return list(await asyncio.gather(*(one(a) for a in adapters)))


async def analyze(
    ingested: IngestedFile,
    question_text: str,
    cfg: Settings | None = None,
    use_ai: bool = True,
) -> AnalysisOutcome:
    cfg = cfg or default_settings

    questions: list[ParsedQuestion] = parse_questions(
        question_text,
        max_questions=cfg.max_questions,
        max_chars=cfg.max_question_chars,
    )

    adapters = build_adapters(cfg)
    with make_workspace() as tmp:
        workdir = __import__("pathlib").Path(tmp)
        file_path = ingested.temp_path(workdir)
        results = await _run_adapters(adapters, file_path, workdir, cfg)

        snap_warnings: list[str] = []
        agreed_snapshot, snap_ambiguous = _agree_snapshot(results, snap_warnings)
        model = Normalizer(results, snapshot_id=agreed_snapshot).build()
        model.file_sha256 = ingested.sha256
        model.snapshot_ambiguous = snap_ambiguous or agreed_snapshot == "abstain"
        model.snapshot_notes = [
            note
            for res in results
            for note in ((res.raw or {}).get("snapshot_notes") or [])
        ]
        model.warnings.extend(snap_warnings)

        consensus = ConsensusEngine(model, cfg)

        plans: dict[int, QueryPlan] = {}
        ai_used = False
        ai_error: str | None = None
        if use_ai and cfg.ai_configured and questions:
            client = AIClient(cfg)
            digest = build_digest(model)
            try:
                plans_list = await client.plan_questions(
                    digest,
                    [
                        {
                            "question_number": q.question_number,
                            "text": q.stem[:1500],
                            "options": [f"{o.letter}. {o.text}" for o in q.options],
                            "kind": q.kind.value,
                        }
                        for q in questions
                    ],
                )
                plans = {p.question_number: p for p in plans_list}
                ai_used = bool(plans)
                for message in client.last_batch_errors:
                    model.warnings.append(f"AI batch unavailable ({message})")
            except AIClientError as exc:
                ai_error = str(exc)

        builder = AnswerBuilder(model, consensus)
        results_out: list[AnswerResult] = []
        for q in questions:
            results_out.append(builder.build(q, plans.get(q.question_number)))

    warnings: list[str] = list(model.warnings)
    if ai_error:
        warnings.append(f"AI planning unavailable: {ai_error}")
    elif use_ai and not cfg.ai_configured:
        warnings.append(
            "AI is not configured (AI_API_KEY / AI_MODEL). "
            "Questions were interpreted with deterministic heuristics only."
        )

    snapshot_none = not model.devices
    if snapshot_none:
        warnings.append(
            "No devices were extracted. If this is a .pka, its snapshot blocks may be empty "
            "or the file may not contain network configuration."
        )

    response = AnalysisResponse(
        file_name=ingested.file_name,
        file_sha256=ingested.sha256,
        file_bytes=ingested.size_bytes,
        snapshot_id=model.snapshot_id,
        snapshot_ambiguous=model.snapshot_ambiguous,
        snapshot_notes=model.snapshot_notes,
        parsers=[r.report for r in results],
        consensus_policy=cfg.consensus_policy,
        ai_used=ai_used,
        network_summary=_summary(model, consensus),
        results=results_out,
        warnings=warnings,
    )
    return AnalysisOutcome(response=response, model=model, adapter_results=results)


def _agree_snapshot(results: list, warnings: list[str]) -> tuple[str, bool]:
    """Every adapter must have selected the same snapshot; else abstain.

    Abstained engines contribute no observations anyway; a disagreement between
    engines that DID extract is a bug signal, so the model abstains too.
    Returns ``(snapshot_id, ambiguous)``.
    """
    ids: set[str] = set()
    ambiguous = False
    snapshot_amb = False
    for res in results:
        raw = res.raw or {}
        sid = raw.get("snapshot")
        if raw.get("snapshot_abstained") or raw.get("snapshot_ambiguous"):
            snapshot_amb = True
        if sid and sid not in ("abstain", "unknown"):
            ids.add(str(sid))
            if raw.get("snapshot_ambiguous"):
                ambiguous = True
    if len(ids) > 1:
        warnings.append(
            "adapters disagreed about the selected snapshot (" + ", ".join(sorted(ids)) + "); "
            "abstaining instead of merging"
        )
        return "abstain", True
    if ambiguous or snapshot_amb:
        warnings.append("snapshot selection was ambiguous for at least one adapter")
    return next(iter(ids), ""), ambiguous


def _summary(model: NetworkModel, consensus: ConsensusEngine) -> dict:
    cmap = consensus.consensus_map()
    counts: dict[str, int] = {}
    for entry in cmap.values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return {
        "devices": len(model.devices),
        "interfaces": len(model.interfaces),
        "links": len(model.links),
        "routes": len(model.routes),
        "vlans": len(model.vlans),
        "acls": len(model.acls),
        "consensus_required": consensus.required,
        "engines_contributing": consensus.available_engines(),
        "field_status_counts": counts,
        "conflicts": consensus.all_conflicts(),
    }


async def health(cfg: Settings | None = None) -> dict:
    cfg = cfg or default_settings
    adapters = build_adapters(cfg)
    reports: list[dict] = []
    for adapter in adapters:
        available, message = adapter.probe()
        reports.append(
            {
                "engine": adapter.engine_id,
                "name": adapter.display_name,
                "state": (ParserState.OK if available else ParserState.UNAVAILABLE).value,
                "available": available,
                "message": message,
                "capabilities": list(adapter.capabilities),
                "limitations": list(adapter.limitations),
            }
        )
    available_count = sum(1 for r in reports if r["available"])
    return {
        "status": "ok",
        "version": VERSION,
        "parsers": reports,
        "available_count": available_count,
        "strict_three_engine_ready": available_count == 3,
        "ai_configured": cfg.ai_configured,
        "consensus_policy": cfg.consensus_policy,
        "settings": cfg.public_dict(),
    }
