"""FastAPI application for TRIDENT.

Endpoints:
  GET  /               minimal single-page UI
  GET  /api/health     health + adapter availability
  GET  /api/parsers    parser capability information
  POST /api/analyze    multipart: file + questions

Security posture: localhost-only by default, no telemetry, no auth, file never
written outside a private temp workspace, API key never serialised.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import REPO_ROOT, settings
from .ingestion import IngestionError, ingest
from .models import AnalysisResponse
from .phase3_api import router as phase3_router
from .pipeline import VERSION, analyze, build_adapters, health
from .reasoning.questions import QuestionParseError

logger = logging.getLogger("trident")
WEB_DIR = REPO_ROOT / "trident" / "web"

app = FastAPI(
    title="TRIDENT",
    version=VERSION,
    description="Local, read-only Cisco Packet Tracer analysis with three-engine consensus.",
    docs_url="/api/docs",
    redoc_url=None,
)


# Phase 3 routes: simulator status, modes, and the payload builders they expose.
# Mounted before the UI routes so /api/phase3/* resolves to the router, not the
# static mount.
app.include_router(phase3_router)


@app.get("/api/health", response_model=None)
async def health_endpoint() -> JSONResponse:
    payload = await health(settings)
    return JSONResponse(payload)


@app.get("/api/parsers")
async def parsers_endpoint() -> JSONResponse:
    adapters = build_adapters(settings)
    out = []
    for adapter in adapters:
        available, message = adapter.probe()
        out.append(
            {
                "engine": adapter.engine_id,
                "name": adapter.display_name,
                "available": available,
                "message": message,
                "capabilities": list(adapter.capabilities),
                "limitations": list(adapter.limitations),
            }
        )
    return JSONResponse(
        {
            "parsers": out,
            "available_count": sum(1 for p in out if p["available"]),
            "consensus_policy": settings.consensus_policy,
            "strict_three_engine_ready": all(p["available"] for p in out),
        }
    )


@app.post("/api/network/analyze")
async def analyze_network_endpoint(
    file: UploadFile = File(...),
    mode: str = Form("quick"),
    export: str = Form("json"),
):
    """Analyze Mode: a device-by-device report with no questions required.

    ``mode`` is ``quick`` (static only) or ``deep`` (allows a Ghost escalation,
    currently reported rather than performed because the browser path never starts
    a simulator implicitly). ``export`` is ``json``, ``markdown`` or ``text``.
    """
    from fastapi.responses import PlainTextResponse

    from .deepcore.analyze import analyze_network

    try:
        data = await file.read(settings.max_file_bytes + 1)
        ingested = ingest(file.filename or "", data, settings)
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="could not read the uploaded file") from None

    try:
        outcome = await analyze(ingested, "analyze", settings, use_ai=False)
    except Exception as exc:
        logger.exception("analyze mode failed")
        raise HTTPException(
            status_code=500, detail=f"analysis failed: {type(exc).__name__}"
        ) from None

    report = analyze_network(outcome.model)
    if mode.lower() == "deep":
        report.warnings.append(
            "Deep Analyze was requested. Runtime experiments are not started "
            "implicitly from the browser; run the simulator CLI for live evidence."
        )

    if export.lower() == "markdown":
        return PlainTextResponse(report.to_markdown(), media_type="text/markdown")
    if export.lower() == "text":
        return PlainTextResponse(report.to_text(), media_type="text/plain")
    return report.as_dict()


@app.post("/api/analyze/stream")
async def analyze_stream_endpoint(
    file: UploadFile = File(...),
    questions: str = Form(...),
    use_ai: bool = Form(True),
):
    """Same analysis, delivered as Server-Sent Events.

    Answers are emitted individually, so a caller can render the first resolved
    answer without waiting for the last. Stage events name real phases.
    """
    import asyncio

    from fastapi.responses import StreamingResponse

    from .streaming import AnswerStreamer

    try:
        data = await file.read(settings.max_file_bytes + 1)
        ingested = ingest(file.filename or "", data, settings)
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="could not read the uploaded file") from None

    if not questions or not questions.strip():
        raise HTTPException(status_code=400, detail="no questions provided")

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def emit_stage(name: str) -> None:
        # Called from the pipeline as each phase actually begins. Hop back to
        # the event loop because the pipeline runs synchronously inside a
        # threadpool when awaited.
        loop.call_soon_threadsafe(queue.put_nowait, ("stage", name))

    def emit_answer(answer) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, ("answer", answer))

    async def run_analysis() -> None:
        try:
            outcome = await analyze(
                ingested,
                questions,
                settings,
                use_ai=use_ai,
                on_stage=emit_stage,
                on_answer=emit_answer,
            )
            loop.call_soon_threadsafe(queue.put_nowait, ("complete", outcome.response))
        except QuestionParseError as exc:
            loop.call_soon_threadsafe(queue.put_nowait, ("error", str(exc)))
        except Exception as exc:
            logger.exception("streamed analysis failed")
            loop.call_soon_threadsafe(
                queue.put_nowait, ("error", f"analysis failed: {type(exc).__name__}")
            )

    task = asyncio.create_task(run_analysis())

    async def frames():
        streamer = AnswerStreamer()
        try:
            while True:
                kind, payload = await queue.get()
                if kind == "stage":
                    yield streamer.stage(payload).to_sse()
                elif kind == "answer":
                    yield streamer.answer(payload).to_sse()
                elif kind == "complete":
                    yield streamer.complete(payload).to_sse()
                    break
                elif kind == "error":
                    yield streamer.error(payload).to_sse()
                    break
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(frames(), media_type="text/event-stream")


@app.post("/api/analyze/verify", response_model=None)
async def analyze_verify_endpoint(
    file: UploadFile = File(...),
    questions: str = Form(...),
    use_ai: bool = Form(True),
):
    """Analysis plus an independent re-derivation of every answer."""
    from .verification.independent import IndependentVerifier

    try:
        data = await file.read(settings.max_file_bytes + 1)
        ingested = ingest(file.filename or "", data, settings)
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    if not questions or not questions.strip():
        raise HTTPException(status_code=400, detail="no questions provided")

    try:
        outcome = await analyze(ingested, questions, settings, use_ai=use_ai)
    except QuestionParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception as exc:
        logger.exception("verification failed")
        raise HTTPException(
            status_code=500, detail=f"analysis failed: {type(exc).__name__}"
        ) from None

    report = IndependentVerifier(outcome.model).verify(outcome.response.results)
    payload = outcome.response.model_dump()
    payload["verification"] = report.as_dict()
    return payload


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_endpoint(
    file: UploadFile = File(...),
    questions: str = Form(...),
    use_ai: bool = Form(True),
) -> AnalysisResponse:
    try:
        data = await file.read(settings.max_file_bytes + 1)
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="could not read the uploaded file") from None

    try:
        ingested = ingest(file.filename or "", data, settings)
    except IngestionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    if not questions or not questions.strip():
        raise HTTPException(status_code=400, detail="no questions provided")

    try:
        outcome = await analyze(ingested, questions, settings, use_ai=use_ai)
    except QuestionParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception as exc:
        logger.exception("analysis failed")
        raise HTTPException(
            status_code=500, detail=f"analysis failed: {type(exc).__name__}"
        ) from None

    return outcome.response


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


if WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


def run() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    uvicorn.run(
        "trident.server:app",
        host=settings.host,
        port=settings.port,
        log_level="info",
    )
