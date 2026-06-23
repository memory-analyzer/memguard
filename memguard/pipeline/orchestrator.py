"""
memguard.pipeline.orchestrator
================================
The central pipeline that:
  1. Runs all applicable analysis tools in parallel
  2. Parses and deduplicates errors
  3. Symbolizes stack traces + attaches source context
  4. Batches errors through AI analysis (multi-pass)
  5. Builds InteractiveSessions for every analysed error
  6. Persists the full ScanResult to SQLite
  7. Emits progress events over an asyncio.Queue for the TUI/API
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from ..core.runner   import ToolOrchestrator
from ..core.parsers  import parse_tool_output
from ..core.symbolizers import Symbolizer
from ..core.schema   import (
    AnalysisTool, InteractiveSession, Language, MemoryError,
    ScanConfig, ScanResult, ScanTarget, SessionState, Severity,
)
from ..ai.analyzer   import analyze_error, AnalysisResult, batch_analyze
from ..ai.client     import best_available_model

log = logging.getLogger(__name__)

RESULTS_DIR = Path.home() / ".memguard" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Progress events
# ---------------------------------------------------------------------------

@dataclass
class PipelineEvent:
    kind:    str          # scan_start | tool_done | parse_done | ai_start |
    #                        ai_progress | ai_done | session_ready | complete | error
    payload: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(errors: list[MemoryError]) -> list[MemoryError]:
    """Remove duplicate errors (same fingerprint). Keep highest-severity copy."""
    seen: dict[str, MemoryError] = {}
    SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
    for err in errors:
        fp = err.fingerprint
        if fp not in seen:
            seen[fp] = err
        else:
            existing = seen[fp]
            if SEV_ORDER.index(err.severity) < SEV_ORDER.index(existing.severity):
                err.duplicate_of = None
                seen[fp] = err
            else:
                err.duplicate_of = existing.id
    return list(seen.values())


def _prioritise(errors: list[MemoryError]) -> list[MemoryError]:
    """Sort: critical first, then by bytes leaked desc, then by file."""
    SEV_ORDER = {s: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    )}
    return sorted(errors, key=lambda e: (
        SEV_ORDER.get(e.severity, 9),
        -(e.bytes_leaked or 0),
        (e.primary_location.file if e.primary_location else ""),
    ))


# ---------------------------------------------------------------------------
# Stats aggregator
# ---------------------------------------------------------------------------

def _compute_stats(result: ScanResult) -> None:
    result.total_bytes_leaked = sum(
        e.bytes_leaked or 0 for e in result.errors
    )
    result.error_count_by_type = {}
    result.error_count_by_severity = {}
    for e in result.errors:
        result.error_count_by_type[e.bug_type.value] = (
            result.error_count_by_type.get(e.bug_type.value, 0) + 1
        )
        result.error_count_by_severity[e.severity.value] = (
            result.error_count_by_severity.get(e.severity.value, 0) + 1
        )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _persist(result: ScanResult) -> Path:
    out = RESULTS_DIR / f"{result.scan_id}.json"
    out.write_text(result.model_dump_json(indent=2))
    log.info("Scan result saved → %s", out)
    return out


def load_result(scan_id: str) -> ScanResult | None:
    p = RESULTS_DIR / f"{scan_id}.json"
    if p.exists():
        return ScanResult.model_validate_json(p.read_text())
    return None


def list_results() -> list[dict]:
    results = []
    for p in sorted(RESULTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            data = json.loads(p.read_text())
            results.append({
                "scan_id":    data["scan_id"],
                "started_at": data.get("started_at"),
                "total":      sum(data.get("error_count_by_severity", {}).values()),
                "critical":   data.get("error_count_by_severity", {}).get("critical", 0),
                "high":       data.get("error_count_by_severity", {}).get("high", 0),
            })
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

class Pipeline:
    def __init__(
        self,
        config: ScanConfig,
        event_queue: asyncio.Queue | None = None,
    ):
        self.cfg    = config
        self.events = event_queue or asyncio.Queue()

    async def _emit(self, kind: str, **payload):
        await self.events.put(PipelineEvent(kind=kind, payload=payload))

    # ---------------------------------------------------------------- stage 1
    async def _stage_scan(self, result: ScanResult) -> dict[AnalysisTool, str]:
        await self._emit("scan_start", tools=[t.value for t in self.cfg.tools])
        result.state = SessionState.SCANNING

        orchestrator = ToolOrchestrator(self.cfg)
        raw_results  = await orchestrator.run_all(self.cfg.target)

        raw_outputs: dict[AnalysisTool, str] = {}
        for tool, tool_result in raw_results.items():
            raw_outputs[tool] = tool_result.output
            result.raw_outputs[tool.value] = tool_result.output
            # Parse immediately so we can report error count in tool_done
            errors_preview = parse_tool_output(tool, tool_result.output)
            await self._emit("tool_done",
                             tool=tool.value,
                             duration_ms=tool_result.duration_ms,
                             from_cache=tool_result.from_cache,
                             error_count=len(errors_preview))
        return raw_outputs

    # ---------------------------------------------------------------- stage 2
    async def _stage_parse(
        self, raw_outputs: dict[AnalysisTool, str], result: ScanResult
    ) -> list[MemoryError]:
        all_errors: list[MemoryError] = []
        for tool, raw in raw_outputs.items():
            errors = parse_tool_output(tool, raw)
            all_errors.extend(errors)
            log.info("Parsed %d errors from %s", len(errors), tool.value)

        deduped = _deduplicate(all_errors)
        ordered = _prioritise(deduped)
        # Filter out UNKNOWN bug types with no useful info
        ordered = [e for e in ordered if not (
            e.bug_type.value == "unknown" and not e.source_context and not e.primary_location
        )]
        ordered = ordered[: self.cfg.max_errors]

        await self._emit("parse_done",
                         total=len(all_errors),
                         unique=len(deduped),
                         capped=len(ordered))
        return ordered

    # ---------------------------------------------------------------- stage 3
    async def _stage_symbolize(
        self, errors: list[MemoryError]
    ) -> list[MemoryError]:
        sym = Symbolizer(
            binary   = self.cfg.target.binary,
            language = self.cfg.target.language,
        )
        enriched = await sym.enrich_errors(errors)
        await self._emit("symbolize_done", count=len(enriched))
        return enriched

    # ---------------------------------------------------------------- stage 4
    async def _stage_analyze(
        self, errors: list[MemoryError], result: ScanResult
    ) -> None:
        result.state = SessionState.ANALYZING
        model        = self.cfg.ai_model or await best_available_model()

        await self._emit("ai_start", model=model, count=len(errors))

        completed = 0

        async def progress_cb(i: int, total: int, ar: AnalysisResult):
            nonlocal completed
            completed += 1
            result.analyses.append(ar.analysis)

            # Build interactive session for this error
            session = InteractiveSession(
                error_id    = ar.analysis.error_id,
                analysis_id = ar.analysis.error_id,
                steps       = ar.steps,
            )
            result.sessions.append(session)

            await self._emit("ai_progress",
                             completed=completed,
                             total=total,
                             error_id=ar.analysis.error_id,
                             bug_type=errors[i].bug_type.value,
                             severity=errors[i].severity.value,
                             root_cause=ar.analysis.root_cause)

        await batch_analyze(
            errors,
            model=model,
            concurrency=1,   # sequential — Ollama handles one 14B analysis at a time
            progress_cb=progress_cb,
        )

        await self._emit("ai_done", total_analyses=len(result.analyses))

    # ---------------------------------------------------------------- run all
    async def run(self) -> ScanResult:
        result = ScanResult(config=self.cfg)
        t0     = time.monotonic()

        try:
            raw_outputs = await self._stage_scan(result)
            errors      = await self._stage_parse(raw_outputs, result)
            errors      = await self._stage_symbolize(errors)
            result.errors = errors
            _compute_stats(result)

            await self._stage_analyze(errors, result)

            result.state       = SessionState.DONE
            result.finished_at = datetime.now(timezone.utc)
            result.duration_ms = int((time.monotonic() - t0) * 1000)

            _persist(result)
            await self._emit("complete",
                             scan_id=result.scan_id,
                             duration_ms=result.duration_ms,
                             total_errors=len(result.errors))
        except Exception as exc:
            result.state = SessionState.FAILED
            await self._emit("error", message=str(exc))
            log.exception("Pipeline failed")
            raise

        return result
