"""
memguard.api.server
===================
FastAPI backend:
  GET  /scans              — list past scans
  GET  /scans/{id}         — full scan result
  POST /scans              — trigger new scan (async, WebSocket progress)
  GET  /scans/{id}/errors  — paginated errors
  GET  /scans/{id}/errors/{eid}/analysis — AI analysis for one error
  WS   /ws/scan            — real-time scan progress + AI streaming
  POST /scans/{id}/errors/{eid}/chat — chat with AI about an error
  GET  /health             — system health
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..core.schema import ScanConfig, ScanTarget, Language, AnalysisTool
from ..pipeline.orchestrator import Pipeline, load_result, list_results
from ..ai.client import list_local_models, best_available_model
from ..core.runner import available_tools

log = logging.getLogger(__name__)

app = FastAPI(
    title="MemGuard API",
    description="AI-powered memory leak detector",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target:      str
    tools:       list[str] = []
    model:       str = "auto"
    compile_cmd: str | None = None
    args:        list[str] = []
    max_errors:  int = 50
    no_ai:       bool = False
    memhint_enabled: bool = False
    memhint_source_dir: str | None = None


class ChatRequest(BaseModel):
    message: str
    model:   str = "auto"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    import shutil
    tools = {
        t: shutil.which(t) is not None
        for t in ["valgrind", "clang", "cppcheck", "ollama"]
    }
    models = await list_local_models()
    return {
        "status": "ok",
        "tools": tools,
        "models": models,
    }


@app.get("/scans")
async def get_scans():
    return list_results()


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return result.model_dump()


@app.get("/scans/{scan_id}/errors")
async def get_errors(scan_id: str, page: int = 0, size: int = 20):
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404)
    errors = result.errors[page * size: (page + 1) * size]
    return {
        "total": len(result.errors),
        "page": page, "size": size,
        "errors": [e.model_dump() for e in errors],
    }


@app.get("/scans/{scan_id}/errors/{error_id}/analysis")
async def get_analysis(scan_id: str, error_id: str):
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404)
    analysis = next((a for a in result.analyses if a.error_id == error_id), None)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    return analysis.model_dump()


@app.get("/scans/{scan_id}/viz", response_class=HTMLResponse)
async def get_visualization(scan_id: str):
    """Generate and return interactive memory visualization."""
    from ..core.visualizer import generate_visualization
    result = load_result(scan_id)
    if not result or not result.errors:
        raise HTTPException(404, "Scan not found or no errors")
    return generate_visualization(
        result.errors,
        scan_id=scan_id,
        target=str(result.config.target.binary or result.config.target.source_dir or ""),
    )


@app.post("/scans/{scan_id}/errors/{error_id}/chat")
async def chat_about_error(scan_id: str, error_id: str, req: ChatRequest):
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404)
    err      = next((e for e in result.errors if e.id == error_id), None)
    analysis = next((a for a in result.analyses if a.error_id == error_id), None)
    if not err or not analysis:
        raise HTTPException(404)


@app.post("/scans/{scan_id}/errors/{error_id}/ai-debug")
async def ai_debug_error(scan_id: str, error_id: str):
    """AI deep analysis: root cause, fix, and debugging guidance."""
    from ..ai.explainability import generate_reasoning_chain, backtrack_allocation
    from ..ai.client import best_available_model
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404)
    err = next((e for e in result.errors if e.id == error_id), None)
    analysis = next((a for a in result.analyses if a.error_id == error_id), None)
    if not err:
        raise HTTPException(404)

    model = await best_available_model()
    response = {}

    # Reasoning chain
    try:
        chain = await generate_reasoning_chain(err, analysis, model)
        response["reasoning"] = {
            "steps": [{"step": s.step, "title": s.title,
                       "observation": s.observation, "evidence": s.evidence,
                       "inference": s.inference, "confidence": s.confidence,
                       "alternatives": s.alternatives} for s in chain.steps],
            "verdict": chain.final_verdict,
            "confidence": chain.overall_confidence,
            "counterfactual": chain.counterfactual,
        }
    except Exception as e:
        response["reasoning"] = {"error": str(e)}

    # Backtracking (for leaks and UAF)
    if err.bug_type.value in ("memory_leak", "use_after_free", "double_free"):
        try:
            bt = await backtrack_allocation(err, model)
            response["backtrack"] = {
                "allocated_at": bt.allocated_at,
                "allocated_via": bt.allocated_via,
                "passed_to": bt.passed_to,
                "should_free_at": bt.should_free_at,
                "actually_freed": bt.actually_freed,
                "ownership_chain": bt.ownership_chain,
                "lost_at": bt.lost_at,
            }
        except Exception as e:
            response["backtrack"] = {"error": str(e)}

    return response


@app.get("/scans/{scan_id}/taint")
async def get_taint_analysis(scan_id: str):
    """Run taint flow analysis on scan results."""
    from ..core.taintflow import run_taint_analysis
    from ..core.runner import _discover_sources_from_binary
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404)

    binary = str(result.config.target.binary or "")
    src_dir = ""
    if binary:
        sources = await _discover_sources_from_binary(binary)
        if sources:
            src_dir = str(Path(sources[0]).parent)
    if not src_dir and binary:
        src_dir = str(Path(binary).parent)

    report = run_taint_analysis(src_dir, result.errors, binary)

    return {
        "risk_summary": report.risk_summary,
        "functions_analyzed": report.functions_analyzed,
        "data_flow_edges": report.data_flow_edges,
        "tainted_variables": report.tainted_variables,
        "taint_sources": [{"type": s.source_type, "call": s.call_site,
                           "function": s.function, "file": s.file,
                           "line": s.line, "risk": s.risk_level,
                           "desc": s.description,
                           "tainted_var": s.tainted_var} for s in report.taint_sources],
        "taint_paths": [{"source_call": p.source.call_site,
                         "source_type": p.source.source_type,
                         "source_func": p.source.function,
                         "source_var": p.source.tainted_var,
                         "bug_id": p.target_bug_id,
                         "bug_type": p.target_bug_type,
                         "bug_location": p.target_location,
                         "path": p.path_functions,
                         "path_edges": p.path_edges,
                         "path_variables": p.path_variables,
                         "confidence": p.confidence,
                         "risk": p.risk_assessment,
                         "data_flow": p.data_flow_detail} for p in report.taint_paths],
        "reachable": report.reachable_bugs,
        "isolated": report.isolated_bugs,
        "total": report.total_bugs,
        "call_graph_size": report.call_graph_size,
    }


@app.post("/heaptrack/{target:path}")
async def run_heaptrack_api(target: str):
    """Run heaptrack on a binary and return the visualization HTML."""
    from ..core.heaptrack import run_heaptrack, parse_heaptrack, generate_heaptrack_viz
    p = Path(target)
    if not p.exists():
        raise HTTPException(404, f"Binary not found: {target}")
    rec = await run_heaptrack(str(p), timeout=60)
    if not rec:
        raise HTTPException(500, "heaptrack recording failed")
    report = await parse_heaptrack(rec, str(p))
    html = generate_heaptrack_viz(report)
    from starlette.responses import HTMLResponse
    return HTMLResponse(html)


@app.get("/scans/{scan_id}/timewarp")
async def get_timewarp(scan_id: str):
    """Generate timewarp script and return debug info."""
    from ..core.timetravel import (
        generate_timewarp_script, save_timewarp_script,
        detect_backend, list_recordings,
    )
    result = load_result(scan_id)
    if not result:
        raise HTTPException(404)

    binary = str(result.config.target.binary or "")
    script = generate_timewarp_script(result.errors, binary, scan_id)
    script_path = save_timewarp_script(script)

    recordings = list_recordings()
    matching = [r for r in recordings if Path(r.binary).name == Path(binary).name]

    return {
        "scan_id": scan_id,
        "binary": binary,
        "backend": detect_backend(),
        "breakpoints": [{"location": b.location, "function": b.function,
                         "bug_type": b.bug_type, "description": b.description}
                        for b in script.breakpoints],
        "launch_cmd": script.launch_cmd,
        "script_path": script_path,
        "instructions": script.instructions,
        "recordings": [{"id": r.recording_id, "duration_ms": r.duration_ms,
                         "events": r.events, "tool": r.tool, "size_mb": r.size_mb}
                        for r in matching[:5]],
    }

    from ..ai.client import complete
    from ..ai.analyzer import LANG_SYSTEM

    system = LANG_SYSTEM.get(err.language, "You are a memory safety expert.")
    system += (
        f"\n\nContext: {err.bug_type.value} error. "
        f"Root cause: {analysis.root_cause}"
    )
    model = req.model if req.model != "auto" else await best_available_model()
    response = await complete(
        [{"role": "user", "content": req.message}],
        model=model, system=system, temperature=0.2,
    )
    return {"response": response, "model": model}


# ---------------------------------------------------------------------------
# WebSocket scan endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    """
    WebSocket protocol:
      Client sends: JSON ScanRequest
      Server sends: stream of JSON event objects
        {"kind": "scan_start", ...}
        {"kind": "tool_done",  ...}
        {"kind": "ai_progress", ...}
        {"kind": "ai_stream", "token": "..."}   ← streaming AI tokens
        {"kind": "complete", "scan_id": "..."}
        {"kind": "error", "message": "..."}
    """
    await ws.accept()
    try:
        raw = await ws.receive_text()
        req = ScanRequest.model_validate_json(raw)
    except Exception as e:
        await ws.send_json({"kind": "error", "message": str(e)})
        await ws.close()
        return

    # Detect language
    from ..core.schema import Language
    target_path = req.target
    p = Path(target_path).expanduser().resolve()

    # Validate target exists before launching tools
    if not p.exists():
        await ws.send_json({
            "kind": "error",
            "message": f"Target not found: {target_path}",
        })
        await ws.close()
        return

    lang = {
        ".c": Language.C, ".cpp": Language.CPP,
        ".py": Language.PYTHON, ".rs": Language.RUST,
    }.get(p.suffix.lower(), Language.UNKNOWN) if p.is_file() else Language.UNKNOWN

    # Resolve tools
    if req.tools:
        tool_list = [AnalysisTool(t) for t in req.tools]
    else:
        tool_list = available_tools(lang)

    # Resolve model
    model = req.model
    if model == "auto":
        try:
            model = await best_available_model()
        except RuntimeError as e:
            await ws.send_json({"kind": "error", "message": str(e)})
            return

    target = ScanTarget(
        binary     = str(p) if p.is_file() else None,
        source_dir = str(p) if p.is_dir()  else None,
        files      = [str(p)] if p.suffix == ".py" else [],
        language   = lang,
        compile_cmd= req.compile_cmd,
        args       = req.args,
    )
    cfg = ScanConfig(
        target=target, tools=tool_list,
        max_errors=req.max_errors, ai_model=model,
    )

    # ── Run MemHint if enabled ──
    if req.memhint_enabled:
        try:
            from ..core.memhint import run_memhint_pipeline
            from ..core.runner import _discover_sources_from_binary

            # Auto-detect source directory from binary DWARF info
            memhint_src = req.memhint_source_dir
            if not memhint_src and p.is_file():
                await ws.send_json({"kind": "memhint_progress", "message": "Auto-detecting source from binary DWARF info..."})
                discovered = await _discover_sources_from_binary(str(p))
                if discovered:
                    # Use the directory of the first discovered source file
                    memhint_src = str(Path(discovered[0]).parent)
                    await ws.send_json({"kind": "memhint_progress", "message": f"Found source at: {memhint_src}"})
                else:
                    # Fallback: use binary's parent directory
                    memhint_src = str(p.parent)

            if not memhint_src:
                memhint_src = str(p.parent) if p.is_file() else str(p)

            await ws.send_json({"kind": "memhint_start", "source_dir": memhint_src})

            report = await run_memhint_pipeline(
                memhint_src, model=model, max_functions=300,
            )

            await ws.send_json({
                "kind": "memhint_done",
                "extracted": report.functions_extracted,
                "candidates": report.candidates_filtered,
                "summaries": report.summaries_generated,
                "validated": report.summaries_validated,
                "allocators": [s.to_dict() for s in report.allocators],
                "deallocators": [s.to_dict() for s in report.deallocators],
                "duration_ms": report.duration_ms,
            })
        except Exception as e:
            await ws.send_json({"kind": "memhint_error", "message": str(e)})

    event_q  = asyncio.Queue()
    pipeline = Pipeline(cfg, event_q)

    async def forward_events():
        while True:
            ev = await event_q.get()
            try:
                await ws.send_json({"kind": ev.kind, **ev.payload})
            except WebSocketDisconnect:
                return
            if ev.kind in ("complete", "error"):
                break

    fwd_task = asyncio.create_task(forward_events())
    try:
        await pipeline.run()
    except Exception as e:
        await ws.send_json({"kind": "error", "message": str(e)})
    finally:
        await fwd_task
        try:
            await ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Simple HTML dashboard (single-page, no build step needed)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MemGuard</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--cyan:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--purple:#bc8cff;--text:#c9d1d9;--dim:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:monospace}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
header h1{color:var(--cyan);font-size:1.4rem}
header span{color:var(--dim);font-size:.85rem}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
.card h2{color:var(--cyan);margin-bottom:1rem;font-size:1rem}
input{background:var(--bg);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:.5rem .75rem;font-family:inherit;width:100%;margin-bottom:.75rem;font-size:.9rem}
.btns{display:flex;gap:.5rem;flex-wrap:wrap}
.btn{background:var(--cyan);color:#000;border:none;border-radius:4px;padding:.6rem 1.5rem;cursor:pointer;font-weight:700;font-family:inherit;font-size:.9rem}
.btn:hover{filter:brightness(1.15)}
.btn2{background:var(--purple);color:#fff}
.badge-grid{display:flex;gap:1rem;flex-wrap:wrap}
.badge{background:#21262d;border-radius:6px;padding:.75rem 1.25rem;text-align:center;min-width:90px}
.badge .n{font-size:2rem;font-weight:700}
.badge .l{font-size:.7rem;color:var(--dim);text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;color:var(--dim);padding:.5rem .75rem;border-bottom:1px solid var(--border)}
td{padding:.5rem .75rem;border-bottom:1px solid #21262d}
.log{background:var(--bg);border-radius:4px;padding:1rem;font-size:.8rem;height:220px;overflow-y:auto;white-space:pre-wrap;color:var(--dim)}
.sev{border-radius:3px;padding:2px 6px;font-size:.75rem;font-weight:700}
.critical{background:#f85149;color:#000}.high{color:#f85149}.medium{color:#d29922}.low{color:#58a6ff}.info{color:#8b949e}
#pb{height:3px;background:var(--cyan);width:0%;transition:width .3s;margin-bottom:1rem}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;overflow-y:auto}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:8px;max-width:900px;margin:2rem auto;padding:2rem;position:relative}
.viz-tab{background:var(--surface);color:var(--dim);border:1px solid var(--border);border-radius:4px;padding:.3rem .75rem;cursor:pointer;font-size:.75rem;font-weight:600;transition:all .2s}
.viz-tab:hover{color:var(--text);border-color:var(--cyan)}
.viz-tab.active{background:var(--cyan);color:#000;border-color:var(--cyan)}
.close-btn{position:absolute;top:1rem;right:1rem;cursor:pointer;color:var(--dim);font-size:1.2rem;background:none;border:none;font-family:inherit}
.divider{border:none;border-top:1px solid var(--border);margin:.75rem 0}
.chat-box{margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border)}
.chat-msgs{height:320px;overflow-y:auto;margin-bottom:.5rem;font-size:.88rem;line-height:1.5}
.chat-row{display:flex;gap:.5rem}
.chat-row input{flex:1;margin-bottom:0}
pre{background:var(--bg);padding:1rem;border-radius:4px;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;line-height:1.5}
</style>
</head>
<body>
<header><h1>MemGuard</h1><span>AI-Powered Memory Leak Detector</span></header>
<div class="container">
<div id="pb"></div>
<div class="card">
  <h2>New Scan</h2>
  <input id="inp-target"  placeholder="Binary path or Python script  e.g. /tmp/test_leaks" />
  <input id="inp-compile" placeholder="Compile command (optional)" />
  <input id="inp-args"    placeholder="Binary arguments (optional)" />
  <div style="margin:.5rem 0;padding:.75rem;background:#1c2128;border:1px solid var(--border);border-radius:6px">
    <label style="display:flex;align-items:center;gap:.5rem;cursor:pointer;font-size:.9rem">
      <input type="checkbox" id="chk-memhint" style="width:16px;height:16px;accent-color:#bc8cff" />
      <span style="font-weight:600;color:#bc8cff">MemHint</span>
      <span style="color:var(--dim);font-size:.75rem">— Auto-discover custom allocators (LLM + Z3) and inject into scan</span>
    </label>
    <input id="inp-memhint-src" placeholder="Source directory (leave empty = auto-detect from binary DWARF)" style="display:none;margin-top:.5rem" />
    <div id="memhint-auto-note" style="display:none;margin-top:.4rem;font-size:.75rem;color:var(--dim)">
      Source directory will be auto-detected from binary debug info. Or enter a path manually above.
    </div>
  </div>
  <div class="btns">
    <button class="btn" id="btn-live">Run Scan</button>
    <button class="btn" id="btn-heap" style="background:#8957e5" onclick="runHeaptrack()">Heap Profile</button>
  </div>
</div>
<div class="card">
  <h2>Live Log</h2>
  <div class="log" id="log">Ready. Enter a target path and click Run Scan.</div>
</div>
<div id="stats-card" class="card" style="display:none">
  <h2>Scan Summary</h2>
  <div class="badge-grid" id="badges"></div>
</div>
<div id="memhint-card" class="card" style="display:none">
  <h2 style="color:#bc8cff">MemHint Results</h2>
  <p style="color:var(--dim);font-size:.8rem;margin-bottom:.75rem">Custom memory management functions discovered via LLM + Z3 validation</p>
  <div class="badge-grid" id="mh-badges"></div>
  <div id="mh-allocs" style="margin-top:.75rem"></div>
  <div id="mh-deallocs" style="margin-top:.5rem"></div>
</div>
<div id="results-card" class="card" style="display:none">
  <h2>Issues Found</h2>
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Location</th><th>Tool</th><th>Bytes</th></tr></thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<div id="viz-card" class="card" style="display:none">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.75rem">
    <h2 style="margin:0">Memory Visualization</h2>
    <div style="display:flex;gap:.5rem">
      <button class="viz-tab active" onclick="switchVizTab('timeline')">Allocation Timeline</button>
      <button class="viz-tab" onclick="switchVizTab('heatmap')">Heap Heatmap</button>
      <button class="viz-tab" onclick="switchVizTab('flow')">Pointer Flow</button>
      <button style="background:#30363d;color:var(--dim);border:1px solid var(--border);border-radius:4px;padding:.3rem .75rem;cursor:pointer;font-size:.75rem" onclick="window.open('/scans/'+scanId+'/viz','_blank')">Open Full Page</button>
    </div>
  </div>
  <iframe id="viz-iframe" style="width:100%;height:550px;border:1px solid var(--border);border-radius:6px;background:#0d1117" frameborder="0"></iframe>
</div>
<div class="card">
  <h2>Scan History</h2>
  <div id="history"><em style="color:var(--dim)">Loading...</em></div>
</div>
</div>
<div class="overlay" id="overlay">
  <div class="modal">
    <button class="close-btn" id="close-modal">X</button>
    <div id="modal-body"></div>
  </div>
</div>
<script src="/static/app.js"></script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML

# Mount static AFTER all routes so it does not shadow /
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


def serve(host: str = "127.0.0.1", port: int = 7331):
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    serve()
