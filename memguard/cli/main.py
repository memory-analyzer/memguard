"""
memguard CLI
============
Commands:
  scan    — Analyse a binary or source directory
  fix     — Re-open an existing scan result for interactive fixing
  watch   — File-watcher mode: re-scan on source change
  report  — Pretty-print or export a past scan
  history — List all past scans
  models  — Show/manage local Ollama models
  doctor  — Check tool availability and system health
"""

from __future__ import annotations
import os
import subprocess
import time

import asyncio
import json
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import box

app     = typer.Typer(
    name="memguard",
    help="[bold cyan]MemGuard[/] — AI-powered memory leak detector & interactive debugger",
    rich_markup_mode="rich",
    add_completion=True,
)
console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_language(path: str):
    from ..core.schema import Language
    p = Path(path)
    if p.is_file():
        lang = {
            ".c": Language.C, ".cpp": Language.CPP,
            ".cc": Language.CPP, ".cxx": Language.CPP,
            ".py": Language.PYTHON, ".rs": Language.RUST,
        }.get(p.suffix.lower())
        # No extension = compiled binary, assume C
        return lang if lang else Language.C
    # Directory: look at majority of source files
    counts = {Language.C: 0, Language.CPP: 0,
              Language.PYTHON: 0, Language.RUST: 0}
    for f in Path(path).rglob("*"):
        lang = {".c": Language.C, ".cpp": Language.CPP,
                ".py": Language.PYTHON, ".rs": Language.RUST}.get(
                    f.suffix.lower()
                )
        if lang:
            counts[lang] += 1
    return max(counts, key=counts.get) if any(counts.values()) else Language.C


def _default_tools(language):
    from ..core.schema import Language, AnalysisTool
    from ..core.runner import available_tools
    return available_tools(language)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument(..., help="Binary path, source dir, or Python script"),
    tools:  str = typer.Option("auto", "--tools", "-t",
                               help="Comma-separated tools or 'auto'"),
    model:  str = typer.Option("auto", "--model", "-m",
                               help="Ollama model or 'auto'"),
    compile_cmd: str = typer.Option(None, "--compile",
                                    help="Compile command (needed for ASan)"),
    args:   str = typer.Option("", "--args", "-a",
                               help="Arguments to pass to the binary"),
    max_errors: int = typer.Option(50, "--max-errors"),
    no_ai:  bool = typer.Option(False, "--no-ai",
                                help="Skip AI analysis (tools only)"),
    output: str = typer.Option(None, "--out", "-o",
                               help="Save JSON report to file"),
    concurrency: int = typer.Option(2, "--concurrency",
                                    help="Parallel AI analysis jobs"),
    verbose: bool = typer.Option(False, "--verbose", "-v",
                                 help="Show debug logs (tool commands, XML sizes)"),
):
    """[bold cyan]Scan[/] a binary or source for memory issues with full AI analysis."""
    if verbose:
        import logging as _log
        _log.basicConfig(level=_log.DEBUG,
                         format="[%(name)s] %(message)s")
    asyncio.run(_scan_async(
        target, tools, model, compile_cmd, args,
        max_errors, no_ai, output, concurrency,
    ))


async def _scan_async(
    target_path, tools_str, model_str, compile_cmd,
    args_str, max_errors, no_ai, output, concurrency,
):
    from ..core.schema import (
        ScanConfig, ScanTarget, AnalysisTool, Language,
    )
    from ..core.runner import available_tools
    from ..pipeline.orchestrator import Pipeline
    from ..ai.client import best_available_model
    from .tui import (
        print_banner, ScanProgress, render_error_table,
        render_error_detail, render_analysis_panel, render_fix_panel,
        render_scan_summary, stream_analysis_display,
        InteractiveTUI,
    )
    from ..debugger.interactive import InteractiveDebugger
    import rich.prompt as rp

    print_banner()

    language   = _detect_language(target_path)
    console.print(f"[dim]Target:[/] [cyan]{target_path}[/]  "
                  f"[dim]Language:[/] [cyan]{language.value}[/]")

    # Resolve tools
    if tools_str == "auto":
        tool_list = available_tools(language)
    else:
        tool_list = [AnalysisTool(t.strip()) for t in tools_str.split(",")]

    console.print(f"[dim]Tools:[/] {', '.join(t.value for t in tool_list)}\n")

    # Resolve model
    if model_str == "auto":
        try:
            model_str = await best_available_model()
        except RuntimeError as e:
            console.print(f"[bold red]{e}[/]")
            raise typer.Exit(1)

    console.print(f"[dim]AI Model:[/] [purple]{model_str}[/]\n")

    target = ScanTarget(
        binary      = target_path if Path(target_path).is_file() else None,
        source_dir  = target_path if Path(target_path).is_dir()  else None,
        files       = [target_path] if Path(target_path).suffix == ".py" else [],
        language    = language,
        compile_cmd = compile_cmd,
        args        = args_str.split() if args_str else [],
    )

    cfg = ScanConfig(
        target      = target,
        tools       = tool_list,
        max_errors  = max_errors,
        ai_model    = model_str,
    )

    # Wire progress events → TUI
    event_q  = asyncio.Queue()
    pipeline = Pipeline(cfg, event_q)

    # Collect all events; drain queue after pipeline finishes
    events_log: list = []

    async def consume_events():
        while True:
            ev = await event_q.get()
            events_log.append(ev)
            event_q.task_done()
            if ev.kind in ("complete", "error"):
                break

    consumer = asyncio.create_task(consume_events())
    result   = await pipeline.run()
    await consumer

    # ── Replay events into TUI now that all data is ready ──
    tool_results: dict = {}
    for ev in events_log:
        if ev.kind == "tool_done":
            tool_results[ev.payload["tool"]] = ev.payload.get("error_count", 0)

    # Print tool summary table
    from rich.table import Table as _Table
    from rich import box as _box
    ttbl = _Table(box=_box.SIMPLE, show_header=False, padding=(0, 2))
    ttbl.add_column(style="dim")
    ttbl.add_column()
    ttbl.add_column(justify="right")
    for tool_name, cnt in tool_results.items():
        color = "green" if cnt == 0 else "bold red"
        ttbl.add_row(
            "✓", f"[cyan]{tool_name}[/]",
            f"[{color}]{cnt} issue{'s' if cnt != 1 else ''}[/]"
        )
    console.print(ttbl)

    # --- Display results ---
    console.print()
    console.print(render_scan_summary(result))
    console.print()

    if not result.errors:
        console.print("[bold green]✓ No memory issues found![/]")
        return

    console.print(render_error_table(result.errors))
    console.print()

    # ── Novel: CVE Pattern Matches ──
    from ..ai.explainability import match_cve_patterns, find_bug_relationships
    from rich.panel import Panel

    cve_matches = match_cve_patterns(result.errors)
    if cve_matches:
        top = cve_matches[:3]
        cve_lines = []
        for m in top:
            c = m["cve"]
            cve_lines.append(
                f"[red]{c.cve_id}[/] {c.name} "
                f"[dim](CVSS {c.cvss_score}, {int(c.similarity*100)}% similar)[/]"
            )
        console.print(Panel(
            "\n".join(cve_lines),
            title=f"[bold red]Similar CVEs ({len(cve_matches)} matched)[/]",
            border_style="red",
        ))

    # ── Novel: Bug Relationships ──
    rels = find_bug_relationships(result.errors)
    if rels:
        rel_lines = []
        icons = {"causes": "->", "masks": ">>", "amplifies": "**", "same_root_cause": "=="}
        for r in rels[:5]:
            icon = icons.get(r.relationship, "--")
            rel_lines.append(f"[cyan]{r.from_id}[/] {icon} [cyan]{r.to_id}[/]  "
                           f"[dim]{r.explanation}[/]")
        console.print(Panel(
            "\n".join(rel_lines),
            title="[bold cyan]Bug Relationships[/]",
            border_style="cyan",
        ))

    # ── Novel: Binary Hardening Quick Check ──
    binary_path = result.config.target.binary
    if binary_path and Path(binary_path).is_file():
        try:
            from ..core.hardening import check_mitigations, correlate_bugs_with_mitigations
            mits = await check_mitigations(binary_path)
            disabled = [m for m in mits if not m.enabled and m.name not in ("Sanitizer", "Debug Info")]
            if disabled:
                exploitable = correlate_bugs_with_mitigations(result.errors, mits)
                trivial = [c for c in exploitable if c.exploitability in ("TRIVIAL", "LIKELY")]
                mit_names = ", ".join(m.name for m in disabled)
                warn = f"[red]Missing:[/] {mit_names}"
                if trivial:
                    warn += f"\n[red bold]{len(trivial)} bug(s) exploitable due to missing mitigations[/]"
                warn += f"\n[dim]Run: memguard harden {binary_path} --scan {result.scan_id[:8]}[/]"
                console.print(Panel(warn,
                    title="[bold red]Hardening[/]",
                    border_style="red"))
        except Exception:
            pass  # Non-critical — don't break scan on hardening check failure

    console.print()

    if no_ai:
        if output:
            Path(output).write_text(result.model_dump_json(indent=2))
            console.print(f"[green]Report saved → {output}[/]")
        return

    # Interactive selection loop
    while True:
        choice = rp.Prompt.ask(
            "\n[bold cyan]Select issue # for details (or 'q' to quit)[/]",
            default="q",
        ).strip()

        if choice.lower() == "q":
            break

        try:
            idx = int(choice) - 1
            err = result.errors[idx]
        except (ValueError, IndexError):
            console.print("[red]Invalid selection[/]")
            continue

        # Find matching analysis
        analysis = next(
            (a for a in result.analyses if a.error_id == err.id), None
        )

        console.print(render_error_detail(err, idx + 1, len(result.errors)))
        console.print()

        if analysis:
            console.print(render_analysis_panel(analysis))
            console.print()
            console.print(render_fix_panel(analysis))
            console.print()

            fix_choice = rp.Prompt.ask(
                "[bold cyan]Start interactive guided fix? [y/n][/]",
                default="n",
            ).strip().lower()

            if fix_choice == "y":
                session = next(
                    (s for s in result.sessions if s.error_id == err.id), None
                )
                if not session:
                    console.print("[red]No session available for this error[/]")
                    continue

                session.steps = next(
                    (r.steps for r in [
                        type("R", (), {"steps": [], "analysis": a})()
                        for a in result.analyses if a.error_id == err.id
                    ]), []
                )

                # Re-load steps from pipeline result
                from ..pipeline.orchestrator import load_result
                full = load_result(result.scan_id)
                if full:
                    session = next(
                        (s for s in full.sessions if s.error_id == err.id), session
                    )

                root_dir = (
                    str(Path(err.primary_location.file).parent)
                    if err.primary_location else "."
                )

                debugger = InteractiveDebugger(
                    session  = session,
                    error    = err,
                    analysis = analysis,
                    root_dir = root_dir,
                    model    = model_str,
                )
                tui = InteractiveTUI(debugger)
                await tui.run()

    if output:
        Path(output).write_text(result.model_dump_json(indent=2))
        console.print(f"[green]Report saved → {output}[/]")

    console.print(f"\n[dim]Scan ID: {result.scan_id}[/]")


# ---------------------------------------------------------------------------
# fix  (reopen existing scan)
# ---------------------------------------------------------------------------

@app.command()
def fix(
    scan_id: str = typer.Argument(..., help="Scan ID from a previous run"),
    error_index: int = typer.Option(0, "--error", "-e", help="Error index (0-based)"),
):
    """[bold green]Re-open[/] an existing scan result for interactive guided fixing."""
    asyncio.run(_fix_async(scan_id, error_index))


async def _fix_async(scan_id: str, error_index: int):
    from ..pipeline.orchestrator import load_result
    from ..debugger.interactive import InteractiveDebugger
    from .tui import InteractiveTUI, print_banner

    print_banner()
    result = load_result(scan_id)
    if not result:
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)

    if error_index >= len(result.errors):
        console.print(f"[red]Error index {error_index} out of range "
                      f"(scan has {len(result.errors)} errors)[/]")
        raise typer.Exit(1)

    err      = result.errors[error_index]
    analysis = next((a for a in result.analyses if a.error_id == err.id), None)
    session  = next((s for s in result.sessions if s.error_id == err.id), None)

    if not analysis or not session:
        console.print("[red]Analysis data not found for this error[/]")
        raise typer.Exit(1)

    root_dir = (
        str(Path(err.primary_location.file).parent)
        if err.primary_location else "."
    )

    debugger = InteractiveDebugger(
        session=session, error=err, analysis=analysis, root_dir=root_dir,
    )
    await InteractiveTUI(debugger).run()


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------

@app.command()
def watch(
    source_dir: str = typer.Argument(".", help="Directory to watch"),
    binary: str = typer.Option(None, "--binary", "-b"),
    compile_cmd: str = typer.Option(None, "--compile"),
    debounce: float = typer.Option(2.0, "--debounce",
                                   help="Seconds to wait after last change"),
):
    """[bold yellow]Watch[/] source files and re-scan on every change."""
    asyncio.run(_watch_async(source_dir, binary, compile_cmd, debounce))


async def _watch_async(source_dir, binary, compile_cmd, debounce):
    try:
        from watchfiles import awatch
    except ImportError:
        console.print("[red]Install watchfiles: pip install watchfiles[/]")
        raise typer.Exit(1)

    console.print(f"[cyan]Watching {source_dir} for changes...[/] (Ctrl-C to stop)\n")
    last_scan = 0.0

    async for changes in awatch(source_dir):
        now = time.monotonic()
        if now - last_scan < debounce:
            continue
        last_scan = now

        changed = [str(c[1]) for c in changes]
        console.print(f"\n[yellow]Changed:[/] {', '.join(Path(c).name for c in changed[:3])}")
        console.rule("[cyan]Re-scanning...[/]")

        if compile_cmd:
            import shlex
            r = subprocess.run(shlex.split(compile_cmd), capture_output=True)
            if r.returncode != 0:
                console.print(f"[red]Compile failed:\n{r.stderr.decode()[:500]}[/]")
                continue

        await _scan_async(
            binary or source_dir, "auto", "auto",
            compile_cmd, "", 20, False, None, 1,
        )


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@app.command()
def report(
    scan_id: str = typer.Argument(...),
    fmt: str = typer.Option("table", "--format", "-f",
                            help="table | json | markdown | sarif"),
    output: str = typer.Option(None, "--out", "-o"),
):
    """[bold]Export[/] a past scan as table, JSON, Markdown, or SARIF."""
    from ..pipeline.orchestrator import load_result
    from .tui import render_error_table, render_scan_summary

    result = load_result(scan_id)
    if not result:
        # Try prefix match
        from pathlib import Path as _Path
        results_dir = _Path.home() / ".memguard" / "results"
        matches = list(results_dir.glob(f"{scan_id}*.json"))
        if matches:
            from ..pipeline.orchestrator import ScanResult as _SR
            result = _SR.model_validate_json(matches[0].read_text())
        else:
            console.print(f"[red]Scan {scan_id} not found[/]")
            raise typer.Exit(1)

    if fmt == "table":
        console.print(render_scan_summary(result))
        console.print(render_error_table(result.errors))

    elif fmt == "json":
        text = result.model_dump_json(indent=2)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]Saved → {output}[/]")
        else:
            print(text)

    elif fmt == "markdown":
        lines = [
            f"# MemGuard Report — {result.scan_id}",
            f"**Date**: {result.started_at}  |  **Duration**: {result.duration_ms}ms\n",
            f"## Summary",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev, cnt in result.error_count_by_severity.items():
            lines.append(f"| {sev} | {cnt} |")
        lines += ["", "## Issues", ""]
        for i, err in enumerate(result.errors, 1):
            loc = str(err.primary_location) if err.primary_location else "unknown"
            lines.append(f"### {i}. {err.bug_type.value} — {err.severity.value}")
            lines.append(f"**Location**: `{loc}`  ")
            lines.append(f"**Tool**: {err.tool.value}  ")
            lines.append(f"{err.message}\n")
            analysis = next((a for a in result.analyses if a.error_id == err.id), None)
            if analysis:
                lines.append(f"**Root cause**: {analysis.root_cause}\n")
                for fix in analysis.fixes:
                    lines.append(f"**Fix**: {fix.description}")
                    if fix.diff:
                        lines.append(f"```diff\n{fix.diff}\n```")
            lines.append("")
        text = "\n".join(lines)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]Saved → {output}[/]")
        else:
            print(text)

    elif fmt == "sarif":
        # SARIF 2.1.0 for IDE/CI integration
        runs = []
        for err in result.errors:
            loc = err.primary_location
            runs.append({
                "ruleId": err.bug_type.value,
                "level": {"critical": "error", "high": "error",
                          "medium": "warning", "low": "note",
                          "info": "none"}.get(err.severity.value, "warning"),
                "message": {"text": err.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.file if loc else "unknown"},
                        "region": {"startLine": loc.line if loc else 1},
                    }
                }] if loc else [],
            })
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "memguard"}}, "results": runs}],
        }
        text = json.dumps(sarif, indent=2)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]SARIF saved → {output}[/]")
        else:
            print(text)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------

@app.command()
def history(limit: int = typer.Option(20, "--limit", "-n")):
    """[bold]List[/] past scan results."""
    from ..pipeline.orchestrator import list_results

    results = list_results()[:limit]
    if not results:
        console.print("[dim]No scan history found.[/]")
        return

    t = Table(title="Scan History", box=box.ROUNDED, border_style="cyan")
    t.add_column("Scan ID", style="dim")
    t.add_column("Date")
    t.add_column("Total", justify="right")
    t.add_column("Critical", justify="right", style="bold red")
    t.add_column("High",     justify="right", style="red")

    for r in results:
        t.add_row(
            r["scan_id"][:16],
            str(r.get("started_at", ""))[:19],
            str(r["total"]),
            str(r["critical"]),
            str(r["high"]),
        )
    console.print(t)


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------

@app.command()
def models(
    pull: str = typer.Option(None, "--pull", help="Pull a model via ollama"),
):
    """[bold purple]Manage[/] local Ollama models for AI analysis."""
    asyncio.run(_models_async(pull))


async def _models_async(pull: str | None):
    from ..ai.client import list_local_models, DEFAULT_MODEL, FALLBACK_MODEL, FAST_MODEL

    if pull:
        console.print(f"[cyan]Pulling {pull}...[/]")
        subprocess.run(["ollama", "pull", pull])
        return

    installed = await list_local_models()
    t = Table(title="Local Models", box=box.ROUNDED, border_style="purple")
    t.add_column("Model")
    t.add_column("Role")
    t.add_column("Status")

    roles = {
        DEFAULT_MODEL:  "Primary (best quality)",
        FALLBACK_MODEL: "Fallback (complex leaks)",
        FAST_MODEL:     "Fast (triage)",
    }
    for m in installed:
        role   = next((v for k, v in roles.items() if k in m), "—")
        status = "[green]✓ installed[/]"
        t.add_row(m, role, status)

    if not installed:
        console.print("[red]No models installed. Run:[/]")
        console.print(f"  [cyan]memguard models --pull {DEFAULT_MODEL}[/]")
    else:
        console.print(t)


# ---------------------------------------------------------------------------
# record — Record execution for time-travel replay
# ---------------------------------------------------------------------------

@app.command()
def record(
    binary: str = typer.Argument(..., help="Binary to record"),
    args: str = typer.Option("", "--args", "-a", help="Program arguments"),
    timeout: int = typer.Option(60, "--timeout", "-t", help="Max seconds"),
):
    """[bold cyan]Record[/] — record program execution for time-travel replay"""
    from ..core.timetravel import record_execution, check_rr_prerequisites, detect_backend
    from rich.panel import Panel
    import asyncio

    backend = detect_backend()
    if backend == "none":
        console.print("[red]No time-travel backend found.[/]")
        console.print("  Install rr: [cyan]sudo apt install rr[/]")
        console.print("  Then: [cyan]sudo sysctl kernel.perf_event_paranoid=1[/]")
        raise typer.Exit(1)

    if backend == "rr":
        issues = check_rr_prerequisites()
        if issues:
            console.print("[yellow]rr prerequisites:[/]")
            for issue in issues:
                console.print(f"  [yellow]{issue}[/]")

    console.print(f"[cyan]Recording with {backend}...[/]")
    run_args = args.split() if args else []

    info = asyncio.run(record_execution(binary, run_args, timeout=timeout))

    color = "green" if info.exit_code == 0 else "yellow"
    console.print(Panel(
        f"[bold green]Recording saved[/]\n\n"
        f"ID:        [cyan]{info.recording_id}[/]\n"
        f"Backend:   {info.tool}\n"
        f"Duration:  {info.duration_ms}ms\n"
        f"Exit code: [{color}]{info.exit_code}[/]\n"
        f"Events:    {info.events}\n"
        f"Size:      {info.size_mb} MB\n"
        f"Dir:       [dim]{info.recording_dir}[/]",
        title="[bold cyan]Time-Travel Recording[/]",
        border_style="cyan",
    ))

    console.print(f"\n[dim]Replay with: memguard replay {info.recording_id}[/]")
    console.print(f"[dim]Or timewarp: memguard timewarp <scan-id> --recording {info.recording_id}[/]")


# ---------------------------------------------------------------------------
# replay — Replay a recording with reverse debugging
# ---------------------------------------------------------------------------

@app.command()
def replay(
    recording_id: str = typer.Argument(..., help="Recording ID"),
):
    """[bold cyan]Replay[/] — replay a recording with reverse debugging"""
    from ..core.timetravel import list_recordings, detect_backend, RECORDINGS_DIR
    from rich.panel import Panel

    # Find recording
    recordings = list_recordings()
    match = None
    for r in recordings:
        if r.recording_id.startswith(recording_id):
            match = r
            break

    if not match:
        console.print(f"[red]Recording '{recording_id}' not found[/]")
        console.print("[dim]List recordings: memguard recordings[/]")
        raise typer.Exit(1)

    if match.tool == "rr":
        trace_path = Path(match.recording_dir) / "trace"
        if not trace_path.exists():
            console.print("[yellow]rr trace not found — using GDB reverse debug[/]")
            match.tool = "gdb"

    if match.tool == "rr":
        trace_path = Path(match.recording_dir) / "trace"
        cmd_parts = ["rr", "replay", str(trace_path)]
    else:
        # Create an interactive replay script that restores the recording
        rec_file = Path(match.recording_dir) / "gdb_record.rec"
        replay_script = Path(match.recording_dir) / "replay.gdb"
        replay_script.write_text(
            "set pagination off\n"
            "set confirm off\n"
            "set environment GLIBC_TUNABLES glibc.cpu.hwcaps=-AVX2,-AVX,-AVX_Fast_Unaligned_Load\n"
            "break main\n"
            "run\n"
            "record\n"
            "echo \\n=== MemGuard Time-Travel Debugger ===\\n\n"
            "echo Type 'continue' to run to end, then 'reverse-continue' to go backwards\\n\n"
            "echo Type 'reverse-step' to step back one line\\n\n"
            "echo Type 'reverse-next' to step back over function calls\\n\\n\n"
        )
        cmd_parts = ["gdb", "-x", str(replay_script), "--args", match.binary]

    backend_note = ""
    if match.tool == "gdb":
        backend_note = (
            "\n\n[yellow]Note: Using GDB reverse (rr unavailable for this CPU).\n"
            "Type 'record' after 'run' to enable reverse execution.[/]"
        )

    console.print(Panel(
        f"[bold]Launching reverse debugger[/]\n\n"
        f"Recording: [cyan]{match.recording_id}[/]\n"
        f"Binary:    {match.binary}\n"
        f"Backend:   {match.tool}\n\n"
        f"[bold yellow]Key commands:[/]\n"
        f"  reverse-continue (rc) — run backwards\n"
        f"  reverse-step (rs)     — step back one line\n"
        f"  reverse-next (rn)     — step back, skip calls\n"
        f"  reverse-finish        — back to caller\n"
        f"  when <N>              — jump to event N (rr only)"
        f"{backend_note}",
        title="[bold cyan]Time-Travel Replay[/]",
        border_style="cyan",
    ))

    os.execvp(cmd_parts[0], cmd_parts)


# ---------------------------------------------------------------------------
# timewarp — Auto-debug bugs with reverse execution
# ---------------------------------------------------------------------------

@app.command()
def timewarp(
    scan_id: str = typer.Argument(..., help="Scan ID with detected bugs"),
    recording: str = typer.Option(None, "--recording", "-r", help="Recording ID to replay"),
    issue: int = typer.Option(0, "--issue", "-i", help="Focus on specific issue (0=all)"),
    launch: bool = typer.Option(False, "--launch", "-l", help="Auto-launch debugger"),
):
    """[bold cyan]Timewarp[/] — auto-set breakpoints at bugs and reverse-debug"""
    from ..core.timetravel import (
        generate_timewarp_script, save_timewarp_script, detect_backend,
    )
    from rich.panel import Panel

    result = _load_scan_result(scan_id)
    if not result:
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)

    errors = result.errors
    if issue > 0 and issue <= len(errors):
        errors = [errors[issue - 1]]

    binary = str(result.config.target.binary or "")
    if not binary:
        console.print("[red]Scan has no binary target — timewarp requires a binary[/]")
        raise typer.Exit(1)

    script = generate_timewarp_script(errors, binary, scan_id[:8], recording)
    script_path = save_timewarp_script(script)

    # Show breakpoints
    console.print(Panel(
        f"[bold]{len(script.breakpoints)} breakpoint(s) set at detected bugs[/]",
        title="[bold cyan]Time-Travel Debug Script[/]",
        border_style="cyan",
    ))

    for i, bp in enumerate(script.breakpoints, 1):
        color = {"use_after_free": "red", "double_free": "red",
                 "buffer_overflow": "red", "race_condition": "yellow",
                 "memory_leak": "cyan", "null_deref": "yellow"}.get(bp.bug_type, "white")
        console.print(Panel(
            f"[{color}]{bp.bug_type.upper()}[/] in [bold]{bp.function}()[/]\n"
            f"Location: [cyan]{bp.location}[/]\n"
            f"[dim]{bp.description}[/]",
            border_style=color,
        ))

    # Instructions
    console.print("\n[bold yellow]How to use:[/]")
    for step in script.instructions:
        console.print(f"  {step}")

    # Launch command
    console.print(Panel(
        f"[bold cyan]{script.launch_cmd}[/]",
        title="[bold green]Launch Command[/]",
        border_style="green",
    ))

    console.print(f"[dim]Script saved to: {script_path}[/]")

    if launch:
        console.print("\n[cyan]Launching debugger...[/]")
        # Check if rr actually works on this CPU
        if "rr replay" in script.launch_cmd:
            import subprocess as _sp
            test = _sp.run(["rr", "record", "--bind-to-cpu=0", "/bin/true"],
                           capture_output=True, text=True, timeout=5)
            if test.returncode != 0 and "unknown" in (test.stdout + test.stderr).lower():
                console.print("[yellow]rr doesn't support this CPU — launching GDB instead[/]")
                gdb_cmd = ["gdb", "-x", "/tmp/memguard_timewarp.gdb",
                           "--args", binary]
                os.execvp("gdb", gdb_cmd)
        os.execvp(script.launch_cmd.split()[0], script.launch_cmd.split())


# ---------------------------------------------------------------------------
# recordings — List saved recordings
# ---------------------------------------------------------------------------

@app.command()
def recordings():
    """[bold cyan]List[/] saved time-travel recordings"""
    from ..core.timetravel import list_recordings
    from rich.table import Table

    recs = list_recordings()
    if not recs:
        console.print("[dim]No recordings. Create one with: memguard record <binary>[/]")
        return

    t = Table(title="Saved Recordings", show_header=True, header_style="bold cyan")
    t.add_column("ID", style="cyan")
    t.add_column("Binary")
    t.add_column("Backend")
    t.add_column("Duration", justify="right")
    t.add_column("Events", justify="right")
    t.add_column("Size", justify="right")

    for r in recs:
        t.add_row(
            r.recording_id,
            Path(r.binary).name,
            r.tool,
            f"{r.duration_ms}ms",
            str(r.events),
            f"{r.size_mb} MB",
        )
    console.print(t)


# ---------------------------------------------------------------------------
# memhint — Neuro-Symbolic MM Function Discovery
# ---------------------------------------------------------------------------

@app.command()
def memhint(
    source_dir: str = typer.Argument(..., help="Source directory to analyze"),
    model: str = typer.Option("qwen2.5-coder:14b-instruct-q4_K_M", "--model", "-m"),
    output: str = typer.Option(None, "--output", "-o", help="Save summaries to JSON"),
    no_z3: bool = typer.Option(False, "--no-z3", help="Skip Z3 validation"),
    max_funcs: int = typer.Option(500, "--max-functions", help="Max files to scan"),
):
    """[bold cyan]MemHint[/] — discover custom allocators/deallocators with LLM + Z3"""
    from ..core.memhint import run_memhint_pipeline, save_summaries, Z3_AVAILABLE
    from rich.panel import Panel
    from rich.table import Table

    def on_progress(msg):
        console.print(f"  [dim]{msg}[/]")

    console.print(Panel(
        "[bold]Neuro-Symbolic Memory Management Discovery[/]\n"
        "[dim]LLM classifies functions → Z3 validates reachability[/]",
        title="[bold cyan]MemHint Pipeline[/]",
        border_style="cyan",
    ))

    report = asyncio.run(run_memhint_pipeline(
        source_dir, model=model, max_functions=max_funcs,
        skip_z3=no_z3, progress_callback=on_progress,
    ))

    # Summary table
    console.print(Panel(
        f"[bold]Pipeline Summary[/]\n\n"
        f"Functions extracted:  {report.functions_extracted}\n"
        f"Candidates filtered: {report.candidates_filtered}\n"
        f"LLM summaries:       {report.summaries_generated}\n"
        f"Z3 validated:        {report.summaries_validated}\n"
        f"Duration:            {report.duration_ms}ms\n"
        f"Z3 available:        {'yes' if Z3_AVAILABLE else 'no'}",
        title="[bold green]Results[/]",
        border_style="green",
    ))

    # Allocators table
    if report.allocators:
        t = Table(title=f"Custom Allocators ({len(report.allocators)})",
                  show_header=True, header_style="bold green")
        t.add_column("Function", style="cyan")
        t.add_column("Target")
        t.add_column("Validated", justify="center")
        t.add_column("Confidence", justify="right")
        for s in report.allocators[:30]:
            v = "[green]✓[/]" if s.validated else "[red]✗[/]"
            t.add_row(s.name, s.target, v, f"{s.confidence:.0%}")
        console.print(t)

    # Deallocators table
    if report.deallocators:
        t = Table(title=f"Custom Deallocators ({len(report.deallocators)})",
                  show_header=True, header_style="bold red")
        t.add_column("Function", style="cyan")
        t.add_column("Target")
        t.add_column("Validated", justify="center")
        t.add_column("Confidence", justify="right")
        for s in report.deallocators[:30]:
            v = "[green]✓[/]" if s.validated else "[red]✗[/]"
            t.add_row(s.name, s.target, v, f"{s.confidence:.0%}")
        console.print(t)

    # Infer flags
    if report.infer_flags:
        console.print(Panel(
            f"[bold]Infer integration:[/]\n"
            f"[cyan]infer run --pulse {report.infer_flags} -- gcc ...[/]\n\n"
            f"[bold]MemGuard integration:[/]\n"
            f"[cyan]memguard scan <binary> --tools infer --memhint-summaries hints.json[/]",
            title="[bold green]Usage[/]",
            border_style="green",
        ))

    # Save summaries
    if output:
        all_summaries = report.allocators + report.deallocators
        save_summaries(all_summaries, output)
        console.print(f"[green]Summaries saved → {output}[/]")
    else:
        default_path = str(Path.home() / ".memguard" / "memhint_summaries.json")
        all_summaries = report.allocators + report.deallocators
        Path(default_path).parent.mkdir(parents=True, exist_ok=True)
        save_summaries(all_summaries, default_path)
        console.print(f"[dim]Summaries auto-saved → {default_path}[/]")


# ---------------------------------------------------------------------------
# taint — Taint Flow Analysis
# ---------------------------------------------------------------------------

@app.command()
def taint(
    scan_id: str = typer.Argument(..., help="Scan ID to analyze"),
    source_dir: str = typer.Option(None, "--source", "-s", help="Source directory"),
):
    """[bold red]Taint[/] — trace external input to memory bugs"""
    from ..core.taintflow import run_taint_analysis
    from rich.panel import Panel
    from rich.table import Table

    result = _load_scan_result(scan_id)
    if not result:
        console.print(f"[red]Scan {scan_id} not found[/]")
        raise typer.Exit(1)

    # Auto-detect source dir from binary DWARF
    src = source_dir
    if not src:
        binary = str(result.config.target.binary or "")
        if binary:
            src_files = asyncio.run(
                __import__('memguard.core.runner', fromlist=['_discover_sources_from_binary'])
                ._discover_sources_from_binary(binary)
            ) if binary else []
            if src_files:
                src = str(Path(src_files[0]).parent)
        if not src:
            console.print("[red]No source directory found. Use --source <dir>[/]")
            raise typer.Exit(1)

    console.print(f"[red]Analyzing taint flow from {src}...[/]")
    report = run_taint_analysis(src, result.errors, str(result.config.target.binary or ""))

    # Summary
    console.print(Panel(
        f"[bold]{report.risk_summary}[/]\n\n"
        f"Taint sources found: [cyan]{len(report.taint_sources)}[/]\n"
        f"Call graph:          [cyan]{report.call_graph_size}[/] functions\n"
        f"Taint paths:         [cyan]{len(report.taint_paths)}[/]\n"
        f"Bugs reachable:      [red]{report.reachable_bugs}[/] / {report.total_bugs}\n"
        f"Bugs isolated:       [green]{report.isolated_bugs}[/] / {report.total_bugs}",
        title="[bold red]Taint Flow Analysis[/]",
        border_style="red",
    ))

    # Taint sources table
    if report.taint_sources:
        t = Table(title=f"Input Sources ({len(report.taint_sources)})",
                  show_header=True, header_style="bold")
        t.add_column("Type", style="yellow")
        t.add_column("Call", style="cyan")
        t.add_column("Function")
        t.add_column("Location", style="dim")
        t.add_column("Risk", justify="center")
        for s in report.taint_sources[:20]:
            rc = {"high": "[red]HIGH[/]", "medium": "[yellow]MED[/]", "low": "[green]LOW[/]"}.get(s.risk_level, s.risk_level)
            t.add_row(s.source_type, s.call_site + "()", s.function + "()", f"{s.file}:{s.line}", rc)
        console.print(t)

    # Taint paths
    if report.taint_paths:
        console.print()
        for p in report.taint_paths[:10]:
            color = "red" if p.source.risk_level == "high" else "yellow"
            flow = " → ".join(p.path_functions)
            console.print(Panel(
                f"[bold]{p.source.call_site}()[/] ({p.source.source_type}) → "
                f"[{color}]{p.target_bug_type.upper()}[/] at {p.target_location}\n"
                f"[dim]Flow: {flow}[/]\n"
                f"Confidence: {p.confidence:.0%}\n\n"
                f"{p.risk_assessment}",
                border_style=color,
            ))
    elif report.taint_sources:
        console.print("[green]No taint paths reach detected bugs — externally isolated.[/]")


# ---------------------------------------------------------------------------
# heapprofile — Heap memory profiling with heaptrack
# ---------------------------------------------------------------------------

@app.command()
def heapprofile(
    binary: str = typer.Argument(..., help="Binary to profile"),
    args: str = typer.Option("", "--args", "-a", help="Program arguments"),
    timeout: int = typer.Option(60, "--timeout", "-t"),
    open_browser: bool = typer.Option(True, "--open/--no-open"),
):
    """[bold purple]HeapProfile[/] — heap memory profiling with heaptrack"""
    from ..core.heaptrack import run_heaptrack, parse_heaptrack, generate_heaptrack_viz
    from rich.panel import Panel

    if not shutil.which("heaptrack"):
        console.print("[red]heaptrack not installed[/]")
        console.print("  [cyan]sudo apt install heaptrack[/]")
        raise typer.Exit(1)

    console.print("[purple]Recording heap activity...[/]")
    run_args = args.split() if args else []
    rec_file = asyncio.run(run_heaptrack(binary, run_args, timeout=timeout))

    if not rec_file:
        console.print("[red]heaptrack recording failed[/]")
        raise typer.Exit(1)

    console.print(f"[green]Recording: {rec_file}[/]")
    console.print("[purple]Parsing heap profile...[/]")

    report = asyncio.run(parse_heaptrack(rec_file, binary))

    console.print(Panel(
        f"[bold]Peak heap:[/] [purple]{report.peak_heap_bytes:,}[/] bytes\n"
        f"[bold]Total allocations:[/] {report.total_allocations:,}\n"
        f"[bold]Total allocated:[/] {report.total_bytes_allocated:,} bytes\n"
        f"[bold]Temporary:[/] {report.total_temporary:,} ({report.total_temporary_pct:.1f}%)\n"
        f"[bold]Leaked:[/] [red]{report.leaked_bytes:,}[/] bytes\n"
        f"[bold]Top consumers:[/] {len(report.top_sites)}",
        title="[bold purple]Heap Profile[/]",
        border_style="purple",
    ))

    # Generate and open visualization
    html = generate_heaptrack_viz(report)
    out_path = Path(tempfile.mkdtemp(prefix="mg_heap_")) / "heap_profile.html"
    out_path.write_text(html)
    console.print(f"[green]Visualization saved → {out_path}[/]")

    if open_browser:
        import webbrowser
        webbrowser.open(f"file://{out_path}")


# ---------------------------------------------------------------------------
# harden — Binary Security Hardening Audit
# ---------------------------------------------------------------------------

@app.command()
def harden(
    binary: str = typer.Argument(..., help="Binary to audit"),
    scan_id: str = typer.Option(None, "--scan", "-s", help="Correlate with scan results"),
):
    """[bold cyan]Harden[/] — audit binary security mitigations and correlate with detected bugs"""
    from ..core.hardening import generate_hardening_report
    from rich.panel import Panel
    from rich.table import Table
    import asyncio

    errors = []
    if scan_id:
        result = _load_scan_result(scan_id)
        if result:
            errors = result.errors

    report = asyncio.run(generate_hardening_report(binary, errors))

    # Grade header
    gc = {"A+": "green", "A": "green", "B": "cyan", "C": "yellow",
          "D": "red", "F": "red"}.get(report.grade, "white")
    console.print(Panel(
        f"[bold {gc}]{report.hardening_score}/100  Grade: {report.grade}[/]\n"
        f"[dim]{report.binary}[/]",
        title="[bold cyan]Binary Hardening Audit[/]",
        border_style="cyan",
    ))

    # Mitigations table
    t = Table(show_header=True, header_style="bold")
    t.add_column("Mitigation", style="white", min_width=18)
    t.add_column("Status", justify="center", min_width=8)
    t.add_column("Detail")
    t.add_column("To Enable", style="dim")

    for m in report.mitigations:
        status = "[green]ENABLED[/]" if m.enabled else "[red]DISABLED[/]"
        t.add_row(m.name, status, m.detail,
                  m.compiler_flag if not m.enabled else "")
    console.print(t)

    # Critical findings
    if report.critical_findings:
        console.print()
        for finding in report.critical_findings:
            color = "red" if "CRITICAL" in finding else "yellow"
            console.print(f"  [{color}]{finding}[/]")

    # Exploit correlations
    if report.correlations:
        console.print()
        console.print(Panel(
            f"[bold]{len(report.correlations)} bug(s) assessed for exploitability[/]",
            title="[bold red]Exploit Correlation[/]",
            border_style="red",
        ))

        for c in report.correlations:
            ec = {"TRIVIAL": "red bold", "LIKELY": "red",
                  "POSSIBLE": "yellow", "UNLIKELY": "green"}.get(c.exploitability, "dim")
            console.print(Panel(
                f"[bold]{c.bug_type.upper()}[/] at [cyan]{c.bug_location}[/]\n"
                f"Exploitability: [{ec}]{c.exploitability}[/]\n\n"
                f"[dim]{c.attack_scenario}[/]\n\n"
                + (f"[red]Missing mitigations:[/]\n" +
                   "\n".join(f"  - {m}" for m in c.missing_mitigations)
                   if c.missing_mitigations else
                   "[green]All relevant mitigations enabled[/]"),
                border_style="red" if c.exploitability in ("TRIVIAL", "LIKELY") else "yellow",
            ))

    # Recompile suggestion
    if report.recommended_flags:
        console.print(Panel(
            f"[bold]Recommended recompile:[/]\n"
            f"[cyan]{report.recompile_cmd}[/]\n\n"
            f"[dim]Flags: {' '.join(report.recommended_flags)}[/]",
            title="[bold green]Fix[/]",
            border_style="green",
        ))


# ---------------------------------------------------------------------------
# viz — Interactive Memory Visualization
# ---------------------------------------------------------------------------

@app.command()
def viz(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    out: str = typer.Option(None, "--out", "-o", help="Output HTML file"),
    no_open: bool = typer.Option(False, "--no-open", help="Don't auto-open browser"),
):
    """[bold cyan]Visualize[/] — interactive memory allocation timeline, heap heatmap, pointer flow"""
    from ..core.visualizer import generate_visualization

    result = _load_scan_result(scan_id)
    if not result or not result.errors:
        console.print("[red]Scan not found or no errors to visualize[/]")
        raise typer.Exit(1)

    html = generate_visualization(
        result.errors,
        scan_id=scan_id,
        target=str(result.config.target.binary or result.config.target.source_dir or ""),
    )

    out_path = out or f"/tmp/memguard_viz_{scan_id[:8]}.html"
    Path(out_path).write_text(html)
    console.print(f"[green]Visualization saved to {out_path}[/]")

    if not no_open:
        import webbrowser
        webbrowser.open(f"file://{Path(out_path).resolve()}")
        console.print("[cyan]Opened in browser[/]")


# ---------------------------------------------------------------------------
# backtrack — Allocation Ownership Lifecycle
# ---------------------------------------------------------------------------

@app.command()
def backtrack(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    issue: int = typer.Option(1, "--issue", "-i", help="Issue number"),
):
    """[bold cyan]Backtrack[/] — trace pointer ownership from malloc to leak"""
    from ..ai.explainability import backtrack_allocation
    from rich.panel import Panel

    result = _load_scan_result(scan_id)
    if not result or issue < 1 or issue > len(result.errors):
        console.print("[red]Scan or issue not found[/]")
        raise typer.Exit(1)

    err = result.errors[issue - 1]
    console.print(f"[cyan]Backtracking allocation for issue #{issue}...[/]")

    import asyncio
    lifecycle = asyncio.run(backtrack_allocation(err))

    # Allocation origin
    console.print(Panel(
        f"[bold green]ALLOCATED[/] {lifecycle.size or '?'} bytes\n"
        f"  Via:  [cyan]{lifecycle.allocated_via}[/]\n"
        f"  At:   [yellow]{lifecycle.allocated_at}[/]",
        title="[bold]Birth[/]",
        border_style="green",
    ))

    # Ownership chain
    if lifecycle.ownership_chain:
        chain_lines = []
        for i, step in enumerate(lifecycle.ownership_chain):
            arrow = "  |" if i < len(lifecycle.ownership_chain) - 1 else "  X"
            chain_lines.append(f"  [cyan]{step}[/]")
            chain_lines.append(f"  [dim]{arrow}[/]")
        console.print(Panel(
            "\n".join(chain_lines),
            title="[bold]Ownership Chain[/]",
            border_style="cyan",
        ))

    # Handoffs
    if lifecycle.passed_to:
        for p in lifecycle.passed_to:
            console.print(f"  [dim]>[/] {p}")

    # Where it should have been freed
    console.print(Panel(
        f"[bold]Should free at:[/]  [green]{lifecycle.should_free_at}[/]\n"
        f"[bold]Actually freed:[/] [red]{lifecycle.actually_freed}[/]\n"
        f"[bold]Lost at:[/]        [red]{lifecycle.lost_at}[/]",
        title="[bold red]Death (or lack thereof)[/]",
        border_style="red",
    ))


# ---------------------------------------------------------------------------
# diff — Regression Detection
# ---------------------------------------------------------------------------

@app.command()
def diff(
    scan_a: str = typer.Argument(..., help="Baseline scan ID"),
    scan_b: str = typer.Argument(..., help="New scan ID"),
):
    """[bold cyan]Diff[/] — compare two scans for regressions and fixes"""
    from ..ai.explainability import diff_scans
    from rich.panel import Panel
    from rich.table import Table

    result_a = _load_scan_result(scan_a)
    result_b = _load_scan_result(scan_b)
    if not result_a or not result_b:
        console.print("[red]One or both scans not found[/]")
        raise typer.Exit(1)

    d = diff_scans(result_a.errors, result_b.errors, scan_a[:8], scan_b[:8])

    color = "red" if d.regression else "green"
    console.print(Panel(
        f"[bold {color}]{d.summary}[/]",
        title=f"[bold cyan]Diff: {scan_a[:8]} → {scan_b[:8]}[/]",
        border_style="cyan",
    ))

    if d.fixed_bugs:
        console.print(f"\n[bold green]Fixed ({len(d.fixed_bugs)}):[/]")
        for e in d.fixed_bugs:
            loc = f"{e.primary_location.file.split('/')[-1]}:{e.primary_location.line}" if e.primary_location else "?"
            console.print(f"  [green]- {e.bug_type.value}[/] at {loc} ({e.bytes_leaked or '?'} bytes)")

    if d.new_bugs:
        console.print(f"\n[bold red]New ({len(d.new_bugs)}):[/]")
        for e in d.new_bugs:
            loc = f"{e.primary_location.file.split('/')[-1]}:{e.primary_location.line}" if e.primary_location else "?"
            console.print(f"  [red]+ {e.bug_type.value}[/] at {loc} ({e.bytes_leaked or '?'} bytes)")

    if d.persistent_bugs:
        console.print(f"\n[dim]Persistent ({len(d.persistent_bugs)}):[/]")
        for e in d.persistent_bugs:
            loc = f"{e.primary_location.file.split('/')[-1]}:{e.primary_location.line}" if e.primary_location else "?"
            console.print(f"  [dim]= {e.bug_type.value} at {loc}[/]")

    if d.bytes_delta != 0:
        sign = "+" if d.bytes_delta > 0 else ""
        dc = "red" if d.bytes_delta > 0 else "green"
        console.print(f"\n[{dc}]Leak delta: {sign}{d.bytes_delta:,} bytes[/]")


# ---------------------------------------------------------------------------
# verify — Fix Verification (recompile + rescan)
# ---------------------------------------------------------------------------

@app.command()
def verify(
    source: str = typer.Argument(..., help="Source file path"),
    compile_cmd: str = typer.Option(..., "--compile", "-c", help="Compile command"),
    binary: str = typer.Option(..., "--binary", "-b", help="Output binary path"),
    baseline: str = typer.Option(None, "--baseline", help="Baseline scan ID to diff against"),
):
    """[bold cyan]Verify[/] — recompile and rescan to prove a fix works"""
    from ..ai.explainability import verify_fix
    from rich.panel import Panel
    import asyncio

    original_errors = []
    if baseline:
        result = _load_scan_result(baseline)
        if result:
            original_errors = result.errors

    console.print(f"[cyan]Compiling {source}...[/]")
    console.print(f"[cyan]Rescanning {binary}...[/]")

    v = asyncio.run(verify_fix(source, compile_cmd, binary, original_errors))

    if not v.compiles:
        console.print(Panel(
            f"[bold red]COMPILE FAILED[/]\n{v.compile_output[:300]}",
            title="[red]Verification Failed[/]",
            border_style="red",
        ))
        return

    color = "green" if v.verified else "red"
    icon = "VERIFIED" if v.verified else "NOT VERIFIED"
    console.print(Panel(
        f"[bold {color}]{icon}[/]\n\n"
        f"Original issues:  {v.original_errors}\n"
        f"Remaining:        {v.remaining_errors}\n"
        f"Fixed:            [green]{v.fixed_count}[/]\n"
        f"New regressions:  [{'red' if v.new_regressions else 'green'}]{v.new_regressions}[/]\n\n"
        f"[dim]{v.details}[/]",
        title="[bold cyan]Fix Verification[/]",
        border_style=color,
    ))


# ---------------------------------------------------------------------------
# suppress — Generate Valgrind Suppression File
# ---------------------------------------------------------------------------

@app.command()
def suppress(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    out: str = typer.Option("memguard.supp", "--out", "-o", help="Output .supp file"),
):
    """[bold cyan]Suppress[/] — generate a Valgrind suppression file for known issues"""
    from ..ai.explainability import generate_suppressions

    result = _load_scan_result(scan_id)
    if not result:
        console.print("[red]Scan not found[/]")
        raise typer.Exit(1)

    supp_text = generate_suppressions(result.errors)
    Path(out).write_text(supp_text)

    vg_count = sum(1 for e in result.errors if e.tool.value == "valgrind")
    console.print(f"[green]Generated {out} with {vg_count} suppression(s)[/]")
    console.print(f"[dim]Usage: valgrind --suppressions={out} ./your_binary[/]")


# ---------------------------------------------------------------------------
# cves — CVE Pattern Matching
# ---------------------------------------------------------------------------

@app.command()
def cves(
    scan_id: str = typer.Argument(..., help="Scan ID"),
):
    """[bold cyan]CVE Matcher[/] — match bugs against known vulnerabilities"""
    from ..ai.explainability import match_cve_patterns
    from rich.panel import Panel

    result = _load_scan_result(scan_id)
    if not result:
        console.print("[red]Scan not found[/]")
        raise typer.Exit(1)

    matches = match_cve_patterns(result.errors)
    if not matches:
        console.print("[green]No known CVE patterns matched.[/]")
        return

    console.print(Panel(
        f"[bold red]{len(matches)} CVE pattern(s) matched[/]\n"
        "[dim]Pattern similarities, not confirmed vulnerabilities[/]",
        title="[bold cyan]CVE Pattern Matches[/]",
        border_style="red",
    ))

    for m in matches:
        c = m["cve"]
        ec = {"high": "red", "medium": "yellow", "low": "green"}.get(c.exploit_likelihood, "dim")
        console.print(Panel(
            f"[bold red]{c.cve_id}[/] — [bold]{c.name}[/]\n"
            f"[dim]{c.description}[/]\n"
            f"CVSS: [bold]{c.cvss_score}[/] | "
            f"Similarity: [cyan]{int(c.similarity*100)}%[/] | "
            f"Exploit: [{ec}]{c.exploit_likelihood}[/] | "
            f"Your bug: [yellow]{m['bug_type']}[/] ({m['your_severity']})",
            border_style="red",
        ))


# ---------------------------------------------------------------------------
# explain — AI Reasoning Chain
# ---------------------------------------------------------------------------

@app.command()
def explain(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    issue: int = typer.Option(1, "--issue", "-i", help="Issue number"),
):
    """[bold cyan]Reasoning Chain[/] — transparent step-by-step AI logic"""
    from ..ai.explainability import generate_reasoning_chain
    from rich.panel import Panel

    result = _load_scan_result(scan_id)
    if not result or issue < 1 or issue > len(result.errors):
        console.print("[red]Scan or issue not found[/]")
        raise typer.Exit(1)

    err = result.errors[issue - 1]
    analysis = next((a for a in result.analyses if a.error_id == err.id), None)

    console.print(f"[cyan]Generating reasoning chain for issue #{issue}...[/]")

    import asyncio
    chain = asyncio.run(generate_reasoning_chain(err, analysis))

    for step in chain.steps:
        sc = "green" if step.confidence >= 0.8 else "yellow" if step.confidence >= 0.5 else "red"
        alts = ""
        if step.alternatives:
            alts = f"\n[dim]Ruled out: {'; '.join(step.alternatives)}[/]"
        console.print(Panel(
            f"[bold]Observe:[/] {step.observation}\n"
            f"[bold]Evidence:[/] [cyan]{step.evidence}[/]\n"
            f"[bold]Infer:[/] {step.inference}\n"
            f"[bold]Confidence:[/] [{sc}]{step.confidence:.0%}[/]{alts}",
            title=f"[bold cyan]Step {step.step}: {step.title}[/]",
            border_style="cyan",
        ))

    cc = "green" if chain.overall_confidence >= 0.8 else "yellow" if chain.overall_confidence >= 0.5 else "red"
    console.print(Panel(
        f"[bold]{chain.final_verdict}[/]\n\n"
        f"Confidence: [{cc}]{chain.overall_confidence:.0%}[/]\n"
        f"[dim]Counterfactual: {chain.counterfactual}[/]",
        title="[bold green]Verdict[/]",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# Helper: load scan result by prefix
# ---------------------------------------------------------------------------

def _load_scan_result(scan_id: str):
    from ..pipeline.orchestrator import ScanResult, load_result
    from pathlib import Path as _P

    result = load_result(scan_id)
    if result:
        return result

    results_dir = _P.home() / ".memguard" / "results"
    matches = sorted(results_dir.glob(f"{scan_id}*.json"))
    if matches:
        return ScanResult.model_validate_json(matches[0].read_text())
    return None


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

@app.command()
def doctor():
    """[bold]Check[/] tool availability and system health."""
    checks = {
        "valgrind":        "Valgrind (memcheck, massif)",
        "clang":           "Clang (ASan/MSan/UBSan)",
        "cppcheck":        "cppcheck (static analysis)",
        "clang-tidy":      "clang-tidy (C++ checks)",
        "addr2line":       "addr2line (stack symbolizer)",
        "llvm-symbolizer": "llvm-symbolizer (better symbolizer)",
        "python":          "Python (tracemalloc/memray)",
        "cargo":           "Cargo (Rust/Miri)",
        "infer":           "Infer (Facebook static analyzer)",
        "rr":              "rr (time-travel debugger)",
        "heaptrack":       "heaptrack (heap memory profiler)",
        "ollama":          "Ollama (AI backend)",
        "git":             "Git (branch/rollback)",
    }
    t = Table(title="System Health", box=box.ROUNDED)
    t.add_column("Tool")
    t.add_column("Description")
    t.add_column("Status")

    all_ok = True
    for binary, desc in checks.items():
        found = shutil.which(binary) is not None
        if not found:
            all_ok = False
        t.add_row(
            f"[bold]{binary}[/]",
            desc,
            "[green]✓[/]" if found else "[red]✗ not found[/]",
        )

    console.print(t)

    if not all_ok:
        console.print("\n[yellow]Install missing tools:[/]")
        console.print("  [dim]sudo apt install valgrind clang cppcheck clang-tidy binutils[/]")
        console.print("  [dim]curl -fsSL https://ollama.ai/install.sh | sh[/]")
        console.print(f"  [dim]ollama pull qwen2.5-coder:14b-instruct-q4_K_M[/]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(7331, "--port"),
):
    """[bold]Launch[/] the web dashboard at http://localhost:7331"""
    console.print(f"[cyan]Starting MemGuard dashboard at http://{host}:{port}[/]")
    console.print("[dim]Press Ctrl+C to stop[/]")
    from ..api.server import serve as _serve
    _serve(host=host, port=port)


def main():
    app()


if __name__ == "__main__":
    main()


@app.command(name="clear-cache")
def clear_cache(
    results: bool = typer.Option(False, "--results", help="Also clear saved scan results"),
):
    """[bold red]Clear[/] the tool output cache so tools re-run on next scan."""
    from pathlib import Path as _Path
    cache_dir   = _Path.home() / ".memguard" / "cache"
    results_dir = _Path.home() / ".memguard" / "results"

    dirs = [(cache_dir, "tool cache")]
    if results:
        dirs.append((results_dir, "scan results"))

    for d, label in dirs:
        if not d.exists():
            console.print(f"[dim]{label}: nothing to clear[/]")
            continue
        files = list(d.glob("*.json"))
        for f in files:
            f.unlink()
        console.print(f"[green]✓ Cleared {len(files)} {label} entries from {d}[/]")

    console.print("[cyan]Done. Next scan will re-run all tools.[/]")
