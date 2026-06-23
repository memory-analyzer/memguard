"""
memguard.core.timetravel
=========================
Time-Travel Debugging — record program execution and replay backwards
to find the exact moment memory corruption occurs.

Inspired by Undo.io's commercial product, built on open-source tools:
  - rr (Mozilla) — record & replay with full reverse debugging
  - GDB reverse — fallback when rr is unavailable

Workflow:
  1. memguard record <binary> — record execution with rr
  2. memguard replay <recording> — replay with reverse debugging
  3. memguard timewarp <scan-id> — auto-set breakpoints at bug sites,
     reverse-continue to find root cause

Novel integration: MemGuard scan results → automatic rr breakpoint
scripts → one command from "bug detected" to "watching it happen backwards"
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .schema import (
    AnalysisTool, BugType, Language, MemoryError, Severity, SourceLocation,
)

log = logging.getLogger(__name__)

RECORDINGS_DIR = Path.home() / ".memguard" / "recordings"
RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RecordingInfo:
    recording_id: str
    binary: str
    args: list[str]
    recording_dir: str
    duration_ms: int
    exit_code: int
    events: int             # rr event count
    tool: str               # "rr" or "gdb"
    size_mb: float


@dataclass
class TimewarpBreakpoint:
    location: str           # "server_sim.c:92"
    function: str           # "log_request"
    bug_type: str           # "use_after_free"
    condition: str | None   # optional GDB condition
    watchpoint: str | None  # memory address to watch
    description: str        # what to look for at this point


@dataclass
class TimewarpScript:
    recording_id: str | None
    scan_id: str
    breakpoints: list[TimewarpBreakpoint]
    gdb_script: str         # full GDB/rr command script
    launch_cmd: str         # command to run
    instructions: list[str] # step-by-step for the user


@dataclass
class MemoryEvent:
    """A single memory operation in the execution timeline."""
    event_type: str         # "malloc", "free", "read", "write", "realloc"
    address: str
    size: int
    function: str
    file: str
    line: int
    timestamp: int          # rr event number or instruction count


# ═══════════════════════════════════════════════════════════════════════════
# Tool detection
# ═══════════════════════════════════════════════════════════════════════════

def detect_backend() -> str:
    """Detect available time-travel debugging backend."""
    if shutil.which("rr"):
        return "rr"
    if shutil.which("gdb"):
        return "gdb"
    return "none"


def check_rr_prerequisites() -> list[str]:
    """Check system requirements for rr recording."""
    issues = []

    # Check rr is installed
    if not shutil.which("rr"):
        issues.append("rr not installed — install with: sudo apt install rr")
        return issues

    # Check perf_event_paranoid
    try:
        val = Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip()
        if int(val) > 1:
            issues.append(
                f"perf_event_paranoid = {val} (needs ≤ 1) — "
                "fix with: sudo sysctl kernel.perf_event_paranoid=1"
            )
    except (OSError, ValueError):
        pass

    # Check kernel.yama.ptrace_scope
    try:
        val = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
        if int(val) > 0:
            issues.append(
                f"ptrace_scope = {val} (may need 0 for rr) — "
                "fix with: sudo sysctl kernel.yama.ptrace_scope=0"
            )
    except (OSError, ValueError):
        pass

    # Check CPU supports performance counters
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        if "perf_ctr" not in cpuinfo and "rdpmc" not in cpuinfo:
            # Not a reliable check but hint
            pass
    except OSError:
        pass

    return issues


# ═══════════════════════════════════════════════════════════════════════════
# Record execution
# ═══════════════════════════════════════════════════════════════════════════

async def record_execution(
    binary: str,
    args: list[str] | None = None,
    env: dict | None = None,
    timeout: int = 60,
    recording_id: str | None = None,
) -> RecordingInfo:
    """Record program execution using rr for later replay."""
    backend = detect_backend()
    if backend == "none":
        raise RuntimeError("No time-travel backend found. Install rr: sudo apt install rr")

    if recording_id is None:
        recording_id = f"rec_{int(time.time())}_{Path(binary).stem}"

    rec_dir = RECORDINGS_DIR / recording_id
    rec_dir.mkdir(parents=True, exist_ok=True)

    binary = str(Path(binary).resolve())
    run_args = args or []

    if backend == "rr":
        return await _record_with_rr(binary, run_args, env, timeout, recording_id, rec_dir)
    else:
        return await _record_with_gdb(binary, run_args, env, timeout, recording_id, rec_dir)


async def _record_with_rr(
    binary: str, args: list[str], env: dict | None,
    timeout: int, rec_id: str, rec_dir: Path,
) -> RecordingInfo:
    """Record with Mozilla rr. Falls back to GDB if CPU unsupported."""
    cmd = ["rr", "record", "--output-trace-dir", str(rec_dir / "trace"), binary] + args

    full_env = {**os.environ, **(env or {})}
    t0 = time.monotonic()

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=full_env,
    )

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        output = f"[memguard] Recording timed out after {timeout}s"

    duration_ms = int((time.monotonic() - t0) * 1000)
    exit_code = proc.returncode or 0

    # Check for unsupported CPU — fallback to GDB
    if "unknown" in output.lower() and ("cpu" in output.lower() or "microarch" in output.lower()):
        log.warning("rr does not support this CPU: %s", output.strip().splitlines()[-1] if output.strip() else "unknown")
        log.info("Falling back to GDB reverse debugging")
        return await _record_with_gdb(binary, args, env, timeout, rec_id, rec_dir)

    # Check for perf_event errors
    if exit_code != 0 and "perf_event" in output:
        log.warning("rr perf_event error — try: sudo sysctl kernel.perf_event_paranoid=1")

    # Parse rr output for event count
    events = 0
    for line in output.splitlines():
        if "events" in line.lower():
            import re
            m = re.search(r"(\d+)\s*events?", line)
            if m:
                events = int(m.group(1))

    # Calculate recording size
    trace_dir = rec_dir / "trace"
    size_mb = 0.0
    if trace_dir.exists():
        size_bytes = sum(f.stat().st_size for f in trace_dir.rglob("*") if f.is_file())
        size_mb = round(size_bytes / (1024 * 1024), 2)

    # Save metadata
    info = RecordingInfo(
        recording_id=rec_id,
        binary=binary,
        args=args,
        recording_dir=str(rec_dir),
        duration_ms=duration_ms,
        exit_code=exit_code,
        events=events,
        tool="rr",
        size_mb=size_mb,
    )

    meta_path = rec_dir / "memguard_meta.json"
    meta_path.write_text(json.dumps({
        "recording_id": info.recording_id,
        "binary": info.binary,
        "args": info.args,
        "duration_ms": info.duration_ms,
        "exit_code": info.exit_code,
        "events": info.events,
        "tool": info.tool,
        "size_mb": info.size_mb,
    }, indent=2))

    log.info("rr recording saved: %s (%d events, %.1f MB, %dms)",
             rec_id, events, size_mb, duration_ms)
    return info


async def _record_with_gdb(
    binary: str, args: list[str], env: dict | None,
    timeout: int, rec_id: str, rec_dir: Path,
) -> RecordingInfo:
    """Fallback: record execution trace with GDB process record."""
    # Create GDB script for recording
    # Disable AVX2 — GDB process record can't handle VEX-prefixed instructions
    gdb_script = (
        "set pagination off\n"
        "set confirm off\n"
        "set environment GLIBC_TUNABLES glibc.cpu.hwcaps=-AVX2,-AVX,-AVX_Fast_Unaligned_Load\n"
        "break main\n"
        "run\n"
        "record\n"
        "continue\n"
        "record save " + str(rec_dir / "gdb_record.rec") + "\n"
        "quit\n"
    )
    script_path = rec_dir / "record.gdb"
    script_path.write_text(gdb_script)

    args_str = " ".join(shlex.quote(a) for a in args)
    cmd = ["gdb", "-batch", "-x", str(script_path),
           "--args", binary] + args

    t0 = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, **(env or {})},
    )

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()

    duration_ms = int((time.monotonic() - t0) * 1000)

    rec_file = rec_dir / "gdb_record.rec"
    size_mb = round(rec_file.stat().st_size / (1024*1024), 2) if rec_file.exists() else 0

    info = RecordingInfo(
        recording_id=rec_id,
        binary=binary, args=args,
        recording_dir=str(rec_dir),
        duration_ms=duration_ms,
        exit_code=proc.returncode or 0,
        events=0, tool="gdb", size_mb=size_mb,
    )

    (rec_dir / "memguard_meta.json").write_text(json.dumps({
        "recording_id": info.recording_id,
        "binary": info.binary,
        "tool": info.tool,
        "duration_ms": info.duration_ms,
        "size_mb": info.size_mb,
    }, indent=2))

    return info


# ═══════════════════════════════════════════════════════════════════════════
# List recordings
# ═══════════════════════════════════════════════════════════════════════════

def list_recordings() -> list[RecordingInfo]:
    """List all saved recordings."""
    recordings = []
    for meta_file in RECORDINGS_DIR.rglob("memguard_meta.json"):
        try:
            data = json.loads(meta_file.read_text())
            recordings.append(RecordingInfo(
                recording_id=data.get("recording_id", meta_file.parent.name),
                binary=data.get("binary", "??"),
                args=data.get("args", []),
                recording_dir=str(meta_file.parent),
                duration_ms=data.get("duration_ms", 0),
                exit_code=data.get("exit_code", 0),
                events=data.get("events", 0),
                tool=data.get("tool", "??"),
                size_mb=data.get("size_mb", 0),
            ))
        except (json.JSONDecodeError, OSError):
            continue
    recordings.sort(key=lambda r: r.recording_id, reverse=True)
    return recordings


# ═══════════════════════════════════════════════════════════════════════════
# Timewarp — generate debugging scripts from scan results
# ═══════════════════════════════════════════════════════════════════════════

def generate_timewarp_script(
    errors: list[MemoryError],
    binary: str,
    scan_id: str = "",
    recording_id: str | None = None,
) -> TimewarpScript:
    """Generate a GDB/rr script that sets breakpoints at all detected bugs
    and enables reverse debugging to find root causes."""
    backend = detect_backend()
    breakpoints = []

    for err in errors:
        loc = err.primary_location
        if not loc or not loc.file or not loc.line:
            continue

        filename = Path(loc.file).name
        location = f"{filename}:{loc.line}"

        # Determine what to watch based on bug type
        watchpoint = None
        condition = None
        description = ""

        if err.bug_type == BugType.USE_AFTER_FREE:
            description = (
                "USE-AFTER-FREE: Program will hit this breakpoint when the freed "
                "pointer is accessed. Use 'reverse-continue' to go back to the "
                "free() call, then 'reverse-continue' again to find the allocation."
            )
            # If we have the address from the error, set a hardware watchpoint
            if err.stack and err.stack[0].address:
                watchpoint = err.stack[0].address

        elif err.bug_type == BugType.DOUBLE_FREE:
            description = (
                "DOUBLE-FREE: Break at the second free(). Use 'reverse-continue' "
                "to find the first free(), then 'reverse-continue' to the allocation."
            )

        elif err.bug_type == BugType.MEMORY_LEAK:
            description = (
                f"MEMORY LEAK: {err.bytes_leaked or '?'} bytes allocated here but "
                "never freed. Step forward through the function to see where the "
                "pointer is lost (overwritten, goes out of scope, return value ignored)."
            )

        elif err.bug_type == BugType.BUFFER_OVERFLOW:
            description = (
                "BUFFER OVERFLOW: Break at the overflow site. Use 'reverse-stepi' "
                "to watch memory being corrupted byte-by-byte backwards. "
                "Set a watchpoint on the corrupted address to find the exact write."
            )

        elif err.bug_type == BugType.NULL_DEREF:
            description = (
                "NULL DEREF: Break at the dereference. Use 'reverse-continue' to "
                "find where the pointer was set to NULL (or never initialized). "
                "Watch the pointer variable to see its full history."
            )

        elif err.bug_type == BugType.RACE_CONDITION:
            description = (
                "RACE CONDITION: Break at the unsynchronized access. In rr, all "
                "threads are deterministic — use 'info threads' then 'thread N' to "
                "inspect each thread's state. Reverse to see interleaving."
            )

        elif err.bug_type == BugType.UNINIT_READ:
            description = (
                "UNINIT READ: Break at the read. Use 'reverse-continue' to the "
                "variable's declaration. The variable was never assigned between "
                "declaration and use. Check all code paths."
            )

        else:
            description = f"{err.bug_type.value.upper()} at {location}"

        # Build function name
        func = "??"
        if err.stack:
            for f in err.stack:
                if f.function and f.function != "??" and not f.function.startswith("_"):
                    func = f.function
                    break

        breakpoints.append(TimewarpBreakpoint(
            location=location,
            function=func,
            bug_type=err.bug_type.value,
            condition=condition,
            watchpoint=watchpoint,
            description=description,
        ))

    # ── Generate GDB/rr script ──
    script_lines = [
        "# MemGuard Time-Travel Debug Script",
        f"# Scan: {scan_id}",
        f"# Binary: {binary}",
        f"# Backend: {backend}",
        "#",
        "# REVERSE COMMANDS:",
        "#   reverse-continue  — run backwards to previous breakpoint",
        "#   reverse-step      — step one source line backwards",
        "#   reverse-next      — step backwards over function calls",
        "#   reverse-finish    — run backwards to caller",
        "#",
        "# MEMGUARD AI COMMANDS:",
        "#   mg-ai             — AI explains current program state",
        "#   mg-why            — AI explains why this bug happens",
        "#   mg-suggest        — AI suggests next debugging step",
        "#   mg-uaf-trace      — auto-trace UAF: access → free → alloc",
        "#   mg-trace-ptr ADDR — reverse-trace pointer to last write",
        "#   mg-heap           — show heap state",
        "#",
        "set pagination off",
        "set confirm off",
        "set print pretty on",
        "set print array on",
        "",
    ]

    # Add breakpoints for each bug
    for i, bp in enumerate(breakpoints, 1):
        script_lines.append(f"# ── Bug {i}: {bp.bug_type.upper()} in {bp.function}() ──")
        script_lines.append(f"# {bp.description}")
        script_lines.append(f"break {bp.location}")
        if bp.watchpoint:
            script_lines.append(f"# watch *{bp.watchpoint}")
        if bp.condition:
            script_lines.append(f"condition $bpnum {bp.condition}")
        script_lines.append("")

    # Add AI-powered GDB Python commands
    ollama_url = os.environ.get("MEMGUARD_OLLAMA_URL", "http://localhost:11434")

    # Build bug context string for the AI
    bug_summaries = []
    for bp in breakpoints:
        bug_summaries.append(f"  {bp.bug_type.upper()} at {bp.location} in {bp.function}()")
    bugs_str = "\\n".join(bug_summaries)

    script_lines.extend([
        "# ── MemGuard AI-Powered Commands (GDB Python API) ──",
        "python",
        "import gdb, json, urllib.request, os",
        "",
        f'OLLAMA_URL = "{ollama_url}/api/generate"',
        'OLLAMA_MODEL = "qwen2.5-coder:14b-instruct-q4_K_M"',
        f'KNOWN_BUGS = """{bugs_str}"""',
        "",
        "def mg_ai_query(prompt):",
        "    try:",
        "        payload = json.dumps({",
        '            "model": OLLAMA_MODEL,',
        '            "prompt": prompt,',
        '            "stream": False,',
        '            "options": {"temperature": 0.1, "num_predict": 800}',
        "        }).encode()",
        "        req = urllib.request.Request(",
        "            OLLAMA_URL,",
        '            data=payload,',
        '            headers={"Content-Type": "application/json"},',
        "        )",
        "        with urllib.request.urlopen(req, timeout=360) as resp:",
        "            data = json.loads(resp.read())",
        '            return data.get("response", "No response")',
        "    except Exception as e:",
        '        return f"AI unavailable: {e}"',
        "",
        "def get_context():",
        '    """Gather rich context: source, backtrace, locals, registers."""',
        "    ctx = []",
        "    # Current location",
        "    try:",
        '        frame = gdb.selected_frame()',
        '        ctx.append(f"Current function: {frame.name()}")',
        '        sal = frame.find_sal()',
        '        if sal.symtab:',
        '            ctx.append(f"Location: {sal.symtab.filename}:{sal.line}")',
        "    except: pass",
        "    # Source code around current line",
        "    try:",
        '        src = gdb.execute("list", to_string=True)',
        '        ctx.append(f"Source code:\\n{src}")',
        "    except: pass",
        "    # Wider source context",
        "    try:",
        '        src_wide = gdb.execute("list -20,+20", to_string=True)',
        '        ctx.append(f"Extended source:\\n{src_wide}")',
        "    except: pass",
        "    # Full backtrace",
        "    try:",
        '        bt = gdb.execute("backtrace", to_string=True)',
        '        ctx.append(f"Full backtrace:\\n{bt}")',
        "    except: pass",
        "    # Local variables",
        "    try:",
        '        locals_str = gdb.execute("info locals", to_string=True)',
        '        ctx.append(f"Local variables:\\n{locals_str}")',
        "    except: pass",
        "    # Function arguments",
        "    try:",
        '        args_str = gdb.execute("info args", to_string=True)',
        '        ctx.append(f"Function arguments:\\n{args_str}")',
        "    except: pass",
        "    # Known bugs from scan",
        '    ctx.append(f"\\nKnown bugs detected by MemGuard scan:\\n{KNOWN_BUGS}")',
        '    return "\\n".join(ctx)',
        "",
        "class MgAiCommand(gdb.Command):",
        '    """AI explains current program state with full context."""',
        '    def __init__(self):',
        '        super().__init__("mg-ai", gdb.COMMAND_USER)',
        '    def invoke(self, arg, from_tty):',
        '        ctx = get_context()',
        '        gdb.write("\\n[MemGuard AI] Analyzing current state...\\n\\n")',
        '        prompt = (',
        '            "You are a memory safety expert debugging a C program using time-travel debugging (rr). "',
        '            "Analyze the current program state and explain what is happening.\\n\\n"',
        '            "CONTEXT:\\n"',
        '            f"{ctx}\\n\\n"',
        '            "INSTRUCTIONS:\\n"',
        '            "1. What function are we in and what does it do?\\n"',
        '            "2. Look at the source code - identify any memory bugs visible (leaks, UAF, null deref, overflow)\\n"',
        '            "3. Check the local variables - any NULL pointers, unfreed allocations, or suspicious values?\\n"',
        '            "4. Does this location match any of the known bugs?\\n"',
        '            "Be specific - reference exact line numbers and variable names from the source code."',
        '        )',
        '        result = mg_ai_query(prompt)',
        '        gdb.write(f"{result}\\n\\n")',
        "",
        "class MgWhyCommand(gdb.Command):",
        '    """AI explains why this bug happens with root cause analysis."""',
        '    def __init__(self):',
        '        super().__init__("mg-why", gdb.COMMAND_USER)',
        '    def invoke(self, arg, from_tty):',
        '        ctx = get_context()',
        '        gdb.write("\\n[MemGuard AI] Analyzing root cause...\\n\\n")',
        '        prompt = (',
        '            "You are a memory safety expert reverse-debugging a C program. "',
        '            "A memory bug was detected at this location. Explain the ROOT CAUSE.\\n\\n"',
        '            "CONTEXT:\\n"',
        '            f"{ctx}\\n\\n"',
        '            "ANSWER THESE:\\n"',
        '            "1. What is the exact bug? (leak, UAF, null deref, race, overflow)\\n"',
        '            "2. Which line of source code causes it?\\n"',
        '            "3. What variable or pointer is involved?\\n"',
        '            "4. WHY does it happen - what is missing? (missing free, missing NULL check, missing fclose, missing mutex)\\n"',
        '            "5. What is the fix? Show the exact code change needed.\\n"',
        '            "Be specific with line numbers and variable names."',
        '        )',
        '        result = mg_ai_query(prompt)',
        '        gdb.write(f"{result}\\n\\n")',
        "",
        "class MgSuggestCommand(gdb.Command):",
        '    """AI suggests next debugging step."""',
        '    def __init__(self):',
        '        super().__init__("mg-suggest", gdb.COMMAND_USER)',
        '    def invoke(self, arg, from_tty):',
        '        ctx = get_context()',
        '        gdb.write("\\n[MemGuard AI] Suggesting next step...\\n\\n")',
        '        prompt = (',
        '            "You are helping debug a C program using rr time-travel debugger. "',
        '            "Based on the current state, suggest the SINGLE BEST next GDB command.\\n\\n"',
        '            "CONTEXT:\\n"',
        '            f"{ctx}\\n\\n"',
        '            "Available commands:\\n"',
        '            "- continue: run forward to next breakpoint\\n"',
        '            "- reverse-continue: run BACKWARDS to previous breakpoint\\n"',
        '            "- reverse-step: step back one source line\\n"',
        '            "- reverse-next: step back over function calls\\n"',
        '            "- reverse-finish: go back to caller\\n"',
        '            "- print <var>: inspect a variable\\n"',
        '            "- watch <expr>: break when value changes\\n"',
        '            "- info locals: show all local variables\\n\\n"',
        '            "Give ONE specific command and explain WHY in one sentence."',
        '        )',
        '        result = mg_ai_query(prompt)',
        '        gdb.write(f"{result}\\n\\n")',
        "",
        "class MgFixCommand(gdb.Command):",
        '    """AI generates a fix for the current bug."""',
        '    def __init__(self):',
        '        super().__init__("mg-fix", gdb.COMMAND_USER)',
        '    def invoke(self, arg, from_tty):',
        '        ctx = get_context()',
        '        gdb.write("\\n[MemGuard AI] Generating fix...\\n\\n")',
        '        prompt = (',
        '            "You are a C memory safety expert. Based on the current debug state, "',
        '            "generate the EXACT code fix for this bug.\\n\\n"',
        '            "CONTEXT:\\n"',
        '            f"{ctx}\\n\\n"',
        '            "Show the fix as:\\n"',
        '            "BEFORE: (the buggy lines)\\n"',
        '            "AFTER: (the fixed lines)\\n"',
        '            "EXPLANATION: (one sentence why this fixes the bug)"',
        '        )',
        '        result = mg_ai_query(prompt)',
        '        gdb.write(f"{result}\\n\\n")',
        "",
        "MgAiCommand()",
        "MgWhyCommand()",
        "MgSuggestCommand()",
        "MgFixCommand()",
        "end",
        "",
        "# ── Standard MemGuard macros ──",
        "define mg-heap",
        "  info proc mappings",
        "  echo \\n=== Heap summary ===\\n",
        "  call (void)malloc_stats()",
        "end",
        "",
        "define mg-trace-ptr",
        "  echo Watching pointer: $arg0\\n",
        "  watch *$arg0",
        "  reverse-continue",
        "  echo \\n=== Found: last write to this address ===\\n",
        "  frame",
        "  list",
        "end",
        "",
        "define mg-uaf-trace",
        "  echo === UAF Root Cause Trace ===\\n",
        "  echo Step 1: You are at the invalid access\\n",
        "  echo Step 2: reverse-continue to find the free()\\n",
        "  echo Step 3: reverse-continue again for the malloc()\\n",
        "  echo \\nRunning reverse-continue...\\n",
        "  reverse-continue",
        "end",
        "",
        "# ── Start ──",
    ])
    if backend == "rr":
        script_lines.extend([
            "# rr: no 'run' or 'record' needed — rr handles it",
            "echo \\n=== MemGuard Time-Travel Debugger (rr) ===\\n",
            "echo Breakpoints set at all detected bugs.\\n",
            "echo Type 'continue' to run forward to first bug.\\n",
            "echo Then 'reverse-continue' to travel backwards.\\n",
            "echo AI commands: mg-ai, mg-why, mg-suggest\\n\\n",
        ])
    else:
        script_lines.extend([
            "set environment GLIBC_TUNABLES glibc.cpu.hwcaps=-AVX2,-AVX,-AVX_Fast_Unaligned_Load",
            "break main",
            "run",
            "record",
            "echo \\n=== MemGuard Time-Travel Debugger (GDB) ===\\n",
            "echo Breakpoints set at all detected bugs.\\n",
            "echo Type 'continue' to run forward to first bug.\\n",
            "echo Then 'reverse-continue' to travel backwards.\\n",
            "echo AI commands: mg-ai, mg-why, mg-suggest\\n\\n",
        ])

    gdb_script = "\n".join(script_lines)

    # Build launch command
    if backend == "rr" and recording_id:
        rec_path = RECORDINGS_DIR / recording_id / "trace"
        launch_cmd = f"rr replay -x /tmp/memguard_timewarp.gdb {rec_path}"
    elif backend == "rr":
        launch_cmd = f"rr replay -x /tmp/memguard_timewarp.gdb"
    else:
        args_str = ""
        launch_cmd = f"gdb -x /tmp/memguard_timewarp.gdb --args {binary} {args_str}"

    # Build user instructions
    instructions = _build_instructions(backend, breakpoints, recording_id)

    return TimewarpScript(
        recording_id=recording_id,
        scan_id=scan_id,
        breakpoints=breakpoints,
        gdb_script=gdb_script,
        launch_cmd=launch_cmd,
        instructions=instructions,
    )


def _build_instructions(
    backend: str,
    breakpoints: list[TimewarpBreakpoint],
    recording_id: str | None,
) -> list[str]:
    """Build step-by-step instructions for the user."""
    steps = []

    if backend == "rr":
        if not recording_id:
            steps.append(
                "Step 1: Record the program — "
                "memguard record /tmp/server_sim"
            )
            steps.append(
                "Step 2: Replay with timewarp script — "
                "the command below opens rr with breakpoints at all detected bugs"
            )
        else:
            steps.append(
                "Step 1: Launch rr replay with the command below — "
                "breakpoints are pre-set at all detected bug locations"
            )

        steps.append(
            "Step 3: Type 'continue' — rr runs to the first bug"
        )
        steps.append(
            "Step 4: Type 'reverse-continue' — rr runs BACKWARDS to find the cause"
        )
        steps.append(
            "Step 5: For UAF bugs, type 'mg-uaf-trace' — auto-traces alloc → free → crash"
        )
        steps.append(
            "Step 6: For leaks, type 'mg-trace-ptr <addr>' — finds where pointer was last written"
        )
    else:
        steps.append(
            "Step 1: Launch GDB with the command below"
        )
        steps.append(
            "Step 2: Type 'continue' — runs to first bug breakpoint"
        )
        steps.append(
            "Step 3: Type 'reverse-continue' — steps backwards (GDB process record)"
        )
        steps.append(
            "Note: GDB reverse is slower than rr. Install rr for better experience: "
            "sudo apt install rr"
        )

    # Add bug-specific tips
    uaf_bugs = [bp for bp in breakpoints if bp.bug_type == "use_after_free"]
    race_bugs = [bp for bp in breakpoints if bp.bug_type == "race_condition"]
    leak_bugs = [bp for bp in breakpoints if bp.bug_type == "memory_leak"]

    if uaf_bugs:
        steps.append(
            f"TIP: {len(uaf_bugs)} UAF bug(s) detected. At the crash site, "
            "run 'mg-uaf-trace' to automatically reverse through: "
            "invalid access → free() → original malloc()"
        )

    if race_bugs:
        steps.append(
            f"TIP: {len(race_bugs)} race(s) detected. In rr, thread scheduling "
            "is deterministic — use 'info threads' + 'thread N' to inspect "
            "each thread at the race point"
        )

    if leak_bugs:
        steps.append(
            f"TIP: {len(leak_bugs)} leak(s) detected. Set a watchpoint on the "
            "leaked pointer variable and step forward to see where ownership is lost"
        )

    return steps


# ═══════════════════════════════════════════════════════════════════════════
# Save and load timewarp scripts
# ═══════════════════════════════════════════════════════════════════════════

def save_timewarp_script(script: TimewarpScript) -> str:
    """Save the GDB script to disk and return the path."""
    path = "/tmp/memguard_timewarp.gdb"
    Path(path).write_text(script.gdb_script)
    return path
