"""
memguard.core.runner
====================
Orchestrates ALL Valgrind tools + sanitizers in parallel:
  - memcheck: leaks, UAF, double-free, uninit reads, invalid access
  - massif: heap profiling over time, peak memory, allocation hotspots
  - helgrind: thread error detection (races, deadlocks)
  - --track-fds: file descriptor leaks
  - cachegrind: cache miss profiling (optional)
  - ASan/LSan/MSan/UBSan/TSan
  - cppcheck, clang-tidy
  - memray, tracemalloc (Python)
  - Miri (Rust)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import AsyncIterator

from ..core.schema import AnalysisTool, Language, ScanConfig, ScanTarget

log = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".memguard" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CACHE_TTL_SEC = 3600          # entries older than 1h are stale
CACHE_MAX_FILES = 100         # hard cap on cache entries


def _cache_cleanup() -> None:
    """Remove stale entries and enforce the file-count cap (oldest first)."""
    try:
        entries = sorted(CACHE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
        now = time.time()
        for p in entries:
            if now - p.stat().st_mtime > CACHE_TTL_SEC:
                p.unlink(missing_ok=True)
        entries = sorted(CACHE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
        while len(entries) > CACHE_MAX_FILES:
            entries.pop(0).unlink(missing_ok=True)
    except OSError as e:
        log.debug("Cache cleanup skipped: %s", e)


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------

def available_tools(language: Language) -> list[AnalysisTool]:
    if language == Language.UNKNOWN:
        language = Language.C
    found = []
    checks = {
        AnalysisTool.VALGRIND:    ("valgrind",   [Language.C, Language.CPP]),
        AnalysisTool.HELGRIND:    ("valgrind",   [Language.C, Language.CPP]),
        AnalysisTool.CPPCHECK:    ("cppcheck",   [Language.C, Language.CPP]),
        AnalysisTool.INFER:       ("infer",      [Language.C, Language.CPP]),
        AnalysisTool.CLANG_TIDY:  ("clang-tidy", [Language.C, Language.CPP]),
        AnalysisTool.MEMRAY:      ("memray",     [Language.PYTHON]),
        AnalysisTool.MIRI:        ("cargo",      [Language.RUST]),
    }
    for tool, (binary, langs) in checks.items():
        if language in langs and shutil.which(binary):
            found.append(tool)
    # ASan/LSan require recompilation with -fsanitize — only auto-include
    # if user might provide --compile, not by default on bare binaries
    return found


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(target: ScanTarget, tool: AnalysisTool) -> str:
    h = hashlib.sha256()
    h.update(tool.value.encode())
    h.update((target.binary or "").encode())
    for f in sorted(target.files):
        p = Path(f)
        if p.exists():
            h.update(p.read_bytes())
    return h.hexdigest()[:24]


def _cache_get(key: str) -> str | None:
    p = CACHE_DIR / f"{key}.json"
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError) as e:
            log.debug("Corrupt cache entry %s: %s", key, e)
            p.unlink(missing_ok=True)
            return None
        if time.time() - data.get("ts", 0) < CACHE_TTL_SEC:
            log.debug("Cache hit %s (age %.0fs)", key, time.time() - data["ts"])
            return data.get("output")
    return None


def _cache_set(key: str, output: str) -> None:
    try:
        (CACHE_DIR / f"{key}.json").write_text(
            json.dumps({"ts": time.time(), "output": output}))
        _cache_cleanup()
    except OSError as e:
        log.debug("Cache write failed for %s: %s", key, e)


# ---------------------------------------------------------------------------
# Process runner
# ---------------------------------------------------------------------------

class ToolRunResult:
    def __init__(self, tool: AnalysisTool, output: str,
                 returncode: int, duration_ms: int, from_cache: bool = False,
                 extra_outputs: dict | None = None):
        self.tool          = tool
        self.output        = output
        self.returncode    = returncode
        self.duration_ms   = duration_ms
        self.from_cache    = from_cache
        self.extra_outputs = extra_outputs or {}


async def _run_cmd(args: list[str], env: dict | None = None,
                   timeout: int = 120) -> tuple[str, int]:
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, **(env or {})},
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), proc.returncode or 0
    except asyncio.TimeoutError:
        if proc is not None:
            proc.kill()
            # Reap the process to avoid a zombie
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                log.error("Process %s did not die after kill()", args[0])
        return f"[memguard] TIMEOUT after {timeout}s", -1
    except FileNotFoundError as e:
        return f"[memguard] Tool not found: {e}", -2


# ---------------------------------------------------------------------------
# Valgrind memcheck — FULL FEATURED
# ---------------------------------------------------------------------------

async def run_valgrind(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.VALGRIND
    if not target.binary:
        return ToolRunResult(tool, "", 0, 0)

    key = _cache_key(target, tool)
    if cfg.cache_results and (cached := _cache_get(key)):
        return ToolRunResult(tool, cached, 0, 0, from_cache=True)

    xml_fd, xml_file = tempfile.mkstemp(suffix=".xml", prefix="mg_vg_")
    os.close(xml_fd)

    args = [
        "valgrind",
        "--tool=memcheck",
        # Leak detection — comprehensive
        "--leak-check=full",
        "--show-leak-kinds=all",        # definite, indirect, possible, reachable
        "--leak-resolution=high",       # merge fewer stacks → more distinct leaks
        "--undef-value-errors=yes",     # uninitialised value errors
        # FD tracking — catch unclosed files/sockets
        "--track-fds=yes",
        # Allocation tracking
        "--xtree-memory=full",          # full alloc/dealloc tracking tree
        "--expensive-definedness-checks=yes",
        # Output control
        "--num-callers=16",
        "--error-exitcode=0",
        "--xml=yes",
        f"--xml-file={xml_file}",
        "--child-silent-after-fork=yes",
        "--fair-sched=no",
        target.binary,
        *(target.args),
    ]
    if cfg.suppress_file:
        args.insert(1, f"--suppressions={cfg.suppress_file}")

    log.info("Valgrind command: %s", " ".join(args[:8]) + " ...")
    t0 = time.monotonic()
    stdout_txt, rc = await _run_cmd(args, target.env, cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)
    log.info("Valgrind finished: rc=%d ms=%d stdout=%d chars", rc, ms, len(stdout_txt))

    xml_path = Path(xml_file)
    output = xml_path.read_text(errors="replace") if xml_path.exists() else ""
    xml_path.unlink(missing_ok=True)
    log.info("Valgrind XML: %d bytes", len(output))

    # Extract FD leak info from stdout (not in XML)
    fd_leaks = ""
    for line in stdout_txt.splitlines():
        if "Open file descriptor" in line or "FILE DESCRIPTORS" in line or "inherited" in line.lower():
            fd_leaks += line + "\n"

    extra = {"fd_leaks": fd_leaks, "stdout": stdout_txt}

    if output and len(output) > 50 and cfg.cache_results:
        _cache_set(key, output)
    return ToolRunResult(tool, output, rc, ms, extra_outputs=extra)


# ---------------------------------------------------------------------------
# Valgrind Massif — heap profiling
# ---------------------------------------------------------------------------

async def run_massif(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.VALGRIND  # reuses valgrind tool enum
    if not target.binary:
        return ToolRunResult(tool, "", 0, 0)

    ms_fd, ms_file = tempfile.mkstemp(suffix=".out", prefix="mg_massif_")
    os.close(ms_fd)

    args = [
        "valgrind",
        "--tool=massif",
        "--stacks=yes",                 # include stack memory
        "--depth=12",
        "--detailed-freq=1",            # every snapshot is detailed
        "--max-snapshots=50",
        f"--massif-out-file={ms_file}",
        target.binary,
        *(target.args),
    ]

    t0 = time.monotonic()
    _, rc = await _run_cmd(args, target.env, cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)

    ms_path = Path(ms_file)
    output = ms_path.read_text(errors="replace") if ms_path.exists() else ""
    ms_path.unlink(missing_ok=True)

    # Also get ms_print formatted output for AI context
    ms_print = ""
    if shutil.which("ms_print") and output:
        ms_fd2, ms_file2 = tempfile.mkstemp(suffix=".out")
        os.close(ms_fd2)
        Path(ms_file2).write_text(output)
        ms_print_out, _ = await _run_cmd(["ms_print", ms_file2], timeout=10)
        ms_print = ms_print_out
        Path(ms_file2).unlink(missing_ok=True)

    return ToolRunResult(tool, output, rc, ms, extra_outputs={"massif_print": ms_print})


# ---------------------------------------------------------------------------
# Valgrind Helgrind — thread error detector (races, deadlocks, lock order)
# ---------------------------------------------------------------------------

async def run_helgrind(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.HELGRIND
    if not target.binary:
        return ToolRunResult(tool, "", 0, 0)

    key = _cache_key(target, tool)
    if cfg.cache_results and (cached := _cache_get(key)):
        return ToolRunResult(tool, cached, 0, 0, from_cache=True)

    xml_fd, xml_file = tempfile.mkstemp(suffix=".xml", prefix="mg_hg_")
    os.close(xml_fd)

    args = [
        "valgrind",
        "--tool=helgrind",
        "--history-level=full",         # full happens-before tracking
        "--conflict-cache-size=2000000",
        "--check-stack-refs=yes",
        "--num-callers=16",
        "--error-exitcode=0",
        "--xml=yes",
        f"--xml-file={xml_file}",
        target.binary,
        *(target.args),
    ]

    log.info("Helgrind command: %s", " ".join(args[:6]) + " ...")
    t0 = time.monotonic()
    _, rc = await _run_cmd(args, target.env, cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)

    xml_path = Path(xml_file)
    output = xml_path.read_text(errors="replace") if xml_path.exists() else ""
    xml_path.unlink(missing_ok=True)
    log.info("Helgrind XML: %d bytes", len(output))

    if output and len(output) > 50 and cfg.cache_results:
        _cache_set(key, output)
    return ToolRunResult(tool, output, rc, ms)


# ---------------------------------------------------------------------------
# ASan / LSan / MSan / UBSan
# ---------------------------------------------------------------------------

async def run_asan(target: ScanTarget, cfg: ScanConfig,
                   sanitizer: str = "address,leak") -> ToolRunResult:
    tool_map = {
        "address,leak": AnalysisTool.ASAN,
        "memory":       AnalysisTool.MSAN,
        "undefined":    AnalysisTool.UBSAN,
        "thread":       AnalysisTool.TSAN,
    }
    tool = tool_map.get(sanitizer, AnalysisTool.ASAN)

    binary = target.binary
    if not binary:
        return ToolRunResult(tool, "", 0, 0)

    # ASan only works on binaries compiled with -fsanitize flags
    if not target.compile_cmd:
        log.info("Skipping %s — no --compile flag (binary not built with sanitizers)", sanitizer)
        return ToolRunResult(tool, "", 0, 0)

    if target.compile_cmd:
        san_flags = f"-fsanitize={sanitizer} -fno-omit-frame-pointer -g -O1"
        compile_cmd = target.compile_cmd
        for comp in ("gcc ", "clang ", "g++ ", "clang++ "):
            compile_cmd = compile_cmd.replace(comp, f"{comp}{san_flags} ")
        out, rc = await _run_cmd(compile_cmd.split(), timeout=60)
        if rc != 0:
            return ToolRunResult(tool, f"Compile failed:\n{out}", rc, 0)

    env = {
        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=0:print_stats=1:log_path=/tmp/mg_asan",
        "LSAN_OPTIONS": "print_suppressions=0:verbosity=1",
        **target.env,
    }

    t0 = time.monotonic()
    output, rc = await _run_cmd([binary, *target.args], env, cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)

    for lf in Path("/tmp").glob("mg_asan.*"):
        output += "\n" + lf.read_text(errors="replace")
        lf.unlink(missing_ok=True)
    return ToolRunResult(tool, output, rc, ms)


# ---------------------------------------------------------------------------
# Source file discovery from binary DWARF debug info
# ---------------------------------------------------------------------------

async def _discover_sources_from_binary(binary: str) -> list[str]:
    """Extract source file paths from a compiled binary's debug info.
    
    DWARF stores comp_dir (directory) and filename separately in .debug_str.
    We collect both, combine them, and verify which files exist on disk.
    Only returns files that are plausibly the binary's own source — filters
    out system headers, build trees, .venv, etc.
    """
    sources: list[str] = []
    seen: set[str] = set()
    _SRC_EXT = (".c", ".cpp", ".cc", ".cxx")
    binary_stem = Path(binary).stem  # e.g., "server_sim"

    # Directories to SKIP — not user source code
    _SKIP_DIRS = {"/usr/", "/lib/", "/opt/", ".venv/", "/rr/", "/build/",
                  "/node_modules/", "/.cache/", "/site-packages/",
                  "/include/", "/sysdeps/", "/csu/", "/elf/"}

    def _is_user_source(path: str) -> bool:
        """Filter out system/build files — only keep user source code."""
        return not any(skip in path for skip in _SKIP_DIRS)

    # Method 1: readelf -p .debug_str (fast, works on most binaries)
    if shutil.which("readelf"):
        out, rc = await _run_cmd(
            ["readelf", "-p", ".debug_str", binary], timeout=10)
        if rc != 0:
            out, rc = await _run_cmd(
                ["readelf", "-p", ".debug_line_str", binary], timeout=10)

        if rc == 0:
            dirs = []
            names = []
            for line in out.splitlines():
                parts = line.strip().split("]", 1)
                if len(parts) < 2:
                    continue
                val = parts[1].strip()
                if not val:
                    continue
                if val.endswith(_SRC_EXT):
                    names.append(val)
                elif "/" in val and not val.startswith("-") and " " not in val:
                    if _is_user_source(val):
                        dirs.append(val)

            # Try full paths first (some compilers store absolute paths)
            for n in names:
                if "/" in n and Path(n).is_file() and _is_user_source(n) and n not in seen:
                    seen.add(n)
                    sources.append(n)

            # Combine user directories with source filenames
            if not sources:
                for d in dirs:
                    for n in names:
                        candidate = str(Path(d) / Path(n).name)
                        if (candidate not in seen and Path(candidate).is_file()
                                and _is_user_source(candidate)):
                            seen.add(candidate)
                            sources.append(candidate)

    # Method 2: fallback with strings (if readelf failed)
    if not sources and shutil.which("strings"):
        out, rc = await _run_cmd(["strings", binary], timeout=10)
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if (line.endswith(_SRC_EXT) and "/" in line
                        and Path(line).is_file() and _is_user_source(line)
                        and line not in seen):
                    seen.add(line)
                    sources.append(line)

    # Final safety: limit to 10 source files max
    return sources[:10]


# ---------------------------------------------------------------------------
# Facebook Infer — static analysis (null deref, resource leaks, races, UAF)
# ---------------------------------------------------------------------------

async def run_infer(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.INFER
    src_dir = target.source_dir or (
        str(Path(target.binary).parent) if target.binary else None)

    # Collect source files — but NEVER rglob from broad dirs like /tmp/
    files = target.files or []
    if not files and src_dir:
        src_path = Path(src_dir)
        # Only use rglob for dedicated source directories, not /tmp/ or /home/
        broad_dirs = {"/tmp", "/home", "/var", "/", "/opt", "/usr", "/root"}
        if str(src_path) not in broad_dirs:
            files = ([str(f) for f in src_path.rglob("*.c")]
                     + [str(f) for f in src_path.rglob("*.cpp")])
        else:
            # Just check immediate directory (non-recursive)
            files = ([str(f) for f in src_path.glob("*.c")]
                     + [str(f) for f in src_path.glob("*.cpp")])

    # If scanning a binary and no source files in its directory,
    # extract source paths from DWARF debug info
    if not files and target.binary:
        log.info("Infer: no source in %s — checking binary debug info", src_dir)
        found_sources = await _discover_sources_from_binary(target.binary)
        if found_sources:
            files = found_sources
            log.info("Infer: discovered %d source(s): %s",
                     len(files), [Path(f).name for f in files[:5]])

    if not files:
        log.info("Infer: no source files found — skipping")
        return ToolRunResult(tool, "", 0, 0)

    key = _cache_key(target, tool)
    if cfg.cache_results and (cached := _cache_get(key)):
        return ToolRunResult(tool, cached, 0, 0, from_cache=True)

    infer_out = Path(tempfile.mkdtemp(prefix="mg_infer_"))
    work_dir = Path(tempfile.mkdtemp(prefix="mg_infer_obj_"))
    t0 = time.monotonic()

    # ── Load MemHint summaries for custom allocator/deallocator injection ──
    memhint_flags = []
    memhint_path = Path.home() / ".memguard" / "memhint_summaries.json"
    if memhint_path.exists():
        try:
            import json as _json
            data = _json.loads(memhint_path.read_text())
            alloc_names = []
            dealloc_names = []
            for name, hints in data.get("hints", {}).items():
                for h in hints:
                    if h.get("role") == "Allocator" and h.get("validated", False):
                        alloc_names.append(name)
                    elif h.get("role") == "Deallocator" and h.get("validated", False):
                        dealloc_names.append(name)
            if alloc_names:
                pattern = "^(" + "|".join(alloc_names) + ")$"
                memhint_flags.extend(["--pulse-model-alloc-pattern", pattern])
                log.info("MemHint: injecting %d custom allocators into Infer", len(alloc_names))
            if dealloc_names:
                pattern = "^(" + "|".join(dealloc_names) + ")$"
                memhint_flags.extend(["--pulse-model-free-pattern", pattern])
                log.info("MemHint: injecting %d custom deallocators into Infer", len(dealloc_names))
        except Exception as e:
            log.debug("MemHint summaries load failed: %s", e)

    for src_file in files[:20]:
        compiler = "gcc"
        if src_file.endswith((".cpp", ".cxx", ".cc")):
            compiler = "g++"
        obj_name = Path(src_file).stem + ".o"
        args = [
            "infer", "run",
            "--no-progress-bar",
            "--results-dir", str(infer_out),
        ] + memhint_flags + [
            "--", compiler, "-c", "-g", "-O0",
            str(src_file),
            "-o", str(work_dir / obj_name),
        ]
        out, rc = await _run_cmd(args, target.env, timeout=120)
        # Infer rc=2 means "found issues" — that's success for us
        if rc not in (0, 2):
            log.warning("Infer failed on %s: rc=%d output=%s",
                        src_file, rc, out[:200])

    ms = int((time.monotonic() - t0) * 1000)

    report_path = infer_out / "report.json"
    output = report_path.read_text(errors="replace") if report_path.exists() else "[]"

    shutil.rmtree(str(infer_out), ignore_errors=True)
    shutil.rmtree(str(work_dir), ignore_errors=True)

    if output and len(output) > 10 and cfg.cache_results:
        _cache_set(key, output)

    log.info("Infer finished: %dms, report=%d bytes", ms, len(output))
    return ToolRunResult(tool, output, 0, ms)


# ---------------------------------------------------------------------------
# cppcheck / clang-tidy
# ---------------------------------------------------------------------------

async def run_cppcheck(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.CPPCHECK
    src = (target.source_dir
           or (str(Path(target.files[0]).parent) if target.files else None)
           or (str(Path(target.binary).parent) if target.binary else None)
           or ".")
    key = _cache_key(target, tool)
    if cfg.cache_results and (cached := _cache_get(key)):
        return ToolRunResult(tool, cached, 0, 0, from_cache=True)

    args = ["cppcheck", "--enable=all", "--inconclusive", "--xml",
            "--xml-version=2", "--suppress=missingIncludeSystem", src]
    t0 = time.monotonic()
    output, rc = await _run_cmd(args, timeout=cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)
    if cfg.cache_results:
        _cache_set(key, output)
    return ToolRunResult(tool, output, rc, ms)


async def run_clang_tidy(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.CLANG_TIDY
    src_dir = target.source_dir or (
        str(Path(target.binary).parent) if target.binary else None)
    files = target.files or (
        list(Path(src_dir).rglob("*.c")) + list(Path(src_dir).rglob("*.cpp"))
        if src_dir else [])
    if not files:
        return ToolRunResult(tool, "", 0, 0)
    key = _cache_key(target, tool)
    if cfg.cache_results and (cached := _cache_get(key)):
        return ToolRunResult(tool, cached, 0, 0, from_cache=True)

    checks = "clang-analyzer-*,bugprone-*,performance-*,cppcoreguidelines-*,modernize-*"
    args = ["clang-tidy", f"--checks={checks}"] + [str(f) for f in files[:30]] + ["--", "-std=c17"]
    t0 = time.monotonic()
    output, rc = await _run_cmd(args, timeout=cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)
    if cfg.cache_results:
        _cache_set(key, output)
    return ToolRunResult(tool, output, rc, ms)


# ---------------------------------------------------------------------------
# Python tools
# ---------------------------------------------------------------------------

async def run_tracemalloc(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.TRACEMALLOC
    script = target.files[0] if target.files else target.binary
    wrapper = f"""
import tracemalloc, json, runpy, sys
tracemalloc.start(25)
sys.argv = {[script] + target.args!r}
try:
    runpy.run_path({str(script)!r}, run_name="__main__")
except SystemExit:
    pass
snapshot = tracemalloc.take_snapshot()
stats = snapshot.statistics("lineno")
print(json.dumps([
    {{"file": str(s.traceback[0].filename), "line": s.traceback[0].lineno,
      "size": s.size, "count": s.count,
      "traceback": [{{"file": str(f.filename), "line": f.lineno}} for f in s.traceback]}}
    for s in stats[:100]
]))
"""
    tf_fd, tf = tempfile.mkstemp(suffix=".py", prefix="mg_trace_")
    os.close(tf_fd)
    Path(tf).write_text(wrapper)
    t0 = time.monotonic()
    out, rc = await _run_cmd(["python", tf], target.env, cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)
    Path(tf).unlink(missing_ok=True)
    return ToolRunResult(tool, out, rc, ms)


async def run_miri(target: ScanTarget, cfg: ScanConfig) -> ToolRunResult:
    tool = AnalysisTool.MIRI
    cwd = target.source_dir or str(Path(target.files[0]).parent if target.files else ".")
    args = ["cargo", "+nightly", "miri", "test", "--", "--nocapture"]
    env = {**target.env, "MIRIFLAGS": "-Zmiri-disable-isolation"}
    t0 = time.monotonic()
    out, rc = await _run_cmd(args, env, cfg.timeout_sec)
    ms = int((time.monotonic() - t0) * 1000)
    return ToolRunResult(tool, out, rc, ms)


# ---------------------------------------------------------------------------
# Parallel orchestrator
# ---------------------------------------------------------------------------

class ToolOrchestrator:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg

    async def run_all(self, target: ScanTarget) -> dict[AnalysisTool, ToolRunResult]:
        tools = self.cfg.tools or available_tools(target.language)
        log.info("Running tools: %s", [t.value for t in tools])

        dispatch = {
            AnalysisTool.VALGRIND:    lambda: run_valgrind(target, self.cfg),
            AnalysisTool.HELGRIND:    lambda: run_helgrind(target, self.cfg),
            AnalysisTool.ASAN:        lambda: run_asan(target, self.cfg, "address,leak"),
            AnalysisTool.LSAN:        lambda: run_asan(target, self.cfg, "address,leak"),
            AnalysisTool.MSAN:        lambda: run_asan(target, self.cfg, "memory"),
            AnalysisTool.UBSAN:       lambda: run_asan(target, self.cfg, "undefined"),
            AnalysisTool.TSAN:        lambda: run_asan(target, self.cfg, "thread"),
            AnalysisTool.INFER:       lambda: run_infer(target, self.cfg),
            AnalysisTool.CPPCHECK:    lambda: run_cppcheck(target, self.cfg),
            AnalysisTool.CLANG_TIDY:  lambda: run_clang_tidy(target, self.cfg),
            AnalysisTool.TRACEMALLOC: lambda: run_tracemalloc(target, self.cfg),
            AnalysisTool.MIRI:        lambda: run_miri(target, self.cfg),
        }

        tasks = {t: asyncio.create_task(dispatch[t]()) for t in tools if t in dispatch}
        results = {}
        for coro in asyncio.as_completed(tasks.values()):
            result = await coro
            results[result.tool] = result
            log.info("Done: %s in %dms (cache=%s)", result.tool.value, result.duration_ms, result.from_cache)
        return results
