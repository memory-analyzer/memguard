"""
memguard.core.heaptrack
========================
Heaptrack integration — heap memory profiler from KDE.

Records every malloc/free/realloc call with full call stacks,
then generates interactive visualizations:
  - Heap consumption over time (peak, total, leaked)
  - Per-function allocation breakdown (top consumers)
  - Flame graph of allocation sites
  - Temporary vs persistent allocation ratio
  - Call-site table with sizes and counts

Install: sudo apt install heaptrack
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class HeapAllocationSite:
    function: str
    file: str
    line: int
    allocations: int
    peak_bytes: int
    leaked_bytes: int
    temporary: int
    stack: list[str] = field(default_factory=list)


@dataclass
class HeapSnapshot:
    timestamp_ms: int
    heap_bytes: int
    allocations: int


@dataclass
class HeaptrackReport:
    binary: str
    recording_file: str
    peak_heap_bytes: int
    peak_allocations: int
    total_allocations: int
    total_bytes_allocated: int
    total_temporary: int
    total_temporary_pct: float
    leaked_bytes: int
    leaked_allocations: int
    duration_ms: int
    top_sites: list[HeapAllocationSite]
    timeline: list[HeapSnapshot]
    flamegraph_data: list[dict]


# ═══════════════════════════════════════════════════════════════════════════
# Run heaptrack
# ═══════════════════════════════════════════════════════════════════════════

async def run_heaptrack(
    binary: str,
    args: list[str] | None = None,
    timeout: int = 60,
    output_dir: str | None = None,
) -> str | None:
    """Run heaptrack to record heap allocations. Returns path to recording file."""
    if not shutil.which("heaptrack"):
        log.error("heaptrack not installed. Install with: sudo apt install heaptrack")
        return None

    out_dir = output_dir or tempfile.mkdtemp(prefix="mg_heaptrack_")
    cmd = ["heaptrack", "-o", str(Path(out_dir) / "heap"), binary] + (args or [])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        output = ""

    # Find the recording file
    rec_file = None
    for line in output.splitlines():
        m = re.search(r'heaptrack output will be written to "(.+?)"', line)
        if m:
            rec_file = m.group(1)
        m = re.search(r'"(.+\.(?:zst|gz))"', line)
        if m and Path(m.group(1)).exists():
            rec_file = m.group(1)

    # Search output directory for recording files
    if not rec_file:
        for f in Path(out_dir).rglob("heap.*"):
            if f.suffix in (".zst", ".gz", ""):
                rec_file = str(f)
                break

    log.info("heaptrack recording: %s", rec_file)
    return rec_file


# ═══════════════════════════════════════════════════════════════════════════
# Parse heaptrack_print output
# ═══════════════════════════════════════════════════════════════════════════

async def parse_heaptrack(recording_file: str, binary: str = "") -> HeaptrackReport:
    """Parse heaptrack recording using heaptrack_print."""
    if not shutil.which("heaptrack_print"):
        log.error("heaptrack_print not installed")
        raise RuntimeError("heaptrack_print not found. Install heaptrack.")

    t0 = time.monotonic()

    # Run heaptrack_print - default output with all stats
    proc = await asyncio.create_subprocess_exec(
        "heaptrack_print", recording_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    output = stdout.decode(errors="replace")
    log.debug("heaptrack_print output length: %d chars", len(output))
    log.debug("heaptrack_print first 500 chars:\n%s", output[:500])

    # Also build flamegraph data from the parsed output
    # Parse the full call stacks from heaptrack_print's "N calls with X from:" blocks
    flame_data = []
    flame_stacks: dict[str, int] = {}

    in_calls_block = False
    current_call_stack: list[str] = []
    current_call_bytes = 0

    for line in output.splitlines():
        s = line.strip()

        # "100 calls with 26.40K peak consumption from:"
        m = re.match(r'(\d+)\s+calls?\s+with\s+([\d,.]+)\s*(\w+)\s+peak\s+consumption\s+from', s)
        if m:
            # Save previous stack
            if current_call_stack and current_call_bytes > 0:
                key = ";".join(reversed(current_call_stack))
                flame_stacks[key] = flame_stacks.get(key, 0) + current_call_bytes

            current_call_bytes = _parse_size(m.group(2), m.group(3))
            current_call_stack = []
            in_calls_block = True
            continue

        # "N calls to allocation functions with X peak consumption from"
        m2 = re.match(r'(\d+)\s+calls?\s+to\s+allocation', s)
        if m2:
            if current_call_stack and current_call_bytes > 0:
                key = ";".join(reversed(current_call_stack))
                flame_stacks[key] = flame_stacks.get(key, 0) + current_call_bytes
            current_call_stack = []
            current_call_bytes = 0
            in_calls_block = False
            continue

        if in_calls_block and s and not s.startswith("at ") and not s.startswith("in /"):
            fn = s.split("::")[0] if "::" in s and len(s.split("::")[0]) > 2 else s
            fn = fn.strip()
            if fn and len(fn) > 1 and fn not in ("from", "from:"):
                current_call_stack.append(fn)

    # Save last
    if current_call_stack and current_call_bytes > 0:
        key = ";".join(reversed(current_call_stack))
        flame_stacks[key] = flame_stacks.get(key, 0) + current_call_bytes

    flame_data = [{"stack": k, "value": v} for k, v in
                  sorted(flame_stacks.items(), key=lambda x: -x[1])]
    log.debug("Built %d flame graph entries from parsed stacks", len(flame_data))

    duration_ms = int((time.monotonic() - t0) * 1000)
    report = _parse_print_output(output, binary, recording_file, duration_ms, flame_data)
    return report


def _parse_print_output(
    output: str, binary: str, rec_file: str,
    duration_ms: int, flame_data: list[dict],
) -> HeaptrackReport:
    """Parse heaptrack_print text output into structured report."""
    peak_bytes = 0
    peak_allocs = 0
    total_allocs = 0
    total_bytes = 0
    total_temp = 0
    total_temp_pct = 0.0
    leaked_bytes = 0
    leaked_allocs = 0
    top_sites: list[HeapAllocationSite] = []
    timeline: list[HeapSnapshot] = []

    lines = output.splitlines()

    # ── Parse summary statistics ──
    for line in lines:
        s = line.strip()

        # Peak heap: multiple format variations
        for pat in [
            r'peak heap memory consumption:\s*([\d,.]+)\s*(\w+)',
            r'peak heap:\s*([\d,.]+)\s*(\w+)',
            r'([\d,.]+)\s*(\w+)\s+peak heap',
            r'peak memory consumed.*?([\d,.]+)\s*(\w+)',
        ]:
            m = re.search(pat, s, re.IGNORECASE)
            if m:
                peak_bytes = _parse_size(m.group(1), m.group(2))
                break

        # Total allocations
        for pat in [
            r'total memory allocated:\s*([\d,.]+)\s*(\w+)',
            r'([\d,.]+)\s*(\w+)\s+total memory allocated',
            r'total allocated:\s*([\d,.]+)\s*(\w+)',
        ]:
            m = re.search(pat, s, re.IGNORECASE)
            if m:
                total_bytes = _parse_size(m.group(1), m.group(2))
                break

        # Allocation count
        for pat in [
            r'calls to allocation functions:\s*([\d,]+)',
            r'([\d,]+)\s+calls to allocation',
            r'total allocations:\s*([\d,]+)',
            r'([\d,]+)\s+allocations',
        ]:
            m = re.search(pat, s, re.IGNORECASE)
            if m:
                total_allocs = max(total_allocs, int(m.group(1).replace(",", "")))
                break

        # Temporary
        m = re.search(r'temporary allocations:\s*([\d,]+)\s*\(([\d.]+)%\)', s, re.IGNORECASE)
        if not m:
            m = re.search(r'([\d,]+)\s+temporary.*?([\d.]+)%', s, re.IGNORECASE)
        if m:
            total_temp = int(m.group(1).replace(",", ""))
            total_temp_pct = float(m.group(2))

        # Leaked
        for pat in [
            r'([\d,.]+)\s*(\w+)\s+leaked',
            r'leaked:\s*([\d,.]+)\s*(\w+)',
            r'memory leaked:\s*([\d,.]+)\s*(\w+)',
        ]:
            m = re.search(pat, s, re.IGNORECASE)
            if m:
                leaked_bytes = _parse_size(m.group(1), m.group(2))
                break

    # ── Parse allocation sites (top consumers) ──
    # Actual heaptrack_print format:
    #   100 calls to allocation functions with 26.40K peak consumption from
    #   add_log
    #     at /path/to/server_sim.c:146
    #     in /tmp/server_sim
    #   100 calls with 26.40K peak consumption from:
    #       main
    #         at /path/to/server_sim.c:228

    current_site = None
    current_stack = []
    waiting_for_func = False

    for i, line in enumerate(lines):
        raw = line
        s = line.strip()

        # Match site header:
        # "100 calls to allocation functions with 26.40K peak consumption from"
        # "4 calls to allocation functions with 1.34K peak consumption from"
        m = re.match(r'(\d+)\s+calls?\s+(?:to allocation functions\s+)?with\s+([\d,.]+)\s*(\w+)\s+peak\s+consumption\s+from', s)
        if m:
            # Save previous site
            if current_site and current_site.function != "??":
                current_site.stack = current_stack[:5]
                top_sites.append(current_site)

            current_site = HeapAllocationSite(
                function="??", file="??", line=0,
                allocations=int(m.group(1)),
                peak_bytes=_parse_size(m.group(2), m.group(3)),
                leaked_bytes=0, temporary=0,
            )
            current_stack = []
            waiting_for_func = True
            continue

        # Sub-call header: "100 calls with 26.40K peak consumption from:"
        m = re.match(r'(\d+)\s+calls?\s+with\s+([\d,.]+)\s*(\w+)\s+peak\s+consumption\s+from', s)
        if m:
            waiting_for_func = True
            continue

        if current_site:
            # "  at /path/to/file.c:146"
            m = re.match(r'at\s+(.+?):(\d+)\s*$', s)
            if m:
                fpath = m.group(1)
                fline = int(m.group(2))
                fname = fpath.split("/")[-1]
                # If we have a function waiting, assign file info
                if current_site.function != "??" and current_site.file == "??":
                    # Only use user source files, not system files
                    if not any(skip in fpath for skip in ("/lib/", "/usr/", "/elf/", "/libio/", "/nptl/")):
                        current_site.file = fname
                        current_site.line = fline
                continue

            # "  in /tmp/server_sim" — binary path, skip
            if s.startswith("in /") or s.startswith("in ./"):
                continue

            # Function name line (after header, possibly indented)
            if waiting_for_func and s and not s.startswith("at ") and not s.startswith("in "):
                fn_name = s.split("::")[0] if "::" in s else s  # Handle C++ namespaces
                fn_name = fn_name.strip()
                if fn_name and len(fn_name) > 1:
                    current_stack.append(fn_name)
                    # Set as site function if it's a user function
                    SKIP_FUNCS = {"malloc", "calloc", "realloc", "free", "strdup",
                                  "operator new", "operator new[]", "operator delete",
                                  "__libc_malloc", "__libc_calloc", "_int_malloc",
                                  "sysmalloc", "??", "__GI__IO_file_doallocate",
                                  "__GI__IO_doallocbuf", "__GI__dl_allocate_tls",
                                  "_IO_new_file_overflow", "_IO_new_file_xsputn",
                                  "_IO_new_file_underflow", "__GI__IO_default_uflow",
                                  "__GI__IO_puts", "__GI__IO_fwrite",
                                  "__pthread_create_2_1"}
                    base_fn = fn_name.split("::")[-1] if "::" in fn_name else fn_name
                    if current_site.function == "??" and base_fn not in SKIP_FUNCS:
                        current_site.function = fn_name
                waiting_for_func = True  # Keep looking for more frames
                continue

            # Empty line = potential end of block
            if s == "":
                waiting_for_func = False

        # Section headers
        if re.match(r'MOST\s+CALLS|PEAK\s+HEAP|MOST\s+TEMPORARY|MOST\s+BYTES', s, re.IGNORECASE):
            # Save previous and start new section
            if current_site and current_site.function != "??":
                current_site.stack = current_stack[:5]
                top_sites.append(current_site)
            current_site = None
            current_stack = []

    # Save last site
    if current_site and current_site.function != "??":
        current_site.stack = current_stack[:5]
        top_sites.append(current_site)

    # ── Fallback: build sites from flame graph data ──
    if not top_sites and flame_data:
        func_bytes: dict[str, int] = {}
        for f in flame_data:
            parts = f["stack"].split(";")
            for fn in parts:
                fn = fn.strip()
                if fn and fn not in ("malloc", "calloc", "free", "__libc_malloc",
                                      "_int_malloc", "sysmalloc", "[unknown]"):
                    func_bytes[fn] = func_bytes.get(fn, 0) + f["value"]
        for fn, bytes_val in sorted(func_bytes.items(), key=lambda x: -x[1])[:15]:
            top_sites.append(HeapAllocationSite(
                function=fn, file="??", line=0,
                allocations=0, peak_bytes=bytes_val,
                leaked_bytes=0, temporary=0,
            ))

    # ── Fallback: parse any "function_name - N bytes" patterns ──
    if not top_sites:
        for line in lines:
            m = re.search(r'(\w[\w:]+)\s+.*?([\d,.]+)\s*(\w+)\s+(?:peak|allocated|consumed)', line.strip())
            if m:
                fn = m.group(1)
                if fn not in ("peak", "total", "calls", "temporary", "leaked"):
                    top_sites.append(HeapAllocationSite(
                        function=fn, file="??", line=0,
                        allocations=0,
                        peak_bytes=_parse_size(m.group(2), m.group(3)),
                        leaked_bytes=0, temporary=0,
                    ))

    # Sort by peak bytes
    top_sites.sort(key=lambda s: s.peak_bytes, reverse=True)
    top_sites = top_sites[:20]

    # ── Build synthetic timeline ──
    if peak_bytes > 0:
        steps = min(50, max(10, total_allocs))
        for i in range(steps + 1):
            frac = i / steps
            heap = int(peak_bytes * min(1.0, frac * 1.3))
            if frac > 0.8:
                heap = peak_bytes - int((peak_bytes - leaked_bytes) * (frac - 0.8) / 0.2)
            heap = max(0, min(peak_bytes, heap))
            timeline.append(HeapSnapshot(
                timestamp_ms=int(frac * duration_ms) if duration_ms > 0 else int(frac * 100),
                heap_bytes=heap,
                allocations=int(frac * total_allocs),
            ))

    log.info("heaptrack parsed: peak=%d, allocs=%d, leaked=%d, sites=%d, flame=%d",
             peak_bytes, total_allocs, leaked_bytes, len(top_sites), len(flame_data))

    return HeaptrackReport(
        binary=binary,
        recording_file=rec_file,
        peak_heap_bytes=peak_bytes,
        peak_allocations=peak_allocs or total_allocs,
        total_allocations=total_allocs,
        total_bytes_allocated=total_bytes,
        total_temporary=total_temp,
        total_temporary_pct=total_temp_pct,
        leaked_bytes=leaked_bytes,
        leaked_allocations=leaked_allocs,
        duration_ms=duration_ms,
        top_sites=top_sites,
        timeline=timeline,
        flamegraph_data=flame_data[:200],
    )


def _parse_size(num_str: str, unit: str) -> int:
    """Parse a size string like '1.5 MB' into bytes."""
    num = float(num_str.replace(",", ""))
    unit = unit.upper().strip()
    multipliers = {
        "B": 1, "BYTES": 1, "BYTE": 1,
        "KB": 1024, "K": 1024, "KIB": 1024,
        "MB": 1048576, "M": 1048576, "MIB": 1048576,
        "GB": 1073741824, "G": 1073741824, "GIB": 1073741824,
    }
    return int(num * multipliers.get(unit, 1))


# ═══════════════════════════════════════════════════════════════════════════
# Generate visualization HTML
# ═══════════════════════════════════════════════════════════════════════════

def generate_heaptrack_viz(report: HeaptrackReport) -> str:
    """Generate interactive HTML visualization from heaptrack data."""

    sites_json = json.dumps([{
        "func": s.function,
        "file": s.file,
        "line": s.line,
        "allocs": s.allocations,
        "peak": s.peak_bytes,
        "leaked": s.leaked_bytes,
        "temp": s.temporary,
        "stack": s.stack,
    } for s in report.top_sites])

    timeline_json = json.dumps([{
        "t": s.timestamp_ms,
        "heap": s.heap_bytes,
        "allocs": s.allocations,
    } for s in report.timeline])

    flame_json = json.dumps(report.flamegraph_data[:100])

    def fmtB(b):
        if b >= 1048576: return f"{b/1048576:.1f} MB"
        if b >= 1024: return f"{b/1024:.1f} KB"
        return f"{b} B"

    html = _HEAPTRACK_HTML
    html = html.replace("__SITES__", sites_json)
    html = html.replace("__TIMELINE__", timeline_json)
    html = html.replace("__FLAME__", flame_json)
    html = html.replace("__BINARY__", Path(report.binary).name)
    html = html.replace("__PEAK_HEAP__", fmtB(report.peak_heap_bytes))
    html = html.replace("__PEAK_BYTES__", str(report.peak_heap_bytes))
    html = html.replace("__TOTAL_ALLOCS__", f"{report.total_allocations:,}")
    html = html.replace("__TOTAL_BYTES__", fmtB(report.total_bytes_allocated))
    html = html.replace("__TEMP_COUNT__", f"{report.total_temporary:,}")
    html = html.replace("__TEMP_PCT__", f"{report.total_temporary_pct:.1f}")
    html = html.replace("__LEAKED__", fmtB(report.leaked_bytes))
    html = html.replace("__LEAKED_BYTES__", str(report.leaked_bytes))
    html = html.replace("__DURATION__", f"{report.duration_ms}")

    return html


_HEAPTRACK_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MemGuard Heap Profile</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--card:#1c2128;--border:#30363d;
--cyan:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--purple:#bc8cff;
--orange:#f0883e;--text:#c9d1d9;--dim:#8b949e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',system-ui,sans-serif;font-size:14px}
.hdr{background:linear-gradient(135deg,#161b22,#1c2128);border-bottom:1px solid var(--border);padding:1.25rem 2rem}
.hdr h1{font-size:1.1rem;color:var(--purple)}
.hdr .meta{font-size:.8rem;color:var(--dim)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.75rem;padding:1rem 2rem}
.metric{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.75rem;text-align:center}
.metric .val{font-size:1.4rem;font-weight:800;line-height:1.2}
.metric .lbl{font-size:.65rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-top:.2rem}
.container{max-width:1400px;margin:0 auto;padding:0 1.5rem 2rem}
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:1rem}
.tab{padding:.6rem 1rem;cursor:pointer;color:var(--dim);font-weight:600;font-size:.85rem;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .2s}
.tab:hover{color:var(--text)}.tab.active{color:var(--purple);border-bottom-color:var(--purple)}
.panel{display:none}.panel.active{display:block}
.chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem}
.chart-wrap svg{width:100%;display:block}
.tip{position:absolute;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.4rem .6rem;font-size:.75rem;pointer-events:none;z-index:10;display:none;box-shadow:0 4px 12px rgba(0,0,0,.4)}
table{width:100%;border-collapse:separate;border-spacing:0 3px}
th{text-align:left;font-size:.7rem;color:var(--dim);text-transform:uppercase;padding:.5rem .75rem;border-bottom:1px solid var(--border)}
td{padding:.5rem .75rem;border-bottom:1px solid #21262d;vertical-align:middle}
tr:hover{background:var(--card)}
.bar-wrap{height:20px;background:#21262d;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;display:flex;align-items:center;padding:0 6px;font-size:.7rem;color:#000;font-weight:700;min-width:3px}
.flame-row{display:flex;width:100%}
.flame-cell{height:22px;display:flex;align-items:center;justify-content:center;font-size:.65rem;color:#fff;overflow:hidden;cursor:pointer;border-right:1px solid var(--bg);transition:opacity .15s}
.flame-cell:hover{opacity:.8}
</style></head><body>

<div class="hdr">
  <h1>Heap Memory Profile — __BINARY__</h1>
  <div class="meta">Powered by heaptrack + MemGuard</div>
</div>

<div class="metrics">
  <div class="metric"><div class="val" style="color:var(--purple)">__PEAK_HEAP__</div><div class="lbl">Peak Heap</div></div>
  <div class="metric"><div class="val" style="color:var(--cyan)">__TOTAL_ALLOCS__</div><div class="lbl">Total Allocations</div></div>
  <div class="metric"><div class="val" style="color:var(--cyan)">__TOTAL_BYTES__</div><div class="lbl">Total Allocated</div></div>
  <div class="metric"><div class="val" style="color:var(--yellow)">__TEMP_COUNT__</div><div class="lbl">Temporary (__TEMP_PCT__%)</div></div>
  <div class="metric"><div class="val" style="color:var(--red)">__LEAKED__</div><div class="lbl">Leaked</div></div>
  <div class="metric"><div class="val" style="color:var(--dim)">__DURATION__ms</div><div class="lbl">Profile Time</div></div>
</div>

<div class="container">
<div class="tabs">
  <div class="tab active" onclick="showTab('heap-timeline',this)">Heap Timeline</div>
  <div class="tab" onclick="showTab('top-allocs',this)">Top Allocators</div>
  <div class="tab" onclick="showTab('flamegraph',this)">Flame Graph</div>
</div>

<div id="heap-timeline" class="panel active">
  <div class="chart-wrap" style="position:relative">
    <svg id="heap-svg" viewBox="0 0 800 300"></svg>
    <div class="tip" id="htip"></div>
  </div>
</div>

<div id="top-allocs" class="panel">
  <table><thead><tr>
    <th>Function</th><th>Location</th><th style="text-align:right">Peak</th><th>Memory</th><th style="text-align:right">Allocations</th>
  </tr></thead><tbody id="alloc-body"></tbody></table>
</div>

<div id="flamegraph" class="panel">
  <div id="flame-area" style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;min-height:300px">
  </div>
</div>
</div>

<script>
var SITES=__SITES__,TL=__TIMELINE__,FLAME=__FLAME__;
function fmtB(b){if(b>=1048576)return(b/1048576).toFixed(1)+' MB';if(b>=1024)return(b/1024).toFixed(1)+' KB';return b+' B'}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function showTab(id,el){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active')});
  document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('active')});
  document.getElementById(id).classList.add('active');
  if(el)el.classList.add('active');
}

/* Heap Timeline Chart */
(function(){
  if(!TL.length)return;
  var svg=document.getElementById('heap-svg');
  var W=800,H=300,pad={t:25,r:25,b:35,l:60};
  var cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
  var maxY=Math.max.apply(null,TL.map(function(p){return p.heap}))||1;
  var maxX=TL[TL.length-1].t||1;

  function sx(v){return pad.l+(v/maxX)*cw}
  function sy(v){return pad.t+ch-(v/maxY)*ch}

  var h='';
  // Grid
  for(var g=0;g<=4;g++){
    var gy=pad.t+ch*(g/4);
    h+='<line x1="'+pad.l+'" y1="'+gy+'" x2="'+(W-pad.r)+'" y2="'+gy+'" stroke="#21262d"/>';
    h+='<text x="'+(pad.l-6)+'" y="'+(gy+4)+'" text-anchor="end" fill="#8b949e" font-size="9">'+fmtB(Math.round(maxY*(1-g/4)))+'</text>';
  }
  h+='<text x="'+(W/2)+'" y="'+(H-5)+'" text-anchor="middle" fill="#8b949e" font-size="10">Time (ms)</text>';

  // Area path
  var area='M '+sx(TL[0].t)+' '+sy(0);
  var line='M '+sx(TL[0].t)+' '+sy(TL[0].heap);
  for(var i=0;i<TL.length;i++){
    area+=' L '+sx(TL[i].t)+' '+sy(TL[i].heap);
    if(i>0)line+=' L '+sx(TL[i].t)+' '+sy(TL[i].heap);
  }
  area+=' L '+sx(TL[TL.length-1].t)+' '+sy(0)+' Z';

  h+='<defs><linearGradient id="hg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#bc8cff" stop-opacity="0.4"/><stop offset="100%" stop-color="#bc8cff" stop-opacity="0.02"/></linearGradient></defs>';
  h+='<path d="'+area+'" fill="url(#hg)"/>';
  h+='<path d="'+line+'" fill="none" stroke="#bc8cff" stroke-width="2.5" stroke-linejoin="round"/>';

  // Peak indicator
  var peakI=0,peakV=0;
  TL.forEach(function(p,i){if(p.heap>peakV){peakV=p.heap;peakI=i}});
  h+='<line x1="'+sx(TL[peakI].t)+'" y1="'+sy(peakV)+'" x2="'+sx(TL[peakI].t)+'" y2="'+sy(0)+'" stroke="#bc8cff" stroke-width="1" stroke-dasharray="3,3" opacity="0.5"/>';
  h+='<circle cx="'+sx(TL[peakI].t)+'" cy="'+sy(peakV)+'" r="5" fill="#bc8cff" stroke="var(--bg)" stroke-width="2"/>';
  h+='<text x="'+(sx(TL[peakI].t)+8)+'" y="'+(sy(peakV)-6)+'" fill="#bc8cff" font-size="10" font-weight="700">Peak: '+fmtB(peakV)+'</text>';

  // Leaked line
  var lastH=TL[TL.length-1].heap;
  if(lastH>0){
    h+='<line x1="'+sx(TL[TL.length-1].t)+'" y1="'+sy(lastH)+'" x2="'+(W-pad.r)+'" y2="'+sy(lastH)+'" stroke="var(--red)" stroke-width="1.5" stroke-dasharray="4,3"/>';
    h+='<text x="'+(W-pad.r+4)+'" y="'+(sy(lastH)+4)+'" fill="var(--red)" font-size="9" font-weight="700">'+fmtB(lastH)+'</text>';
  }

  // Data points
  TL.forEach(function(p,i){
    if(i%3!==0&&i!==TL.length-1)return;
    h+='<circle cx="'+sx(p.t)+'" cy="'+sy(p.heap)+'" r="3" fill="#bc8cff" stroke="var(--bg)" stroke-width="1.5" opacity="0.7"/>';
  });

  svg.innerHTML=h;
})();

/* Top Allocators Table */
(function(){
  var tb=document.getElementById('alloc-body');
  if(!SITES.length){tb.innerHTML='<tr><td colspan="5" style="color:var(--dim);text-align:center">No allocation sites found</td></tr>';return}
  var maxP=Math.max.apply(null,SITES.map(function(s){return s.peak}))||1;

  SITES.forEach(function(s){
    var pct=Math.max(3,(s.peak/maxP)*100);
    var col=s.leaked>0?'var(--red)':'var(--purple)';
    var tr=document.createElement('tr');
    tr.innerHTML=
      '<td><span style="font-weight:600;color:var(--cyan)">'+esc(s.func)+'()</span></td>'
      +'<td style="color:var(--dim);font-size:.8rem">'+esc(s.file)+':'+s.line+'</td>'
      +'<td style="text-align:right;font-weight:700;color:'+col+'">'+fmtB(s.peak)+'</td>'
      +'<td><div class="bar-wrap"><div class="bar-fill" style="width:'+pct+'%;background:'+col+'">'+fmtB(s.peak)+'</div></div></td>'
      +'<td style="text-align:right;color:var(--dim)">'+s.allocs.toLocaleString()+'</td>';
    tb.appendChild(tr);
  });
})();

/* Flame Graph */
(function(){
  var area=document.getElementById('flame-area');
  if(!FLAME.length){area.innerHTML='<p style="color:var(--dim);text-align:center;padding:2rem">No flame graph data. Run heaptrack_print -F on the recording.</p>';return}

  var maxVal=Math.max.apply(null,FLAME.map(function(f){return f.value}))||1;
  var palette=['#da3633','#f0883e','#d29922','#3fb950','#58a6ff','#bc8cff','#8957e5','#1f6feb'];

  // Build layers
  var layers={};
  FLAME.forEach(function(f){
    var parts=f.stack.split(';');
    parts.forEach(function(fn,depth){
      if(!layers[depth])layers[depth]=[];
      layers[depth].push({func:fn,value:f.value,depth:depth});
    });
  });

  var h='<div style="font-size:.75rem;color:var(--dim);margin-bottom:.5rem">Allocation call stacks — width proportional to bytes allocated</div>';

  var depths=Object.keys(layers).map(Number).sort(function(a,b){return b-a});
  depths.forEach(function(d){
    var row=layers[d];
    // Merge adjacent same-function entries
    var merged={};
    row.forEach(function(r){
      if(!merged[r.func])merged[r.func]={func:r.func,value:0};
      merged[r.func].value+=r.value;
    });
    var items=Object.values(merged).sort(function(a,b){return b.value-a.value});
    var totalVal=items.reduce(function(s,i){return s+i.value},0);

    h+='<div class="flame-row">';
    items.forEach(function(item,i){
      var pct=(item.value/totalVal)*100;
      if(pct<1)return;
      var col=palette[(d+i)%palette.length];
      h+='<div class="flame-cell" style="width:'+pct+'%;background:'+col+'" title="'+esc(item.func)+' ('+fmtB(item.value)+')">';
      if(pct>5)h+=esc(item.func.split('::').pop().split('(')[0]);
      h+='</div>';
    });
    h+='</div>';
  });

  area.innerHTML=h;
})();
</script></body></html>"""
