"""
memguard.core.visualizer
=========================
Generates interactive memory visualizations:

1. MEMORY PROFILE — SVG line chart of cumulative heap usage over time
2. ALLOCATION TIMELINE — Gantt-style lifecycle bars (born → freed/leaked)
3. HEAP TREEMAP — proportional boxes showing which functions own memory
4. POINTER FLOW GRAPH — ownership arrows with curved connectors

Outputs self-contained HTML that opens in any browser.
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from dataclasses import dataclass

from .schema import MemoryError, BugType, Severity, AnalysisTool


@dataclass
class AllocationBlock:
    alloc_id: int
    address: str
    size: int
    alloc_func: str
    alloc_file: str
    alloc_line: int
    alloc_via: str
    free_func: str | None
    free_file: str | None
    free_line: int | None
    leaked: bool
    bug_type: str
    severity: str
    stack_depth: int
    ownership_chain: list[str]


def _extract_allocations(errors: list[MemoryError]) -> list[AllocationBlock]:
    """Extract allocation blocks from scan errors for visualization."""
    blocks = []
    for i, err in enumerate(errors):
        alloc_via = "malloc"
        alloc_func = "??"
        alloc_file = "??"
        alloc_line = 0

        if err.allocation_info and err.allocation_info.stack:
            for f in err.allocation_info.stack:
                if f.function in ("malloc", "calloc", "realloc", "strdup",
                                  "strndup", "fopen", "operator new"):
                    alloc_via = f.function
                elif f.function and f.function != "??" and not f.function.startswith("_"):
                    alloc_func = f.function
                    alloc_file = (f.file or "??").split("/")[-1]
                    alloc_line = f.line or 0
                    break

        if alloc_func == "??" and err.primary_location:
            alloc_file = (err.primary_location.file or "??").split("/")[-1]
            alloc_line = err.primary_location.line or 0
            if err.stack:
                for f in err.stack:
                    if f.function and f.function != "??" and not f.function.startswith("_"):
                        alloc_func = f.function
                        break

        leaked = err.bug_type in (BugType.MEMORY_LEAK,)
        free_func = None
        free_file = None
        free_line = None

        if err.free_info and err.free_info.stack:
            for f in err.free_info.stack:
                if f.function and f.function != "??" and not f.function.startswith("_"):
                    free_func = f.function
                    free_file = (f.file or "??").split("/")[-1]
                    free_line = f.line or 0
                    break

        if err.bug_type == BugType.USE_AFTER_FREE:
            leaked = False
            if not free_func:
                free_func = alloc_func
                free_file = alloc_file

        chain = []
        SKIP_FNS = {"malloc", "calloc", "realloc", "free", "strdup", "strndup",
                     "operator new", "operator delete", "fopen", "fclose",
                     "fopen@@GLIBC_2.2.5", "__fopen_internal", "??", "_end",
                     "_start", "__libc_start_main", "start_thread", "clone", "clone3"}
        if err.stack:
            for f in err.stack:
                if f.function and f.function not in SKIP_FNS:
                    chain.append(f.function)

        blocks.append(AllocationBlock(
            alloc_id=i,
            address=err.stack[0].address if err.stack and err.stack[0].address else f"0x{i:04x}",
            size=err.bytes_leaked or 0,
            alloc_func=alloc_func,
            alloc_file=alloc_file,
            alloc_line=alloc_line,
            alloc_via=alloc_via,
            free_func=free_func,
            free_file=free_file,
            free_line=free_line,
            leaked=leaked,
            bug_type=err.bug_type.value,
            severity=err.severity.value,
            stack_depth=len(err.stack or []),
            ownership_chain=chain[:6],
        ))

    return blocks


def generate_visualization(errors: list[MemoryError],
                           scan_id: str = "",
                           target: str = "") -> str:
    """Generate a self-contained interactive HTML visualization."""
    blocks = _extract_allocations(errors)
    blocks_json = json.dumps([{
        "id": b.alloc_id,
        "addr": b.address,
        "size": b.size,
        "alloc_func": b.alloc_func,
        "alloc_file": b.alloc_file,
        "alloc_line": b.alloc_line,
        "alloc_via": b.alloc_via,
        "free_func": b.free_func,
        "free_file": b.free_file,
        "free_line": b.free_line,
        "leaked": b.leaked,
        "bug_type": b.bug_type,
        "severity": b.severity,
        "chain": b.ownership_chain,
    } for b in blocks])

    func_sizes: dict[str, dict] = {}
    for b in blocks:
        key = b.alloc_func
        if key not in func_sizes:
            func_sizes[key] = {"total": 0, "count": 0, "leaked": 0, "leaked_bytes": 0}
        func_sizes[key]["total"] += b.size
        func_sizes[key]["count"] += 1
        if b.leaked:
            func_sizes[key]["leaked"] += 1
            func_sizes[key]["leaked_bytes"] += b.size

    heatmap_json = json.dumps([
        {"func": k, **v} for k, v in
        sorted(func_sizes.items(), key=lambda x: x[1]["total"], reverse=True)
    ])

    total_leaked = sum(b.size for b in blocks if b.leaked)
    total_alloc = sum(b.size for b in blocks)
    leak_count = sum(1 for b in blocks if b.leaked)
    freed_count = sum(1 for b in blocks if not b.leaked)

    # Build memory profile events for the chart
    events = []
    cumulative = 0
    for i, b in enumerate(blocks):
        cumulative += b.size
        events.append({"x": i, "y": cumulative, "type": "alloc", "func": b.alloc_func, "size": b.size})
        if not b.leaked and b.free_func:
            events.append({"x": i + 0.5, "y": cumulative - b.size, "type": "free", "func": b.free_func, "size": b.size})
            cumulative -= b.size
    events_json = json.dumps(events)

    html = _VIZ_HTML
    html = html.replace("__BLOCKS__", blocks_json)
    html = html.replace("__HEATMAP__", heatmap_json)
    html = html.replace("__EVENTS__", events_json)
    html = html.replace("__SCAN_ID__", scan_id[:16])
    html = html.replace("__TARGET__", target.split("/")[-1])
    html = html.replace("__TOTAL_ALLOC__", f"{total_alloc:,}")
    html = html.replace("__TOTAL_LEAKED__", f"{total_leaked:,}")
    html = html.replace("__BUG_COUNT__", str(len(blocks)))
    html = html.replace("__LEAK_COUNT__", str(leak_count))
    html = html.replace("__FREED_COUNT__", str(freed_count))
    html = html.replace("__LEAK_PCT__", f"{(total_leaked / total_alloc * 100) if total_alloc else 0:.1f}")

    return html


_VIZ_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MemGuard Memory Visualization</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--card:#1c2128;--border:#30363d;
--cyan:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--purple:#bc8cff;
--orange:#f0883e;--text:#c9d1d9;--dim:#8b949e;--bright:#f0f6fc}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',system-ui,sans-serif;font-size:14px}

/* Header */
.hdr{background:linear-gradient(135deg,#161b22 0%,#1c2128 100%);border-bottom:1px solid var(--border);padding:1.25rem 2rem}
.hdr-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem}
.hdr h1{font-size:1.1rem;color:var(--cyan);display:flex;align-items:center;gap:.5rem}
.hdr h1 svg{width:20px;height:20px}
.hdr .meta{font-size:.8rem;color:var(--dim)}

/* Metrics row */
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;padding:1rem 2rem}
.metric{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}
.metric .val{font-size:1.6rem;font-weight:800;line-height:1.2}
.metric .lbl{font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-top:.25rem}

/* Tabs */
.container{max-width:1400px;margin:0 auto;padding:0 1.5rem 2rem}
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:1.25rem;overflow-x:auto}
.tab{padding:.7rem 1.25rem;cursor:pointer;color:var(--dim);font-weight:600;font-size:.85rem;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .2s;white-space:nowrap;user-select:none}
.tab:hover{color:var(--text)}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.panel{display:none}
.panel.active{display:block}

/* Profile chart */
.chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem;position:relative}
.chart-wrap svg{width:100%;display:block}
.chart-tooltip{position:absolute;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.5rem .75rem;font-size:.75rem;pointer-events:none;z-index:10;display:none;box-shadow:0 4px 12px rgba(0,0,0,.4)}

/* Timeline */
.tl-table{width:100%;border-collapse:separate;border-spacing:0 3px}
.tl-table th{text-align:left;font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;padding:.5rem .75rem;border-bottom:1px solid var(--border)}
.tl-row{cursor:pointer;transition:background .15s}
.tl-row:hover{background:var(--card)}
.tl-row td{padding:.5rem .75rem;border-bottom:1px solid #21262d;vertical-align:middle}
.tl-func{font-weight:600;color:var(--cyan);font-size:.85rem}
.tl-loc{color:var(--dim);font-size:.75rem}
.tl-bytes{font-weight:700;font-variant-numeric:tabular-nums;text-align:right}
.tl-status{display:inline-flex;align-items:center;gap:.3rem;font-size:.75rem;font-weight:600;padding:.2rem .6rem;border-radius:10px}
.tl-status.leaked{background:rgba(248,81,73,.15);color:var(--red)}
.tl-status.freed{background:rgba(63,185,80,.15);color:var(--green)}
.tl-status.uaf{background:rgba(210,153,34,.15);color:var(--yellow)}
.tl-bar-cell{width:35%}
.tl-bar-wrap{height:22px;background:#21262d;border-radius:4px;position:relative;overflow:hidden}
.tl-bar-fill{height:100%;border-radius:4px;display:flex;align-items:center;padding:0 6px;font-size:.7rem;color:#000;font-weight:700;min-width:4px;transition:width .5s ease}

/* Treemap */
.treemap{display:flex;flex-wrap:wrap;gap:4px;padding:4px}
.tm-cell{border-radius:6px;padding:.75rem;display:flex;flex-direction:column;justify-content:center;cursor:pointer;transition:transform .15s,box-shadow .15s;position:relative;overflow:hidden;min-height:70px}
.tm-cell:hover{transform:scale(1.02);box-shadow:0 4px 20px rgba(0,0,0,.3)}
.tm-cell .nm{font-weight:700;font-size:.85rem;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.5)}
.tm-cell .sz{font-size:1.2rem;font-weight:800;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.5)}
.tm-cell .dt{font-size:.7rem;opacity:.8;color:#fff}

/* Flow graph */
.flow-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.5rem;position:relative;min-height:400px}
svg.flow-svg{position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none}
.fl-node{position:absolute;background:var(--card);border:2px solid var(--border);border-radius:10px;padding:.6rem 1rem;cursor:pointer;transition:all .2s;z-index:2;min-width:120px}
.fl-node:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.3)}
.fl-node.leaked{border-color:var(--red);box-shadow:0 0 12px rgba(248,81,73,.2)}
.fl-node.freed{border-color:var(--green)}
.fl-node .fn{font-weight:700;font-size:.85rem}
.fl-node .st{font-size:.7rem;color:var(--dim);margin-top:.15rem}

/* Detail drawer */
.drawer{position:fixed;right:0;top:0;width:380px;height:100vh;background:var(--surface);border-left:1px solid var(--border);z-index:100;transform:translateX(100%);transition:transform .25s ease;overflow-y:auto;padding:1.5rem;box-shadow:-4px 0 20px rgba(0,0,0,.3)}
.drawer.open{transform:translateX(0)}
.drawer-close{position:absolute;top:1rem;right:1rem;background:none;border:none;color:var(--dim);font-size:1.2rem;cursor:pointer}
.drawer h3{color:var(--cyan);font-size:1rem;margin-bottom:1rem;padding-right:2rem}
.drawer .fld{margin:.6rem 0}
.drawer .fld .k{font-size:.65rem;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.drawer .fld .v{font-size:.9rem;margin-top:.15rem}
.chain{display:flex;align-items:center;gap:.3rem;flex-wrap:wrap;margin:.5rem 0}
.chain .step{background:#21262d;padding:.3rem .6rem;border-radius:4px;font-size:.75rem;border:1px solid var(--border)}
.chain .step.born{border-color:var(--green);color:var(--green)}
.chain .step.dead{border-color:var(--red);color:var(--red)}
.chain .arr{color:var(--cyan);font-weight:700;font-size:.8rem}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:99;display:none}
.overlay.open{display:block}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-row">
    <h1>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/></svg>
      MemGuard Memory Profile
    </h1>
    <div class="meta">Scan __SCAN_ID__ &middot; __TARGET__</div>
  </div>
</div>

<div class="metrics">
  <div class="metric"><div class="val" style="color:var(--cyan)">__BUG_COUNT__</div><div class="lbl">Allocations Tracked</div></div>
  <div class="metric"><div class="val" style="color:var(--red)">__TOTAL_LEAKED__</div><div class="lbl">Bytes Leaked</div></div>
  <div class="metric"><div class="val" style="color:var(--green)">__FREED_COUNT__</div><div class="lbl">Properly Freed</div></div>
  <div class="metric"><div class="val" style="color:var(--red)">__LEAK_COUNT__</div><div class="lbl">Leaked</div></div>
  <div class="metric"><div class="val" style="color:var(--orange)">__LEAK_PCT__%</div><div class="lbl">Leak Ratio</div></div>
  <div class="metric"><div class="val" style="color:var(--text)">__TOTAL_ALLOC__</div><div class="lbl">Total Allocated</div></div>
</div>

<div class="container">
<div class="tabs">
  <div class="tab active" onclick="showTab('profile',this)">Memory Profile</div>
  <div class="tab" onclick="showTab('timeline',this)">Allocation Table</div>
  <div class="tab" onclick="showTab('treemap',this)">Heap Treemap</div>
  <div class="tab" onclick="showTab('flow',this)">Ownership Flow</div>
</div>

<div id="profile" class="panel active">
  <div class="chart-wrap">
    <svg id="profile-svg" viewBox="0 0 800 300"></svg>
    <div class="chart-tooltip" id="chart-tip"></div>
  </div>
</div>

<div id="timeline" class="panel">
  <table class="tl-table"><thead><tr>
    <th>Function</th><th>Via</th><th>Location</th><th style="text-align:right">Size</th><th>Memory Bar</th><th>Status</th>
  </tr></thead><tbody id="tl-body"></tbody></table>
</div>

<div id="treemap" class="panel">
  <div id="tm-area" class="treemap"></div>
</div>

<div id="flow" class="panel">
  <div id="flow-area" class="flow-wrap"></div>
</div>
</div>

<div class="overlay" id="overlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <button class="drawer-close" onclick="closeDrawer()">&times;</button>
  <h3 id="dr-title"></h3>
  <div id="dr-body"></div>
</div>

<script>
var B=__BLOCKS__,H=__HEATMAP__,EV=__EVENTS__;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function fmtB(b){if(b>=1048576)return(b/1048576).toFixed(1)+' MB';if(b>=1024)return(b/1024).toFixed(1)+' KB';return b+' B'}
function showTab(id,el){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active')});
  document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('active')});
  document.getElementById(id).classList.add('active');
  if(el)el.classList.add('active');
}
function openDrawer(b){
  var d=document.getElementById('drawer'),o=document.getElementById('overlay');
  document.getElementById('dr-title').textContent=b.bug_type.replace(/_/g,' ').toUpperCase()+' in '+b.alloc_func+'()';
  var h='';
  h+='<div class="fld"><div class="k">Address</div><div class="v" style="font-family:monospace">'+esc(b.addr)+'</div></div>';
  h+='<div class="fld"><div class="k">Size</div><div class="v" style="font-weight:700;font-size:1.1rem;color:var(--cyan)">'+fmtB(b.size)+'<span style="color:var(--dim);font-size:.8rem;font-weight:400"> ('+b.size+' bytes)</span></div></div>';
  h+='<div class="fld"><div class="k">Allocated By</div><div class="v"><span style="color:var(--cyan)">'+esc(b.alloc_via)+'</span>() in <b>'+esc(b.alloc_func)+'</b>() at '+esc(b.alloc_file)+':'+b.alloc_line+'</div></div>';
  h+='<div class="fld"><div class="k">Freed By</div><div class="v">'+(b.free_func?'<span style="color:var(--green)">'+esc(b.free_func)+'() at '+esc(b.free_file)+':'+b.free_line+'</span>':'<span style="color:var(--red);font-weight:700">NEVER FREED</span>')+'</div></div>';
  h+='<div class="fld"><div class="k">Status</div><div class="v"><span class="tl-status '+(b.leaked?'leaked':'freed')+'">'+(b.leaked?'LEAKED':'FREED')+'</span></div></div>';
  h+='<div class="fld"><div class="k">Bug Type</div><div class="v">'+b.bug_type.replace(/_/g,' ').toUpperCase()+'</div></div>';
  h+='<div class="fld"><div class="k">Severity</div><div class="v">'+b.severity.toUpperCase()+'</div></div>';
  if(b.chain.length){
    h+='<div class="fld"><div class="k">Ownership Chain</div></div>';
    h+='<div class="chain">';
    b.chain.forEach(function(fn,i){
      var cls=i===0?'born':(i===b.chain.length-1&&b.leaked)?'dead':'';
      h+='<div class="step '+cls+'">'+esc(fn)+'()</div>';
      if(i<b.chain.length-1)h+='<span class="arr">&rarr;</span>';
    });
    if(b.leaked)h+='<span class="arr">&rarr;</span><div class="step dead">LEAKED</div>';
    h+='</div>';
  }
  document.getElementById('dr-body').innerHTML=h;
  d.classList.add('open');o.classList.add('open');
}
function closeDrawer(){
  document.getElementById('drawer').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
}

/* ── Memory Profile Chart ── */
(function(){
  if(!EV.length)return;
  var svg=document.getElementById('profile-svg');
  var W=800,H=300,pad={t:30,r:30,b:40,l:60};
  var cw=W-pad.l-pad.r,ch=H-pad.t-pad.b;
  var maxY=Math.max.apply(null,EV.map(function(e){return e.y}))||1;
  var maxX=Math.max.apply(null,EV.map(function(e){return e.x}))||1;
  function sx(v){return pad.l+(v/maxX)*cw}
  function sy(v){return pad.t+ch-(v/maxY)*ch}

  // Grid lines
  var gridH='';
  for(var g=0;g<=4;g++){
    var gy=pad.t+ch*(g/4);
    var gv=Math.round(maxY*(1-g/4));
    gridH+='<line x1="'+pad.l+'" y1="'+gy+'" x2="'+(W-pad.r)+'" y2="'+gy+'" stroke="#21262d" stroke-width="1"/>';
    gridH+='<text x="'+(pad.l-8)+'" y="'+(gy+4)+'" text-anchor="end" fill="#8b949e" font-size="10">'+fmtB(gv)+'</text>';
  }
  // Axis labels
  gridH+='<text x="'+(W/2)+'" y="'+(H-5)+'" text-anchor="middle" fill="#8b949e" font-size="11">Allocation Sequence</text>';
  gridH+='<text x="15" y="'+(H/2)+'" text-anchor="middle" fill="#8b949e" font-size="11" transform="rotate(-90,15,'+(H/2)+')">Heap Usage</text>';

  // Build area path
  var pts=EV.filter(function(e){return e.type==='alloc'||e.type==='free'});
  if(pts.length===0)return;
  var areaPath='M '+sx(pts[0].x)+' '+sy(0)+' L '+sx(pts[0].x)+' '+sy(pts[0].y);
  for(var i=1;i<pts.length;i++){
    areaPath+=' L '+sx(pts[i].x)+' '+sy(pts[i].y);
  }
  areaPath+=' L '+sx(pts[pts.length-1].x)+' '+sy(0)+' Z';

  // Line path
  var linePath='M '+sx(pts[0].x)+' '+sy(pts[0].y);
  for(var i=1;i<pts.length;i++){
    linePath+=' L '+sx(pts[i].x)+' '+sy(pts[i].y);
  }

  // Leaked area (final value stays)
  var lastY=pts[pts.length-1].y;
  var leakedColor=lastY>0?'rgba(248,81,73,0.15)':'rgba(63,185,80,0.15)';

  var svgH=gridH;
  // Area fill
  svgH+='<path d="'+areaPath+'" fill="url(#areaGrad)" opacity="0.6"/>';
  // Line
  svgH+='<path d="'+linePath+'" fill="none" stroke="var(--cyan)" stroke-width="2.5" stroke-linejoin="round"/>';

  // Data points
  pts.forEach(function(p,i){
    var cx=sx(p.x),cy=sy(p.y);
    var col=p.type==='alloc'?'var(--cyan)':'var(--green)';
    svgH+='<circle cx="'+cx+'" cy="'+cy+'" r="4" fill="'+col+'" stroke="var(--bg)" stroke-width="2" style="cursor:pointer" '
      +'onmouseenter="showTip(evt,\''+esc(p.func)+'()\',\''+p.type+': '+fmtB(p.size)+'\',\'Heap: '+fmtB(p.y)+'\')" '
      +'onmouseleave="hideTip()"/>';
  });

  // Leaked indicator line
  if(lastY>0){
    svgH+='<line x1="'+sx(pts[pts.length-1].x)+'" y1="'+sy(lastY)+'" x2="'+(W-pad.r)+'" y2="'+sy(lastY)+'" stroke="var(--red)" stroke-width="1.5" stroke-dasharray="4,3"/>';
    svgH+='<text x="'+(W-pad.r+5)+'" y="'+(sy(lastY)+4)+'" fill="var(--red)" font-size="10" font-weight="700">'+fmtB(lastY)+' leaked</text>';
  }

  // Gradient
  svgH+='<defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">'
    +'<stop offset="0%" stop-color="#58a6ff" stop-opacity="0.4"/>'
    +'<stop offset="100%" stop-color="#58a6ff" stop-opacity="0.02"/>'
    +'</linearGradient></defs>';

  svg.innerHTML=svgH;
})();

window.showTip=function(evt,l1,l2,l3){
  var tip=document.getElementById('chart-tip');
  tip.innerHTML='<div style="font-weight:700;color:var(--cyan)">'+l1+'</div><div>'+l2+'</div><div style="color:var(--dim)">'+l3+'</div>';
  tip.style.display='block';
  var r=tip.parentElement.getBoundingClientRect();
  tip.style.left=(evt.clientX-r.left+12)+'px';
  tip.style.top=(evt.clientY-r.top-40)+'px';
};
window.hideTip=function(){document.getElementById('chart-tip').style.display='none'};

/* ── Allocation Table ── */
(function(){
  var tb=document.getElementById('tl-body');
  var maxSz=Math.max.apply(null,B.map(function(b){return b.size}))||1;
  var colors={memory_leak:'var(--red)',use_after_free:'var(--yellow)',double_free:'var(--purple)',
    buffer_overflow:'var(--orange)',null_deref:'var(--cyan)',race_condition:'var(--purple)',uninit_read:'var(--yellow)'};

  B.forEach(function(b){
    var tr=document.createElement('tr');
    tr.className='tl-row';
    tr.onclick=function(){openDrawer(b)};
    var col=colors[b.bug_type]||'var(--cyan)';
    var pct=Math.max(4,(b.size/maxSz)*100);
    var statusCls=b.leaked?'leaked':(b.bug_type==='use_after_free'?'uaf':'freed');
    var statusTxt=b.leaked?'LEAKED':(b.bug_type==='use_after_free'?'UAF':'FREED');

    tr.innerHTML=
      '<td><span class="tl-func">'+esc(b.alloc_func)+'()</span></td>'
      +'<td style="color:var(--dim);font-size:.8rem">'+esc(b.alloc_via)+'</td>'
      +'<td><span class="tl-loc">'+esc(b.alloc_file)+':'+b.alloc_line+'</span></td>'
      +'<td class="tl-bytes" style="color:'+col+'">'+fmtB(b.size)+'</td>'
      +'<td class="tl-bar-cell"><div class="tl-bar-wrap"><div class="tl-bar-fill" style="width:'+pct+'%;background:'+col+'">'+fmtB(b.size)+'</div></div></td>'
      +'<td><span class="tl-status '+statusCls+'">'+statusTxt+'</span></td>';
    tb.appendChild(tr);
  });
})();

/* ── Heap Treemap ── */
(function(){
  var area=document.getElementById('tm-area');
  if(!H.length)return;
  var total=H.reduce(function(s,h){return s+h.total},0)||1;
  var palette=['#1f6feb','#238636','#8957e5','#f0883e','#da3633','#58a6ff','#3fb950','#bc8cff','#d29922'];

  H.forEach(function(h,i){
    var pct=(h.total/total)*100;
    if(pct<2)return;
    var cell=document.createElement('div');
    cell.className='tm-cell';
    var leakRatio=h.leaked_bytes/(h.total||1);
    var bg=leakRatio>0.5?'linear-gradient(135deg,#da3633,#8b2020)':leakRatio>0?'linear-gradient(135deg,#d29922,#8b6914)':'linear-gradient(135deg,'+palette[i%palette.length]+',#21262d)';
    cell.style.cssText='background:'+bg+';flex:'+Math.max(1,Math.round(pct/5))+' 1 '+Math.max(100,pct*2)+'px';
    cell.innerHTML='<div class="nm">'+esc(h.func)+'()</div><div class="sz">'+fmtB(h.total)+'</div>'
      +'<div class="dt">'+h.count+' alloc'+(h.leaked>0?' &middot; <b>'+h.leaked+' leaked</b>':' &middot; all freed')+'</div>';
    cell.onclick=function(){
      var rel=B.filter(function(b){return b.alloc_func===h.func});
      if(rel.length)openDrawer(rel[0]);
    };
    area.appendChild(cell);
  });
})();

/* ── Ownership Flow ── */
(function(){
  var area=document.getElementById('flow-area');
  var SKIP=['malloc','calloc','realloc','free','strdup','strndup','operator new','operator delete',
    'fopen','fclose','fopen@@GLIBC_2.2.5','__fopen_internal','??','_end','_start','__libc_start_main',
    'start_thread','clone','clone3'];
  var funcs={};
  B.forEach(function(b){
    var uc=b.chain.filter(function(fn){return SKIP.indexOf(fn)===-1});
    if(!uc.length)return;
    uc.forEach(function(fn,i){
      if(!funcs[fn])funcs[fn]={name:fn,allocs:0,leaked:0,freed:0,bytes:0,conns:[]};
      if(i===0){funcs[fn].allocs++;funcs[fn].bytes+=b.size;if(b.leaked)funcs[fn].leaked++;else funcs[fn].freed++}
      if(i<uc.length-1){var t=uc[i+1];if(funcs[fn].conns.indexOf(t)===-1)funcs[fn].conns.push(t)}
    });
  });
  var fl=Object.values(funcs);
  if(!fl.length){area.innerHTML='<p style="color:var(--dim);padding:2rem;text-align:center">No ownership flow data</p>';return}

  fl.sort(function(a,b){return b.bytes-a.bytes});
  var cols=Math.min(3,Math.ceil(Math.sqrt(fl.length)));
  var aw=area.offsetWidth||800;
  var colW=(aw-80)/(cols+0.5);
  var aH=Math.max(400,Math.ceil(fl.length/cols)*100+60);
  area.style.height=aH+'px';

  var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('class','flow-svg');svg.setAttribute('width','100%');svg.setAttribute('height','100%');
  svg.innerHTML='<defs><marker id="arw" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0 0L10 5L0 10z" fill="#58a6ff"/></marker></defs>';
  area.appendChild(svg);

  var pos={};
  fl.forEach(function(fn,i){
    var c=i%cols,r=Math.floor(i/cols);
    var x=50+c*colW,y=40+r*100;
    pos[fn.name]={x:x,y:y};
    var nd=document.createElement('div');
    nd.className='fl-node'+(fn.leaked>0?' leaked':' freed');
    nd.style.left=x+'px';nd.style.top=y+'px';
    nd.innerHTML='<div class="fn" style="color:'+(fn.leaked>0?'var(--red)':'var(--green)')+'">'+esc(fn.name)+'()</div>'
      +'<div class="st">'+fmtB(fn.bytes)+' &middot; '+fn.allocs+' alloc'+(fn.leaked>0?' &middot; '+fn.leaked+' leaked':'')+'</div>';
    nd.onclick=function(){
      var rel=B.filter(function(b){return b.alloc_func===fn.name||b.chain.indexOf(fn.name)!==-1});
      if(rel.length)openDrawer(rel[0]);
    };
    area.appendChild(nd);
  });

  var drawn={};
  fl.forEach(function(fn){
    fn.conns.forEach(function(t){
      var k=fn.name+'->'+t;if(drawn[k]||!pos[fn.name]||!pos[t])return;drawn[k]=true;
      var f=pos[fn.name],to=pos[t];
      var path=document.createElementNS('http://www.w3.org/2000/svg','path');
      var mx=(f.x+to.x)/2+60,my=(f.y+to.y)/2;
      path.setAttribute('d','M'+(f.x+60)+','+(f.y+25)+' Q'+mx+','+my+' '+(to.x+60)+','+(to.y+25));
      path.setAttribute('fill','none');path.setAttribute('stroke','#58a6ff');
      path.setAttribute('stroke-width','1.5');path.setAttribute('stroke-dasharray','6,3');
      path.setAttribute('marker-end','url(#arw)');path.setAttribute('opacity','0.6');
      svg.appendChild(path);
    });
  });
})();
</script>
</body>
</html>"""
