"""
memguard.ai.analyzer — Enhanced 4-pass AI analysis with rich Valgrind context.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from ..core.schema import (
    AIAnalysis, BestPractice, BugType, CodeFix, DebugStep,
    FixConfidence, Language, MemoryError, Severity,
)
from .client import complete, complete_json, best_available_model
import json
from pathlib import Path

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Language-specific system prompts
# ---------------------------------------------------------------------------

LANG_SYSTEM = {
    Language.C: (
        "You are a world-class C memory safety expert. You deeply understand malloc/free "
        "lifecycle, ownership semantics, POSIX APIs, Valgrind memcheck internals (definite vs "
        "indirect vs possible vs reachable losses), AddressSanitizer, file descriptor management, "
        "and buffer arithmetic. You write fixes using idiomatic C with clear ownership patterns."
    ),
    Language.CPP: (
        "You are a C++ memory safety expert. You advocate RAII, smart pointers "
        "(unique_ptr, shared_ptr, weak_ptr), span, string_view, and the C++ Core Guidelines. "
        "You replace raw new/delete with modern equivalents and explain rule of 0/3/5."
    ),
    Language.PYTHON: (
        "You are a Python memory expert. You understand CPython reference counting, "
        "the garbage collector, reference cycles, tracemalloc, memray, and common leak patterns."
    ),
    Language.RUST: (
        "You are a Rust safety expert. You understand ownership, borrowing, lifetimes, "
        "unsafe blocks, Miri, and common unsound patterns."
    ),
}

# ---------------------------------------------------------------------------
# Schema strings for structured JSON output
# ---------------------------------------------------------------------------

TRIAGE_SCHEMA = '{"confirmed_bug_type":"string","confirmed_severity":"string","confidence":"string","one_line_summary":"string"}'

ANALYSIS_SCHEMA = '{"root_cause":"string","explanation":"string","impact":"string","cwe_ids":["string"]}'

FIX_SCHEMA = ('{"fixes":[{"description":"string",'
              '"find":"EXACT lines copied verbatim from the source to be replaced",'
              '"replace":"the corrected lines that go in their place",'
              '"confidence":"high|medium|low","pattern":"string",'
              '"test_suggestion":"string"}],'
              '"best_practices":[{"title":"string","explanation":"string"}]}')

STEPS_SCHEMA = '{"steps":[{"step_number":1,"title":"string","description":"string","code_before":"string","code_after":"string","explanation":"string","validation":"string"}]}'


# ---------------------------------------------------------------------------
# Context builder — RICH Valgrind-specific context
# ---------------------------------------------------------------------------

def _build_error_context(err: MemoryError) -> str:
    parts = []

    # ── Header with Valgrind-specific terminology ──
    kind_names = {
        BugType.MEMORY_LEAK: "MEMORY LEAK",
        BugType.USE_AFTER_FREE: "USE-AFTER-FREE (heap-use-after-free)",
        BugType.DOUBLE_FREE: "DOUBLE FREE (Invalid free / delete)",
        BugType.BUFFER_OVERFLOW: "BUFFER OVERFLOW (Invalid read/write)",
        BugType.NULL_DEREF: "NULL POINTER DEREFERENCE",
        BugType.UNINIT_READ: "UNINITIALISED VALUE USE",
        BugType.INVALID_FREE: "INVALID FREE (mismatched free/delete)",
        BugType.HEAP_CORRUPTION: "HEAP CORRUPTION",
    }
    parts.append(f"## {kind_names.get(err.bug_type, err.bug_type.value.upper())}")
    parts.append(f"Tool: {err.tool.value} | Severity: {err.severity.value}")
    parts.append(f"Message: {err.message}")

    if err.bytes_leaked:
        parts.append(f"Bytes leaked: {err.bytes_leaked:,}")
    if err.alloc_count:
        parts.append(f"Blocks: {err.alloc_count}")
    if err.detail:
        parts.append(f"Detail: {err.detail}")

    # ── Stack trace with annotations ──
    if err.stack:
        parts.append("\n### Error Stack Trace")
        for f in err.stack[:10]:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.address or "??")
            mod = f" [{f.module}]" if f.module and "vgpreload" not in f.module else ""
            parts.append(f"  #{f.index} {f.function or '??'} at {loc}{mod}")

    # ── Allocation site (where the leaked memory was allocated) ──
    if err.allocation_info and err.allocation_info.stack:
        ai = err.allocation_info
        parts.append(f"\n### Allocation Site ({ai.kind or 'unknown'}, {ai.size or '?'} bytes)")
        for f in ai.stack[:6]:
            loc = f"{f.file}:{f.line}" if f.file and f.line else (f.address or "??")
            parts.append(f"  #{f.index} {f.function or '??'} at {loc}")

    # ── Identify USER code responsible (skip system/glibc frames) ──
    _skip = {"strdup.c","strndup.c","iofopen.c","iofdopen.c","malloc.c","calloc.c","realloc.c"}
    user_frames = [f for f in (err.stack or [])
                   if f.file and f.line and f.file.split("/")[-1] not in _skip]
    if user_frames:
        uf = user_frames[0]
        parts.append(f"\nUSER CODE RESPONSIBLE: {uf.function or '??'} at {uf.file}:{uf.line}")
    if len(user_frames) > 1:
        cf = user_frames[1]
        parts.append(f"CALLED FROM: {cf.function or '??'} at {cf.file}:{cf.line}")

    # ── Source: prefer full file, then function body, then snippet ──
    if err.source_context:
        ctx = err.source_context
        if ctx.full_file_content:
            parts.append(f"\nFULL SOURCE FILE ({ctx.location.file}):")
            for i, line in enumerate(ctx.full_file_content.splitlines(), 1):
                marker = " >>>" if i == ctx.location.line else "    "
                parts.append(f"{marker} {i:4d} | {line}")
        elif ctx.function_body:
            start = ctx.function_start_line or 1
            parts.append(f"\nFUNCTION (starting line {start}):")
            for i, line in enumerate(ctx.function_body.splitlines(), start):
                marker = " >>>" if i == ctx.location.line else "    "
                parts.append(f"{marker} {i:4d} | {line}")
        else:
            parts.append(f"\nSOURCE AROUND ERROR ({ctx.location}):")
            for l in ctx.before_lines[-5:]:
                parts.append(f"     | {l}")
            parts.append(f" >>> | {ctx.target_line}   <<< ERROR")
            for l in ctx.after_lines[:5]:
                parts.append(f"     | {l}")

    # ── Bug-specific guidance for the AI ──
    parts.append("\n### Analysis Instructions")
    if err.bug_type == BugType.MEMORY_LEAK:
        parts.append(
            "This is a Valgrind Leak_DefinitelyLost/IndirectlyLost error. "
            "Identify EXACTLY which malloc/calloc/realloc/strdup/fopen call is leaking, "
            "trace the ownership path, find where free/fclose SHOULD be called, and "
            "generate a fix that adds the correct deallocation. If it is a linked list "
            "or tree, generate a full free_* traversal function."
        )
    elif err.bug_type == BugType.USE_AFTER_FREE:
        parts.append(
            "Identify the free() call and the subsequent use. Explain the dangling pointer. "
            "Fix by either: (a) setting ptr to NULL after free, (b) restructuring to avoid the use, "
            "or (c) using a reference-counted or RAII pattern."
        )
    elif err.bug_type == BugType.DOUBLE_FREE:
        parts.append(
            "Identify both free() calls. Fix by setting ptr = NULL after first free "
            "and checking for NULL before second free, or restructure ownership."
        )
    elif err.bug_type == BugType.BUFFER_OVERFLOW:
        parts.append(
            "Identify the array/buffer size and the access that exceeds it. "
            "Fix by adding bounds checking, using strncpy instead of strcpy, "
            "or using a larger buffer."
        )
    elif err.bug_type == BugType.UNINIT_READ:
        parts.append(
            "Identify the variable used without initialization. "
            "Fix by initializing it at declaration or before first use."
        )
    elif err.tool.value == "infer":
        parts.append(
            "This issue was found by Facebook Infer STATIC ANALYSIS — detected "
            "at compile time, not runtime. Infer uses separation logic to prove memory "
            "safety violations exist on reachable code paths. The bug_trace shows the "
            "exact execution path. Fix the issue on the reported path. "
            "Common Infer bugs: NULL_DEREFERENCE (conditional null), RESOURCE_LEAK_C "
            "(file not closed on error path), BUFFER_OVERRUN (off-by-one), "
            "USE_AFTER_FREE, UNINITIALIZED_VALUE."
        )
    elif err.bug_type == BugType.RACE_CONDITION:
        parts.append(
            "This is a Helgrind data race or lock error. Two threads access the same "
            "memory without proper synchronisation. Identify the shared variable, show "
            "both access sites, and fix with: (a) pthread_mutex_lock/unlock around the "
            "critical section, (b) _Atomic qualifier on the variable, or (c) restructuring "
            "to eliminate shared mutable state. Include the full mutex declaration and usage."
        )

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Fix Validator — catch dangerous AI-generated patterns
# ---------------------------------------------------------------------------

import re as _re

def _validate_fix(find_text: str, replace_text: str, bug_type) -> str | None:
    """Check a fix for dangerous patterns. Returns warning string or None."""
    if not replace_text:
        return None

    lines = replace_text.strip().splitlines()

    # Pattern 1: free() immediately followed by use of same pointer
    for i, line in enumerate(lines):
        m = _re.search(r'free\s*\(\s*(\w+)\s*\)', line)
        if m:
            freed_var = m.group(1)
            # Check if any subsequent line uses the freed variable
            # (excluding ptr=NULL assignments and if(ptr) checks)
            for subsequent in lines[i + 1:]:
                stripped = subsequent.strip()
                # Skip safe patterns: ptr=NULL, if(!ptr), if(ptr==NULL)
                if _re.match(rf'{freed_var}\s*=\s*NULL', stripped):
                    continue
                if _re.match(rf'if\s*\(\s*!?\s*{freed_var}', stripped):
                    continue
                # Dangerous: using freed pointer
                if _re.search(rf'\b{freed_var}\b', stripped):
                    # Safe: reassignment (freed_var = something_else)
                    if _re.match(rf'{freed_var}\s*=\s*', stripped):
                        continue
                    # Safe: freeing in another free() call (double-free guard)
                    if _re.search(rf'free\s*\(\s*{freed_var}', stripped):
                        continue
                    return f"Use-after-free: '{freed_var}' freed on line {i+1} but used on line {lines.index(subsequent)+1}"

    # Pattern 2: free() right after malloc/calloc (makes allocation useless)
    for i, line in enumerate(lines):
        if _re.search(r'malloc\s*\(|calloc\s*\(', line):
            m = _re.search(r'(\w+)\s*=\s*(?:malloc|calloc)', line)
            if m and i + 1 < len(lines):
                var = m.group(1)
                next_line = lines[i + 1].strip()
                if _re.search(rf'free\s*\(\s*{var}\s*\)', next_line):
                    return f"Useless allocation: '{var}' freed immediately after malloc"

    # Pattern 3: Missing free for a leak fix that claims to fix a leak
    if bug_type == BugType.MEMORY_LEAK:
        if "free" not in replace_text and "fclose" not in replace_text:
            # Check if it's a structural fix (adding cleanup function)
            if "free_" not in replace_text and "cleanup" not in replace_text:
                pass  # Don't warn — might be a valid structural fix

    return None


# ---------------------------------------------------------------------------
# Analysis passes — optimized prompts
# ---------------------------------------------------------------------------

def _load_memhint_context() -> str:
    """Load discovered custom MM functions to give AI context."""
    memhint_path = Path.home() / ".memguard" / "memhint_summaries.json"
    if not memhint_path.exists():
        return ""
    try:
        data = json.loads(memhint_path.read_text())
        allocs = []
        deallocs = []
        for name, hints in data.get("hints", {}).items():
            for h in hints:
                if h.get("validated"):
                    if h["role"] == "Allocator":
                        allocs.append(f"{name}() → returns heap memory via {h['target']}")
                    else:
                        deallocs.append(f"{name}() → frees {h['target']}")
        if not allocs and not deallocs:
            return ""
        parts = ["CUSTOM MEMORY MANAGEMENT FUNCTIONS (discovered by MemHint):"]
        if allocs:
            parts.append("Custom allocators: " + "; ".join(allocs))
        if deallocs:
            parts.append("Custom deallocators: " + "; ".join(deallocs))
        parts.append("These are project-specific — treat them like malloc/free in your analysis.")
        return "\n".join(parts)
    except Exception:
        return ""


# Cache the context once per session
_MEMHINT_CTX = None

def _get_memhint_ctx() -> str:
    global _MEMHINT_CTX
    if _MEMHINT_CTX is None:
        _MEMHINT_CTX = _load_memhint_context()
    return _MEMHINT_CTX


async def _pass_triage(err, model, context):
    memhint = _get_memhint_ctx()
    extra = f"\n\n{memhint}" if memhint else ""
    msgs = [{"role": "user", "content": (
        f"Quick triage:\n\n{context[:800]}{extra}\n\nClassify bug type and severity."
    )}]
    return await complete_json(msgs, TRIAGE_SCHEMA, model=model)


async def _pass_deep_analysis(err, model, context, triage):
    memhint = _get_memhint_ctx()
    extra = f"\n\n{memhint}" if memhint else ""
    msgs = [{"role": "user", "content": (
        f"Analyze this {triage.get('confirmed_bug_type', 'memory')} error:\n\n"
        f"{context[:1500]}{extra}\n\n"
        f"Triage: {triage.get('one_line_summary', '')}\n"
        "Give root_cause (1-2 sentences identifying the exact line and variable), "
        "explanation (2-3 sentences for a senior dev), impact, cwe_ids."
    )}]
    return await complete_json(msgs, ANALYSIS_SCHEMA, model=model)


async def _pass_fix_generation(err, model, context, triage, analysis):
    # Use full file if available, else function body
    source = ""
    if err.source_context:
        if err.source_context.full_file_content:
            source = err.source_context.full_file_content
        elif err.source_context.function_body:
            source = err.source_context.function_body
    if not source:
        source = context[:1500]

    file_hint = ""
    if err.primary_location:
        file_hint = f"The fix MUST target: {err.primary_location.file}\n"

    memhint = _get_memhint_ctx()
    memhint_rules = ""
    if memhint:
        memhint_rules = (
            f"\n{memhint}\n"
            "- Custom allocator leak: the CALLER must free the return value.\n"
            "- Custom deallocator: use the project's own free function, not raw free().\n"
        )

    msgs = [{"role": "user", "content": (
        f"Fix this {err.bug_type.value} in {err.language.value}.\n\n"
        f"Root cause: {analysis.get('root_cause', '')}\n\n"
        f"{file_hint}"
        f"FULL source code:\n```{err.language.value}\n{source}\n```\n\n"
        f"{memhint_rules}"
        "Produce a fix as a FIND/REPLACE pair:\n"
        "- 'find': copy EXACT lines from source above. Keep minimal (2-5 lines).\n"
        "- 'replace': those lines with the fix.\n\n"
        "Rules:\n"
        "- malloc leak: add free(ptr) before function returns.\n"
        "- strdup leak: fix the CALLER — store result, use it, then free(). "
        "Example: 'char *s = strdup_func(...); /* use */ free(s);'\n"
        "- fopen leak: add fclose(fp) before function returns.\n"
        "- Linked list leak: add a free_list() function + call it from main.\n"
        "- UAF: MOVE the free() AFTER the last use, NOT just add NULL check.\n"
        "- Double-free: guard with 'if(ptr){free(ptr);ptr=NULL;}'.\n"
        "- Race: wrap with pthread_mutex_lock/unlock.\n\n"
        "NEVER DO THESE (they introduce NEW bugs):\n"
        "- NEVER free() a pointer and then use it on the next line.\n"
        "- NEVER add free(ptr) BEFORE the code that uses ptr.\n"
        "- NEVER free() immediately after malloc() — that makes the allocation useless.\n"
        "- NEVER add free() inside a loop that accumulates items (e.g. linked list builder). "
        "Instead add a cleanup function called AFTER the loop/at program exit.\n"
        "- NEVER set ptr=NULL as a UAF 'fix' if the code still reads ptr AFTER the free. "
        "The fix is to MOVE the free() to AFTER the last read.\n\n"
        "CRITICAL: 'find' must match lines in the source above EXACTLY. "
        "Target the USER's .c file, NOT strdup.c/iofopen.c/malloc.c."
    )}]
    result = await complete_json(msgs, FIX_SCHEMA, model=model)

    # Build diffs from find/replace
    import difflib
    src_lines = source.splitlines() if source else []
    start_line = 1
    file_name = (err.primary_location.file.split("/")[-1]
                 if err.primary_location else "source.c")

    for fix in result.get("fixes", []):
        find_t = (fix.get("find") or "").strip("\n")
        repl_t = (fix.get("replace") or "").strip("\n")
        fix["find_text"] = find_t
        fix["replace_text"] = repl_t

        if not find_t:
            fix["diff"] = ""
            fix["applicable"] = False
            continue

        # Locate find_t in the function body to compute real line numbers
        diff_text, applicable = _build_diff(
            src_lines, find_t, repl_t, start_line, file_name
        )
        fix["diff"] = diff_text
        fix["applicable"] = applicable

    return result


def _build_diff(func_lines, find_t, repl_t, func_start_line, file_name):
    """Locate find_t within func_lines and build a unified diff with real line numbers."""
    import difflib
    find_lines = find_t.splitlines()
    repl_lines = repl_t.splitlines()
    if not find_lines:
        return "", False

    # Find where find_lines occurs (fuzzy on leading/trailing whitespace)
    def norm(s):
        return s.strip()

    n = len(func_lines)
    m = len(find_lines)
    match_at = -1
    for i in range(n - m + 1):
        if all(norm(func_lines[i + j]) == norm(find_lines[j]) for j in range(m)):
            match_at = i
            break

    if match_at < 0:
        # Couldn't locate — produce a best-effort context-free diff
        body = "--- a/%s\n+++ b/%s\n@@ fix @@\n" % (file_name, file_name)
        for l in find_lines:
            body += "-" + l + "\n"
        for l in repl_lines:
            body += "+" + l + "\n"
        return body, False

    abs_line = func_start_line + match_at
    ctx_before = func_lines[max(0, match_at - 2):match_at]
    ctx_after  = func_lines[match_at + m: match_at + m + 2]

    hunk_old_count = len(ctx_before) + m + len(ctx_after)
    hunk_new_count = len(ctx_before) + len(repl_lines) + len(ctx_after)
    hunk_start = abs_line - len(ctx_before)

    lines = [
        "--- a/%s" % file_name,
        "+++ b/%s" % file_name,
        "@@ -%d,%d +%d,%d @@" % (hunk_start, hunk_old_count, hunk_start, hunk_new_count),
    ]
    for l in ctx_before:
        lines.append(" " + l)
    for l in find_lines:
        lines.append("-" + l)
    for l in repl_lines:
        lines.append("+" + l)
    for l in ctx_after:
        lines.append(" " + l)
    return "\n".join(lines), True


async def _pass_step_decomposition(err, model, context, fix_data):
    best_fix = (fix_data.get("fixes") or [{}])[0]
    msgs = [{"role": "user", "content": (
        f"Break this fix into 3 guided steps:\n"
        f"Fix: {best_fix.get('description', '')}\n"
        f"Diff:\n{best_fix.get('diff', '')[:500]}\n"
        "Return 3 steps. Step 1: identify the problem line. "
        "Step 2: write the fix code. Step 3: verify with Valgrind."
    )}]
    return await complete_json(msgs, STEPS_SCHEMA, model=model)


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    analysis: AIAnalysis
    steps: list[DebugStep]
    raw_triage: dict
    raw_analysis: dict
    raw_fixes: dict
    raw_steps: dict


async def analyze_error(err: MemoryError, model: str | None = None) -> AnalysisResult:
    if model is None:
        model = await best_available_model()

    context = _build_error_context(err)
    t_start = time.monotonic()

    log.info("Analyzing %s [%s] with %s", err.bug_type.value, err.id[:8], model)

    triage = await _pass_triage(err, model, context)
    log.debug("Triage: %s", triage.get("one_line_summary"))

    deep = await _pass_deep_analysis(err, model, context, triage)

    fixes_raw = await _pass_fix_generation(err, model, context, triage, deep)

    try:
        steps_raw = await _pass_step_decomposition(err, model, context, fixes_raw)
    except Exception:
        steps_raw = {"steps": []}

    total_ms = int((time.monotonic() - t_start) * 1000)

    # ── Validate and assemble CodeFix objects ──
    code_fixes = []
    for fx in fixes_raw.get("fixes", []):
        conf = fx.get("confidence", "medium")
        replace = fx.get("replace_text", "") or ""
        find = fx.get("find_text", "") or ""

        # ── Fix Validator: catch dangerous AI-generated fixes ──
        warning = _validate_fix(find, replace, err.bug_type)
        if warning:
            log.warning("Fix rejected for %s: %s", err.id[:8], warning)
            fx["description"] = f"[UNSAFE — {warning}] {fx.get('description', '')}"
            conf = "low"
            fx["applicable"] = False

        code_fixes.append(CodeFix(
            description    = fx.get("description", ""),
            diff           = fx.get("diff", ""),
            find_text      = fx.get("find_text"),
            replace_text   = fx.get("replace_text"),
            patched_source = fx.get("patched_source"),
            confidence     = FixConfidence(conf) if conf in FixConfidence._value2member_map_ else FixConfidence.MEDIUM,
            pattern        = fx.get("pattern", "manual"),
            breaking_change= fx.get("breaking_change", False),
            test_suggestion= fx.get("test_suggestion"),
            applicable     = fx.get("applicable", True),
        ))

    # ── CWE Validator: fix common wrong CWE references ──
    _CWE_FOR_TYPE = {
        BugType.MEMORY_LEAK:     ["CWE-401"],
        BugType.USE_AFTER_FREE:  ["CWE-416"],
        BugType.DOUBLE_FREE:     ["CWE-415"],
        BugType.BUFFER_OVERFLOW: ["CWE-122", "CWE-787"],
        BugType.NULL_DEREF:      ["CWE-476"],
        BugType.RACE_CONDITION:  ["CWE-362"],
        BugType.UNINIT_READ:     ["CWE-457"],
        BugType.DANGLING_POINTER:["CWE-825"],
        BugType.INVALID_FREE:    ["CWE-761"],
        BugType.STACK_OVERFLOW:  ["CWE-121"],
    }
    cwe_ids = deep.get("cwe_ids", [])
    correct_cwes = _CWE_FOR_TYPE.get(err.bug_type, [])
    if correct_cwes and not any(c in cwe_ids for c in correct_cwes):
        cwe_ids = correct_cwes + cwe_ids  # prepend correct one

    best_practices = [
        BestPractice(
            title=bp.get("title", ""), explanation=bp.get("explanation", ""),
            example=bp.get("example"), bad_example=bp.get("bad_example"),
            references=bp.get("references", []),
        ) for bp in fixes_raw.get("best_practices", [])
    ]

    ai_analysis = AIAnalysis(
        error_id=err.id, model=model,
        root_cause=deep.get("root_cause", ""),
        explanation=deep.get("explanation", ""),
        impact=deep.get("impact", ""),
        cwe_ids=cwe_ids,
        fixes=code_fixes, best_practices=best_practices,
        confidence=FixConfidence(triage.get("confidence", "medium")
                                 if triage.get("confidence") in FixConfidence._value2member_map_
                                 else "medium"),
        analysis_ms=total_ms,
    )

    debug_steps = [
        DebugStep(
            step_number=s.get("step_number", i + 1),
            title=s.get("title", f"Step {i + 1}"),
            description=s.get("description", ""),
            code_before=s.get("code_before"),
            code_after=s.get("code_after"),
            explanation=s.get("explanation", ""),
            validation=s.get("validation"),
        ) for i, s in enumerate(steps_raw.get("steps", []))
    ]

    log.info("Analysis complete: %dms, %d fixes, %d steps", total_ms, len(code_fixes), len(debug_steps))

    return AnalysisResult(
        analysis=ai_analysis, steps=debug_steps,
        raw_triage=triage, raw_analysis=deep,
        raw_fixes=fixes_raw, raw_steps=steps_raw,
    )


async def batch_analyze(errors, model=None, concurrency=1, progress_cb=None):
    if model is None:
        model = await best_available_model()
    sem = asyncio.Semaphore(concurrency)

    async def bounded(err, i):
        async with sem:
            try:
                result = await analyze_error(err, model)
                if progress_cb:
                    await progress_cb(i, len(errors), result)
                return result
            except Exception as exc:
                log.error("Analysis failed for %s: %s", err.id[:8], exc)
                return None

    tasks = [bounded(e, i) for i, e in enumerate(errors)]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def stream_analysis_narrative(err, model):
    context = _build_error_context(err)
    system = LANG_SYSTEM.get(err.language, LANG_SYSTEM.get(Language.C, ""))
    msgs = [{"role": "user", "content": (
        f"Explain this {err.bug_type.value} error clearly and conversationally:\n\n"
        f"{context}\n\nWalk through: what went wrong, why it is dangerous, how to fix it."
    )}]
    gen = await complete(msgs, model=model, system=system, stream=True)
    async for token in gen:
        yield token
