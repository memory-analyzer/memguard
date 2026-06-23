"""
memguard.core.parsers
=====================
Comprehensive parsers for all tools → list[MemoryError].
Key improvement: properly extracts bytes_leaked, allocation sizes,
block counts, and FD leak info from Valgrind XML.
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET

from .schema import (
    AllocationInfo, AnalysisTool, BugType, Language,
    MemoryError, Severity, SourceFrame, SourceLocation,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Valgrind kind → (BugType, Severity)
# ---------------------------------------------------------------------------

VALGRIND_KIND_MAP = {
    "Leak_DefinitelyLost":    (BugType.MEMORY_LEAK,     Severity.HIGH),
    "Leak_IndirectlyLost":    (BugType.MEMORY_LEAK,     Severity.MEDIUM),
    "Leak_PossiblyLost":      (BugType.MEMORY_LEAK,     Severity.LOW),
    "Leak_StillReachable":    (BugType.MEMORY_LEAK,     Severity.INFO),
    "InvalidRead":            (BugType.BUFFER_OVERFLOW,  Severity.CRITICAL),
    "InvalidWrite":           (BugType.BUFFER_OVERFLOW,  Severity.CRITICAL),
    "InvalidFree":            (BugType.INVALID_FREE,     Severity.CRITICAL),
    "MismatchedFree":         (BugType.INVALID_FREE,     Severity.HIGH),
    "UninitCondition":        (BugType.UNINIT_READ,      Severity.MEDIUM),
    "UninitValue":            (BugType.UNINIT_READ,      Severity.MEDIUM),
    "SyscallParam":           (BugType.UNINIT_READ,      Severity.MEDIUM),
    "Overlap":                (BugType.BUFFER_OVERFLOW,  Severity.HIGH),
    "InvalidJump":            (BugType.NULL_DEREF,       Severity.CRITICAL),
    "FishyValue":             (BugType.UNKNOWN,          Severity.LOW),
    "ClientCheck":            (BugType.UNKNOWN,          Severity.LOW),
}


def _int_or_none(text):
    if text is None:
        return None
    try:
        return int(text.replace(",", ""))
    except (ValueError, AttributeError):
        return None


def _parse_vg_frame(frame_el, index):
    return SourceFrame(
        index    = index,
        address  = frame_el.findtext("ip"),
        function = frame_el.findtext("fn"),
        file     = frame_el.findtext("file"),
        line     = _int_or_none(frame_el.findtext("line")),
        module   = frame_el.findtext("obj"),
    )


# ---------------------------------------------------------------------------
# Valgrind XML parser — extracts ALL fields properly
# ---------------------------------------------------------------------------

def parse_valgrind_xml(xml_text: str) -> list[MemoryError]:
    if not xml_text or len(xml_text) < 50:
        return []
    # Clean up malformed XML
    xml_text = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", xml_text)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log.warning("Valgrind XML parse error: %s", e)
        return []

    errors = []
    seen = set()

    for err_el in root.findall(".//error"):
        kind = err_el.findtext("kind", "")
        bug_type, severity = VALGRIND_KIND_MAP.get(kind, (BugType.UNKNOWN, Severity.MEDIUM))

        # Extract the human-readable message
        what = err_el.findtext("what") or err_el.findtext("xwhat/text") or kind

        # ── Extract BYTES LEAKED from xwhat ──
        leaked_bytes = _int_or_none(err_el.findtext("xwhat/leakedbytes"))
        leaked_blocks = _int_or_none(err_el.findtext("xwhat/leakedblocks"))

        # Also parse bytes from the "what" text if not in xwhat
        if leaked_bytes is None and what:
            m = re.search(r"(\d[\d,]*)\s+bytes?\s+in\s+(\d[\d,]*)\s+blocks?", what)
            if m:
                leaked_bytes = int(m.group(1).replace(",", ""))
                leaked_blocks = int(m.group(2).replace(",", ""))

        # ── Error stack trace ──
        stack = []
        first_stack = err_el.find(".//stack")
        if first_stack is not None:
            for i, f in enumerate(first_stack.findall("frame")):
                stack.append(_parse_vg_frame(f, i))

        # ── Primary location: prefer USER code over system/glibc frames ──
        _SYS = {"strdup.c","strndup.c","iofopen.c","iofdopen.c",
                "malloc.c","calloc.c","realloc.c","mmap.c","clone.c"}
        primary = None
        for f in stack:
            if not (f.file and f.line):
                continue
            basename = f.file.split("/")[-1]
            if basename in _SYS:
                continue
            if f.file.startswith("/usr/") or f.file.startswith("/build/"):
                continue
            if "vgpreload" in (f.module or ""):
                continue
            primary = SourceLocation(file=f.file, line=f.line)
            break
        # Fallback: any frame with file:line
        if not primary:
            for f in stack:
                if f.file and f.line:
                    primary = SourceLocation(file=f.file, line=f.line)
                    break

        # ── Allocation stack (for leak errors, second <stack>) ──
        alloc_info = None
        all_stacks = err_el.findall(".//stack")
        if len(all_stacks) >= 2:
            alloc_frames = [_parse_vg_frame(f, i) for i, f in enumerate(all_stacks[1].findall("frame"))]
            alloc_kind = None
            for af in alloc_frames:
                if af.function in ("malloc", "calloc", "realloc", "operator new", "operator new[]",
                                   "strdup", "strndup", "memalign", "aligned_alloc"):
                    alloc_kind = af.function
                    break
            alloc_info = AllocationInfo(
                size  = leaked_bytes,
                count = leaked_blocks,
                stack = alloc_frames,
                kind  = alloc_kind,
            )

        # ── Auxillary info (for InvalidRead/Write: address details) ──
        auxwhat = err_el.findtext("auxwhat", "")
        detail = None
        if auxwhat:
            detail = auxwhat

        # ── Reclassify InvalidRead/Write as USE_AFTER_FREE ──
        # Valgrind auxwhat says "Address ... is N bytes inside a block of size M free'd"
        # when the read/write hits a freed block. Also check if second stack
        # mentions "free" — that's the deallocation site.
        free_info = None
        if kind in ("InvalidRead", "InvalidWrite"):
            is_uaf = False
            if auxwhat and "free'd" in auxwhat:
                is_uaf = True
            if not is_uaf and len(all_stacks) >= 2:
                for af in alloc_frames:
                    if af.function in ("free", "operator delete",
                                       "operator delete[]", "cfree"):
                        is_uaf = True
                        break
            if is_uaf:
                bug_type = BugType.USE_AFTER_FREE
                # Store the free site stack in free_info
                if len(all_stacks) >= 2:
                    free_frames = [_parse_vg_frame(f, i)
                                   for i, f in enumerate(all_stacks[1].findall("frame"))]
                    free_info = AllocationInfo(
                        size=leaked_bytes, count=leaked_blocks,
                        stack=free_frames, kind="free",
                    )
                    # If there's a third stack, that's the original allocation
                    if len(all_stacks) >= 3:
                        alloc_frames_3 = [_parse_vg_frame(f, i)
                                          for i, f in enumerate(all_stacks[2].findall("frame"))]
                        alloc_info = AllocationInfo(
                            size=leaked_bytes, count=leaked_blocks,
                            stack=alloc_frames_3, kind=None,
                        )

        me = MemoryError(
            tool             = AnalysisTool.VALGRIND,
            language         = Language.C,
            bug_type         = bug_type,
            severity         = severity,
            message          = what,
            detail           = detail,
            stack            = stack,
            primary_location = primary,
            allocation_info  = alloc_info,
            free_info        = free_info,
            bytes_leaked     = leaked_bytes,
            alloc_count      = leaked_blocks,
        )

        if me.fingerprint not in seen:
            seen.add(me.fingerprint)
            errors.append(me)

    log.info("Parsed %d errors from Valgrind XML (%d bytes)", len(errors), len(xml_text))
    return errors


# ---------------------------------------------------------------------------
# ASan / LSan text parser
# ---------------------------------------------------------------------------

_ASAN_FRAME_RE = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(.*?)(?::(\d+)(?::(\d+))?)?$",
    re.MULTILINE,
)
_LSAN_BLOCK_RE = re.compile(
    r"Direct leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:\s*((?:#\d+.*\n?)+)",
)

ASAN_KIND_PATTERNS = [
    (re.compile(r"heap-buffer-overflow"),       BugType.BUFFER_OVERFLOW, Severity.CRITICAL),
    (re.compile(r"stack-buffer-overflow"),      BugType.STACK_OVERFLOW,  Severity.CRITICAL),
    (re.compile(r"heap-use-after-free"),        BugType.USE_AFTER_FREE,  Severity.CRITICAL),
    (re.compile(r"double-free"),                BugType.DOUBLE_FREE,     Severity.CRITICAL),
    (re.compile(r"null-dereference"),           BugType.NULL_DEREF,      Severity.CRITICAL),
    (re.compile(r"detected memory leaks"),      BugType.MEMORY_LEAK,     Severity.HIGH),
    (re.compile(r"stack-overflow"),             BugType.STACK_OVERFLOW,  Severity.CRITICAL),
    (re.compile(r"global-buffer-overflow"),     BugType.BUFFER_OVERFLOW, Severity.CRITICAL),
]


def _parse_asan_frames(block):
    frames = []
    for m in _ASAN_FRAME_RE.finditer(block):
        idx, func, loc, line, col = int(m.group(1)), m.group(2), m.group(3), m.group(4), m.group(5)
        file_ = loc.strip() if loc.strip().endswith((".c", ".cpp", ".h", ".py")) else None
        frames.append(SourceFrame(
            index=idx, function=func, file=file_ or loc.strip(),
            line=int(line) if line else None, column=int(col) if col else None,
        ))
    return frames


def parse_asan_output(text: str, tool: AnalysisTool = AnalysisTool.ASAN) -> list[MemoryError]:
    if not text.strip():
        return []
    errors = []
    blocks = re.split(r"(?=ERROR:|WARNING:)", text)
    for block in blocks:
        if not block.strip():
            continue
        bug_type, severity = BugType.UNKNOWN, Severity.MEDIUM
        for pat, bt, sev in ASAN_KIND_PATTERNS:
            if pat.search(block, re.IGNORECASE):
                bug_type, severity = bt, sev
                break
        first_line = block.split("\n")[0].strip()
        stack = _parse_asan_frames(block)
        primary = next((SourceLocation(file=f.file, line=f.line)
                        for f in stack if f.file and f.line), None)
        errors.append(MemoryError(
            tool=tool, language=Language.C, bug_type=bug_type,
            severity=severity, message=first_line[:200],
            stack=stack, primary_location=primary,
        ))

    # LSan leak blocks
    for m in _LSAN_BLOCK_RE.finditer(text):
        size, count, trace = int(m.group(1)), int(m.group(2)), m.group(3)
        stack = _parse_asan_frames(trace)
        primary = next((SourceLocation(file=f.file, line=f.line)
                        for f in stack if f.file and f.line), None)
        errors.append(MemoryError(
            tool=AnalysisTool.LSAN, language=Language.C,
            bug_type=BugType.MEMORY_LEAK, severity=Severity.HIGH,
            message=f"Direct leak of {size} bytes in {count} object(s)",
            stack=stack, primary_location=primary,
            bytes_leaked=size, alloc_count=count,
        ))
    return errors


# ---------------------------------------------------------------------------
# cppcheck XML parser
# ---------------------------------------------------------------------------

CPPCHECK_KIND_MAP = {
    "memleak": BugType.MEMORY_LEAK, "resourceLeak": BugType.MEMORY_LEAK,
    "doubleFree": BugType.DOUBLE_FREE, "nullPointer": BugType.NULL_DEREF,
    "bufferAccessOutOfBounds": BugType.BUFFER_OVERFLOW,
    "useAfterFree": BugType.USE_AFTER_FREE, "uninitvar": BugType.UNINIT_READ,
}

def parse_cppcheck_xml(xml_text):
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    errors = []
    for err_el in root.findall(".//error"):
        eid = err_el.get("id", "")
        sev_map = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "style": Severity.LOW}
        severity = sev_map.get(err_el.get("severity"), Severity.INFO)
        bug_type = CPPCHECK_KIND_MAP.get(eid, BugType.UNKNOWN)
        msg = err_el.get("msg", "")
        stack, primary = [], None
        for i, loc in enumerate(err_el.findall("location")):
            f, l, c = loc.get("file"), int(loc.get("line", 0)), int(loc.get("column", 0))
            stack.append(SourceFrame(index=i, file=f, line=l or None, column=c or None))
            if not primary and f and l:
                primary = SourceLocation(file=f, line=l, column=c or None)
        errors.append(MemoryError(
            tool=AnalysisTool.CPPCHECK, language=Language.C, bug_type=bug_type,
            severity=severity, message=msg, stack=stack, primary_location=primary,
        ))
    return errors


# ---------------------------------------------------------------------------
# Python tracemalloc JSON parser
# ---------------------------------------------------------------------------

def parse_tracemalloc_json(json_text):
    try:
        records = json.loads(json_text)
    except (json.JSONDecodeError, ValueError):
        return []
    errors = []
    for rec in records[:20]:
        size = rec.get("size", 0)
        stack = [SourceFrame(index=i, file=f.get("file"), line=f.get("line"))
                 for i, f in enumerate(rec.get("traceback", []))]
        primary = next((SourceLocation(file=f.file, line=f.line)
                        for f in stack if f.file and f.line), None)
        severity = Severity.HIGH if size > 1_000_000 else Severity.MEDIUM if size > 100_000 else Severity.LOW
        errors.append(MemoryError(
            tool=AnalysisTool.TRACEMALLOC, language=Language.PYTHON,
            bug_type=BugType.PYTHON_LARGE_OBJECT, severity=severity,
            message=f"Large allocation: {size:,} bytes in {rec.get('count', 0)} objects",
            stack=stack, primary_location=primary,
            bytes_leaked=size, alloc_count=rec.get("count"),
        ))
    return errors


# ---------------------------------------------------------------------------
# Helgrind XML parser — race conditions, deadlocks, lock order violations
# ---------------------------------------------------------------------------

HELGRIND_KIND_MAP = {
    "Race":               (BugType.RACE_CONDITION,  Severity.CRITICAL),
    "UnlockUnlocked":     (BugType.RACE_CONDITION,  Severity.HIGH),
    "UnlockForeign":      (BugType.RACE_CONDITION,  Severity.HIGH),
    "UnlockBogus":        (BugType.RACE_CONDITION,  Severity.HIGH),
    "PthAPIerror":        (BugType.RACE_CONDITION,  Severity.MEDIUM),
    "LockOrder":          (BugType.RACE_CONDITION,  Severity.HIGH),
    "Misc":               (BugType.RACE_CONDITION,  Severity.MEDIUM),
}


def parse_helgrind_xml(xml_text: str) -> list[MemoryError]:
    if not xml_text or len(xml_text) < 50:
        return []
    xml_text = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", xml_text)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log.warning("Helgrind XML parse error: %s", e)
        return []

    errors = []
    seen = set()

    for err_el in root.findall(".//error"):
        kind = err_el.findtext("kind", "")
        bug_type, severity = HELGRIND_KIND_MAP.get(kind, (BugType.RACE_CONDITION, Severity.MEDIUM))

        what = err_el.findtext("what") or err_el.findtext("xwhat/text") or kind

        # Primary stack
        stack = []
        first_stack = err_el.find(".//stack")
        if first_stack is not None:
            for i, f in enumerate(first_stack.findall("frame")):
                stack.append(_parse_vg_frame(f, i))

        primary = None
        for f in stack:
            if f.file and f.line and not f.file.startswith("/usr/"):
                primary = SourceLocation(file=f.file, line=f.line)
                break

        # Auxwhat — often describes the second thread or lock
        auxwhat = err_el.findtext("auxwhat", "")
        detail = auxwhat if auxwhat else None

        me = MemoryError(
            tool             = AnalysisTool.HELGRIND,
            language         = Language.C,
            bug_type         = bug_type,
            severity         = severity,
            message          = what,
            detail           = detail,
            stack            = stack,
            primary_location = primary,
        )

        if me.fingerprint not in seen:
            seen.add(me.fingerprint)
            errors.append(me)

    log.info("Parsed %d errors from Helgrind XML", len(errors))
    return errors


# ---------------------------------------------------------------------------
# Facebook Infer JSON parser
# ---------------------------------------------------------------------------

INFER_BUG_MAP = {
    "NULL_DEREFERENCE":        (BugType.NULL_DEREF,       Severity.CRITICAL),
    "NULLPTR_DEREFERENCE":     (BugType.NULL_DEREF,       Severity.CRITICAL),
    "MEMORY_LEAK":             (BugType.MEMORY_LEAK,      Severity.HIGH),
    "MEMORY_LEAK_C":           (BugType.MEMORY_LEAK,      Severity.HIGH),
    "RESOURCE_LEAK_C":         (BugType.MEMORY_LEAK,      Severity.HIGH),
    "RESOURCE_LEAK":           (BugType.MEMORY_LEAK,      Severity.HIGH),
    "BUFFER_OVERRUN_L1":       (BugType.BUFFER_OVERFLOW,  Severity.CRITICAL),
    "BUFFER_OVERRUN_L2":       (BugType.BUFFER_OVERFLOW,  Severity.HIGH),
    "BUFFER_OVERRUN_L3":       (BugType.BUFFER_OVERFLOW,  Severity.MEDIUM),
    "BUFFER_OVERRUN_L4":       (BugType.BUFFER_OVERFLOW,  Severity.LOW),
    "BUFFER_OVERRUN_L5":       (BugType.BUFFER_OVERFLOW,  Severity.LOW),
    "BUFFER_OVERRUN_S2":       (BugType.BUFFER_OVERFLOW,  Severity.HIGH),
    "USE_AFTER_FREE":          (BugType.USE_AFTER_FREE,   Severity.CRITICAL),
    "USE_AFTER_DELETE":        (BugType.USE_AFTER_FREE,   Severity.CRITICAL),
    "USE_AFTER_LIFETIME":      (BugType.USE_AFTER_FREE,   Severity.HIGH),
    "DOUBLE_FREE":             (BugType.DOUBLE_FREE,      Severity.CRITICAL),
    "UNINITIALIZED_VALUE":     (BugType.UNINIT_READ,      Severity.MEDIUM),
    "DEAD_STORE":              (BugType.UNKNOWN,          Severity.LOW),
    "THREAD_SAFETY_violation": (BugType.RACE_CONDITION,   Severity.HIGH),
    "LOCK_CONSISTENCY_VIOLATION": (BugType.RACE_CONDITION, Severity.HIGH),
    "DIVIDE_BY_ZERO":          (BugType.UNKNOWN,          Severity.HIGH),
    "INTEGER_OVERFLOW_L1":     (BugType.UNKNOWN,          Severity.MEDIUM),
    "STACK_VARIABLE_ADDRESS_ESCAPE": (BugType.DANGLING_POINTER, Severity.HIGH),
}


def parse_infer_json(json_text: str) -> list[MemoryError]:
    """Parse Infer's report.json output."""
    if not json_text or json_text.strip() in ("", "[]"):
        return []
    try:
        reports = json.loads(json_text)
    except (json.JSONDecodeError, ValueError) as e:
        log.warning("Infer JSON parse error: %s", e)
        return []

    if not isinstance(reports, list):
        return []

    errors = []
    seen = set()

    for issue in reports:
        infer_type = issue.get("bug_type", "UNKNOWN")
        bug_type, severity = INFER_BUG_MAP.get(
            infer_type, (BugType.UNKNOWN, Severity.MEDIUM))

        # Skip low-value noise
        if infer_type in ("DEAD_STORE", "CONDITION_ALWAYS_TRUE",
                          "CONDITION_ALWAYS_FALSE"):
            continue

        qualifier = issue.get("qualifier", "")
        procedure = issue.get("procedure", "")
        file_path = issue.get("file", "")
        line = issue.get("line", 0)
        column = issue.get("column", 0)

        message = f"[Infer] {infer_type}: {qualifier}"
        if len(message) > 200:
            message = message[:197] + "..."

        # Build stack from bug_trace
        stack = []
        for i, frame in enumerate(issue.get("bug_trace", [])):
            stack.append(SourceFrame(
                index=i,
                file=frame.get("filename"),
                line=frame.get("line_number"),
                column=frame.get("column_number"),
                function=frame.get("procedure_name"),
            ))

        primary = SourceLocation(
            file=file_path, line=line, column=column
        ) if file_path and line else None

        me = MemoryError(
            tool=AnalysisTool.INFER,
            language=Language.C,
            bug_type=bug_type,
            severity=severity,
            message=message,
            detail=f"In function: {procedure}" if procedure else None,
            stack=stack,
            primary_location=primary,
        )

        fp = me.fingerprint
        if fp not in seen:
            seen.add(fp)
            errors.append(me)

    log.info("Parsed %d issues from Infer report", len(errors))
    return errors


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def parse_tool_output(tool: AnalysisTool, output: str) -> list[MemoryError]:
    dispatch = {
        AnalysisTool.VALGRIND:     parse_valgrind_xml,
        AnalysisTool.ASAN:         lambda t: parse_asan_output(t, AnalysisTool.ASAN),
        AnalysisTool.LSAN:         lambda t: parse_asan_output(t, AnalysisTool.LSAN),
        AnalysisTool.MSAN:         lambda t: parse_asan_output(t, AnalysisTool.MSAN),
        AnalysisTool.UBSAN:        lambda t: parse_asan_output(t, AnalysisTool.UBSAN),
        AnalysisTool.TSAN:         lambda t: parse_asan_output(t, AnalysisTool.TSAN),
        AnalysisTool.HELGRIND:     parse_helgrind_xml,
        AnalysisTool.INFER:        parse_infer_json,
        AnalysisTool.CPPCHECK:     parse_cppcheck_xml,
        AnalysisTool.TRACEMALLOC:  parse_tracemalloc_json,
        AnalysisTool.MEMRAY:       parse_tracemalloc_json,
    }
    parser = dispatch.get(tool)
    if not parser:
        return []
    try:
        return parser(output)
    except (ET.ParseError, json.JSONDecodeError) as exc:
        # Malformed tool output — expected occasionally, log and continue
        log.warning("Parser could not decode %s output: %s", tool.value, exc)
        return []
    except Exception:
        # Programming error in the parser itself — log full traceback so
        # bugs like an undefined variable are never silently swallowed
        log.exception("BUG in %s parser — please report this traceback", tool.value)
        return []
