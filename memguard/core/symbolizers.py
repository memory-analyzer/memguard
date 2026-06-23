"""
memguard.core.symbolizers
==========================
Resolves raw stack frames → file:line:function using addr2line / llvm-symbolizer,
then fetches the surrounding source context for each error site.
"""

from __future__ import annotations
import re

import asyncio
import logging
import shutil
from pathlib import Path

from .schema import (
    Language, MemoryError, SourceContext, SourceFrame, SourceLocation,
)

log = logging.getLogger(__name__)

CONTEXT_LINES = 8   # lines before/after the error line


# ---------------------------------------------------------------------------
# addr2line / llvm-symbolizer
# ---------------------------------------------------------------------------

async def _addr2line(binary: str, addresses: list[str]) -> dict[str, str]:
    """Batch-resolve addresses. Returns addr → 'function\nfile:line'."""
    if not addresses:
        return {}
    tool = "llvm-symbolizer" if shutil.which("llvm-symbolizer") else "addr2line"
    args = [tool, "-e", binary, "-f", "-C"] + addresses
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        lines  = out.decode(errors="replace").splitlines()
    except Exception:
        return {}

    result = {}
    for i, addr in enumerate(addresses):
        base = i * 2
        if base + 1 < len(lines):
            result[addr] = f"{lines[base]}\n{lines[base+1]}"
    return result


def _resolve_from_string(raw: str) -> tuple[str | None, str | None, int | None]:
    """Parse 'function\nfile:line' from addr2line output."""
    lines = raw.strip().splitlines()
    func  = lines[0].strip() if lines else None
    if len(lines) > 1:
        loc_part = lines[1].strip()
        if ":" in loc_part:
            parts = loc_part.rsplit(":", 1)
            try:
                return func, parts[0], int(parts[1])
            except ValueError:
                pass
        return func, loc_part, None
    return func, None, None


# ---------------------------------------------------------------------------
# Source reader
# ---------------------------------------------------------------------------

def _read_source_context(
    file: str, line: int, language: Language,
    before: int = CONTEXT_LINES, after: int = CONTEXT_LINES,
) -> SourceContext | None:
    p = Path(file)
    if not p.exists():
        # Try relative path resolution
        for candidate in Path.cwd().rglob(p.name):
            p = candidate
            break
        else:
            return None

    try:
        all_lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return None

    n         = len(all_lines)
    start     = max(0, line - before - 1)
    end       = min(n, line + after)
    target_i  = line - 1

    ctx = SourceContext(
        location     = SourceLocation(file=str(p), line=line),
        before_lines = all_lines[start:target_i],
        target_line  = all_lines[target_i] if 0 <= target_i < n else "",
        after_lines  = all_lines[line:end],
        language     = language,
        snippet_start_line = start + 1,
    )

    # Try to extract the enclosing function
    body, start_line = _extract_function_body(all_lines, target_i, language)
    ctx.function_body = body
    ctx.function_start_line = start_line
    return ctx


def _extract_function_body(
    lines: list[str], target_idx: int, language: Language,
):
    """Returns (body_text, start_line_1indexed) or (None, None)."""
    if language == Language.PYTHON:
        fn_re = re.compile(r"^(def |async def )")
    else:
        fn_re = re.compile(r"\)\s*\{?\s*$")

    n_lines = len(lines)
    if target_idx < 0 or target_idx >= n_lines:
        return None, None
    start = target_idx
    for i in range(min(target_idx, n_lines - 1), max(-1, target_idx - 80), -1):
        if fn_re.search(lines[i]):
            start = i
            break

    depth = 0
    end   = min(len(lines), target_idx + 200)
    for i in range(start, end):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth < 0 or (depth == 0 and i > start + 2):
            end = i + 1
            break

    body = "\n".join(lines[start:min(end, start + 150)])
    if len(body) > 20:
        return body, start + 1
    return None, None


# ---------------------------------------------------------------------------
# Main symbolizer
# ---------------------------------------------------------------------------

class Symbolizer:
    def __init__(self, binary: str | None = None, language: Language = Language.C):
        self.binary   = binary
        self.language = language

    async def enrich_errors(self, errors: list[MemoryError]) -> list[MemoryError]:
        """Resolve addresses + attach source context to every error."""
        # Collect all unresolved addresses
        unresolved: dict[str, list[tuple[MemoryError, SourceFrame]]] = {}
        for err in errors:
            for frame in err.stack:
                if frame.address and (not frame.file or not frame.line):
                    unresolved.setdefault(frame.address, []).append((err, frame))

        if unresolved and self.binary:
            resolved = await _addr2line(self.binary, list(unresolved.keys()))
            for addr, mapping in resolved.items():
                func, file_, line = _resolve_from_string(mapping)
                for _err, frame in unresolved.get(addr, []):
                    if func and func not in ("??", ""):
                        frame.function = func
                    if file_ and file_ != "??":
                        frame.file = file_
                    if line:
                        frame.line = line

        # Attach source context to primary location of each error
        for err in errors:
            loc = err.primary_location
            if not loc:
                # Derive from first good frame
                for f in err.stack:
                    if f.file and f.line:
                        loc = SourceLocation(file=f.file, line=f.line)
                        err.primary_location = loc
                        break

            if loc:
                ctx = _read_source_context(loc.file, loc.line, self.language)
                if ctx:
                    err.source_context = ctx
                    # Attach full file if small enough — gives AI complete picture
                    try:
                        full = Path(loc.file).read_text(errors="replace")
                        if len(full.splitlines()) < 300:
                            ctx.full_file_content = full
                    except OSError:
                        pass
                    # Also attach snippets to individual frames
                    for frame in err.stack[:5]:
                        if frame.file and frame.line:
                            fc = _read_source_context(
                                frame.file, frame.line, self.language, before=3, after=3
                            )
                            if fc:
                                frame.snippet = fc.target_line
                                frame.snippet_start_line = frame.line

            # Refine language from file extension
            if err.primary_location:
                ext = Path(err.primary_location.file).suffix.lower()
                err.language = {
                    ".c": Language.C, ".cpp": Language.CPP,
                    ".cc": Language.CPP, ".cxx": Language.CPP,
                    ".py": Language.PYTHON, ".rs": Language.RUST,
                }.get(ext, self.language)

        return errors
