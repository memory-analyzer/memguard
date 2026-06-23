"""
memguard.languages
==================
Language-specific heuristics, pattern detectors, and additional context
builders layered ON TOP of the generic AI analysis.

Each language module:
  - Detects extra patterns the generic tools miss
  - Enriches MemoryError with language-specific metadata
  - Provides targeted prompt fragments for the AI
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

from ..core.schema import BugType, Language, MemoryError, Severity, SourceFrame


# ============================================================================
# C / C++
# ============================================================================

class CAnalyzer:
    """Additional static heuristics for C/C++ source files."""

    # Patterns that almost always indicate leaks / bad practices
    LEAK_PATTERNS = [
        (re.compile(r"\bmalloc\s*\("),        "malloc without free check"),
        (re.compile(r"\bcalloc\s*\("),        "calloc without free check"),
        (re.compile(r"\brealloc\s*\("),       "realloc — original ptr lost on failure"),
        (re.compile(r"\bstrdup\s*\("),        "strdup result must be freed"),
        (re.compile(r"\bnew\b.*\["),          "array new — use std::vector"),
        (re.compile(r"\bfopen\s*\("),         "FILE* must be fclose'd"),
    ]

    UAF_PATTERNS = [
        re.compile(r"\bfree\s*\(\s*(\w+)\s*\).*\1\s*[^=]"),   # free then use
    ]

    GOOD_PATTERNS_CPP = [
        (re.compile(r"\bstd::unique_ptr\b"),  "unique_ptr"),
        (re.compile(r"\bstd::shared_ptr\b"),  "shared_ptr"),
        (re.compile(r"\bstd::vector\b"),      "vector"),
        (re.compile(r"\bstd::string\b"),      "string"),
        (re.compile(r"RAII"),                 "RAII"),
    ]

    def scan_file(self, path: str) -> list[dict]:
        """Return list of {line, col, pattern, message} dicts."""
        findings = []
        try:
            text  = Path(path).read_text(errors="replace")
            lines = text.splitlines()
        except OSError:
            return findings

        is_cpp = Path(path).suffix.lower() in (".cpp", ".cc", ".cxx", ".hpp")

        for lineno, line in enumerate(lines, 1):
            # Skip comments
            stripped = re.sub(r"//.*$", "", line)
            stripped = re.sub(r"/\*.*?\*/", "", stripped)
            for pat, msg in self.LEAK_PATTERNS:
                if pat.search(stripped):
                    findings.append({
                        "line": lineno, "col": 0,
                        "pattern": pat.pattern, "message": msg,
                        "severity": "low",
                    })

        return findings

    def suggest_modern_cpp(self, error: MemoryError) -> list[str]:
        """Return modernisation suggestions based on bug type."""
        tips = {
            BugType.MEMORY_LEAK: [
                "Replace `malloc`/`free` with `std::unique_ptr<T>` for single ownership",
                "Use `std::make_unique<T>()` (C++14+) — zero overhead, exception-safe",
                "For shared ownership use `std::shared_ptr` with `std::make_shared`",
                "Stack-allocate small objects where possible; heap only when necessary",
            ],
            BugType.USE_AFTER_FREE: [
                "Set pointer to `nullptr` immediately after `free()` / `delete`",
                "Use `std::unique_ptr` — it nullifies on destruction automatically",
                "Audit all raw pointer copies; prefer reference-counted ownership",
            ],
            BugType.DOUBLE_FREE: [
                "Rule of 5: if you define destructor, define copy/move ctor & assignment",
                "Prefer `std::unique_ptr` which prevents double-free by design",
                "Wrap heap resources in RAII classes",
            ],
            BugType.BUFFER_OVERFLOW: [
                "Replace C arrays with `std::vector` or `std::array`",
                "Use `std::span` (C++20) for non-owning views with bounds checking",
                "Enable `-D_FORTIFY_SOURCE=2` in release builds",
                "Compile with `-fsanitize=address,undefined` during testing",
            ],
            BugType.NULL_DEREF: [
                "Check pointer before dereference or use `assert(ptr != nullptr)`",
                "Prefer `std::optional<T>` over nullable pointers for optional values",
                "Use `gsl::not_null<T*>` to enforce non-null at type level",
            ],
        }
        return tips.get(error.bug_type, [
            "Consider using AddressSanitizer: compile with -fsanitize=address",
            "Run with Valgrind --leak-check=full for exhaustive analysis",
        ])


# ============================================================================
# Python
# ============================================================================

class PythonAnalyzer:
    """AST-based reference cycle and large-object detector for Python."""

    CYCLE_PATTERNS = [
        # Class that stores self in a global/class-level structure
        re.compile(r"class\s+\w+.*:\s*\n(?:.*\n)*?\s+\w+\s*=\s*\[\]"),
        # lambda / callback storing outer scope
        re.compile(r"self\.\w+\s*=\s*lambda"),
    ]

    def scan_file(self, path: str) -> list[dict]:
        findings = []
        try:
            source = Path(path).read_text()
            tree   = ast.parse(source, filename=path)
        except (OSError, SyntaxError):
            return findings

        for node in ast.walk(tree):
            # Detect __del__ (signals manual resource management)
            if isinstance(node, ast.FunctionDef) and node.name == "__del__":
                findings.append({
                    "line": node.lineno, "col": node.col_offset,
                    "pattern": "__del__",
                    "message": "__del__ can prevent garbage collection of cyclic references",
                    "severity": "medium",
                })
            # Detect global caches that grow unbounded
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(node.value, (ast.Dict, ast.List, ast.Set)):
                            if target.id.upper() == target.id:  # ALL_CAPS → global
                                findings.append({
                                    "line": node.lineno, "col": 0,
                                    "pattern": "global_container",
                                    "message": f"Global container `{target.id}` may grow unbounded",
                                    "severity": "low",
                                })

        return findings

    def suggest_fixes(self, error: MemoryError) -> list[str]:
        return {
            BugType.PYTHON_REFERENCE_CYCLE: [
                "Use `weakref.ref()` or `weakref.WeakValueDictionary` for back-references",
                "Call `gc.collect()` explicitly after deleting large object graphs",
                "Avoid storing `self` in closures/lambdas assigned to instance attrs",
                "Use `objgraph` to visualise reference cycles: `objgraph.show_backrefs(obj)`",
            ],
            BugType.PYTHON_LARGE_OBJECT: [
                "Use generators instead of lists for large sequences",
                "Process data in chunks with `itertools.islice`",
                "Use `numpy` arrays instead of Python lists for numeric data",
                "Profile with `tracemalloc.start(25)` and `snapshot.statistics('lineno')`",
                "Cache with `functools.lru_cache(maxsize=256)` to bound cache size",
            ],
            BugType.MEMORY_LEAK: [
                "Run `import gc; gc.set_debug(gc.DEBUG_LEAK)` to find cycles",
                "Use `memray` for heap profiling: `python -m memray run script.py`",
                "Audit class attributes that accumulate across instances",
                "Use `weakref` for observer/event patterns to avoid retention",
            ],
        }.get(error.bug_type, [
            "Profile with: python -m tracemalloc -n 10 your_script.py",
            "Use memray for flamegraph-based heap profiling",
        ])


# ============================================================================
# Rust
# ============================================================================

class RustAnalyzer:
    """Rust-specific unsafe block detector and Miri output enricher."""

    UNSAFE_PATTERNS = [
        (re.compile(r"\bunsafe\s*\{"),          "unsafe block"),
        (re.compile(r"\bstd::mem::forget\b"),   "mem::forget — bypasses Drop"),
        (re.compile(r"\bBox::from_raw\b"),       "Box::from_raw — manual ownership"),
        (re.compile(r"\*mut\s+\w+"),             "raw mutable pointer"),
        (re.compile(r"\*const\s+\w+"),           "raw const pointer"),
        (re.compile(r"transmute\b"),             "transmute — extremely unsafe"),
        (re.compile(r"ManuallyDrop\b"),          "ManuallyDrop — must call drop manually"),
    ]

    def scan_file(self, path: str) -> list[dict]:
        findings = []
        try:
            lines = Path(path).read_text(errors="replace").splitlines()
        except OSError:
            return findings

        for lineno, line in enumerate(lines, 1):
            for pat, msg in self.UNSAFE_PATTERNS:
                if pat.search(line):
                    findings.append({
                        "line": lineno, "col": 0,
                        "pattern": pat.pattern, "message": msg,
                        "severity": "high" if "transmute" in msg else "medium",
                    })
        return findings

    def suggest_fixes(self, error: MemoryError) -> list[str]:
        return [
            "Run Miri to detect UB in unsafe code: `cargo +nightly miri test`",
            "Consider replacing `unsafe` blocks with safe abstractions",
            "`mem::forget` can be replaced with `ManuallyDrop` for clarity",
            "Use `Pin` for self-referential structures instead of raw pointers",
            "Audit `Box::from_raw` — ensure exactly one `Box::into_raw` pairs with it",
            "Run `cargo clippy -- -W clippy::all -W clippy::pedantic`",
        ]


# ============================================================================
# Dispatcher
# ============================================================================

_c_analyzer  = CAnalyzer()
_py_analyzer = PythonAnalyzer()
_rs_analyzer = RustAnalyzer()


def get_language_tips(error: MemoryError) -> list[str]:
    """Return language-specific tips for this error."""
    if error.language == Language.PYTHON:
        return _py_analyzer.suggest_fixes(error)
    if error.language == Language.RUST:
        return _rs_analyzer.suggest_fixes(error)
    if error.language in (Language.C, Language.CPP):
        return _c_analyzer.suggest_modern_cpp(error)
    return []


def scan_source_file(path: str, language: Language) -> list[dict]:
    """Run language-specific static scan on a source file."""
    if language == Language.PYTHON:
        return _py_analyzer.scan_file(path)
    if language == Language.RUST:
        return _rs_analyzer.scan_file(path)
    if language in (Language.C, Language.CPP):
        return _c_analyzer.scan_file(path)
    return []
