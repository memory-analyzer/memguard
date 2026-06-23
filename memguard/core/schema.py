"""
memguard.core.schema
====================
Unified data models used across all analysis tools, languages, and AI layers.
Every parser normalises its tool-specific output into these models so the rest
of the pipeline is tool-agnostic.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Timezone-aware replacement for the deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc)
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Language(str, Enum):
    C        = "c"
    CPP      = "cpp"
    PYTHON   = "python"
    RUST     = "rust"
    UNKNOWN  = "unknown"


class AnalysisTool(str, Enum):
    VALGRIND      = "valgrind"
    ASAN          = "asan"
    LSAN          = "lsan"
    MSAN          = "msan"
    UBSAN         = "ubsan"
    TSAN          = "tsan"      # thread sanitizer
    CPPCHECK      = "cppcheck"
    CLANG_TIDY    = "clang_tidy"
    MEMRAY        = "memray"    # Python
    TRACEMALLOC   = "tracemalloc"
    RUSTFMT       = "rustfmt"
    MIRI          = "miri"      # Rust interpreter
    HELGRIND      = "helgrind"  # Thread error detector
    INFER         = "infer"     # Facebook Infer static analyzer


class BugType(str, Enum):
    MEMORY_LEAK           = "memory_leak"
    USE_AFTER_FREE        = "use_after_free"
    DOUBLE_FREE           = "double_free"
    BUFFER_OVERFLOW       = "buffer_overflow"
    BUFFER_UNDERFLOW      = "buffer_underflow"
    STACK_OVERFLOW        = "stack_overflow"
    NULL_DEREF            = "null_deref"
    UNINIT_READ           = "uninit_read"
    INVALID_FREE          = "invalid_free"
    HEAP_CORRUPTION       = "heap_corruption"
    RACE_CONDITION        = "race_condition"
    DANGLING_POINTER      = "dangling_pointer"
    INTEGER_OVERFLOW      = "integer_overflow"
    FORMAT_STRING         = "format_string"
    PYTHON_REFERENCE_CYCLE = "python_reference_cycle"
    PYTHON_LARGE_OBJECT   = "python_large_object"
    RUST_UNSAFE_BLOCK     = "rust_unsafe_block"
    UNKNOWN               = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"   # exploitable, crashes, data corruption
    HIGH     = "high"       # definite leak / UAF, significant impact
    MEDIUM   = "medium"     # possible leak, indirect impact
    LOW      = "low"        # best-practice violation, minor overhead
    INFO     = "info"       # informational, style/pattern suggestion


class FixConfidence(str, Enum):
    HIGH    = "high"    # >90% — trivially correct fix
    MEDIUM  = "medium"  # 60-90% — likely correct, review advised
    LOW     = "low"     # <60% — complex, human review required


class FixStatus(str, Enum):
    PENDING   = "pending"
    ACCEPTED  = "accepted"
    REJECTED  = "rejected"
    APPLIED   = "applied"
    ROLLED_BACK = "rolled_back"


class SessionState(str, Enum):
    IDLE       = "idle"
    SCANNING   = "scanning"
    ANALYZING  = "analyzing"
    INTERACTIVE = "interactive"
    PATCHING   = "patching"
    DONE       = "done"
    FAILED     = "failed"


# ---------------------------------------------------------------------------
# Source location models
# ---------------------------------------------------------------------------

class SourceFrame(BaseModel):
    """Single frame in a stack trace."""
    index:    int
    address:  str | None = None
    function: str | None = None
    file:     str | None = None
    line:     int | None = None
    column:   int | None = None
    module:   str | None = None
    inlined:  bool = False
    # Resolved source snippet around this frame (populated by symbolizer)
    snippet:  str | None = None
    snippet_start_line: int | None = None


class SourceLocation(BaseModel):
    file:   str
    line:   int
    column: int | None = None

    def __str__(self) -> str:
        col = f":{self.column}" if self.column else ""
        return f"{self.file}:{self.line}{col}"


class SourceContext(BaseModel):
    """Full source context extracted around the error site."""
    location:      SourceLocation
    before_lines:  list[str] = Field(default_factory=list)  # N lines before
    target_line:   str = ""
    after_lines:   list[str] = Field(default_factory=list)  # N lines after
    language:      Language = Language.UNKNOWN
    function_body: str | None = None   # whole enclosing function if available
    function_start_line: int | None = None  # line where enclosing function starts
    full_file_content: str | None = None   # entire file if <300 lines


# ---------------------------------------------------------------------------
# Memory error models
# ---------------------------------------------------------------------------

class AllocationInfo(BaseModel):
    """Where the allocation that later leaked/corrupted was made."""
    size:    int | None = None
    count:   int | None = None   # for array allocs
    stack:   list[SourceFrame] = Field(default_factory=list)
    kind:    str | None = None   # malloc / new / calloc / etc.


class MemoryError(BaseModel):
    """
    Normalised representation of a single memory error from ANY tool.
    This is the canonical unit that flows through the entire pipeline.
    """
    id:           str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool:         AnalysisTool
    language:     Language
    bug_type:     BugType
    severity:     Severity = Severity.MEDIUM
    message:      str
    detail:       str | None = None

    # Error site
    stack:          list[SourceFrame] = Field(default_factory=list)
    primary_location: SourceLocation | None = None
    source_context: SourceContext | None = None

    # Allocation site (for leak/UAF/double-free)
    allocation_info: AllocationInfo | None = None
    free_info:       AllocationInfo | None = None   # for double-free

    # Metrics
    bytes_leaked:   int | None = None
    bytes_lost:     int | None = None   # indirectly reachable
    alloc_count:    int | None = None

    # Deduplication
    suppressed:     bool = False
    duplicate_of:   str | None = None   # id of canonical error

    # Timestamps
    discovered_at:  datetime = Field(default_factory=_utcnow)

    @computed_field
    @property
    def fingerprint(self) -> str:
        """Stable hash for deduplication across runs."""
        key = f"{self.bug_type}:{self.tool}:"
        key += ":".join(
            f"{f.function}@{f.file}:{f.line}"
            for f in self.stack[:3]
            if f.function
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# AI analysis output
# ---------------------------------------------------------------------------

class CodeFix(BaseModel):
    """A concrete code change produced by the AI."""
    description:    str
    diff:           str                  # unified diff (built programmatically)
    find_text:      str | None = None    # exact original code to find
    replace_text:   str | None = None    # replacement code
    patched_source: str | None = None    # full replacement content
    confidence:     FixConfidence
    pattern:        str                  # RAII, smart_ptr, bounds_check, etc.
    breaking_change: bool = False
    test_suggestion: str | None = None   # suggested test to verify fix
    applicable:     bool = True          # whether find_text was located in source


class BestPractice(BaseModel):
    title:       str
    explanation: str
    example:     str | None = None       # good code example
    bad_example: str | None = None       # what NOT to do
    references:  list[str] = Field(default_factory=list)  # CWE, MISRA, etc.


class AIAnalysis(BaseModel):
    """Full AI analysis result for one MemoryError."""
    error_id:       str
    model:          str
    model_version:  str | None = None

    # Core analysis
    root_cause:     str
    explanation:    str
    impact:         str
    cwe_ids:        list[str] = Field(default_factory=list)
    misra_rules:    list[str] = Field(default_factory=list)

    # Fix
    fixes:          list[CodeFix] = Field(default_factory=list)
    best_practices: list[BestPractice] = Field(default_factory=list)

    # Meta
    confidence:     FixConfidence = FixConfidence.MEDIUM
    tokens_used:    int | None = None
    analysis_ms:    int | None = None
    analyzed_at:    datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Interactive debugger session
# ---------------------------------------------------------------------------

class DebugStep(BaseModel):
    """One step in the interactive guided-fix session."""
    step_number:   int
    title:         str
    description:   str
    code_before:   str | None = None
    code_after:    str | None = None
    explanation:   str
    validation:    str | None = None  # how to verify this step worked
    completed:     bool = False
    skipped:       bool = False
    user_notes:    str | None = None


class InteractiveSession(BaseModel):
    """Full state of a guided interactive fix session."""
    session_id:   str = Field(default_factory=lambda: str(uuid.uuid4()))
    error_id:     str
    analysis_id:  str
    state:        SessionState = SessionState.IDLE

    steps:             list[DebugStep] = Field(default_factory=list)
    current_step:      int = 0
    conversation:      list[dict[str, str]] = Field(default_factory=list)

    started_at:    datetime = Field(default_factory=_utcnow)
    completed_at:  datetime | None = None

    git_branch:    str | None = None   # branch created for this fix
    backup_files:  dict[str, str] = Field(default_factory=dict)  # path → content


# ---------------------------------------------------------------------------
# Scan session (top-level)
# ---------------------------------------------------------------------------

class ScanTarget(BaseModel):
    binary:     str | None = None
    source_dir: str | None = None
    files:      list[str] = Field(default_factory=list)
    language:   Language = Language.UNKNOWN
    compile_cmd: str | None = None
    args:       list[str] = Field(default_factory=list)
    env:        dict[str, str] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    target:        ScanTarget
    tools:         list[AnalysisTool] = Field(default_factory=list)
    max_errors:    int = 500
    timeout_sec:   int = 120
    num_callers:   int = 20
    track_origins: bool = True
    ai_model:      str = "qwen2.5-coder:14b-instruct-q4_K_M"
    ai_fallback:   str = "deepseek-coder-v2:16b-lite-instruct-q4_K_M"
    parallel:      bool = True
    cache_results: bool = True
    suppress_file: str | None = None


class ScanResult(BaseModel):
    scan_id:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    config:     ScanConfig
    state:      SessionState = SessionState.IDLE

    errors:       list[MemoryError] = Field(default_factory=list)
    analyses:     list[AIAnalysis]  = Field(default_factory=list)
    sessions:     list[InteractiveSession] = Field(default_factory=list)

    # Stats
    total_bytes_leaked: int = 0
    error_count_by_type: dict[str, int] = Field(default_factory=dict)
    error_count_by_severity: dict[str, int] = Field(default_factory=dict)

    started_at:   datetime = Field(default_factory=_utcnow)
    finished_at:  datetime | None = None
    duration_ms:  int | None = None

    raw_outputs:  dict[str, str] = Field(default_factory=dict)  # tool → raw


# ---------------------------------------------------------------------------
# Profiling models (heap timeline)
# ---------------------------------------------------------------------------

class HeapSnapshot(BaseModel):
    timestamp_ms: int
    total_bytes:  int
    peak_bytes:   int
    alloc_count:  int
    free_count:   int
    live_objects: int


class HeapProfile(BaseModel):
    snapshots:    list[HeapSnapshot] = Field(default_factory=list)
    peak_bytes:   int = 0
    peak_time_ms: int = 0
    top_allocators: list[dict[str, Any]] = Field(default_factory=list)
