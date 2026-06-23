"""
memguard.core.hardening
========================
Binary Security Hardening Auditor — novel feature that correlates
binary-level security mitigations with detected memory bugs.

No other tool does this: checksec shows mitigations, Valgrind finds bugs,
but NOBODY tells you "Your buffer overflow is exploitable because PIE is
disabled and stack canaries are missing."

MemGuard connects the dots:
  detected bug + missing mitigation = exploitability assessment

Checks: PIE, RELRO, Stack Canary, NX, FORTIFY_SOURCE, ASAN, ASLR
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .schema import BugType, MemoryError, Severity

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Mitigation:
    name: str
    enabled: bool
    detail: str
    compiler_flag: str      # how to enable it
    protects_against: list[str]   # bug types this mitigates


@dataclass
class ExploitCorrelation:
    bug_id: str
    bug_type: str
    bug_location: str
    severity: str
    missing_mitigations: list[str]
    exploitability: str     # "TRIVIAL", "LIKELY", "POSSIBLE", "UNLIKELY"
    attack_scenario: str    # how an attacker would exploit this
    would_prevent: list[str]  # which mitigations would have prevented it


@dataclass
class HardeningReport:
    binary: str
    mitigations: list[Mitigation]
    hardening_score: int    # 0-100
    grade: str              # A-F
    correlations: list[ExploitCorrelation]
    critical_findings: list[str]
    recommended_flags: list[str]
    recompile_cmd: str


# ═══════════════════════════════════════════════════════════════════════════
# Binary analysis using readelf/file/checksec
# ═══════════════════════════════════════════════════════════════════════════

async def _run(args: list[str], timeout: int = 10) -> tuple[str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), proc.returncode or 0
    except (FileNotFoundError, asyncio.TimeoutError):
        return "", -1


async def check_mitigations(binary: str) -> list[Mitigation]:
    """Check binary for security mitigations using readelf/objdump."""
    mitigations = []

    # ── 1. PIE (Position Independent Executable) ──
    # Enables ASLR for the main binary — randomizes code addresses
    out, rc = await _run(["readelf", "-h", binary])
    is_pie = "DYN" in out and "Type:" in out
    pie_detail = "ET_DYN (PIE)" if is_pie else "ET_EXEC (fixed address)"
    mitigations.append(Mitigation(
        name="PIE",
        enabled=is_pie,
        detail=pie_detail,
        compiler_flag="-fPIE -pie",
        protects_against=["buffer_overflow", "use_after_free", "null_deref"],
    ))

    # ── 2. Stack Canary ──
    # Detects stack buffer overflows before return
    out, rc = await _run(["readelf", "-s", binary])
    has_canary = "__stack_chk_fail" in out
    mitigations.append(Mitigation(
        name="Stack Canary",
        enabled=has_canary,
        detail="__stack_chk_fail present" if has_canary else "No stack protector",
        compiler_flag="-fstack-protector-strong",
        protects_against=["buffer_overflow", "stack_overflow"],
    ))

    # ── 3. NX (No-Execute) ──
    # Prevents execution of injected shellcode on stack/heap
    out, rc = await _run(["readelf", "-l", binary])
    has_nx = True  # Default: NX enabled (modern default)
    for line in out.splitlines():
        if "GNU_STACK" in line:
            # If the flags contain "E" (execute), NX is disabled
            has_nx = "RWE" not in line and " E" not in line.split("GNU_STACK")[-1]
            break
    mitigations.append(Mitigation(
        name="NX (No-Execute)",
        enabled=has_nx,
        detail="Stack/heap non-executable" if has_nx else "Stack is EXECUTABLE — shellcode injection possible",
        compiler_flag="-Wl,-z,noexecstack",
        protects_against=["buffer_overflow", "stack_overflow", "use_after_free"],
    ))

    # ── 4. RELRO (Relocation Read-Only) ──
    # Protects GOT from being overwritten
    has_relro = "GNU_RELRO" in out
    # Check for FULL RELRO (BIND_NOW)
    out_dyn, _ = await _run(["readelf", "-d", binary])
    full_relro = has_relro and "BIND_NOW" in out_dyn
    relro_level = "Full" if full_relro else ("Partial" if has_relro else "None")
    mitigations.append(Mitigation(
        name="RELRO",
        enabled=has_relro,
        detail=f"{relro_level} RELRO" + (" — GOT fully protected" if full_relro else ""),
        compiler_flag="-Wl,-z,relro,-z,now" if not full_relro else "(already full)",
        protects_against=["buffer_overflow", "use_after_free"],
    ))

    # ── 5. FORTIFY_SOURCE ──
    # Compile-time + runtime checks on unsafe libc functions
    out_syms, _ = await _run(["readelf", "-s", binary])
    fortified_funcs = []
    unfortified_funcs = []
    _FORTIFY_TARGETS = ["printf", "sprintf", "snprintf", "strcpy", "strncpy",
                        "strcat", "strncat", "memcpy", "memmove", "memset",
                        "read", "recv", "gets", "fgets"]
    for func in _FORTIFY_TARGETS:
        if f"__{func}_chk" in out_syms:
            fortified_funcs.append(func)
        elif func in out_syms:
            unfortified_funcs.append(func)

    has_fortify = len(fortified_funcs) > 0
    mitigations.append(Mitigation(
        name="FORTIFY_SOURCE",
        enabled=has_fortify,
        detail=(f"Fortified: {', '.join(fortified_funcs[:5])}"
                if fortified_funcs
                else f"Unprotected: {', '.join(unfortified_funcs[:5])}"),
        compiler_flag="-D_FORTIFY_SOURCE=2 -O2",
        protects_against=["buffer_overflow"],
    ))

    # ── 6. ASAN/UBSAN instrumentation ──
    has_asan = "__asan_" in out_syms
    has_ubsan = "__ubsan_" in out_syms
    sanitizer = []
    if has_asan:
        sanitizer.append("ASan")
    if has_ubsan:
        sanitizer.append("UBSan")
    mitigations.append(Mitigation(
        name="Sanitizer",
        enabled=bool(sanitizer),
        detail=", ".join(sanitizer) + " instrumented" if sanitizer else "No sanitizer instrumentation",
        compiler_flag="-fsanitize=address,undefined",
        protects_against=["buffer_overflow", "use_after_free", "double_free",
                          "null_deref", "uninit_read"],
    ))

    # ── 7. Debug info (needed for good Valgrind output) ──
    out_dbg, _ = await _run(["readelf", "-S", binary])
    has_debug = ".debug_info" in out_dbg
    mitigations.append(Mitigation(
        name="Debug Info",
        enabled=has_debug,
        detail="DWARF debug symbols present" if has_debug else "Stripped — Valgrind output will lack line numbers",
        compiler_flag="-g",
        protects_against=[],
    ))

    # ── 8. ASLR (system-level check) ──
    aslr_val = "2"
    try:
        aslr_val = Path("/proc/sys/kernel/randomize_va_space").read_text().strip()
    except OSError:
        pass
    aslr_level = {"0": "Disabled", "1": "Partial", "2": "Full"}.get(aslr_val, "Unknown")
    mitigations.append(Mitigation(
        name="ASLR (System)",
        enabled=aslr_val == "2",
        detail=f"randomize_va_space = {aslr_val} ({aslr_level})",
        compiler_flag="echo 2 | sudo tee /proc/sys/kernel/randomize_va_space",
        protects_against=["buffer_overflow", "use_after_free", "null_deref"],
    ))

    return mitigations


# ═══════════════════════════════════════════════════════════════════════════
# Exploitability correlation
# ═══════════════════════════════════════════════════════════════════════════

# Which mitigations prevent which bug type from being exploitable
_MITIGATION_MAP = {
    BugType.BUFFER_OVERFLOW: {
        "Stack Canary": "Stack canary detects overflow before return — prevents RIP control",
        "PIE": "ASLR via PIE randomizes addresses — attacker can't predict jump targets",
        "NX (No-Execute)": "NX prevents executing injected shellcode on stack/heap",
        "FORTIFY_SOURCE": "FORTIFY catches dangerous memcpy/strcpy at compile and runtime",
        "RELRO": "Full RELRO protects GOT from overwrite via buffer overflow",
    },
    BugType.STACK_OVERFLOW: {
        "Stack Canary": "Canary detects stack smashing before control flow hijack",
        "NX (No-Execute)": "Even if stack is smashed, injected code can't execute",
        "PIE": "Return address is randomized — blind ROP is much harder",
    },
    BugType.USE_AFTER_FREE: {
        "PIE": "Heap spray is harder when code addresses are randomized",
        "NX (No-Execute)": "Prevents shellcode execution even if heap is controlled",
        "Sanitizer": "ASan catches UAF immediately with shadow memory tracking",
    },
    BugType.DOUBLE_FREE: {
        "Sanitizer": "ASan detects double-free immediately",
        "PIE": "Heap metadata corruption harder to exploit with randomized addresses",
    },
    BugType.NULL_DEREF: {
        "ASLR (System)": "mmap_min_addr prevents mapping NULL page — NULL deref = crash not exploit",
        "PIE": "Even if NULL page mapped, code addresses are unknown",
    },
    BugType.RACE_CONDITION: {
        "Sanitizer": "TSan (thread sanitizer) detects races — compile with -fsanitize=thread",
    },
    BugType.UNINIT_READ: {
        "Sanitizer": "MSan detects uninitialized reads — compile with -fsanitize=memory",
        "FORTIFY_SOURCE": "Some uninitialized buffer uses caught by fortified libc functions",
    },
}

_ATTACK_SCENARIOS = {
    BugType.BUFFER_OVERFLOW: (
        "Attacker sends crafted input exceeding buffer size. "
        "Overwrites {target} to redirect control flow. "
        "{no_canary}{no_nx}{no_pie}"
    ),
    BugType.USE_AFTER_FREE: (
        "Attacker triggers free, then allocates controlled data in the same slot. "
        "When the dangling pointer is dereferenced, attacker-controlled data "
        "is treated as a valid object. {no_pie}{no_nx}"
    ),
    BugType.DOUBLE_FREE: (
        "Attacker triggers double-free to corrupt heap metadata. "
        "Crafted subsequent allocation returns attacker-controlled address. "
        "Write-what-where primitive allows arbitrary code execution. {no_pie}"
    ),
    BugType.NULL_DEREF: (
        "On older kernels or with mmap_min_addr=0, attacker maps page at NULL "
        "with controlled content. NULL dereference reads attacker data — "
        "can escalate to kernel code execution. {no_aslr}"
    ),
    BugType.RACE_CONDITION: (
        "Attacker exploits timing window between check and use. "
        "TOCTOU allows bypassing access controls or corrupting shared state. "
        "Exploitation may require repeated attempts but is reliable under load."
    ),
    BugType.MEMORY_LEAK: (
        "Not directly exploitable for code execution, but sustained leak "
        "leads to OOM and denial-of-service. At {leak_rate}, service crashes "
        "within predictable timeframe."
    ),
}


def correlate_bugs_with_mitigations(
    errors: list[MemoryError],
    mitigations: list[Mitigation],
) -> list[ExploitCorrelation]:
    """For each detected bug, assess exploitability based on missing mitigations."""
    mit_lookup = {m.name: m for m in mitigations}
    correlations = []

    for err in errors:
        relevant = _MITIGATION_MAP.get(err.bug_type, {})
        if not relevant:
            continue

        missing = []
        would_prevent = []
        for mit_name, explanation in relevant.items():
            mit = mit_lookup.get(mit_name)
            if mit and not mit.enabled:
                missing.append(f"{mit_name}: {explanation}")
                would_prevent.append(mit_name)

        # Exploitability assessment
        if err.bug_type in (BugType.BUFFER_OVERFLOW, BugType.STACK_OVERFLOW):
            if len(missing) >= 3:
                exploitability = "TRIVIAL"
            elif len(missing) >= 2:
                exploitability = "LIKELY"
            elif len(missing) >= 1:
                exploitability = "POSSIBLE"
            else:
                exploitability = "UNLIKELY"
        elif err.bug_type == BugType.USE_AFTER_FREE:
            exploitability = "LIKELY" if len(missing) >= 2 else "POSSIBLE"
        elif err.bug_type == BugType.DOUBLE_FREE:
            exploitability = "LIKELY" if missing else "POSSIBLE"
        elif err.bug_type == BugType.NULL_DEREF:
            exploitability = "POSSIBLE" if missing else "UNLIKELY"
        elif err.bug_type == BugType.RACE_CONDITION:
            exploitability = "POSSIBLE"
        else:
            exploitability = "UNLIKELY"

        # Build attack scenario
        scenario_template = _ATTACK_SCENARIOS.get(err.bug_type, "")
        scenario = scenario_template.format(
            target="return address (stack)" if err.bug_type == BugType.STACK_OVERFLOW else "heap metadata",
            no_canary="Without stack canary, overflow is undetected. " if not mit_lookup.get("Stack Canary", Mitigation("", True, "", "", [])).enabled else "",
            no_nx="Without NX, injected shellcode executes directly. " if not mit_lookup.get("NX (No-Execute)", Mitigation("", True, "", "", [])).enabled else "",
            no_pie="Without PIE/ASLR, addresses are predictable. " if not mit_lookup.get("PIE", Mitigation("", True, "", "", [])).enabled else "",
            no_aslr="Without ASLR, NULL page mapping is straightforward. " if not mit_lookup.get("ASLR (System)", Mitigation("", True, "", "", [])).enabled else "",
            leak_rate=f"{err.bytes_leaked:,} bytes/invocation" if err.bytes_leaked else "unknown rate",
        ).strip()

        loc = ""
        if err.primary_location:
            loc = f"{Path(err.primary_location.file).name}:{err.primary_location.line}"

        correlations.append(ExploitCorrelation(
            bug_id=err.id[:8],
            bug_type=err.bug_type.value,
            bug_location=loc,
            severity=err.severity.value,
            missing_mitigations=missing,
            exploitability=exploitability,
            attack_scenario=scenario,
            would_prevent=would_prevent,
        ))

    # Sort by exploitability
    order = {"TRIVIAL": 0, "LIKELY": 1, "POSSIBLE": 2, "UNLIKELY": 3}
    correlations.sort(key=lambda c: order.get(c.exploitability, 9))
    return correlations


# ═══════════════════════════════════════════════════════════════════════════
# Full hardening report
# ═══════════════════════════════════════════════════════════════════════════

async def generate_hardening_report(
    binary: str,
    errors: list[MemoryError] | None = None,
) -> HardeningReport:
    """Generate a complete binary hardening report with bug correlation."""
    mitigations = await check_mitigations(binary)

    # Score: each mitigation worth points
    weights = {
        "PIE": 15, "Stack Canary": 15, "NX (No-Execute)": 15,
        "RELRO": 10, "FORTIFY_SOURCE": 15, "Sanitizer": 10,
        "Debug Info": 5, "ASLR (System)": 15,
    }
    score = sum(weights.get(m.name, 0) for m in mitigations if m.enabled)
    grade = ("A+" if score >= 95 else "A" if score >= 85 else
             "B" if score >= 70 else "C" if score >= 55 else
             "D" if score >= 40 else "F")

    # Correlate with bugs if provided
    correlations = []
    if errors:
        correlations = correlate_bugs_with_mitigations(errors, mitigations)

    # Critical findings
    critical = []
    trivial = [c for c in correlations if c.exploitability == "TRIVIAL"]
    likely = [c for c in correlations if c.exploitability == "LIKELY"]

    if trivial:
        critical.append(
            f"CRITICAL: {len(trivial)} bug(s) are TRIVIALLY exploitable "
            f"due to missing mitigations"
        )
    if likely:
        critical.append(
            f"WARNING: {len(likely)} bug(s) are LIKELY exploitable"
        )

    for m in mitigations:
        if not m.enabled and m.name in ("PIE", "Stack Canary", "NX (No-Execute)"):
            critical.append(f"{m.name} DISABLED — {m.detail}")

    # Recommended compiler flags (deduplicated)
    rec_flags = []
    seen_flags = set()
    for m in mitigations:
        if not m.enabled and m.compiler_flag and m.name not in ("Debug Info", "ASLR (System)"):
            for flag in m.compiler_flag.split():
                if flag not in seen_flags:
                    seen_flags.add(flag)
                    rec_flags.append(flag)

    # Build recompile command with actual source path from DWARF

    # Discover source file from binary debug info
    source_file = "source.c"
    try:
        from .runner import _discover_sources_from_binary
        found = await _discover_sources_from_binary(binary)
        if found:
            source_file = " ".join(found)
    except Exception:
        pass

    # Check if binary uses pthreads
    out_syms, _ = await _run(["readelf", "-d", binary])
    needs_pthread = "libpthread" in out_syms or "NEEDED" in out_syms and "pthread" in out_syms
    # Also check symbols
    out_s2, _ = await _run(["readelf", "-s", binary])
    if "pthread_create" in out_s2:
        needs_pthread = True
    pthread_flag = " -pthread" if needs_pthread else ""

    binary_name = Path(binary).name
    extra_str = " ".join(rec_flags)
    recompile = f"gcc -g -O2 {extra_str}{pthread_flag} -o /tmp/{binary_name} {source_file}".strip()

    return HardeningReport(
        binary=binary,
        mitigations=mitigations,
        hardening_score=score,
        grade=grade,
        correlations=correlations,
        critical_findings=critical,
        recommended_flags=rec_flags,
        recompile_cmd=recompile,
    )
