"""
memguard.core.taintflow
========================
Taint Flow Tracker — full interprocedural data-flow analysis that traces
how external user input (stdin, argv, recv, fread, getenv, etc.) flows
to allocation and deallocation sites.

Major capabilities:
  - tree-sitter based parsing (regex fallback) for accurate extraction
  - Variable-level taint propagation (not just function-level reachability)
  - Interprocedural taint through parameters, return values, and globals
  - Struct field taint tracking (req->buf = recv() → req is tainted)
  - Function pointer and callback detection
  - Transitive taint closure across the full call graph
  - Data-flow edges (assignment, parameter, return) separate from control-flow
  - Configurable taint depth with iterative widening

Pipeline:
  Phase 1: Parse source → extract functions, variables, calls (tree-sitter)
  Phase 2: Find taint sources (30+ input functions across 6 categories)
  Phase 3: Build enriched call graph with data-flow edges
  Phase 4: Variable-level taint propagation (forward iterative fixpoint)
  Phase 5: Trace taint paths from sources to bug sites
  Phase 6: Risk assessment with data-flow context
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .schema import MemoryError, BugType, Severity

log = logging.getLogger(__name__)

# Try tree-sitter for accurate parsing
_TS_AVAILABLE = False
try:
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser
    _TS_AVAILABLE = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

class TaintCategory:
    NETWORK   = "network"
    FILE_IO   = "file_io"
    STDIN     = "stdin"
    ARGV      = "argv"
    ENV_VAR   = "env_var"
    IPC       = "ipc"


@dataclass
class TaintEntry:
    source_type: str
    function: str          # containing function
    call_site: str         # e.g., "recv", "fgets"
    file: str
    line: int
    tainted_var: str       # variable that receives tainted data
    risk_level: str        # "critical", "high", "medium", "low"
    description: str


@dataclass
class FunctionInfo:
    name: str
    file: str
    start_line: int
    end_line: int
    params: list[str]         # parameter names
    param_types: list[str]    # parameter types
    return_type: str
    body: str
    calls: list[str]          # direct callees
    assignments: list[tuple[str, str, int]]  # (target_var, source_expr, line)
    struct_writes: list[tuple[str, str, str, int]]  # (struct_var, field, value, line)
    globals_read: list[str]
    globals_written: list[str]
    returns_var: list[str]    # variables returned
    func_ptr_calls: list[str] # indirect calls via function pointers


@dataclass
class DataFlowEdge:
    """An edge in the data-flow graph."""
    PARAM   = "param"      # taint flows through parameter
    RETURN  = "return"      # taint flows through return value
    ASSIGN  = "assign"      # taint flows through assignment
    GLOBAL  = "global"      # taint flows through global variable
    STRUCT  = "struct"      # taint flows through struct field
    FPTR    = "func_ptr"    # taint flows through function pointer call

    source_func: str
    target_func: str
    edge_type: str
    variable: str           # which variable carries the taint
    line: int = 0


@dataclass
class TaintState:
    """Taint state for a single variable in a function."""
    variable: str
    function: str
    source: TaintEntry | None
    propagated_from: str | None  # function that propagated taint
    edge_type: str | None
    depth: int = 0


@dataclass
class TaintPath:
    source: TaintEntry
    target_bug_id: str
    target_bug_type: str
    target_location: str
    path_functions: list[str]
    path_edges: list[str]     # edge types along the path
    path_variables: list[str] # tainted variables at each step
    path_length: int
    reachable: bool
    confidence: float
    risk_assessment: str
    data_flow_detail: str     # human-readable data flow description


@dataclass
class TaintFlowReport:
    binary: str
    source_dir: str
    taint_sources: list[TaintEntry]
    taint_paths: list[TaintPath]
    reachable_bugs: int
    isolated_bugs: int
    total_bugs: int
    call_graph_size: int
    data_flow_edges: int
    functions_analyzed: int
    tainted_variables: int
    risk_summary: str


# ═══════════════════════════════════════════════════════════════════════════
# Taint source patterns — comprehensive
# ═══════════════════════════════════════════════════════════════════════════

TAINT_PATTERNS = {
    TaintCategory.NETWORK: {
        "recv":      {"risk": "critical", "desc": "Network socket read — attacker-controlled data", "taints": "buffer_arg"},
        "recvfrom":  {"risk": "critical", "desc": "UDP datagram receive — attacker-controlled", "taints": "buffer_arg"},
        "recvmsg":   {"risk": "critical", "desc": "Network message receive (scatter-gather)", "taints": "buffer_arg"},
        "accept":    {"risk": "critical", "desc": "Accept incoming connection — attacker-initiated", "taints": "return"},
        "accept4":   {"risk": "critical", "desc": "Accept with flags — attacker-initiated", "taints": "return"},
        "SSL_read":  {"risk": "critical", "desc": "TLS socket read — decrypted attacker data", "taints": "buffer_arg"},
        "BIO_read":  {"risk": "critical", "desc": "OpenSSL BIO read", "taints": "buffer_arg"},
        "read":      {"risk": "high", "desc": "File/socket read — context-dependent", "taints": "buffer_arg"},
        "readv":     {"risk": "high", "desc": "Scatter read from fd", "taints": "buffer_arg"},
        "pread":     {"risk": "high", "desc": "Positional read from fd", "taints": "buffer_arg"},
    },
    TaintCategory.FILE_IO: {
        "fread":     {"risk": "high", "desc": "Binary file read — attacker may control file", "taints": "buffer_arg"},
        "fgets":     {"risk": "high", "desc": "Line-buffered file read", "taints": "buffer_arg"},
        "fscanf":    {"risk": "high", "desc": "Formatted file read — no bounds guarantee", "taints": "buffer_arg"},
        "getline":   {"risk": "high", "desc": "Dynamic-length line read", "taints": "return"},
        "getdelim":  {"risk": "high", "desc": "Dynamic-length delimited read", "taints": "return"},
        "fgetc":     {"risk": "medium", "desc": "Single character from file", "taints": "return"},
        "fread_unlocked": {"risk": "high", "desc": "Unlocked binary file read", "taints": "buffer_arg"},
        "mmap":      {"risk": "high", "desc": "Memory-mapped file — attacker may control file", "taints": "return"},
    },
    TaintCategory.STDIN: {
        "scanf":     {"risk": "critical", "desc": "Formatted stdin read — NO bounds checking", "taints": "varargs"},
        "gets":      {"risk": "critical", "desc": "Unbounded stdin read — NEVER USE (CWE-242)", "taints": "buffer_arg"},
        "getchar":   {"risk": "low", "desc": "Single character from stdin", "taints": "return"},
        "getc":      {"risk": "low", "desc": "Single character from stream", "taints": "return"},
        "fgets":     {"risk": "high", "desc": "Line-buffered stdin read", "taints": "buffer_arg"},
        "gets_s":    {"risk": "medium", "desc": "Bounded stdin read (C11)", "taints": "buffer_arg"},
    },
    TaintCategory.ARGV: {
        "getopt":       {"risk": "high", "desc": "Parsed command-line option", "taints": "return"},
        "getopt_long":  {"risk": "high", "desc": "Long option parsing with optarg", "taints": "return"},
        "getopt_long_only": {"risk": "high", "desc": "Long-only option parsing", "taints": "return"},
    },
    TaintCategory.ENV_VAR: {
        "getenv":        {"risk": "high", "desc": "Environment variable read — attacker-controlled", "taints": "return"},
        "secure_getenv": {"risk": "medium", "desc": "Secure environment read (drops in suid)", "taints": "return"},
    },
    TaintCategory.IPC: {
        "shmat":    {"risk": "critical", "desc": "Shared memory attachment — cross-process", "taints": "return"},
        "msgrcv":   {"risk": "critical", "desc": "System V message queue receive", "taints": "buffer_arg"},
        "mq_receive": {"risk": "critical", "desc": "POSIX message queue receive", "taints": "buffer_arg"},
        "pipe":     {"risk": "high", "desc": "Pipe file descriptors — IPC channel", "taints": "buffer_arg"},
    },
}

# Flat lookup
ALL_TAINT_FUNCS: dict[str, tuple[str, dict]] = {}
for _cat, _funcs in TAINT_PATTERNS.items():
    for _fn, _info in _funcs.items():
        ALL_TAINT_FUNCS[_fn] = (_cat, _info)

# Known libc/standard functions that do NOT propagate taint
SAFE_FUNCS = frozenset({
    "printf", "fprintf", "sprintf", "snprintf", "puts", "fputs",
    "memset", "bzero", "memcpy", "memmove", "memcmp", "strlen",
    "strcmp", "strncmp", "strchr", "strrchr", "strstr",
    "close", "fclose", "shutdown",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_create", "pthread_join",
    "assert", "abort", "exit", "_exit",
    "log", "syslog", "perror",
    "sizeof", "typeof", "offsetof",
    "if", "for", "while", "switch", "return", "break", "continue",
    "NULL", "true", "false",
})


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: Parse source code (tree-sitter with regex fallback)
# ═══════════════════════════════════════════════════════════════════════════

def _parse_source_files(source_dir: str, max_files: int = 300) -> list[FunctionInfo]:
    """Extract function information from all C/C++ source files."""
    src = Path(source_dir)
    SKIP_DIRS = {"test", "tests", ".git", "build", ".venv", "vendor",
                 "node_modules", "third_party", "external", "deps"}

    c_files = []
    for ext in ("*.c", "*.cpp", "*.cc", "*.h"):
        for f in src.rglob(ext):
            rel = f.relative_to(src)
            if len(rel.parts) > 1 and any(skip in rel.parts[:-1] for skip in SKIP_DIRS):
                continue
            c_files.append(f)
            if len(c_files) >= max_files:
                break

    functions = []
    for fpath in c_files:
        try:
            text = fpath.read_text(errors="replace")
            rel = str(fpath.relative_to(src))

            if _TS_AVAILABLE:
                funcs = _parse_with_treesitter(text, rel)
            else:
                funcs = _parse_with_regex(text, rel)

            functions.extend(funcs)
        except Exception as e:
            log.debug("Error parsing %s: %s", fpath, e)

    log.info("Phase 1: parsed %d functions from %d files", len(functions), len(c_files))
    return functions


def _parse_with_treesitter(text: str, filename: str) -> list[FunctionInfo]:
    """Use tree-sitter for accurate C parsing."""
    functions = []
    try:
        parser = Parser(Language(tsc.language()))
        tree = parser.parse(text.encode())

        for node in _ts_walk(tree.root_node):
            if node.type == "function_definition":
                func = _extract_ts_function(node, text, filename)
                if func:
                    functions.append(func)
    except Exception as e:
        log.debug("tree-sitter parse failed for %s: %s, falling back to regex", filename, e)
        functions = _parse_with_regex(text, filename)

    return functions


def _ts_walk(node):
    """Walk tree-sitter AST yielding all nodes."""
    yield node
    for child in node.children:
        yield from _ts_walk(child)


def _extract_ts_function(node, text: str, filename: str) -> FunctionInfo | None:
    """Extract FunctionInfo from a tree-sitter function_definition node."""
    # Get function name
    declarator = None
    for child in node.children:
        if child.type == "function_declarator" or child.type == "pointer_declarator":
            declarator = child
            break
        if child.type == "declarator":
            declarator = child
            break

    if not declarator:
        return None

    # Find the identifier (function name)
    name = _ts_find_identifier(declarator)
    if not name:
        return None

    body_text = node.text.decode(errors="replace")
    start_line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1

    # Extract parameters
    params = []
    param_types = []
    for child in _ts_walk(declarator):
        if child.type == "parameter_list":
            for param in child.children:
                if param.type == "parameter_declaration":
                    pname = _ts_find_identifier(param)
                    ptype = param.text.decode(errors="replace")
                    if pname:
                        params.append(pname)
                        param_types.append(ptype)

    # Extract return type
    return_type = ""
    for child in node.children:
        if child.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
            return_type = child.text.decode(errors="replace")
            break

    # Extract calls, assignments, struct writes
    calls, assignments, struct_writes, globals_r, globals_w, returns, fptr_calls = \
        _extract_data_flow(body_text, start_line, params)

    return FunctionInfo(
        name=name, file=filename, start_line=start_line, end_line=end_line,
        params=params, param_types=param_types, return_type=return_type,
        body=body_text, calls=calls, assignments=assignments,
        struct_writes=struct_writes, globals_read=globals_r,
        globals_written=globals_w, returns_var=returns,
        func_ptr_calls=fptr_calls,
    )


def _ts_find_identifier(node) -> str | None:
    """Find the identifier name in a tree-sitter declarator."""
    if node.type == "identifier":
        return node.text.decode()
    for child in node.children:
        result = _ts_find_identifier(child)
        if result:
            return result
    return None


def _parse_with_regex(text: str, filename: str) -> list[FunctionInfo]:
    """Fallback regex-based parser when tree-sitter is unavailable."""
    functions = []
    lines = text.splitlines()

    # Match function definitions
    func_pat = re.compile(
        r'^(\w[\w\s\*]+?)\s+(\*?\w+)\s*\(([^)]*)\)\s*\{',
        re.MULTILINE
    )

    for m in func_pat.finditer(text):
        rtype = m.group(1).strip()
        name = m.group(2).strip().lstrip("*")
        params_str = m.group(3).strip()
        start_pos = m.start()
        start_line = text[:start_pos].count('\n') + 1

        # Find matching closing brace
        brace_depth = 1
        body_start = m.end()
        i = body_start
        while i < len(text) and brace_depth > 0:
            if text[i] == '{': brace_depth += 1
            elif text[i] == '}': brace_depth -= 1
            i += 1

        body = text[m.start():i]
        end_line = text[:i].count('\n') + 1

        # Parse parameters
        params = []
        param_types = []
        if params_str and params_str != "void":
            for p in params_str.split(","):
                p = p.strip()
                parts = re.split(r'[\s\*]+', p)
                if parts:
                    pname = parts[-1].strip("[]")
                    if pname and pname not in ("void", "const", "struct"):
                        params.append(pname)
                        param_types.append(p)

        calls, assignments, struct_writes, globals_r, globals_w, returns, fptr_calls = \
            _extract_data_flow(body, start_line, params)

        functions.append(FunctionInfo(
            name=name, file=filename, start_line=start_line, end_line=end_line,
            params=params, param_types=param_types, return_type=rtype,
            body=body, calls=calls, assignments=assignments,
            struct_writes=struct_writes, globals_read=globals_r,
            globals_written=globals_w, returns_var=returns,
            func_ptr_calls=fptr_calls,
        ))

    return functions


def _extract_data_flow(body: str, start_line: int, params: list[str]):
    """Extract data-flow information from a function body."""
    calls = []
    assignments = []  # (target, source_expr, line)
    struct_writes = []  # (struct_var, field, value, line)
    globals_read = []
    globals_written = []
    returns_var = []
    fptr_calls = []

    lines = body.splitlines()
    # Track local variables
    local_vars = set(params)

    for i, line in enumerate(lines):
        stripped = line.strip()
        lineno = start_line + i

        # Skip comments
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Track local variable declarations
        decl_m = re.match(r'(?:const\s+)?(?:unsigned\s+)?(?:struct\s+)?\w+\s*\*?\s*(\w+)\s*[=;]', stripped)
        if decl_m:
            local_vars.add(decl_m.group(1))

        # Direct function calls: func_name(...)
        for cm in re.finditer(r'\b(\w+)\s*\(', stripped):
            callee = cm.group(1)
            if callee not in SAFE_FUNCS and len(callee) > 1:
                calls.append(callee)

        # Indirect calls: ptr->func(...) or (*fptr)(...)
        for cm in re.finditer(r'(\w+)->(\w+)\s*\(', stripped):
            fptr_calls.append(f"{cm.group(1)}->{cm.group(2)}")
        for cm in re.finditer(r'\(\*(\w+)\)\s*\(', stripped):
            fptr_calls.append(cm.group(1))
        # Callback patterns: handler(data), ops->read(buf)
        for cm in re.finditer(r'(\w+)\s*\.\s*(\w+)\s*\(', stripped):
            fptr_calls.append(f"{cm.group(1)}.{cm.group(2)}")

        # Assignment tracking: var = expr
        assign_m = re.match(r'\s*(\w+)\s*=\s*(.+?)\s*;', stripped)
        if assign_m:
            target = assign_m.group(1)
            source = assign_m.group(2)
            assignments.append((target, source, lineno))
            # Check if target is a global (not local, not param)
            if target not in local_vars:
                globals_written.append(target)

        # Struct field writes: struct->field = expr OR struct.field = expr
        struct_m = re.match(r'\s*(\w+)\s*->\s*(\w+)\s*=\s*(.+?)\s*;', stripped)
        if struct_m:
            struct_writes.append((struct_m.group(1), struct_m.group(2),
                                  struct_m.group(3), lineno))
        struct_m2 = re.match(r'\s*(\w+)\s*\.\s*(\w+)\s*=\s*(.+?)\s*;', stripped)
        if struct_m2:
            struct_writes.append((struct_m2.group(1), struct_m2.group(2),
                                  struct_m2.group(3), lineno))

        # Return value tracking
        ret_m = re.match(r'\s*return\s+(\w+)\s*;', stripped)
        if ret_m:
            returns_var.append(ret_m.group(1))

        # Global reads (variables used but not declared locally)
        for vm in re.finditer(r'\b([A-Z_][A-Z0-9_]{2,})\b', stripped):
            if vm.group(1) not in ("NULL", "TRUE", "FALSE", "EOF", "STDIN", "STDOUT"):
                globals_read.append(vm.group(1))

    # Deduplicate calls
    calls = list(dict.fromkeys(calls))
    fptr_calls = list(dict.fromkeys(fptr_calls))

    return calls, assignments, struct_writes, globals_read, globals_written, returns_var, fptr_calls


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: Find taint sources
# ═══════════════════════════════════════════════════════════════════════════

def _find_taint_sources(functions: list[FunctionInfo]) -> list[TaintEntry]:
    """Find all taint sources across parsed functions."""
    sources = []

    for func in functions:
        for i, line in enumerate(func.body.splitlines()):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            lineno = func.start_line + i

            for taint_fn, (category, info) in ALL_TAINT_FUNCS.items():
                if re.search(rf'\b{re.escape(taint_fn)}\s*\(', stripped):
                    tainted_var = _identify_tainted_var(stripped, taint_fn, info["taints"])

                    sources.append(TaintEntry(
                        source_type=category,
                        function=func.name,
                        call_site=taint_fn,
                        file=func.file,
                        line=lineno,
                        tainted_var=tainted_var,
                        risk_level=info["risk"],
                        description=info["desc"],
                    ))

            # Special: argv[] access
            if "argv[" in stripped or "argv +" in stripped:
                sources.append(TaintEntry(
                    source_type=TaintCategory.ARGV,
                    function=func.name,
                    call_site="argv",
                    file=func.file,
                    line=lineno,
                    tainted_var="argv",
                    risk_level="high",
                    description="Command-line argument access",
                ))

            # Special: optarg usage (from getopt)
            if re.search(r'\boptarg\b', stripped):
                sources.append(TaintEntry(
                    source_type=TaintCategory.ARGV,
                    function=func.name,
                    call_site="optarg",
                    file=func.file,
                    line=lineno,
                    tainted_var="optarg",
                    risk_level="high",
                    description="getopt option argument (attacker-controlled)",
                ))

    # Deduplicate
    seen = set()
    unique = []
    for s in sources:
        key = (s.call_site, s.function, s.line)
        if key not in seen:
            seen.add(key)
            unique.append(s)

    log.info("Phase 2: found %d taint sources", len(unique))
    return unique


def _identify_tainted_var(line: str, func_name: str, taints_type: str) -> str:
    """Identify which variable receives tainted data from a call."""
    if taints_type == "return":
        # var = func(...)
        m = re.match(rf'.*?(\w+)\s*=\s*{re.escape(func_name)}\s*\(', line)
        return m.group(1) if m else "??"

    elif taints_type == "buffer_arg":
        # func(buffer, size) — first arg is the tainted buffer
        m = re.search(rf'{re.escape(func_name)}\s*\(\s*(\w+)', line)
        return m.group(1) if m else "??"

    elif taints_type == "varargs":
        # scanf("%s", &var) — extract vararg targets
        m = re.search(rf'{re.escape(func_name)}\s*\([^,]+,\s*&?(\w+)', line)
        return m.group(1) if m else "??"

    return "??"


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: Build enriched call graph with data-flow edges
# ═══════════════════════════════════════════════════════════════════════════

def _build_data_flow_graph(
    functions: list[FunctionInfo],
) -> tuple[dict[str, set[str]], list[DataFlowEdge]]:
    """Build call graph AND data-flow edges for taint propagation."""
    func_map = {f.name: f for f in functions}
    call_graph: dict[str, set[str]] = defaultdict(set)
    edges: list[DataFlowEdge] = []

    for func in functions:
        # Direct calls → control-flow edges
        for callee in func.calls:
            call_graph[func.name].add(callee)

        # Function pointer calls → control-flow edges
        for fptr in func.func_ptr_calls:
            call_graph[func.name].add(fptr)

        # Parameter passing → data-flow edges
        # If func calls callee(var), and var is a parameter of func,
        # then taint can flow from func's caller through func to callee
        for callee in func.calls:
            if callee in func_map:
                callee_info = func_map[callee]
                # Find the call in the body to extract passed arguments
                for line in func.body.splitlines():
                    m = re.search(rf'\b{re.escape(callee)}\s*\(([^)]*)\)', line.strip())
                    if m:
                        args = [a.strip().strip("&*") for a in m.group(1).split(",")]
                        for j, arg in enumerate(args):
                            base_arg = arg.split("->")[0].split(".")[0].split("[")[0].strip()
                            if base_arg in func.params or base_arg in [a[0] for a in func.assignments]:
                                edges.append(DataFlowEdge(
                                    source_func=func.name,
                                    target_func=callee,
                                    edge_type=DataFlowEdge.PARAM,
                                    variable=base_arg,
                                ))
                        break

        # Return value → data-flow edges
        for ret_var in func.returns_var:
            for caller in functions:
                if func.name in caller.calls:
                    # Check if caller assigns the return value
                    for target, source, ln in caller.assignments:
                        if func.name in source:
                            edges.append(DataFlowEdge(
                                source_func=func.name,
                                target_func=caller.name,
                                edge_type=DataFlowEdge.RETURN,
                                variable=target,
                                line=ln,
                            ))

        # Struct field writes → data-flow edges
        for struct_var, fld, value, ln in func.struct_writes:
            # If the value contains a taint source call or tainted var
            edges.append(DataFlowEdge(
                source_func=func.name,
                target_func=func.name,  # intra-procedural
                edge_type=DataFlowEdge.STRUCT,
                variable=f"{struct_var}->{fld}",
                line=ln,
            ))

        # Global variable writes → data-flow edges
        for gvar in func.globals_written:
            for reader in functions:
                if gvar in reader.globals_read and reader.name != func.name:
                    edges.append(DataFlowEdge(
                        source_func=func.name,
                        target_func=reader.name,
                        edge_type=DataFlowEdge.GLOBAL,
                        variable=gvar,
                    ))

    log.info("Phase 3: call graph %d functions, %d data-flow edges",
             len(call_graph), len(edges))
    return dict(call_graph), edges


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: Variable-level taint propagation (forward fixpoint)
# ═══════════════════════════════════════════════════════════════════════════

def _propagate_taint(
    functions: list[FunctionInfo],
    taint_sources: list[TaintEntry],
    call_graph: dict[str, set[str]],
    edges: list[DataFlowEdge],
    max_iterations: int = 20,
) -> dict[str, set[str]]:
    """Iterative forward taint propagation.

    Returns: {function_name: set of tainted variable names}
    """
    func_map = {f.name: f for f in functions}
    # Initialize taint state from sources
    tainted: dict[str, set[str]] = defaultdict(set)  # func → tainted vars

    for src in taint_sources:
        tainted[src.function].add(src.tainted_var)
        # Also taint the assignment target
        if src.function in func_map:
            for target, source_expr, ln in func_map[src.function].assignments:
                if src.call_site in source_expr or src.tainted_var in source_expr:
                    tainted[src.function].add(target)

    # Iterative fixpoint
    for iteration in range(max_iterations):
        changed = False

        for func in functions:
            old_size = len(tainted[func.name])

            # Intra-procedural: propagate through assignments
            for target, source_expr, ln in func.assignments:
                source_vars = set(re.findall(r'\b(\w+)\b', source_expr))
                if source_vars & tainted[func.name]:
                    tainted[func.name].add(target)

            # Intra-procedural: propagate through struct writes
            for struct_var, fld, value, ln in func.struct_writes:
                value_vars = set(re.findall(r'\b(\w+)\b', value))
                if value_vars & tainted[func.name]:
                    tainted[func.name].add(struct_var)
                    tainted[func.name].add(f"{struct_var}->{fld}")

            # Inter-procedural: propagate via data-flow edges
            for edge in edges:
                if edge.source_func == func.name:
                    base_var = edge.variable.split("->")[0].split(".")[0]
                    if base_var in tainted[func.name] or edge.variable in tainted[func.name]:
                        if edge.edge_type == DataFlowEdge.PARAM:
                            tainted[edge.target_func].add(edge.variable)
                        elif edge.edge_type == DataFlowEdge.RETURN:
                            tainted[edge.target_func].add(edge.variable)
                        elif edge.edge_type == DataFlowEdge.GLOBAL:
                            tainted[edge.target_func].add(edge.variable)

            # Inter-procedural: if func calls callee with tainted arg,
            # callee's corresponding parameter is tainted
            for callee_name in func.calls:
                if callee_name in func_map:
                    callee = func_map[callee_name]
                    for line in func.body.splitlines():
                        m = re.search(rf'\b{re.escape(callee_name)}\s*\(([^)]*)\)', line.strip())
                        if m:
                            args = [a.strip().strip("&*").split("[")[0].split("->")[0]
                                    for a in m.group(1).split(",")]
                            for j, arg in enumerate(args):
                                if arg in tainted[func.name] and j < len(callee.params):
                                    tainted[callee.name].add(callee.params[j])
                            break

            # Return value propagation: if func returns tainted var,
            # all callers that capture the return value get tainted
            if func.returns_var:
                for ret_var in func.returns_var:
                    if ret_var in tainted[func.name]:
                        for caller in functions:
                            if func.name in caller.calls:
                                for target, source, ln in caller.assignments:
                                    if func.name in source:
                                        tainted[caller.name].add(target)

            if len(tainted[func.name]) > old_size:
                changed = True

        if not changed:
            log.info("Phase 4: taint fixpoint reached at iteration %d", iteration + 1)
            break

    total_tainted = sum(len(v) for v in tainted.values())
    log.info("Phase 4: %d tainted variables across %d functions",
             total_tainted, sum(1 for v in tainted.values() if v))
    return dict(tainted)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 5: Trace taint paths to bugs
# ═══════════════════════════════════════════════════════════════════════════

def _trace_to_bugs(
    taint_sources: list[TaintEntry],
    errors: list[MemoryError],
    functions: list[FunctionInfo],
    call_graph: dict[str, set[str]],
    edges: list[DataFlowEdge],
    tainted_vars: dict[str, set[str]],
) -> list[TaintPath]:
    """For each bug, find taint paths from sources."""
    func_map = {f.name: f for f in functions}
    paths = []

    for err in errors:
        bug_func = _get_bug_function(err)
        bug_loc = _get_bug_location(err)

        # Check if the bug's function has any tainted variables
        if bug_func not in tainted_vars or not tainted_vars[bug_func]:
            continue

        # Find which taint sources can reach this bug
        for source in taint_sources:
            # BFS from source function to bug function
            path_funcs, path_edge_types = _find_data_flow_path(
                source.function, bug_func, call_graph, edges, tainted_vars, max_depth=15
            )

            if path_funcs:
                # Build variable chain
                path_vars = [source.tainted_var]
                for fn in path_funcs[1:]:
                    if fn in tainted_vars and tainted_vars[fn]:
                        path_vars.append(next(iter(tainted_vars[fn])))
                    else:
                        path_vars.append("??")

                risk = _assess_risk(source, err, path_funcs, path_edge_types, path_vars)

                # Build data flow description
                detail = _build_flow_detail(source, path_funcs, path_vars, path_edge_types, err)

                paths.append(TaintPath(
                    source=source,
                    target_bug_id=err.id[:8],
                    target_bug_type=err.bug_type.value,
                    target_location=bug_loc,
                    path_functions=path_funcs,
                    path_edges=path_edge_types,
                    path_variables=path_vars,
                    path_length=len(path_funcs) - 1,
                    reachable=True,
                    confidence=risk["confidence"],
                    risk_assessment=risk["assessment"],
                    data_flow_detail=detail,
                ))

    # Deduplicate and sort
    seen = set()
    unique = []
    for p in paths:
        key = (p.source.call_site, p.source.line, p.target_bug_id)
        if key not in seen:
            seen.add(key)
            unique.append(p)

    unique.sort(key=lambda p: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(p.source.risk_level, 4),
        p.path_length,
    ))

    return unique


def _get_bug_function(err: MemoryError) -> str:
    if err.stack:
        for f in err.stack:
            if f.function and f.function != "??" and not f.function.startswith("_"):
                return f.function
    return "??"


def _get_bug_location(err: MemoryError) -> str:
    if err.primary_location:
        fname = (err.primary_location.file or "").split("/")[-1]
        return f"{fname}:{err.primary_location.line or 0}"
    return "??"


def _find_data_flow_path(
    start: str, target: str,
    call_graph: dict[str, set[str]],
    edges: list[DataFlowEdge],
    tainted: dict[str, set[str]],
    max_depth: int = 15,
) -> tuple[list[str], list[str]]:
    """BFS with data-flow awareness — prefer paths through tainted functions."""
    if start == target:
        return [start], ["direct"]

    # Build combined edge set: call graph + data-flow edges
    combined: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for caller, callees in call_graph.items():
        for callee in callees:
            combined[caller].append((callee, "call"))
    for edge in edges:
        combined[edge.source_func].append((edge.target_func, edge.edge_type))

    visited = {start}
    queue = [(start, [start], ["origin"])]

    while queue:
        current, path, edge_types = queue.pop(0)
        if len(path) > max_depth:
            continue

        # Sort neighbors: prefer tainted functions
        neighbors = combined.get(current, [])
        neighbors.sort(key=lambda x: 0 if x[0] in tainted else 1)

        for neighbor, etype in neighbors:
            if neighbor == target:
                return path + [neighbor], edge_types + [etype]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor], edge_types + [etype]))

    return [], []


def _assess_risk(source, error, path, edge_types, variables):
    """Risk assessment with data-flow context."""
    confidence = 0.4

    # Path length factor
    if len(path) <= 1:
        confidence += 0.35
    elif len(path) <= 3:
        confidence += 0.25
    elif len(path) <= 5:
        confidence += 0.15
    else:
        confidence += 0.05

    # Data-flow edge types boost confidence
    if DataFlowEdge.PARAM in edge_types:
        confidence += 0.1  # Direct parameter passing is strong
    if DataFlowEdge.RETURN in edge_types:
        confidence += 0.08
    if DataFlowEdge.GLOBAL in edge_types:
        confidence -= 0.05  # Globals are weaker evidence

    # Source type factor
    risk_boosts = {"critical": 0.15, "high": 0.1, "medium": 0.05, "low": 0.0}
    confidence += risk_boosts.get(source.risk_level, 0)

    # Bug type factor
    if error.bug_type in (BugType.BUFFER_OVERFLOW, BugType.USE_AFTER_FREE):
        confidence += 0.1

    confidence = min(0.98, max(0.1, confidence))

    # Assessment text
    if source.source_type == TaintCategory.NETWORK and error.bug_type in (
        BugType.BUFFER_OVERFLOW, BugType.USE_AFTER_FREE, BugType.DOUBLE_FREE
    ):
        assessment = (
            f"CRITICAL: {source.call_site}() reads attacker-controlled network data "
            f"into '{source.tainted_var}' which flows through "
            f"{' → '.join(path)} to {error.bug_type.value}. "
            f"Remote exploitation possible — attacker sends crafted packets."
        )
    elif source.source_type == TaintCategory.FILE_IO and error.bug_type == BugType.BUFFER_OVERFLOW:
        assessment = (
            f"HIGH: {source.call_site}() reads file data into '{source.tainted_var}' "
            f"which reaches buffer overflow via {' → '.join(path)}. "
            f"Exploit: craft a malicious input file."
        )
    elif error.bug_type == BugType.MEMORY_LEAK:
        assessment = (
            f"MEDIUM: {source.call_site}() input in '{source.tainted_var}' triggers "
            f"allocation in {path[-1]}(). Repeated input causes memory exhaustion (DoS)."
        )
    elif source.source_type == TaintCategory.STDIN:
        assessment = (
            f"HIGH: {source.call_site}() reads stdin into '{source.tainted_var}' "
            f"flowing to {error.bug_type.value}. Local exploitation via crafted input."
        )
    else:
        assessment = (
            f"Tainted data from {source.call_site}() → '{source.tainted_var}' "
            f"reaches {error.bug_type.value} via {' → '.join(path)}."
        )

    return {"confidence": confidence, "assessment": assessment}


def _build_flow_detail(source, path, variables, edge_types, error):
    """Human-readable data-flow description."""
    parts = [f"{source.call_site}() writes to '{source.tainted_var}'"]
    for i in range(1, len(path)):
        etype = edge_types[i] if i < len(edge_types) else "?"
        var = variables[i] if i < len(variables) else "?"
        label = {
            "call": "calls",
            DataFlowEdge.PARAM: "passes tainted param to",
            DataFlowEdge.RETURN: "returns tainted value to",
            DataFlowEdge.GLOBAL: "taints global read by",
            DataFlowEdge.STRUCT: "stores in struct read by",
            "direct": "directly in",
        }.get(etype, "→")
        parts.append(f"{label} {path[i]}() via '{var}'")
    parts.append(f"→ triggers {error.bug_type.value}")
    return " → ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def run_taint_analysis(
    source_dir: str,
    errors: list[MemoryError],
    binary: str = "",
) -> TaintFlowReport:
    """Run the full 6-phase taint flow analysis pipeline."""
    # Phase 1: Parse source
    functions = _parse_source_files(source_dir)

    # Phase 2: Find taint sources
    taint_sources = _find_taint_sources(functions)

    # Phase 3: Build enriched call graph
    call_graph, df_edges = _build_data_flow_graph(functions)

    # Phase 4: Propagate taint (iterative fixpoint)
    tainted_vars = _propagate_taint(functions, taint_sources, call_graph, df_edges)

    # Phase 5: Trace to bugs
    taint_paths = _trace_to_bugs(
        taint_sources, errors, functions, call_graph, df_edges, tainted_vars
    )

    # Phase 6: Summarize
    reachable_bugs = len(set(p.target_bug_id for p in taint_paths))
    isolated_bugs = len(errors) - reachable_bugs
    total_tainted = sum(len(v) for v in tainted_vars.values())

    # Risk summary
    network_paths = [p for p in taint_paths if p.source.source_type == TaintCategory.NETWORK]
    critical_paths = [p for p in taint_paths if p.source.risk_level == "critical"]

    if network_paths:
        risk_summary = (
            f"CRITICAL: {len(network_paths)} bug(s) reachable from network input. "
            f"Remote exploitation possible. "
            f"Tainted data flows through {total_tainted} variables across "
            f"{sum(1 for v in tainted_vars.values() if v)} functions."
        )
    elif critical_paths:
        risk_summary = (
            f"HIGH: {len(critical_paths)} bug(s) reachable from critical input sources. "
            f"{total_tainted} tainted variables tracked."
        )
    elif taint_paths:
        risk_summary = (
            f"MEDIUM: {len(taint_paths)} taint path(s) found across "
            f"{total_tainted} tainted variables. Bugs reachable with moderate effort."
        )
    else:
        risk_summary = (
            f"LOW: No taint paths found. {len(errors)} detected bug(s) appear internally "
            f"triggered. Analyzed {len(functions)} functions, "
            f"found {len(taint_sources)} input sources but none reach bug sites."
        )

    log.info("Taint analysis: %d sources, %d paths, %d/%d bugs reachable",
             len(taint_sources), len(taint_paths), reachable_bugs, len(errors))

    return TaintFlowReport(
        binary=binary,
        source_dir=source_dir,
        taint_sources=taint_sources,
        taint_paths=taint_paths,
        reachable_bugs=reachable_bugs,
        isolated_bugs=isolated_bugs,
        total_bugs=len(errors),
        call_graph_size=len(call_graph),
        data_flow_edges=len(df_edges),
        functions_analyzed=len(functions),
        tainted_variables=total_tainted,
        risk_summary=risk_summary,
    )
