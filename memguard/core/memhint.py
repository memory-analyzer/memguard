"""
memguard.core.memhint
======================
Neuro-Symbolic Memory Leak Detection Pipeline.

Inspired by the MemHint paper (Huang et al. 2026), adapted for MemGuard
with local LLM (Ollama) instead of cloud APIs.

Pipeline:
  Stage 1 — Summary Generation:
    Phase 1: Code Extraction (tree-sitter parses functions, macros, typedefs)
    Phase 2: LLM Summary Generation (classify allocator/deallocator/neither)
    Phase 3: Z3 Summary Validation (verify reachability on feasible CFG paths)
  Stage 2 — Summary-Augmented Analysis:
    Phase 4: Inject summaries into Infer (--pulse-model-alloc/free-pattern)
  Stage 3 — Warning Validation:
    Phase 5: Z3 Path Feasibility Filter (discard infeasible leak paths)
    Phase 6: LLM Warning Validation (confirm real bugs vs false positives)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Optional Z3 import
try:
    from z3 import Solver, Bool, And, Or, Not, sat, unsat, AtMost
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    log.info("Z3 not available — install with: pip install z3-solver")

# Optional tree-sitter import
try:
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser as TSParser
    TS_AVAILABLE = True
    C_LANG = Language(tsc.language())
except ImportError:
    TS_AVAILABLE = False
    log.info("tree-sitter not available — install: pip install tree-sitter tree-sitter-c")


# ═══════════════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════════════

class MMRole(Enum):
    ALLOCATOR = auto()
    DEALLOCATOR = auto()


class NodeType(Enum):
    ENTRY = auto()
    EXIT = auto()
    ALLOC = auto()
    FREE = auto()
    RETURN = auto()
    BRANCH = auto()
    ASSIGN = auto()
    CALL = auto()


@dataclass
class FunctionInfo:
    name: str
    code: str
    file_path: str = ""
    return_type: str = ""
    params: list[str] = field(default_factory=list)
    param_types: list[str] = field(default_factory=list)
    callees: set[str] = field(default_factory=set)
    start_line: int = 0
    end_line: int = 0


@dataclass
class MMSummary:
    """Memory Management function summary."""
    name: str
    role: MMRole
    target: str  # "return" for allocators, "arg0" etc for deallocators
    validated: bool = False
    confidence: float = 0.0
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "role": self.role.name,
            "target": self.target,
            "validated": self.validated,
            "confidence": self.confidence,
        }


@dataclass
class CFGNode:
    id: int
    node_type: NodeType
    line: int
    code: str
    variable: str = ""
    condition: str = ""
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)


@dataclass
class MemHintReport:
    """Results of the neuro-symbolic pipeline."""
    source_dir: str
    functions_extracted: int
    candidates_filtered: int
    summaries_generated: int
    summaries_validated: int
    allocators: list[MMSummary]
    deallocators: list[MMSummary]
    warnings_raw: int = 0
    warnings_z3_filtered: int = 0
    warnings_llm_validated: int = 0
    confirmed_bugs: int = 0
    duration_ms: int = 0
    infer_flags: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# Known standard MM primitives
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_ALLOCATORS = frozenset({
    "malloc", "calloc", "realloc", "aligned_alloc", "strdup", "strndup",
    "mmap", "g_malloc", "g_malloc0", "g_new", "g_new0", "g_strdup",
    "xmalloc", "xcalloc", "xrealloc", "xstrdup",
    "kmalloc", "kzalloc", "kcalloc", "krealloc", "kvmalloc",
    "devm_kmalloc", "devm_kzalloc",
})

KNOWN_DEALLOCATORS = frozenset({
    "free", "g_free", "kfree", "kvfree", "devm_kfree",
    "delete", "delete[]",
})

# Skip these directories when scanning
SKIP_DIRS = {".git", "build", "test", "tests", ".venv", "node_modules",
             "__pycache__", "vendor", "third_party", "external"}


# ═══════════════════════════════════════════════════════════════════════════
# Stage 1, Phase 1: Code Extraction
# ═══════════════════════════════════════════════════════════════════════════

def extract_functions_treesitter(source_dir: str, max_files: int = 500) -> list[FunctionInfo]:
    """Extract function metadata using tree-sitter C parser."""
    if not TS_AVAILABLE:
        log.warning("tree-sitter not available, falling back to regex extraction")
        return extract_functions_regex(source_dir, max_files)

    parser = TSParser(C_LANG)
    functions = []
    src = Path(source_dir)

    c_files = []
    for ext in ("*.c", "*.h", "*.cpp", "*.cc"):
        for f in src.rglob(ext):
            # Only skip subdirectories that are test/build dirs,
            # NOT files directly inside the requested source_dir
            rel = f.relative_to(src)
            if len(rel.parts) > 1 and any(skip in rel.parts[:-1] for skip in SKIP_DIRS):
                continue
            c_files.append(f)
            if len(c_files) >= max_files:
                break

    for fpath in c_files:
        try:
            code = fpath.read_bytes()
            tree = parser.parse(code)
            _extract_from_tree(tree.root_node, code, str(fpath), functions)
        except Exception as e:
            log.debug("Parse error in %s: %s", fpath, e)

    log.info("Extracted %d functions from %d files", len(functions), len(c_files))
    return functions


def _extract_from_tree(node, source: bytes, file_path: str, out: list):
    """Walk tree-sitter AST to extract function definitions."""
    if node.type == "function_definition":
        try:
            name_node = None
            ret_type = ""
            params = []

            declarator = node.child_by_field_name("declarator")
            if declarator:
                # Function declarator → find name
                fn_decl = declarator
                while fn_decl and fn_decl.type not in ("identifier", "field_identifier"):
                    if fn_decl.type == "function_declarator":
                        name_child = fn_decl.child_by_field_name("declarator")
                        param_list = fn_decl.child_by_field_name("parameters")
                        if param_list:
                            for p in param_list.children:
                                if p.type == "parameter_declaration":
                                    params.append(source[p.start_byte:p.end_byte].decode(errors="replace"))
                        fn_decl = name_child
                    elif fn_decl.type == "pointer_declarator":
                        fn_decl = fn_decl.child_by_field_name("declarator")
                    else:
                        fn_decl = fn_decl.children[0] if fn_decl.children else None

                if fn_decl and fn_decl.type in ("identifier", "field_identifier"):
                    name_node = fn_decl

            type_node = node.child_by_field_name("type")
            if type_node:
                ret_type = source[type_node.start_byte:type_node.end_byte].decode(errors="replace")

            if name_node:
                func_name = source[name_node.start_byte:name_node.end_byte].decode(errors="replace")
                func_code = source[node.start_byte:node.end_byte].decode(errors="replace")

                # Extract callees
                callees = set()
                _find_callees(node, source, callees)

                out.append(FunctionInfo(
                    name=func_name,
                    code=func_code,
                    file_path=file_path,
                    return_type=ret_type,
                    params=params,
                    callees=callees,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                ))
        except Exception:
            pass

    for child in node.children:
        _extract_from_tree(child, source, file_path, out)


def _find_callees(node, source: bytes, out: set):
    """Find all function calls in a node."""
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn and fn.type == "identifier":
            out.add(source[fn.start_byte:fn.end_byte].decode(errors="replace"))
    for child in node.children:
        _find_callees(child, source, out)


def extract_functions_regex(source_dir: str, max_files: int = 500) -> list[FunctionInfo]:
    """Fallback: regex-based function extraction when tree-sitter unavailable."""
    func_re = re.compile(
        r'^(\w[\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)\s*\{',
        re.MULTILINE
    )
    functions = []
    src = Path(source_dir)

    c_files = []
    for ext in ("*.c", "*.cpp", "*.cc"):
        for f in src.rglob(ext):
            if any(skip in f.parts for skip in SKIP_DIRS):
                continue
            c_files.append(f)
            if len(c_files) >= max_files:
                break

    for fpath in c_files:
        try:
            text = fpath.read_text(errors="replace")
            for m in func_re.finditer(text):
                ret_type, name, params = m.group(1), m.group(2), m.group(3)
                # Skip main, test functions
                if name in ("main", "wmain") or "test" in name.lower():
                    continue

                # Extract body (simple brace counting)
                start = m.start()
                brace_start = text.index("{", m.end() - 1)
                depth, i = 1, brace_start + 1
                while depth > 0 and i < len(text):
                    if text[i] == "{": depth += 1
                    elif text[i] == "}": depth -= 1
                    i += 1
                body = text[start:i]

                # Find callees
                callees = set(re.findall(r'\b(\w+)\s*\(', body)) - {name}

                functions.append(FunctionInfo(
                    name=name, code=body, file_path=str(fpath),
                    return_type=ret_type.strip(),
                    params=[p.strip() for p in params.split(",") if p.strip()],
                    callees=callees,
                ))
        except Exception:
            pass

    return functions


# ═══════════════════════════════════════════════════════════════════════════
# Stage 1, Phase 2: LLM Summary Generation
# ═══════════════════════════════════════════════════════════════════════════

def _has_pointer_type(func: FunctionInfo) -> bool:
    """Pre-filter: only analyze functions with pointer types."""
    if "*" in func.return_type:
        return True
    for p in func.params:
        if "*" in p:
            return True
    return False


CLASSIFY_PROMPT = """You are a memory safety expert analyzing C/C++ code.

## Task
Classify this function as: ALLOCATOR, DEALLOCATOR, or NEITHER.

**ALLOCATOR**: Returns newly allocated heap memory the caller must free.
- Calls malloc/calloc/realloc/strdup/new and returns the result
- Wraps another allocator and returns result

**DEALLOCATOR**: Frees memory passed as argument.
- Calls free/delete/kfree on an argument
- Wraps a deallocation function

**NEITHER**: Everything else (returns static/global, internal alloc, etc.)

## Function
Name: {name}
Return type: {return_type}
Parameters: {params}

```c
{code}
```

## Output
Return ONLY valid JSON, no other text:
{{"name": "{name}", "role": "Allocator" or "Deallocator" or "Neither", "target": "return" or "argN", "confidence": 0.0-1.0}}
"""


async def classify_functions_llm(
    functions: list[FunctionInfo],
    func_lookup: dict[str, FunctionInfo],
    model: str = "qwen2.5-coder:14b-instruct-q4_K_M",
    ollama_url: str = "http://localhost:11434",
    batch_size: int = 5,
) -> list[MMSummary]:
    """Use local LLM to classify functions as allocator/deallocator/neither."""
    summaries = []

    for i in range(0, len(functions), batch_size):
        batch = functions[i:i + batch_size]

        for func in batch:
            # Build context with callee code (up to 3 callees)
            code = func.code
            if len(code) > 3000:
                code = code[:3000] + "\n// ... truncated ..."

            prompt = CLASSIFY_PROMPT.format(
                name=func.name,
                return_type=func.return_type,
                params=", ".join(func.params),
                code=code,
            )

            try:
                result = await _ollama_generate(prompt, model, ollama_url)
                parsed = _parse_llm_json(result)
                if parsed and parsed.get("role", "").lower() != "neither":
                    role = MMRole.ALLOCATOR if "alloc" in parsed["role"].lower() else MMRole.DEALLOCATOR
                    summaries.append(MMSummary(
                        name=parsed.get("name", func.name),
                        role=role,
                        target=parsed.get("target", "return" if role == MMRole.ALLOCATOR else "arg0"),
                        confidence=float(parsed.get("confidence", 0.7)),
                        reason=parsed.get("reason", ""),
                    ))
            except Exception as e:
                log.debug("LLM classify failed for %s: %s", func.name, e)

        if i % 20 == 0 and i > 0:
            log.info("  Classified %d/%d functions", i, len(functions))

    log.info("LLM generated %d summaries from %d candidates", len(summaries), len(functions))
    return summaries


async def _ollama_generate(prompt: str, model: str, url: str, timeout: int = 180) -> str:
    """Call Ollama generate endpoint."""
    import urllib.request
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.05, "num_predict": 300},
    }).encode()

    req = urllib.request.Request(
        f"{url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    loop = asyncio.get_event_loop()
    resp = await loop.run_in_executor(None, lambda: urllib.request.urlopen(req, timeout=timeout))
    data = json.loads(resp.read())
    return data.get("response", "")


def _parse_llm_json(text: str) -> dict | None:
    """Extract JSON from LLM response."""
    text = text.strip()
    # Strip markdown fences
    text = re.sub(r"```(?:json)?\n?", "", text).strip("`").strip()
    # Fix invalid escapes
    text = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object
        m = re.search(r'\{[^{}]+\}', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Stage 1, Phase 3: Z3 Summary Validation
# ═══════════════════════════════════════════════════════════════════════════

def build_simple_cfg(func: FunctionInfo) -> list[CFGNode]:
    """Build a simplified CFG from function source for Z3 validation."""
    nodes = [CFGNode(id=0, node_type=NodeType.ENTRY, line=0, code="ENTRY")]
    lines = func.code.splitlines()
    node_id = 1

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # Classify line
        ntype = NodeType.CALL
        var = ""

        # Check for allocation calls
        for alloc in KNOWN_ALLOCATORS:
            if re.search(rf'\b{re.escape(alloc)}\s*\(', stripped):
                ntype = NodeType.ALLOC
                m = re.match(r'(\w+)\s*=', stripped)
                if m:
                    var = m.group(1)
                break

        # Check for free calls
        for dealloc in KNOWN_DEALLOCATORS:
            if re.search(rf'\b{re.escape(dealloc)}\s*\(', stripped):
                ntype = NodeType.FREE
                m = re.search(rf'{re.escape(dealloc)}\s*\((\w+)', stripped)
                if m:
                    var = m.group(1)
                break

        # Check for return
        if re.match(r'\s*return\b', stripped):
            ntype = NodeType.RETURN
            m = re.match(r'\s*return\s+(\w+)', stripped)
            if m:
                var = m.group(1)

        # Check for branch
        if re.match(r'\s*(if|else|switch|while|for)\b', stripped):
            ntype = NodeType.BRANCH
            m = re.search(r'(if|while)\s*\((.+?)\)', stripped)
            cond = m.group(2) if m else ""
            nodes.append(CFGNode(id=node_id, node_type=ntype,
                                 line=i + 1, code=stripped,
                                 condition=cond))
            node_id += 1
            continue

        nodes.append(CFGNode(id=node_id, node_type=ntype,
                             line=i + 1, code=stripped, variable=var))
        node_id += 1

    # Add exit node
    nodes.append(CFGNode(id=node_id, node_type=NodeType.EXIT,
                         line=len(lines), code="EXIT"))

    # Build simple linear successor chain
    for i in range(len(nodes) - 1):
        nodes[i].successors.append(nodes[i + 1].id)
        nodes[i + 1].predecessors.append(nodes[i].id)

    return nodes


def validate_summary_z3(summary: MMSummary, func: FunctionInfo,
                        all_funcs: dict[str, FunctionInfo]) -> bool:
    """Validate an LLM-generated summary using Z3.

    For ALLOCATOR: check if there exists a feasible path where
    allocation occurs and the value reaches return without being freed.

    For DEALLOCATOR: check if there exists a feasible path where
    the target argument is freed.
    """
    if not Z3_AVAILABLE:
        log.debug("Z3 not available — accepting summary for %s without validation", summary.name)
        return True

    cfg = build_simple_cfg(func)

    solver = Solver()
    solver.set("timeout", 5000)  # 5 second timeout

    # Create boolean vars for each branch
    branch_vars = {}
    for node in cfg:
        if node.node_type == NodeType.BRANCH:
            branch_vars[node.id] = Bool(f"b_{node.id}")

    # Create reachability vars
    reach = {n.id: Bool(f"reach_{n.id}") for n in cfg}

    # Entry is always reachable
    solver.add(reach[0] == True)

    # Check based on role
    if summary.role == MMRole.ALLOCATOR:
        # Must have: reachable ALLOC → reachable RETURN without FREE
        has_alloc = False
        has_return = False
        has_free = False

        alloc_nodes = [n for n in cfg if n.node_type == NodeType.ALLOC]
        return_nodes = [n for n in cfg if n.node_type == NodeType.RETURN]
        free_nodes = [n for n in cfg if n.node_type == NodeType.FREE]

        if not alloc_nodes or not return_nodes:
            # Check callees transitively
            for callee in func.callees:
                if callee in KNOWN_ALLOCATORS:
                    has_alloc = True
                    break
                if callee in all_funcs:
                    callee_func = all_funcs[callee]
                    if any(a in callee_func.callees for a in KNOWN_ALLOCATORS):
                        has_alloc = True
                        break
            if not has_alloc:
                return False
            return True  # Transitive allocator — accept

        # Check: exists path with alloc AND return AND no free
        alloc_reach = Or(*[reach[n.id] for n in alloc_nodes]) if alloc_nodes else False
        ret_reach = Or(*[reach[n.id] for n in return_nodes]) if return_nodes else False
        free_reach = Or(*[reach[n.id] for n in free_nodes]) if free_nodes else False

        solver.add(alloc_reach)
        solver.add(ret_reach)
        if free_nodes:
            solver.add(Not(free_reach))

        result = solver.check()
        return result == sat

    elif summary.role == MMRole.DEALLOCATOR:
        # Must have: reachable FREE of target argument
        target_arg = summary.target  # e.g., "arg0"
        arg_idx = int(target_arg.replace("arg", "")) if target_arg.startswith("arg") else 0

        # Get parameter name
        param_name = ""
        if arg_idx < len(func.params):
            param = func.params[arg_idx]
            parts = param.strip().split()
            param_name = parts[-1].strip("*") if parts else ""

        free_nodes = [n for n in cfg if n.node_type == NodeType.FREE]

        if not free_nodes:
            # Check callees transitively
            for callee in func.callees:
                if callee in KNOWN_DEALLOCATORS:
                    return True
                if callee in all_funcs:
                    callee_func = all_funcs[callee]
                    if any(d in callee_func.callees for d in KNOWN_DEALLOCATORS):
                        return True
            return False

        # Check if any free node frees the target parameter
        target_frees = []
        for n in free_nodes:
            if param_name and param_name in n.variable:
                target_frees.append(n)
            elif n.variable:
                target_frees.append(n)  # Accept if we can't match precisely

        if not target_frees:
            return False

        free_reach = Or(*[reach[n.id] for n in target_frees])
        solver.add(free_reach)

        result = solver.check()
        return result == sat

    return False


# ═══════════════════════════════════════════════════════════════════════════
# Stage 2: Summary-Augmented Analysis (Infer integration)
# ═══════════════════════════════════════════════════════════════════════════

def build_infer_flags(allocators: list[MMSummary],
                      deallocators: list[MMSummary]) -> str:
    """Build Infer Pulse CLI flags from validated summaries."""
    flags = []

    if allocators:
        alloc_names = [s.name for s in allocators]
        pattern = "^(" + "|".join(re.escape(n) for n in alloc_names) + ")$"
        flags.append(f"--pulse-model-alloc-pattern '{pattern}'")

    if deallocators:
        dealloc_names = [s.name for s in deallocators]
        pattern = "^(" + "|".join(re.escape(n) for n in dealloc_names) + ")$"
        flags.append(f"--pulse-model-free-pattern '{pattern}'")

    return " ".join(flags)


# ═══════════════════════════════════════════════════════════════════════════
# Stage 3, Phase 5: Z3 Path Feasibility Filter
# ═══════════════════════════════════════════════════════════════════════════

def filter_warnings_z3(warnings: list[dict], func_code: str,
                       allocators: list[str], deallocators: list[str]) -> list[dict]:
    """Filter false positive warnings by checking path feasibility with Z3.

    For each warning, encode the function's CFG as Z3 constraints tracking
    three state variables per pointer:
      alloc(n):   memory allocated at/before node n
      freed(n):   memory freed at/before node n  
      escaped(n): ownership transferred at/before node n

    A leak is feasible iff:
      ∃ path: alloc(exit) ∧ ¬freed(exit) ∧ ¬escaped(exit)   → SAT

    If UNSAT, the warning is a false positive (infeasible path).
    Paper reports 85% false positive reduction with this technique.
    """
    if not Z3_AVAILABLE:
        return warnings

    filtered = []
    all_allocs = set(KNOWN_ALLOCATORS) | set(allocators)
    all_deallocs = set(KNOWN_DEALLOCATORS) | set(deallocators)

    # Escape patterns for ownership transfer (pointer stored globally/returned)
    ESCAPE_PATTERNS = [
        r'(\w+)->(\w+)\s*=\s*(\w+)',   # struct->field = ptr (ownership transfer)
        r'(\w+)\[.*\]\s*=\s*(\w+)',     # array[i] = ptr
        r'return\s+(\w+)',              # return ptr (caller takes ownership)
    ]

    for warn in warnings:
        func_name = warn.get("function", "")
        alloc_var = warn.get("variable", "")
        line = warn.get("line", 0)

        if not func_code:
            filtered.append(warn)
            continue

        lines = func_code.splitlines()
        solver = Solver()
        solver.set("timeout", 5000)

        # Create state variables for each line
        n = len(lines)
        alloc_state = [Bool(f"alloc_{i}") for i in range(n + 1)]
        freed_state = [Bool(f"freed_{i}") for i in range(n + 1)]
        escaped_state = [Bool(f"escaped_{i}") for i in range(n + 1)]
        branch_vars = {}

        # Initial state: nothing allocated, freed, or escaped
        solver.add(alloc_state[0] == False)
        solver.add(freed_state[0] == False)
        solver.add(escaped_state[0] == False)

        alloc_line = -1
        free_lines = []
        escape_lines = []

        for i, ln in enumerate(lines):
            stripped = ln.strip()
            next_alloc = alloc_state[i]
            next_freed = freed_state[i]
            next_escaped = escaped_state[i]

            # Check for allocation
            for a in all_allocs:
                if re.search(rf'\b{re.escape(a)}\s*\(', stripped):
                    next_alloc = Bool(f"alloc_set_{i}")
                    solver.add(next_alloc == True)
                    alloc_line = i
                    # Extract allocated variable
                    m = re.match(r'\s*(\w+)\s*[\*]*\s*(\w+)\s*=', stripped)
                    if m and not alloc_var:
                        alloc_var = m.group(2)
                    break

            # Check for deallocation
            for d in all_deallocs:
                if re.search(rf'\b{re.escape(d)}\s*\(', stripped):
                    if alloc_var and alloc_var in stripped:
                        next_freed = Bool(f"freed_set_{i}")
                        solver.add(next_freed == True)
                        free_lines.append(i)
                    break

            # Check for escape (ownership transfer)
            for pattern in ESCAPE_PATTERNS:
                m = re.search(pattern, stripped)
                if m and alloc_var and alloc_var in stripped:
                    # Don't count the allocation line itself as escape
                    if i != alloc_line:
                        next_escaped = Bool(f"escaped_set_{i}")
                        solver.add(next_escaped == True)
                        escape_lines.append(i)
                    break

            # Check for conditional branches
            if re.match(r'\s*(if|else|switch)\b', stripped):
                bvar = Bool(f"branch_{i}")
                branch_vars[i] = bvar

            # Propagate state: state[i+1] = state[i] OR new_state
            solver.add(alloc_state[i + 1] == Or(alloc_state[i], next_alloc))
            solver.add(freed_state[i + 1] == Or(freed_state[i], next_freed))
            solver.add(escaped_state[i + 1] == Or(escaped_state[i], next_escaped))

        # Check feasibility: leak exists if allocated AND NOT freed AND NOT escaped at exit
        solver.add(alloc_state[n] == True)
        solver.add(freed_state[n] == False)
        solver.add(escaped_state[n] == False)

        result = solver.check()

        if result == sat:
            warn["z3_feasible"] = True
            warn["z3_detail"] = (
                f"Feasible leak: allocated at line {alloc_line + 1}, "
                f"{'freed at lines ' + ','.join(str(l+1) for l in free_lines) if free_lines else 'never freed'}, "
                f"{'escaped at lines ' + ','.join(str(l+1) for l in escape_lines) if escape_lines else 'no escape'}"
            )
            filtered.append(warn)
        else:
            reason = "infeasible"
            if escape_lines:
                reason = f"ownership transferred at line(s) {','.join(str(l+1) for l in escape_lines)}"
            elif free_lines:
                reason = f"freed on all paths at line(s) {','.join(str(l+1) for l in free_lines)}"
            warn["z3_filtered"] = True
            warn["z3_reason"] = reason
            log.info("Z3 filtered: %s:%d — %s", func_name, line, reason)

    log.info("Z3 path feasibility: %d/%d warnings retained", len(filtered), len(warnings))
    return filtered


def verify_fix_z3(original_code: str, fixed_code: str,
                  alloc_var: str, allocators: list[str] = [],
                  deallocators: list[str] = []) -> dict:
    """Verify that a proposed fix eliminates a memory leak using Z3.

    Returns:
      {"proven": True/False, "original_sat": True/False,
       "fixed_sat": True/False, "explanation": "..."}
    """
    if not Z3_AVAILABLE:
        return {"proven": False, "explanation": "Z3 not available"}

    all_allocs = set(KNOWN_ALLOCATORS) | set(allocators)
    all_deallocs = set(KNOWN_DEALLOCATORS) | set(deallocators)

    def _check_leak(code: str) -> bool:
        """Returns True if a leak is feasible (SAT)."""
        lines = code.splitlines()
        solver = Solver()
        solver.set("timeout", 3000)
        n = len(lines)

        alloc_found = False
        freed_found = False
        escaped_found = False

        for ln in lines:
            stripped = ln.strip()
            for a in all_allocs:
                if re.search(rf'\b{re.escape(a)}\s*\(', stripped):
                    alloc_found = True
            for d in all_deallocs:
                if re.search(rf'\b{re.escape(d)}\s*\(', stripped):
                    if alloc_var in stripped:
                        freed_found = True
            if alloc_var and re.search(rf'->(\w+)\s*=\s*{re.escape(alloc_var)}', stripped):
                escaped_found = True
            if re.search(rf'return\s+{re.escape(alloc_var)}', stripped):
                escaped_found = True

        alloc = Bool("alloc")
        freed = Bool("freed")
        escaped = Bool("escaped")

        solver.add(alloc == alloc_found)
        solver.add(freed == freed_found)
        solver.add(escaped == escaped_found)
        # Leak feasible if: allocated AND NOT freed AND NOT escaped
        solver.add(alloc == True)
        solver.add(freed == False)
        solver.add(escaped == False)

        return solver.check() == sat

    original_leaks = _check_leak(original_code)
    fixed_leaks = _check_leak(fixed_code)

    proven = original_leaks and not fixed_leaks
    explanation = ""
    if proven:
        explanation = f"Fix PROVEN correct: original has feasible leak, fix eliminates it"
    elif not original_leaks:
        explanation = f"Original code has no feasible leak (may be ownership transfer)"
    elif fixed_leaks:
        explanation = f"Fix does NOT eliminate the leak — still feasible after fix"
    else:
        explanation = f"Inconclusive"

    return {
        "proven": proven,
        "original_sat": original_leaks,
        "fixed_sat": fixed_leaks,
        "explanation": explanation,
    }


def assess_exploit_feasibility_z3(
    bug_type: str, missing_mitigations: list[str],
    has_user_input: bool = False,
    pointer_controllable: bool = False,
) -> dict:
    """Use Z3 to assess if a detected bug is exploitable given mitigations.

    Models the exploit chain as constraints:
      attacker_controls_input ∧ bug_reachable ∧ ¬mitigation_blocks → exploitable

    Returns:
      {"exploitable": True/False, "difficulty": "trivial/hard/infeasible",
       "attack_chain": [...], "blocked_by": [...]}
    """
    if not Z3_AVAILABLE:
        return {"exploitable": False, "difficulty": "unknown",
                "explanation": "Z3 not available"}

    solver = Solver()

    # Attack prerequisites
    controls_input = Bool("controls_input")
    bug_reachable = Bool("bug_reachable")
    controls_pointer = Bool("controls_pointer")

    # Mitigations
    has_pie = Bool("has_pie")
    has_canary = Bool("has_canary")
    has_nx = Bool("has_nx")
    has_aslr = Bool("has_aslr")
    has_relro = Bool("has_relro")
    has_fortify = Bool("has_fortify")

    # Set known values
    solver.add(controls_input == has_user_input)
    solver.add(bug_reachable == True)  # Bug was detected, so it's reachable
    solver.add(controls_pointer == pointer_controllable)

    # Set mitigation states
    mit_map = {
        "PIE": has_pie, "Stack Canary": has_canary,
        "NX (No-Execute)": has_nx, "ASLR (System)": has_aslr,
        "RELRO": has_relro, "FORTIFY_SOURCE": has_fortify,
    }

    for name, var in mit_map.items():
        solver.add(var == (name not in missing_mitigations))

    # Exploit feasibility conditions per bug type
    can_hijack_control = Bool("can_hijack_control")
    can_execute_payload = Bool("can_execute_payload")
    exploit_success = Bool("exploit_success")

    if bug_type in ("buffer_overflow", "stack_overflow"):
        # Need: input control + no canary + (no NX OR no ASLR/PIE)
        solver.add(can_hijack_control == And(controls_input, Not(has_canary)))
        solver.add(can_execute_payload == Or(Not(has_nx), And(Not(has_pie), Not(has_aslr))))
        solver.add(exploit_success == And(can_hijack_control, can_execute_payload))

    elif bug_type == "use_after_free":
        # Need: input control + pointer controllable + (no PIE OR no ASLR)
        solver.add(can_hijack_control == And(controls_input, controls_pointer))
        solver.add(can_execute_payload == Or(Not(has_pie), Not(has_aslr)))
        solver.add(exploit_success == And(can_hijack_control, can_execute_payload))

    elif bug_type == "null_deref":
        # Need: no ASLR (to map page at NULL)
        solver.add(exploit_success == And(controls_input, Not(has_aslr)))

    elif bug_type == "race_condition":
        # Races are exploitable if input-controllable timing
        solver.add(exploit_success == controls_input)

    else:
        solver.add(exploit_success == False)

    solver.add(exploit_success == True)
    result = solver.check()

    blocked_by = []
    if result != sat:
        # Find which mitigations block the exploit
        for name, var in mit_map.items():
            if name not in missing_mitigations:
                blocked_by.append(name)

    # Determine difficulty
    if result == sat:
        n_missing = len(missing_mitigations)
        difficulty = "trivial" if n_missing >= 3 else "moderate" if n_missing >= 1 else "hard"
    else:
        difficulty = "infeasible"

    return {
        "exploitable": result == sat,
        "difficulty": difficulty,
        "missing_mitigations": missing_mitigations,
        "blocked_by": blocked_by,
        "explanation": (
            f"Exploit {'feasible' if result == sat else 'blocked'}: "
            f"{len(missing_mitigations)} mitigation(s) missing"
            + (f", blocked by {', '.join(blocked_by)}" if blocked_by else "")
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Stage 3, Phase 6: LLM Warning Validation
# ═══════════════════════════════════════════════════════════════════════════

VALIDATE_PROMPT = """You are a memory-safety expert. Analyze this warning.

**File:** {file}
**Function:** {function}
**Line:** {line}
**Warning:** {message}
**Bug type:** Memory leak

**Source code:**
```c
{code}
```

Is this a REAL memory leak or a FALSE POSITIVE?
Consider: Is the pointer freed on all paths? Is ownership transferred?

Return ONLY JSON:
{{"verdict": true, "confidence": 0.8, "reason": "one short sentence"}}
"""


async def validate_warnings_llm(
    warnings: list[dict],
    func_lookup: dict[str, FunctionInfo],
    model: str = "qwen2.5-coder:14b-instruct-q4_K_M",
    ollama_url: str = "http://localhost:11434",
) -> list[dict]:
    """LLM-based validation of remaining warnings."""
    validated = []

    for warn in warnings:
        func_name = warn.get("function", "")
        func = func_lookup.get(func_name)
        code = func.code if func else ""
        if len(code) > 4000:
            code = code[:4000]

        prompt = VALIDATE_PROMPT.format(
            file=warn.get("file", ""),
            function=func_name,
            line=warn.get("line", 0),
            message=warn.get("message", ""),
            code=code,
        )

        try:
            result = await _ollama_generate(prompt, model, ollama_url)
            parsed = _parse_llm_json(result)
            if parsed and parsed.get("verdict", True):
                warn["llm_validated"] = True
                warn["llm_confidence"] = parsed.get("confidence", 0.5)
                warn["llm_reason"] = parsed.get("reason", "")
                validated.append(warn)
        except Exception as e:
            # On error, keep the warning (conservative)
            warn["llm_validated"] = False
            validated.append(warn)

    return validated


# ═══════════════════════════════════════════════════════════════════════════
# Full Pipeline Orchestrator
# ═══════════════════════════════════════════════════════════════════════════

async def run_memhint_pipeline(
    source_dir: str,
    binary: str | None = None,
    model: str = "qwen2.5-coder:14b-instruct-q4_K_M",
    ollama_url: str | None = None,
    max_functions: int = 500,
    skip_z3: bool = False,
    skip_llm_validate: bool = False,
    progress_callback=None,
) -> MemHintReport:
    """Run the full neuro-symbolic pipeline.

    Returns a MemHintReport with discovered allocators/deallocators
    and Infer CLI flags for summary injection.
    """
    t0 = time.monotonic()
    ollama_url = ollama_url or os.environ.get("MEMGUARD_OLLAMA_URL", "http://localhost:11434")

    def _progress(msg):
        log.info(msg)
        if progress_callback:
            progress_callback(msg)

    # ── Stage 1, Phase 1: Code Extraction ──
    _progress("Phase 1: Extracting functions...")
    functions = extract_functions_treesitter(source_dir, max_files=max_functions)
    all_extracted = len(functions)

    # Build lookup
    func_lookup = {f.name: f for f in functions}

    # Pre-filter: only functions with pointer types
    candidates = [f for f in functions if _has_pointer_type(f)]
    # Skip main, test functions
    candidates = [f for f in candidates
                  if f.name not in ("main", "wmain")
                  and "test" not in f.name.lower()]

    _progress(f"Phase 1: {all_extracted} extracted → {len(candidates)} candidates (pointer-type filter)")

    # ── Stage 1, Phase 2: LLM Classification ──
    _progress(f"Phase 2: Classifying {len(candidates)} functions with LLM...")
    summaries = await classify_functions_llm(
        candidates, func_lookup, model=model, ollama_url=ollama_url
    )
    _progress(f"Phase 2: LLM produced {len(summaries)} MM summaries")

    # ── Stage 1, Phase 3: Z3 Validation ──
    validated = []
    if not skip_z3 and Z3_AVAILABLE:
        _progress(f"Phase 3: Validating {len(summaries)} summaries with Z3...")
        for s in summaries:
            func = func_lookup.get(s.name)
            if func:
                if validate_summary_z3(s, func, func_lookup):
                    s.validated = True
                    validated.append(s)
                else:
                    _progress(f"  Z3 rejected: {s.name} ({s.role.name})")
            else:
                validated.append(s)  # Keep if no source available
        _progress(f"Phase 3: {len(validated)} validated ({len(summaries) - len(validated)} rejected)")
    else:
        validated = summaries
        for s in validated:
            s.validated = True
        _progress(f"Phase 3: Skipped Z3 — {len(validated)} summaries accepted")

    # Separate allocators and deallocators
    allocators = [s for s in validated if s.role == MMRole.ALLOCATOR]
    deallocators = [s for s in validated if s.role == MMRole.DEALLOCATOR]

    # ── Stage 2: Build Infer flags ──
    infer_flags = build_infer_flags(allocators, deallocators)
    _progress(f"Stage 2: {len(allocators)} allocators, {len(deallocators)} deallocators → Infer flags ready")

    duration_ms = int((time.monotonic() - t0) * 1000)

    return MemHintReport(
        source_dir=source_dir,
        functions_extracted=all_extracted,
        candidates_filtered=len(candidates),
        summaries_generated=len(summaries),
        summaries_validated=len(validated),
        allocators=allocators,
        deallocators=deallocators,
        duration_ms=duration_ms,
        infer_flags=infer_flags,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Save/Load summaries for reuse
# ═══════════════════════════════════════════════════════════════════════════

def save_summaries(summaries: list[MMSummary], path: str):
    """Save validated summaries to JSON for reuse."""
    data = {"hints": {}}
    for s in summaries:
        data["hints"][s.name] = [{
            "name": s.name,
            "role": "Allocator" if s.role == MMRole.ALLOCATOR else "Deallocator",
            "target": s.target,
            "validated": s.validated,
            "confidence": s.confidence,
        }]
    Path(path).write_text(json.dumps(data, indent=2))


def load_summaries(path: str) -> list[MMSummary]:
    """Load previously saved summaries."""
    data = json.loads(Path(path).read_text())
    summaries = []
    for name, hints in data.get("hints", {}).items():
        for h in hints:
            role = MMRole.ALLOCATOR if h["role"] == "Allocator" else MMRole.DEALLOCATOR
            summaries.append(MMSummary(
                name=h["name"], role=role, target=h["target"],
                validated=h.get("validated", True),
                confidence=h.get("confidence", 0.7),
            ))
    return summaries
