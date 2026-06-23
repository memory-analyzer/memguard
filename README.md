# 🛡 MemGuard — AI-Powered Memory Leak Detector & Interactive Debugger

A massive, production-grade memory analysis tool that combines **Valgrind, ASan, LSan, MSan, UBSan, cppcheck, clang-tidy, memray, tracemalloc, and Miri** with a **locally-running LLM** (Qwen2.5-Coder / DeepSeek-Coder) for deep root-cause analysis, fix generation, and an interactive step-by-step guided debugger — all running on your machine with no cloud dependency.

---

## Architecture

```
Input (C/C++/Python/Rust binary or source)
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  Analysis Engine (parallel)                                  │
│  Valgrind  │  ASan/LSan  │  MSan/UBSan  │  cppcheck        │
│  clang-tidy│  memray     │  tracemalloc  │  Miri (Rust)     │
└─────────────────────────────────────────────────────────────┘
        │  raw outputs
        ▼
┌──────────────────────────────────┐
│  Parsers + Deduplication         │
│  XML / text / JSON → MemoryError │
└──────────────────────────────────┘
        │  unified MemoryError[]
        ▼
┌──────────────────────────────────┐
│  Symbolizer                      │
│  addr2line / llvm-symbolizer     │
│  + source context extraction     │
└──────────────────────────────────┘
        │  enriched errors
        ▼
┌─────────────────────────────────────────────────────────────┐
│  AI Analysis Pipeline (Ollama — local GPU)                   │
│  Pass 1: Triage  │  Pass 2: Deep Analysis                    │
│  Pass 3: Fix Gen │  Pass 4: Step Decomposition               │
│  Models: qwen2.5-coder:14b (primary)                         │
│          deepseek-coder-v2:16b (fallback)                    │
│          qwen2.5-coder:7b (fast triage)                      │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  Interfaces                                                   │
│  Rich TUI CLI  │  FastAPI + WebSocket  │  HTML Dashboard      │
│                │  Interactive Debugger  │  Git integration     │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Install system tools

```bash
# Ubuntu / Debian
sudo apt install valgrind clang clang-tidy cppcheck llvm binutils git

# Arch
sudo pacman -S valgrind clang clang-tidy cppcheck llvm

# macOS (Homebrew) — ASan only (no Valgrind)
brew install llvm cppcheck
```

### 2. Install Ollama + best model for RTX 5050

```bash
curl -fsSL https://ollama.ai/install.sh | sh

# Primary: 14B Q4 — best quality, fits in 8GB with minor CPU offload
ollama pull qwen2.5-coder:14b-instruct-q4_K_M

# Fast triage model: 7B Q8 — fully fits in 8GB, very fast
ollama pull qwen2.5-coder:7b-instruct-q8_0

# Fallback: DeepSeek — better on complex multi-file leaks
ollama pull deepseek-coder-v2:16b-lite-instruct-q4_K_M
```

### 3. Install memguard

```bash
git clone https://github.com/you/memguard
cd memguard
pip install -e ".[dev]"

# Verify everything is working
memguard doctor
```

---

## Usage

### Scan a C/C++ binary

```bash
# Compile with debug info
gcc -g -O0 -o myapp myapp.c

# Full scan: Valgrind + cppcheck + clang-tidy + AI analysis
memguard scan ./myapp

# ASan scan (catches UAF/double-free that Valgrind misses)
memguard scan ./myapp --tools asan --compile "gcc -g -O1 -fsanitize=address,leak -o myapp myapp.c"

# All tools, save JSON report
memguard scan ./myapp --tools auto --out report.json
```

### Scan Python

```bash
memguard scan ./my_service.py
memguard scan ./my_service.py --tools tracemalloc,memray
```

### Scan Rust (Miri)

```bash
memguard scan ./rust_project/ --tools miri
```

### Interactive guided fix

After a scan, select any issue to enter the interactive debugger:

```
Select issue # for details: 1

[Issue 1/5] memory_leak — HIGH
📍 src/cache.c:47

AI Analysis:
  Root cause: malloc'd buffer on line 47 is not freed on the early-return
  path at line 52 when the key lookup fails.

Start interactive guided fix? [y/n]: y

━━━━━━━━━━━━━━━━━━ Step 1/4 ━━━━━━━━━━━━━━━━━━
Title: Identify the early return path

[a] apply fix    [v] validate    [e] explain    [c] chat with AI
[alt] alternative approach    [n] next step    [b] back    [r] rollback
Command: e

AI> The function allocates buf = malloc(256) at line 47, then checks if 
    key_lookup() returns NULL at line 52. When it does, the function returns 
    -1 immediately WITHOUT calling free(buf). The fix is to add free(buf) 
    before the return statement on line 53...
```

### Re-open a past scan for fixing

```bash
memguard history
memguard fix abc123def456 --error 0
```

### Watch mode (re-scan on file change)

```bash
memguard watch ./src --binary ./build/myapp --compile "make -C build"
```

### Web dashboard

```bash
memguard serve          # opens http://127.0.0.1:7331
```

### Export reports

```bash
memguard report <scan-id> --format markdown --out report.md
memguard report <scan-id> --format sarif    --out results.sarif   # for VS Code / GitHub
memguard report <scan-id> --format json     --out data.json
```

---

## Supported Bug Types

| Type | Valgrind | ASan | LSan | MSan | UBSan | cppcheck | AI |
|------|----------|------|------|------|-------|----------|----|
| Memory Leak | ✓ | ✓ | ✓ | — | — | ✓ | ✓ |
| Use-After-Free | partial | ✓ | — | — | — | ✓ | ✓ |
| Double Free | ✓ | ✓ | — | — | — | ✓ | ✓ |
| Buffer Overflow | ✓ | ✓ | — | — | ✓ | ✓ | ✓ |
| Uninitialised Read | ✓ | — | — | ✓ | — | ✓ | ✓ |
| NULL Deref | ✓ | ✓ | — | — | ✓ | ✓ | ✓ |
| Race Condition | — | — | — | — | — | — | ✓ (TSan) |
| Integer Overflow | — | — | — | — | ✓ | ✓ | ✓ |
| Python Ref Cycles | — | — | — | — | — | — | ✓ (tracemalloc) |
| Rust UB | — | — | — | — | — | — | ✓ (Miri) |

---

## AI Model Guide for RTX 5050 (8GB VRAM)

| Model | VRAM | Speed | Quality | Use |
|-------|------|-------|---------|-----|
| `qwen2.5-coder:14b-instruct-q4_K_M` | ~7.8GB | ~4 tok/s | ★★★★★ | Default |
| `qwen2.5-coder:7b-instruct-q8_0` | ~7.2GB | ~12 tok/s | ★★★★ | Fast triage |
| `deepseek-coder-v2:16b-lite-instruct-q4_K_M` | ~8.5GB* | ~3 tok/s | ★★★★★ | Complex leaks |

*Slight CPU offload with 8GB — still works fine, ~10% slower.

---

## Project Structure

```
memguard/
├── core/
│   ├── schema.py          # All Pydantic data models
│   ├── runner.py          # Parallel tool orchestration
│   ├── parsers.py         # Valgrind XML, ASan text, cppcheck, tracemalloc parsers
│   └── symbolizers.py     # addr2line + source context extraction
├── ai/
│   ├── client.py          # Ollama streaming client with retry + JSON enforcement
│   └── analyzer.py        # 4-pass analysis pipeline (triage→analysis→fix→steps)
├── debugger/
│   └── interactive.py     # Guided fix session + git integration + rollback
├── pipeline/
│   └── orchestrator.py    # Full pipeline: scan→parse→symbolize→analyze→persist
├── languages/
│   └── __init__.py        # C/C++/Python/Rust language-specific heuristics
├── cli/
│   ├── main.py            # Typer CLI: scan/fix/watch/report/history/models/doctor
│   └── tui.py             # Rich TUI: panels, streaming display, interactive debugger
├── api/
│   └── server.py          # FastAPI + WebSocket + HTML dashboard
└── tests/
    └── fixtures/
        ├── leaky_c/all_bugs.c        # 11 C bug types
        ├── leaky_python/all_bugs.py  # 7 Python leak patterns
        └── leaky_rust/src/main.rs    # 7 Rust unsafe/leak patterns
```

---

## Contributing

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check . && black --check .
mypy memguard/
```
