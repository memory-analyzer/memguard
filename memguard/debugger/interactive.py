"""
memguard.debugger.interactive
==============================
Interactive guided-fix debugger. The developer works through fixes step by
step, talking to the AI at each stage, applying patches, running validation
commands, and rolling back if needed.
"""

from __future__ import annotations
import re

import asyncio
import difflib
from datetime import datetime, timezone
import logging
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import AsyncIterator

from ..core.schema import (
    AIAnalysis, DebugStep, FixStatus, InteractiveSession,
    Language, MemoryError, SessionState,
)
from ..ai.client import complete, best_available_model
from ..ai.analyzer import LANG_SYSTEM

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git_available(path: str) -> bool:
    return (Path(path) / ".git").exists()


def _git_run(args: list[str], cwd: str) -> tuple[str, int]:
    r = subprocess.run(
        ["git"] + args, cwd=cwd,
        capture_output=True, text=True,
    )
    return r.stdout + r.stderr, r.returncode


def create_fix_branch(cwd: str, branch_name: str) -> str | None:
    if not _git_available(cwd):
        return None
    out, rc = _git_run(["checkout", "-b", branch_name], cwd)
    if rc == 0:
        log.info("Created git branch: %s", branch_name)
        return branch_name
    log.warning("Could not create branch: %s", out)
    return None


def git_diff(cwd: str) -> str:
    out, _ = _git_run(["diff", "--no-color"], cwd)
    return out


def git_commit(cwd: str, message: str) -> bool:
    _git_run(["add", "-A"], cwd)
    _, rc = _git_run(["commit", "-m", message], cwd)
    return rc == 0


def git_rollback(cwd: str) -> bool:
    _, rc = _git_run(["checkout", "--", "."], cwd)
    return rc == 0


# ---------------------------------------------------------------------------
# Patch applier
# ---------------------------------------------------------------------------

class PatchApplier:
    BACKUP_DIR = Path.home() / ".memguard" / "backups"

    def __init__(self, root_dir: str):
        self.root  = Path(root_dir)
        self._backups: dict[str, str] = {}
        self.BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    def backup_file(self, path: str) -> bool:
        """Backup in memory AND on disk so rollback survives a crash."""
        p = Path(path)
        if p.exists():
            content = p.read_text()
            self._backups[path] = content
            # Persist a timestamped on-disk copy for crash recovery
            try:
                import hashlib
                stamp = time.strftime("%Y%m%d_%H%M%S")
                digest = hashlib.sha1(path.encode()).hexdigest()[:8]
                disk_backup = self.BACKUP_DIR / f"{p.name}.{digest}.{stamp}.bak"
                disk_backup.write_text(content)
                # Keep only the 20 most recent backups
                backups = sorted(self.BACKUP_DIR.glob("*.bak"),
                                 key=lambda b: b.stat().st_mtime)
                while len(backups) > 20:
                    backups.pop(0).unlink(missing_ok=True)
            except OSError as e:
                log.warning("On-disk backup failed (in-memory only): %s", e)
            return True
        return False

    def apply_unified_diff(self, diff_text: str) -> tuple[bool, str]:
        """Apply a unified diff. Returns (success, message)."""
        if not diff_text.strip():
            return False, "Empty diff"

        # Parse target file from diff header
        lines  = diff_text.splitlines()
        target = None
        for line in lines:
            if line.startswith("+++ "):
                target = line[4:].strip().lstrip("b/").split("\t")[0]
                break

        if not target:
            return False, "Could not determine target file from diff"

        # Try to find the file
        candidates = [
            self.root / target,
            *list(self.root.rglob(Path(target).name)),
        ]
        filepath = next((p for p in candidates if p.exists()), None)
        if not filepath:
            return False, f"File not found: {target}"

        self.backup_file(str(filepath))
        original = filepath.read_text().splitlines(keepends=True)

        try:
            patched = list(difflib.restore(
                [l + "\n" if not l.endswith("\n") else l
                 for l in diff_text.splitlines()],
                which=2,
            ))
            filepath.write_text("".join(patched))
            return True, f"Applied patch to {filepath}"
        except Exception as e:
            return False, f"Patch failed: {e}"

    def apply_full_replacement(self, file_path: str, new_content: str) -> tuple[bool, str]:
        p = Path(file_path) if Path(file_path).is_absolute() else self.root / file_path
        if not p.exists():
            matches = list(self.root.rglob(Path(file_path).name))
            if matches:
                p = matches[0]
            else:
                return False, f"File not found: {file_path}"

        self.backup_file(str(p))
        p.write_text(new_content)
        return True, f"Replaced {p}"

    def rollback_all(self) -> list[str]:
        rolled_back = []
        for path, content in self._backups.items():
            Path(path).write_text(content)
            rolled_back.append(path)
        self._backups.clear()
        return rolled_back

    def rollback_file(self, path: str) -> bool:
        if path in self._backups:
            Path(path).write_text(self._backups[path])
            return True
        return False


# ---------------------------------------------------------------------------
# Validation runner
# ---------------------------------------------------------------------------

async def run_validation(command: str, cwd: str, timeout: int = 60) -> tuple[bool, str]:
    """Run a validation command; returns (passed, output)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        passed = proc.returncode == 0
        return passed, out.decode(errors="replace")
    except asyncio.TimeoutError:
        return False, f"Validation timed out after {timeout}s"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Interactive session manager
# ---------------------------------------------------------------------------

class InteractiveDebugger:
    """
    Manages the full interactive guided-fix session for one error.
    Exposes async methods that the TUI/CLI calls as the user progresses.
    """

    def __init__(
        self,
        session: InteractiveSession,
        error:   MemoryError,
        analysis: AIAnalysis,
        root_dir: str,
        model: str | None = None,
    ):
        self.session   = session
        self.error     = error
        self.analysis  = analysis
        self.root_dir  = root_dir
        self._model    = model
        self._patcher  = PatchApplier(root_dir)
        self._conv: list[dict] = []   # running conversation

    # ------------------------------------------------------------------ setup

    async def start(self) -> InteractiveSession:
        self._model = self._model or await best_available_model()
        self.session.state = SessionState.INTERACTIVE

        # Create git branch for this fix
        slug = re.sub(r"[^a-z0-9]+", "-", self.error.bug_type.value)
        branch = f"memguard/fix-{slug}-{self.error.id[:8]}"
        br = create_fix_branch(self.root_dir, branch)
        self.session.git_branch = br

        self.session.started_at = datetime.now(timezone.utc)
        log.info("Session %s started (branch: %s)", self.session.session_id[:8], br)
        return self.session

    # --------------------------------------------------------------- step nav

    @property
    def current_step(self) -> DebugStep | None:
        idx = self.session.current_step
        if 0 <= idx < len(self.session.steps):
            return self.session.steps[idx]
        return None

    def total_steps(self) -> int:
        return len(self.session.steps)

    def is_complete(self) -> bool:
        return self.session.current_step >= len(self.session.steps)

    def advance(self) -> DebugStep | None:
        step = self.current_step
        if step:
            step.completed = True
        self.session.current_step += 1
        return self.current_step  # returns None when past last step

    def go_back(self) -> DebugStep | None:
        if self.session.current_step > 0:
            self.session.current_step -= 1
            if self.current_step:
                self.current_step.completed = False
        return self.current_step

    def skip_step(self) -> DebugStep | None:
        if self.current_step:
            self.current_step.skipped = True
        return self.advance()

    # --------------------------------------------------------------- apply

    async def apply_current_step(self) -> tuple[bool, str]:
        step = self.current_step
        if not step:
            return False, "No current step"

        best_fix = (self.analysis.fixes or [None])[0]
        if not best_fix:
            return False, "No fix available"

        if not self.error.primary_location:
            return False, "No file location for this error"

        target_file = self.error.primary_location.file

        # Preferred: exact find/replace (most reliable)
        if best_fix.find_text and best_fix.replace_text:
            ok, msg = self._apply_find_replace(
                target_file, best_fix.find_text, best_fix.replace_text
            )
            if ok:
                return True, msg
            return False, msg

        return False, "No find/replace pair available — apply the fix manually from the diff."

    def _apply_find_replace(self, file_path: str, find_t: str, replace_t: str) -> tuple[bool, str]:
        """Locate find_t in the file (whitespace-tolerant) and replace it."""
        from pathlib import Path as _P
        p = _P(file_path)
        if not p.exists():
            matches = list(_P.cwd().rglob(p.name))
            if matches:
                p = matches[0]
            else:
                return False, f"File not found: {file_path}"

        self._patcher.backup_file(str(p))
        content = p.read_text()

        # Exact match first
        if find_t in content:
            p.write_text(content.replace(find_t, replace_t, 1))
            return True, f"Applied fix to {p.name} (exact match)"

        # Whitespace-tolerant match line by line
        file_lines = content.splitlines()
        find_lines = find_t.splitlines()
        m = len(find_lines)
        for i in range(len(file_lines) - m + 1):
            if all(file_lines[i + j].strip() == find_lines[j].strip() for j in range(m)):
                # Preserve the original indentation of the first line
                indent = file_lines[i][:len(file_lines[i]) - len(file_lines[i].lstrip())]
                repl_lines = [indent + rl.lstrip() if rl.strip() else rl
                              for rl in replace_t.splitlines()]
                file_lines[i:i + m] = repl_lines
                p.write_text("\n".join(file_lines) + "\n")
                return True, f"Applied fix to {p.name} (line {i + 1})"

        return False, "Could not locate the original code in the file — apply manually."

    async def validate_current_step(self) -> tuple[bool, str]:
        step = self.current_step
        if not step or not step.validation:
            return True, "No validation command for this step"
        return await run_validation(step.validation, self.root_dir)

    async def rollback(self) -> list[str]:
        files = self._patcher.rollback_all()
        if self.session.git_branch:
            git_rollback(self.root_dir)
        self.session.state = SessionState.IDLE
        return files

    async def commit_fix(self) -> bool:
        if not self.session.git_branch:
            return False
        msg = (
            f"fix({self.error.bug_type.value}): "
            f"{(self.analysis.root_cause or '')[:72]}\n\n"
            f"Detected by memguard ({self.error.tool.value})\n"
            f"Error ID: {self.error.id}\n"
            f"Severity: {self.error.severity.value}\n"
        )
        ok = git_commit(self.root_dir, msg)
        if ok:
            self.session.state = SessionState.DONE
        return ok

    # ------------------------------------------------ AI conversation

    async def chat(self, user_message: str) -> AsyncIterator[str]:
        """
        Stream a conversational AI response grounded in the current error
        and step context.
        """
        system = LANG_SYSTEM.get(self.error.language, LANG_SYSTEM.get(
            Language.UNKNOWN, list(LANG_SYSTEM.values())[0]
        ))

        # Build grounded system prompt
        grounded_system = (
            f"{system}\n\n"
            f"You are guiding a developer through fixing a {self.error.bug_type.value} "
            f"in their {self.error.language.value} code.\n\n"
            f"Error: {self.error.message}\n"
            f"Root cause: {self.analysis.root_cause}\n"
        )

        if self.current_step:
            grounded_system += (
                f"\nCurrent step ({self.session.current_step + 1}/{self.total_steps()}): "
                f"{self.current_step.title}\n"
                f"Description: {self.current_step.description}\n"
            )

        self._conv.append({"role": "user", "content": user_message})

        gen = await complete(
            self._conv,
            model=self._model,
            system=grounded_system,
            stream=True,
            temperature=0.2,
        )

        response_parts = []
        async for token in gen:
            response_parts.append(token)
            yield token

        full_response = "".join(response_parts)
        self._conv.append({"role": "assistant", "content": full_response})

    async def explain_current_step(self) -> AsyncIterator[str]:
        step = self.current_step
        if not step:
            yield "No current step to explain."
            return
        msg = (
            f"Explain step {step.step_number} to me in plain language. "
            f"Step title: '{step.title}'. "
            f"What exactly should I change and why?"
        )
        async for token in self.chat(msg):
            yield token

    async def suggest_alternative(self) -> AsyncIterator[str]:
        step = self.current_step
        msg  = (
            "The current fix approach may not work for my codebase. "
            "Suggest an alternative approach that achieves the same safety goal."
        )
        async for token in self.chat(msg):
            yield token

    # ------------------------------------------------ session summary

    def summary(self) -> dict:
        completed = sum(1 for s in self.session.steps if s.completed)
        skipped   = sum(1 for s in self.session.steps if s.skipped)
        return {
            "session_id":    self.session.session_id,
            "error_type":    self.error.bug_type.value,
            "total_steps":   self.total_steps(),
            "completed":     completed,
            "skipped":       skipped,
            "remaining":     self.total_steps() - completed - skipped,
            "git_branch":    self.session.git_branch,
            "state":         self.session.state.value,
        }
