"""
memguard.cli.tui
================
Rich-based terminal UI with:
  • Animated scanning progress with tool status
  • Live streaming AI analysis tokens
  • Full interactive step-by-step guided debugger
  • Diff viewer with syntax highlighting
  • Conversation mode with the AI
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from ..core.schema import (
    AIAnalysis, AnalysisTool, BugType, DebugStep,
    MemoryError, ScanResult, Severity, SessionState,
)
from ..debugger.interactive import InteractiveDebugger

console = Console(highlight=True, emoji=True)

# Severity colours
SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}
SEV_BADGE = {
    Severity.CRITICAL: "[bold red on white] CRITICAL [/]",
    Severity.HIGH:     "[bold red] HIGH [/]",
    Severity.MEDIUM:   "[bold yellow] MEDIUM [/]",
    Severity.LOW:      "[cyan] LOW [/]",
    Severity.INFO:     "[dim] INFO [/]",
}
BUG_ICON = {
    BugType.MEMORY_LEAK:    "💧",
    BugType.USE_AFTER_FREE: "👻",
    BugType.DOUBLE_FREE:    "💀",
    BugType.BUFFER_OVERFLOW:"💥",
    BugType.NULL_DEREF:     "🔴",
    BugType.UNINIT_READ:    "❓",
    BugType.RACE_CONDITION: "🏁",
    BugType.HEAP_CORRUPTION:"🧨",
}


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
 ███╗   ███╗███████╗███╗   ███╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ████╗ ████║██╔════╝████╗ ████║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██╔████╔██║█████╗  ██╔████╔██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""


def print_banner():
    console.print(
        Panel(
            Align(Text(BANNER, style="bold cyan"), "center"),
            subtitle="[dim]AI-Powered Memory Leak Detector & Interactive Debugger[/]",
            border_style="cyan", box=box.DOUBLE_EDGE,
        )
    )


# ---------------------------------------------------------------------------
# Scanning progress
# ---------------------------------------------------------------------------

class ScanProgress:
    def __init__(self, tools: list[AnalysisTool]):
        self.tools  = tools
        self._prog  = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self._tasks: dict[AnalysisTool, int] = {}

    def __enter__(self):
        self._prog.start()
        for t in self.tools:
            tid = self._prog.add_task(f"[{t.value}]", total=100)
            self._tasks[t] = tid
        return self

    def __exit__(self, *_):
        self._prog.stop()

    def tool_running(self, tool: AnalysisTool):
        if tool in self._tasks:
            self._prog.update(self._tasks[tool], advance=20,
                              description=f"[yellow]⚙  {tool.value}")

    def tool_done(self, tool: AnalysisTool, error_count: int):
        if tool in self._tasks:
            self._prog.update(
                self._tasks[tool], completed=100,
                description=f"[green]✓  {tool.value} ({error_count} issues)",
            )

    def tool_failed(self, tool: AnalysisTool, reason: str):
        if tool in self._tasks:
            self._prog.update(
                self._tasks[tool], completed=100,
                description=f"[red]✗  {tool.value} ({reason[:30]})",
            )


# ---------------------------------------------------------------------------
# Error summary table
# ---------------------------------------------------------------------------

def render_error_table(errors: list[MemoryError]) -> Table:
    t = Table(
        title=f"[bold]Found {len(errors)} memory issue(s)[/]",
        box=box.ROUNDED, border_style="cyan",
        show_header=True, header_style="bold cyan",
    )
    t.add_column("#",        width=4,  style="dim")
    t.add_column("Severity", width=10)
    t.add_column("Type",     width=22)
    t.add_column("Location", width=36)
    t.add_column("Tool",     width=12, style="dim")
    t.add_column("Bytes",    width=10, justify="right")

    for i, err in enumerate(errors, 1):
        icon = BUG_ICON.get(err.bug_type, "•")
        loc  = "—"
        if err.primary_location:
            loc = f"{Path(err.primary_location.file).name}:{err.primary_location.line}"
        t.add_row(
            str(i),
            SEV_BADGE.get(err.severity, err.severity.value),
            f"{icon} {err.bug_type.value.replace('_', ' ')}",
            loc,
            err.tool.value,
            f"{err.bytes_leaked:,}" if err.bytes_leaked else "—",
        )
    return t


# ---------------------------------------------------------------------------
# Error detail panel
# ---------------------------------------------------------------------------

def render_error_detail(err: MemoryError, index: int, total: int) -> Panel:
    icon = BUG_ICON.get(err.bug_type, "•")
    rows = []

    # Header info
    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="dim")
    info_table.add_column()
    info_table.add_row("Type",     f"{icon} [bold]{err.bug_type.value.replace('_', ' ').title()}[/]")
    info_table.add_row("Severity", SEV_BADGE.get(err.severity, ""))
    info_table.add_row("Tool",     f"[cyan]{err.tool.value}[/]")
    if err.bytes_leaked:
        info_table.add_row("Leaked",  f"[red]{err.bytes_leaked:,} bytes[/]")
    if err.primary_location:
        info_table.add_row("Location", f"[yellow]{err.primary_location}[/]")
    rows.append(info_table)

    # Message
    rows.append(Rule(style="dim"))
    rows.append(Text(err.message, style="italic"))

    # Source context
    if err.source_context:
        ctx     = err.source_context
        lang    = err.language.value
        snippet_lines = []
        for i, l in enumerate(ctx.before_lines[-5:]):
            lno = ctx.location.line - len(ctx.before_lines) + i + max(0, len(ctx.before_lines) - 5)
            snippet_lines.append(f"{lno:4d} │ {l}")
        snippet_lines.append(f"{ctx.location.line:4d} │ {ctx.target_line}  ◄── error")
        for i, l in enumerate(ctx.after_lines[:5]):
            snippet_lines.append(f"{ctx.location.line + 1 + i:4d} │ {l}")
        code_str = "\n".join(snippet_lines)
        rows.append(Rule(style="dim"))
        rows.append(Syntax(code_str, lang, theme="monokai", line_numbers=False))

    # Stack trace
    if err.stack:
        rows.append(Rule(style="dim"))
        stack_t = Table.grid(padding=(0, 1))
        for f in err.stack[:8]:
            loc = f"{Path(f.file).name}:{f.line}" if f.file and f.line else (f.address or "??")
            stack_t.add_row(
                f"[dim]#{f.index}[/]",
                f"[bold cyan]{f.function or '??'}[/]",
                f"[dim]{loc}[/]",
            )
        rows.append(stack_t)

    return Panel(
        Group(*rows),
        title=f"[bold cyan]Issue {index}/{total}[/] — [dim]{err.id[:8]}[/]",
        border_style=SEV_STYLE.get(err.severity, "white"),
        box=box.ROUNDED,
    )


# ---------------------------------------------------------------------------
# AI analysis streaming display
# ---------------------------------------------------------------------------

async def stream_analysis_display(
    err: MemoryError,
    stream_fn,   # async generator
) -> str:
    """Display streaming AI narrative with a live panel."""
    buf  = []
    live_text = Text()

    with Live(
        Panel(live_text, title="[bold purple]AI Analysis[/]",
              border_style="purple", box=box.ROUNDED),
        console=console, refresh_per_second=20,
    ) as live:
        async for token in stream_fn:
            buf.append(token)
            live_text.append(token)
            live.update(
                Panel(live_text, title="[bold purple]AI Analysis[/]",
                      border_style="purple", box=box.ROUNDED)
            )

    return "".join(buf)


# ---------------------------------------------------------------------------
# Fix display
# ---------------------------------------------------------------------------

def render_analysis_panel(analysis: AIAnalysis) -> Panel:
    rows = []

    # Root cause
    rows.append(Text("Root Cause", style="bold"))
    rows.append(Text(analysis.root_cause or "—", style="italic yellow"))

    # Explanation
    rows.append(Rule(style="dim"))
    rows.append(Text("Explanation", style="bold"))
    rows.append(Text(analysis.explanation or "—"))

    # Impact
    rows.append(Rule(style="dim"))
    rows.append(Text("Impact", style="bold"))
    rows.append(Text(analysis.impact or "—", style="red"))

    # References
    all_refs = analysis.cwe_ids + analysis.misra_rules
    if all_refs:
        rows.append(Rule(style="dim"))
        rows.append(Text("References: " + " · ".join(all_refs), style="dim cyan"))

    return Panel(
        Group(*rows),
        title="[bold purple]Deep Analysis[/]",
        border_style="purple", box=box.ROUNDED,
    )


def render_fix_panel(analysis: AIAnalysis) -> Panel:
    rows = []
    for i, fix in enumerate(analysis.fixes, 1):
        rows.append(Text(
            f"Fix {i}: {fix.description}",
            style=f"bold {'green' if fix.confidence.value == 'high' else 'yellow'}"
        ))
        rows.append(Text(
            f"Pattern: {fix.pattern}  |  Confidence: {fix.confidence.value}  "
            f"{'|  ⚠ Breaking change' if fix.breaking_change else ''}",
            style="dim"
        ))
        if fix.diff:
            rows.append(Syntax(fix.diff, "diff", theme="monokai"))
        if fix.test_suggestion:
            rows.append(Rule(style="dim"))
            rows.append(Text("Test suggestion:", style="dim"))
            rows.append(Syntax(fix.test_suggestion, "c", theme="monokai"))
        rows.append(Rule(style="dim"))

    if analysis.best_practices:
        rows.append(Text("Best Practices", style="bold cyan"))
        for bp in analysis.best_practices:
            rows.append(Text(f"• {bp.title}", style="bold"))
            rows.append(Text(f"  {bp.explanation}", style="dim"))
            if bp.example:
                rows.append(Syntax(bp.example, "c", theme="monokai"))

    return Panel(
        Group(*rows),
        title="[bold green]Fixes & Best Practices[/]",
        border_style="green", box=box.ROUNDED,
    )


# ---------------------------------------------------------------------------
# Interactive step-through debugger
# ---------------------------------------------------------------------------

class InteractiveTUI:
    """Full interactive TUI for the guided fix session."""

    def __init__(self, debugger: InteractiveDebugger):
        self.dbg = debugger

    def _render_step_header(self, step: DebugStep) -> Panel:
        total   = self.dbg.total_steps()
        current = self.dbg.session.current_step + 1

        prog = Progress(
            TextColumn("[cyan]Step {task.completed}/{task.total}"),
            BarColumn(bar_width=40, complete_style="cyan"),
            console=console,
        )
        task = prog.add_task("", total=total, completed=current - 1)

        info = Table.grid(padding=(0, 2))
        info.add_column(style="bold cyan", width=14)
        info.add_column()
        info.add_row("Step",        f"{current} of {total}")
        info.add_row("Title",       f"[bold]{step.title}[/]")
        info.add_row("Description", step.description)
        if step.validation:
            info.add_row("Validate with", f"[dim]$ {step.validation}[/]")

        return Panel(
            Group(prog, Rule(style="dim"), info),
            title=f"[bold cyan]Step {current}/{total}[/]",
            border_style="cyan", box=box.ROUNDED,
        )

    def _render_step_code(self, step: DebugStep) -> Panel | None:
        if not step.code_before and not step.code_after:
            return None
        rows = []
        if step.code_before:
            rows.append(Text("Before:", style="bold red"))
            rows.append(Syntax(step.code_before, "c", theme="monokai"))
        if step.code_after:
            rows.append(Text("After:", style="bold green"))
            rows.append(Syntax(step.code_after, "c", theme="monokai"))
        if step.explanation:
            rows.append(Rule(style="dim"))
            rows.append(Text(step.explanation, style="italic"))
        return Panel(
            Group(*rows),
            title="[bold]Code Change[/]",
            border_style="yellow", box=box.ROUNDED,
        )

    def _command_menu(self) -> Panel:
        cmds = (
            "[bold cyan]a[/]pply  "
            "[bold cyan]v[/]alidate  "
            "[bold cyan]e[/]xplain  "
            "[bold cyan]c[/]hat  "
            "a[bold cyan]lt[/]ernative  "
            "[bold cyan]n[/]ext  "
            "[bold cyan]b[/]ack  "
            "[bold cyan]s[/]kip  "
            "[bold cyan]r[/]ollback  "
            "[bold cyan]q[/]uit"
        )
        return Panel(cmds, border_style="dim", box=box.SIMPLE)

    async def run(self):
        """Main interactive loop."""
        console.clear()
        print_banner()
        await self.dbg.start()

        console.print(Panel(
            Text(
                f"Starting guided fix for: {self.dbg.error.bug_type.value}\n"
                f"Git branch: {self.dbg.session.git_branch or 'none (no git repo)'}\n"
                f"Steps: {self.dbg.total_steps()}",
                style="cyan"
            ),
            title="[bold]Interactive Debug Session[/]",
            border_style="cyan",
        ))
        console.print()

        while not self.dbg.is_complete():
            step = self.dbg.current_step
            if not step:
                break

            console.print(self._render_step_header(step))
            code_panel = self._render_step_code(step)
            if code_panel:
                console.print(code_panel)
            console.print(self._command_menu())

            raw = Prompt.ask("[bold cyan]Command[/]", default="n").strip().lower()
            # Accept both single-letter shortcuts and full words/phrases
            def _match(raw, *patterns):
                return raw in patterns or any(raw == p[0] for p in patterns if p)
            if raw.startswith("a") and not raw.startswith("alt"):
                cmd = "a"
            elif raw.startswith("alt"):
                cmd = "alt"
            elif raw.startswith("v"):
                cmd = "v"
            elif raw.startswith("e"):
                cmd = "e"
            elif raw.startswith("c"):
                cmd = "c"
            elif raw in ("n", "next", "next step", ""):
                cmd = "n"
            elif raw.startswith("b"):
                cmd = "b"
            elif raw.startswith("s") and not raw.startswith("sk") == False:
                cmd = "s"
            elif raw.startswith("r"):
                cmd = "r"
            elif raw.startswith("q"):
                cmd = "q"
            else:
                cmd = raw  # pass through

            if cmd == "a":
                with console.status("[cyan]Applying patch...[/]"):
                    ok, msg = await self.dbg.apply_current_step()
                if ok:
                    console.print(f"[green]✓ {msg}[/]")
                else:
                    console.print(f"[red]✗ {msg}[/]")

            elif cmd == "v":
                with console.status("[cyan]Running validation...[/]"):
                    ok, out = await self.dbg.validate_current_step()
                style = "green" if ok else "red"
                console.print(Panel(
                    Text(out[:2000], style="dim"),
                    title=f"[{style}]{'PASSED' if ok else 'FAILED'}[/]",
                    border_style=style,
                ))

            elif cmd == "e":
                console.print(Panel("", title="[purple]AI Explanation[/]", border_style="purple"))
                async for token in self.dbg.explain_current_step():
                    console.print(token, end="")
                console.print()

            elif cmd == "c":
                user_msg = Prompt.ask("[bold purple]Ask AI[/]").strip()
                if user_msg:
                    console.print()
                    async for token in self.dbg.chat(user_msg):
                        console.print(token, end="")
                    console.print("\n")

            elif cmd == "alt":
                console.print()
                async for token in self.dbg.suggest_alternative():
                    console.print(token, end="")
                console.print("\n")

            elif cmd == "n":
                self.dbg.advance()

            elif cmd == "b":
                self.dbg.go_back()

            elif cmd == "s":
                self.dbg.skip_step()
                console.print("[dim]Step skipped.[/]")

            elif cmd == "r":
                if Confirm.ask("[bold red]Roll back ALL changes?[/]"):
                    files = await self.dbg.rollback()
                    console.print(f"[yellow]Rolled back: {', '.join(files)}[/]")

            elif cmd == "q":
                if Confirm.ask("[yellow]Exit session? Uncommitted changes will remain.[/]"):
                    break

            console.print()

        # Session complete
        if self.dbg.is_complete():
            summary = self.dbg.summary()
            console.print(Panel(
                Text(
                    f"✓ All {summary['total_steps']} steps complete!\n"
                    f"  Completed: {summary['completed']}  "
                    f"Skipped: {summary['skipped']}\n"
                    f"  Branch: {summary['git_branch'] or 'none'}",
                    style="green"
                ),
                title="[bold green]Session Complete[/]",
                border_style="green",
            ))

            if summary["git_branch"]:
                if Confirm.ask("[bold green]Commit the fix?[/]"):
                    ok = await self.dbg.commit_fix()
                    if ok:
                        console.print(f"[green]✓ Committed to {summary['git_branch']}[/]")
                    else:
                        console.print("[red]Commit failed — commit manually.[/]")


# ---------------------------------------------------------------------------
# Summary / report
# ---------------------------------------------------------------------------

def render_scan_summary(result: ScanResult) -> Panel:
    rows = []

    # Stats grid
    stats = Table.grid(padding=(0, 4))
    stats.add_row(
        f"[bold red]{result.error_count_by_severity.get('critical', 0)}[/] critical",
        f"[red]{result.error_count_by_severity.get('high', 0)}[/] high",
        f"[yellow]{result.error_count_by_severity.get('medium', 0)}[/] medium",
        f"[cyan]{result.error_count_by_severity.get('low', 0)}[/] low",
        f"[dim]{result.error_count_by_severity.get('info', 0)}[/] info",
        f"[bold]{sum(result.error_count_by_severity.values())}[/] total",
    )
    rows.append(stats)
    rows.append(Rule(style="dim"))

    if result.total_bytes_leaked:
        rows.append(Text(
            f"Total memory leaked: {result.total_bytes_leaked:,} bytes",
            style="bold red"
        ))

    if result.duration_ms:
        rows.append(Text(f"Duration: {result.duration_ms / 1000:.1f}s", style="dim"))

    return Panel(
        Group(*rows),
        title="[bold]Scan Summary[/]",
        border_style="cyan", box=box.ROUNDED,
    )
