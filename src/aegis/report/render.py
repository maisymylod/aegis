"""Render the red-team / blue-team scoreboard."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..harness import Scoreboard


def format_scoreboard(board: "Scoreboard") -> str:
    lines = [
        f"Red-team / blue-team scoreboard (run {board.run_id}, backend {board.backend})",
        f"corpus: {board.corpus_size} attack cases",
        "",
        f"  defenses OFF : {board.off.succeeded}/{board.off.total} attacks succeeded "
        f"({board.off.success_rate:.0%} success, {board.off.block_rate:.0%} blocked)",
        f"  defenses ON  : {board.on.succeeded}/{board.on.total} attacks succeeded "
        f"({board.on.success_rate:.0%} success, {board.on.block_rate:.0%} blocked)",
        "",
        "  per-class (defenses off):",
    ]
    for name, score in board.off.by_class.items():
        lines.append(f"    {name:<20} {score.succeeded}/{score.total} succeed")
    lines.append("")
    lines.append("  per-defense, each alone (block rate):")
    for name, score in board.per_defense.items():
        lines.append(f"    {name:<20} blocks {score.block_rate:.0%}")
    return "\n".join(lines)


def scoreboard_markdown(board: "Scoreboard") -> str:
    rows = "\n".join(
        f"| {name} | {s.succeeded}/{s.total} | {s.success_rate:.0%} |"
        for name, s in board.off.by_class.items()
    )
    per_def = "\n".join(
        f"| {name} | {s.block_rate:.0%} |" for name, s in board.per_defense.items()
    )
    return f"""# Attack-surface report — run {board.run_id}

Backend: {board.backend}. Corpus: {board.corpus_size} cases.

| Configuration | Attacks succeeded | Block rate |
|---|---|---|
| defenses off | {board.off.succeeded}/{board.off.total} | {board.off.block_rate:.0%} |
| defenses on | {board.on.succeeded}/{board.on.total} | {board.on.block_rate:.0%} |

## Per attack class (defenses off)

| Class | Succeeded | Success rate |
|---|---|---|
{rows}

## Per defense, each alone

| Defense | Block rate |
|---|---|
{per_def}
"""
