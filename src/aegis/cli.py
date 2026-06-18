"""aegis command-line entry point.

    aegis demo                 run the full self-contained demonstration
    aegis gate --threshold X   CI gate: fail if defenses block < X of the corpus
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import DEFAULT_GATE_THRESHOLD
from .detect.events import write_events
from .harness import run_suite
from .report.render import format_scoreboard, scoreboard_markdown
from .selfcheck import crypto_checks, mtls_checks


def _print_checks(title: str, checks) -> bool:
    print(title)
    all_ok = True
    for c in checks:
        mark = "ok " if c.ok else "FAIL"
        print(f"  [{mark}] {c.label:<22} expected {c.expected:<9} -> {c.actual}")
        all_ok = all_ok and c.ok
    return all_ok


def _demo(args: argparse.Namespace) -> int:
    out = Path(args.out)
    print("=" * 64)
    print("AEGIS — security layer self-check")
    print("=" * 64)
    crypto_ok = _print_checks("Cryptographic command authentication:", crypto_checks())
    print()
    mtls_ok = _print_checks("Mutual TLS (ground station <-> core):", mtls_checks())
    print()

    board = run_suite(run_id=args.run_id)
    print(format_scoreboard(board))
    print()
    print(board.incident.split("\n\n")[0])

    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(scoreboard_markdown(board))
    (out / "incident.md").write_text(board.incident)
    write_events(board.events, out / "events_on.jsonl")
    print(f"\nartifacts written to {out}/")

    if not (crypto_ok and mtls_ok):
        print("\nself-check FAILED", file=sys.stderr)
        return 1
    return 0


def _gate(args: argparse.Namespace) -> int:
    board = run_suite(run_id="gate")
    block = board.on.block_rate
    ok = block >= args.threshold
    print(f"defenses block {block:.0%} of the corpus (threshold {args.threshold:.0%}): "
          f"{'PASS' if ok else 'FAIL'}")
    if not ok:
        print(json.dumps({"block_rate": block, "threshold": args.threshold}), file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the full self-contained demonstration")
    demo.add_argument("--out", default="runs/local")
    demo.add_argument("--run-id", default="local")
    demo.set_defaults(func=_demo)

    gate = sub.add_parser("gate", help="CI gate on the defended block rate")
    gate.add_argument("--threshold", type=float, default=DEFAULT_GATE_THRESHOLD)
    gate.set_defaults(func=_gate)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
