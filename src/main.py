"""CipherCheck command-line entry point.  Run:  python -m src.main"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import __version__, hashes, report
from .analyzer import analyze


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ciphercheck",
        description="Local, offline password security auditor. "
                    "With no input option you are prompted (input is hidden).")
    src = p.add_mutually_exclusive_group()
    src.add_argument("-p", "--password",
                     help="password to audit (INSECURE: visible in shell history / process list)")
    src.add_argument("--stdin", action="store_true", help="read one password from standard input")
    src.add_argument("-f", "--file", type=Path,
                     help="batch mode: audit one password per line (use synthetic data) "
                          "and print aggregate statistics only")
    src.add_argument("--hash", metavar="HASH",
                     help="identify a hash format and explain its security properties (no cracking)")
    p.add_argument("-r", "--report", type=Path, metavar="PATH",
                   help="write a report to PATH")
    p.add_argument("--format", choices=sorted(report.RENDERERS), help="report format (default: from extension)")
    p.add_argument("-q", "--quiet", action="store_true", help="do not print the report to the terminal")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _batch(path: Path, args: argparse.Namespace) -> int:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            analyses = [analyze(line.rstrip("\r\n")) for line in fh if line.strip()]
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    agg = report.aggregate(analyses)
    if not args.quiet:
        print(report.aggregate_text(agg))
    if args.report:
        try:
            out = report.write_aggregate(agg, args.report, args.format)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.hash is not None:
        print(hashes.to_text(args.hash))
        return 0

    if args.file:
        return _batch(args.file, args)

    if args.password is not None:
        print("warning: passwords passed on the command line may be stored in shell history.",
              file=sys.stderr)
        password = args.password
    elif args.stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        try:
            password = getpass.getpass("Password to audit (hidden): ")
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return 130

    result = analyze(password)
    if not args.quiet:
        print(report.to_text(result))
    if args.report:
        try:
            out = report.write_report(result, args.report, args.format)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
