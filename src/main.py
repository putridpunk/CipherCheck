"""CipherCheck command-line entry point.  Run:  python -m src.main"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__, hashes, history, report
from .analyzer import analyze
from .audit import NoPasswordColumn, audit_file
from .friendly import generate_passphrase
from .i18n import LANGUAGES
from .policy import PRESETS as POLICY_PRESETS
from .policy import generate_compliant, load_file as load_policy_file


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
    src.add_argument("--passphrase", nargs="?", const=5, type=int, metavar="WORDS",
                     help="print a random passphrase of WORDS words (default 5) and exit")
    src.add_argument("--check-update", action="store_true",
                     help="check GitHub for a newer release and exit (contacts github.com; "
                          "only when you pass this flag)")
    src.add_argument("--generate-for-policy", metavar="NAME",
                     help="print a freshly generated password that satisfies a named policy "
                          f"({', '.join(sorted(POLICY_PRESETS))}) and exit; use with --policy-file "
                          "for a custom one")
    p.add_argument("--lang", choices=sorted(LANGUAGES), metavar="CODE",
                   help="plain-language output in this language instead of the technical English "
                        f"report ({', '.join(sorted(LANGUAGES))}); also applies to TXT reports")
    p.add_argument("-j", "--jobs", type=int, metavar="N",
                   help="batch mode: worker processes (default: automatic, up to 8; 1 = single process)")
    p.add_argument("--profile", metavar="TEXT",
                   help="personal information to flag if found in the password (your name, a "
                        "birth date, a pet's name, ...; comma-separated, kept only in memory)")
    pol = p.add_mutually_exclusive_group()
    pol.add_argument("-P", "--policy", choices=sorted(POLICY_PRESETS), metavar="NAME",
                     help="batch mode: check each password against a named policy "
                          f"({', '.join(sorted(POLICY_PRESETS))}) and report pass/fail counts")
    pol.add_argument("--policy-file", type=Path, metavar="PATH",
                     help="batch mode (or with --generate-for-policy): a custom policy as a small "
                          "JSON file (see README) instead of a named preset")
    p.add_argument("-r", "--report", type=Path, metavar="PATH", help="write a report to PATH")
    p.add_argument("--format", choices=sorted(set(report.RENDERERS) | set(report.AGG_RENDERERS)),
                   help="report format (default: from extension)")
    p.add_argument("-q", "--quiet", action="store_true", help="do not print the report to the terminal")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _resolve_policy(args: argparse.Namespace):
    """The Policy to use, from -P/--policy or --policy-file, or None if neither was given."""
    if args.policy_file:
        return load_policy_file(args.policy_file)
    if args.policy:
        return POLICY_PRESETS[args.policy]
    return None


def _batch(path: Path, args: argparse.Namespace) -> int:
    show = sys.stderr.isatty() and not args.quiet
    try:
        policy = _resolve_policy(args)
    except (OSError, ValueError) as exc:
        print(f"error: could not read the policy file: {exc}", file=sys.stderr)
        return 2

    def progress(lines: int, fraction: float) -> None:
        if show:
            print(f"\rAnalysing... {lines:,} passwords ({100 * fraction:.0f}%)", end="", file=sys.stderr, flush=True)

    try:
        agg = audit_file(path, workers=args.jobs, progress=progress, policy=policy)
    except NoPasswordColumn as exc:
        print(f"error: {path}: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    if show:
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr)
    assert agg is not None  # only None when cancelled, and nothing cancels the CLI
    history.record(agg["total"], agg["average_estimated_bits"], report.weak_percent(agg))
    if not args.quiet:
        print(report.aggregate_friendly(agg, args.lang) if args.lang else report.aggregate_text(agg))
    if args.report:
        try:
            out = report.write_aggregate(agg, args.report, args.format, args.lang)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # non-Latin scripts on Windows consoles
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8")
            except ValueError:
                pass
    args = build_parser().parse_args(argv)

    if args.passphrase is not None:
        if not 3 <= args.passphrase <= 12:
            print("error: --passphrase takes between 3 and 12 words", file=sys.stderr)
            return 2
        print(generate_passphrase(args.passphrase))
        return 0

    if args.hash is not None:
        print(hashes.to_text(args.hash, args.lang or "en"))
        return 0

    if args.generate_for_policy is not None:
        if args.policy_file:
            try:
                policy = load_policy_file(args.policy_file)
            except (OSError, ValueError) as exc:
                print(f"error: could not read the policy file: {exc}", file=sys.stderr)
                return 2
        elif args.generate_for_policy in POLICY_PRESETS:
            policy = POLICY_PRESETS[args.generate_for_policy]
        else:
            print(f"error: unknown policy {args.generate_for_policy!r} "
                  f"(use one of {', '.join(sorted(POLICY_PRESETS))}, or --policy-file)", file=sys.stderr)
            return 2
        print(generate_compliant(policy))
        return 0

    if args.check_update:
        from . import update_check
        try:
            update_result = update_check.check_for_update()
        except update_check.UpdateCheckError as exc:
            print(f"error: could not check for updates: {exc}", file=sys.stderr)
            return 2
        if update_result is None:
            print(f"CipherCheck {__version__} is up to date.")
        else:
            version, url = update_result
            print(f"A newer version is available: v{version}\n{url}")
        return 0

    if args.file:
        return _batch(args.file, args)

    profile = [t for t in args.profile.split(",") if t.strip()] if args.profile else None

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

    result = analyze(password, profile=profile)
    if not args.quiet:
        print(report.to_friendly_text(result, args.lang) if args.lang else report.to_text(result))
    if args.report:
        try:
            out = report.write_report(result, args.report, args.format, args.lang)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
