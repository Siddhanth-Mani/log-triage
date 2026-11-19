"""Command line entry point: `log-triage FILE [FILE ...]` or `python -m logtriage ...`."""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Optional

from . import __version__
from .detectors import SEVERITIES, Settings, run_all
from .parsers import ParseResult, parse_lines
from .report import at_least, to_html, to_json, to_text

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def read_lines(path: str) -> Iterator[str]:
    if path == "-":
        yield from sys.stdin
        return
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
        yield from fh


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="log-triage",
        description="Read SSH auth logs and web access logs and report brute force, account compromise, "
                    "scanners and injection attempts.",
        epilog="Exit status: 0 nothing at or above --fail-on, 2 findings at or above --fail-on, 1 error.")
    ap.add_argument("files", nargs="+", help="log files (auth.log, secure, access.log; .gz is fine; - for stdin)")
    ap.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    ap.add_argument("-o", "--output", help="write the report here instead of standard output")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year for classic syslog timestamps, which have none (default: this year)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this (default: low)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high",
                    help="exit with status 2 if anything this severe is found (default: high)")
    ap.add_argument("--ignore", action="append", default=[], metavar="CIDR",
                    help="skip activity from this network, e.g. your office or monitoring (repeatable)")
    ap.add_argument("--ssh-failures", type=int, default=Settings.ssh_failures, metavar="N",
                    help="failed logins within --ssh-window that count as brute force (default: %(default)s)")
    ap.add_argument("--ssh-window", type=int, default=10, metavar="MIN", help="minutes (default: %(default)s)")
    ap.add_argument("--web-errors", type=int, default=Settings.web_errors, metavar="N",
                    help="4xx responses within --web-window that count as a scanner (default: %(default)s)")
    ap.add_argument("--web-window", type=int, default=5, metavar="MIN", help="minutes (default: %(default)s)")
    ap.add_argument("--note", default="", help="a line of context printed under the heading of the HTML report")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    ap.add_argument("--version", action="version", version=f"log-triage {__version__}")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        nets = [ipaddress.ip_network(c, strict=False) for c in args.ignore]
    except ValueError as exc:
        print(f"log-triage: --ignore: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for name, value in (("--ssh-failures", args.ssh_failures), ("--ssh-window", args.ssh_window),
                        ("--web-errors", args.web_errors), ("--web-window", args.web_window)):
        if value < 1:
            print(f"log-triage: {name} must be 1 or more", file=sys.stderr)
            return EXIT_ERROR

    settings = Settings(ssh_failures=args.ssh_failures, ssh_window=timedelta(minutes=args.ssh_window),
                        web_errors=args.web_errors, web_window=timedelta(minutes=args.web_window),
                        ignore_networks=nets)
    result = ParseResult()
    for path in args.files:
        try:
            parse_lines(read_lines(path), args.year, result)
        except OSError as exc:
            print(f"log-triage: cannot read {path}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_ERROR

    findings = run_all(result.auth, result.web, settings)
    shown = at_least(findings, args.min_severity)

    if args.format == "json":
        out = to_json(result, shown)
    elif args.format == "html":
        out = to_html(result, shown, sources=[Path(p).name if p != "-" else "stdin" for p in args.files], note=args.note)
    else:
        color = args.color == "always" or (args.color == "auto" and not args.output and sys.stdout.isatty())
        out = to_text(result, shown, color=color)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Wrote {args.output} ({len(shown)} findings)", file=sys.stderr)
    else:
        sys.stdout.write(out)

    if result.lines and result.skipped == result.lines:
        print("log-triage: no line was recognised as an auth or access log entry", file=sys.stderr)
    return EXIT_FINDINGS if at_least(findings, args.fail_on) else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
