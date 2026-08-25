from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

from .attacks import AttackInputError, run_wordlist
from .candidates import CandidateSourceError
from .models import AuditResult
from .pdf import PdfInspectionError, inspect_pdf


def _display(value: object | None) -> str:
    return "not specified" if value is None else str(value)


def _inspect(args: argparse.Namespace) -> int:
    try:
        info = inspect_pdf(args.pdf)
    except PdfInspectionError as exc:
        print(f"Papercut: error: {exc}")
        return 2

    print(f"File: {info.path}")
    print(f"Encrypted: {'yes' if info.encrypted else 'no'}")
    if info.encrypted:
        print(f"Security handler: {_display(info.handler)}")
        print(f"Subfilter: {_display(info.subfilter)}")
        print(f"Algorithm version: {_display(info.version)}")
        print(f"Security revision: {_display(info.revision)}")
        print(f"Key length: {_display(info.key_bits)} bits")
        print(f"Permissions: {_display(info.permissions)}")
        print(f"Metadata encrypted: {_display(info.encrypt_metadata)}")
    return 0


def _print_audit_result(result: AuditResult) -> None:
    status = "SUCCESS" if result.found else "NOT FOUND"
    print(f"Papercut wordlist: {status}")
    if result.password is not None:
        print(f"Password: {result.password}")
    print(f"Attempted: {result.attempted}")
    print(f"Elapsed: {result.elapsed:.3f}s")
    print(f"Rate: {result.rate:.1f} attempts/s")


def _wordlist(args: argparse.Namespace) -> int:
    try:
        result = run_wordlist(args.pdf, args.wordlist, mutate=args.mutate)
    except (AttackInputError, CandidateSourceError, PdfInspectionError) as exc:
        print(f"Papercut: error: {exc}", file=sys.stderr)
        return 2

    _print_audit_result(result)
    return 0 if result.found else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="papercut",
        description="Papercut — authorized PDF password-strength auditing.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser(
        "inspect", help="inspect a PDF's encryption settings"
    )
    inspect_parser.add_argument("pdf", type=Path, help="path to the target PDF")
    inspect_parser.set_defaults(handler=_inspect)

    wordlist_parser = subparsers.add_parser(
        "wordlist", help="test passwords from a wordlist"
    )
    wordlist_parser.add_argument("pdf", type=Path, help="path to the target PDF")
    wordlist_parser.add_argument(
        "wordlist", type=Path, help="path to a UTF-8 wordlist"
    )
    wordlist_parser.add_argument(
        "--mutate",
        action="store_true",
        help="test a bounded set of common variants for each candidate",
    )
    wordlist_parser.set_defaults(handler=_wordlist)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)
