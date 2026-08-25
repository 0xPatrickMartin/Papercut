from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)
