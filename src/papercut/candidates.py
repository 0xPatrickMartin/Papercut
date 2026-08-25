from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


class CandidateSourceError(RuntimeError):
    """Raised when candidates cannot be read from their source."""


def wordlist_candidates(path: Path) -> Iterator[str]:
    """Yield one password per line without buffering the wordlist."""
    try:
        with path.open("r", encoding="utf-8", newline=None) as stream:
            for line in stream:
                yield line.rstrip("\r\n")
    except (OSError, UnicodeError) as exc:
        raise CandidateSourceError(f"could not read wordlist {path}: {exc}") from exc
