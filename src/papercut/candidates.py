from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

NUMERIC_SUFFIXES = ("1", "12", "123", "1234")
YEAR_SUFFIXES = ("2024", "2025", "2026")
SUBSTITUTIONS = (("a", "@"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "$"))


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


def mutation_candidates(base: str) -> Iterator[str]:
    """Yield a bounded, deterministic set of unique variants for one password."""
    seen: set[str] = set()

    def unique(candidate: str) -> Iterator[str]:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate

    yield from unique(base)
    yield from unique(base[:1].upper() + base[1:])
    yield from unique(base.upper())
    yield from unique(base.lower())

    for suffix in NUMERIC_SUFFIXES:
        yield from unique(base + suffix)
    for year in YEAR_SUFFIXES:
        yield from unique(base + year)

    combined = base
    for character, replacement in SUBSTITUTIONS:
        substituted = base.replace(character, replacement)
        yield from unique(substituted)
        combined = combined.replace(character, replacement)
    yield from unique(combined)


def expand_mutations(candidates: Iterable[str]) -> Iterator[str]:
    """Apply bounded mutations to a candidate stream without buffering it."""
    for candidate in candidates:
        yield from mutation_candidates(candidate)
