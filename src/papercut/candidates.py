from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import product
from pathlib import Path
import string

DEFAULT_SEARCH_LIMIT = 1_000_000
NUMERIC_SUFFIXES = ("1", "12", "123", "1234")
YEAR_SUFFIXES = ("2024", "2025", "2026")
SUBSTITUTIONS = (("a", "@"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "$"))
COMMON_SYMBOLS = "!@#$%^&*"
MASK_SETS = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": COMMON_SYMBOLS,
}
CHARSETS = {
    "digits": string.digits,
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "letters": string.ascii_letters,
    "alnum": string.ascii_letters + string.digits,
    "symbols": COMMON_SYMBOLS,
}


class CandidateSourceError(RuntimeError):
    """Raised when candidates cannot be read from their source."""


class CandidateOptionError(ValueError):
    """Raised when candidate-generation options are invalid."""


class SearchSpaceLimitError(CandidateOptionError):
    """Raised when a candidate space exceeds its configured safety limit."""


def _enforce_limit(total: int, limit: int) -> None:
    if limit < 1:
        raise CandidateOptionError("max candidates must be at least 1")
    if total > limit:
        raise SearchSpaceLimitError(
            f"search space has {total:,} candidates; "
            f"increase --max-candidates above the configured limit of {limit:,}"
        )


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


def _parse_mask(mask: str) -> tuple[str, ...]:
    parts: list[str] = []
    index = 0
    while index < len(mask):
        if mask[index] != "?":
            parts.append(mask[index])
            index += 1
            continue
        if index + 1 >= len(mask):
            raise CandidateOptionError("mask cannot end with '?'")
        token = mask[index + 1]
        if token not in MASK_SETS:
            raise CandidateOptionError(
                f"unsupported mask token '?{token}'; use ?l, ?u, ?d, or ?s"
            )
        parts.append(MASK_SETS[token])
        index += 2
    return tuple(parts)


def mask_candidate_count(mask: str) -> int:
    total = 1
    for characters in _parse_mask(mask):
        total *= len(characters)
    return total


def mask_candidates(
    mask: str, *, max_candidates: int = DEFAULT_SEARCH_LIMIT
) -> Iterator[str]:
    parts = _parse_mask(mask)
    total = 1
    for characters in parts:
        total *= len(characters)
    _enforce_limit(total, max_candidates)
    return ("".join(candidate) for candidate in product(*parts))


def _validate_bruteforce_options(
    charset: str, min_length: int, max_length: int
) -> str:
    if charset not in CHARSETS:
        choices = ", ".join(CHARSETS)
        raise CandidateOptionError(
            f"unsupported character set '{charset}'; choose from {choices}"
        )
    if min_length < 1:
        raise CandidateOptionError("minimum length must be at least 1")
    if max_length < min_length:
        raise CandidateOptionError(
            "maximum length must be greater than or equal to minimum length"
        )
    return CHARSETS[charset]


def bruteforce_candidate_count(
    charset: str, min_length: int, max_length: int
) -> int:
    characters = _validate_bruteforce_options(charset, min_length, max_length)
    return sum(len(characters) ** length for length in range(min_length, max_length + 1))


def bruteforce_candidates(
    charset: str,
    min_length: int,
    max_length: int,
    *,
    max_candidates: int = DEFAULT_SEARCH_LIMIT,
) -> Iterator[str]:
    characters = _validate_bruteforce_options(charset, min_length, max_length)
    total = sum(
        len(characters) ** length for length in range(min_length, max_length + 1)
    )
    _enforce_limit(total, max_candidates)

    def generate() -> Iterator[str]:
        for length in range(min_length, max_length + 1):
            for candidate in product(characters, repeat=length):
                yield "".join(candidate)

    return generate()
