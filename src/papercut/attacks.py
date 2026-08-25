from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from time import perf_counter

from .candidates import wordlist_candidates
from .models import AuditResult
from .pdf import inspect_pdf, verify_password

PasswordVerifier = Callable[[Path, str], bool]
Clock = Callable[[], float]


class AttackInputError(RuntimeError):
    """Raised when the target is unsuitable for a password audit."""


def run_attack(
    path: Path,
    candidates: Iterable[str],
    *,
    attack: str,
    verifier: PasswordVerifier = verify_password,
    clock: Clock = perf_counter,
) -> AuditResult:
    """Test a candidate stream sequentially and stop at the first match."""
    info = inspect_pdf(path)
    if not info.encrypted:
        raise AttackInputError(f"target PDF is not encrypted: {path}")

    attempted = 0
    started = clock()
    password: str | None = None
    for candidate in candidates:
        attempted += 1
        if verifier(path, candidate):
            password = candidate
            break

    elapsed = max(0.0, clock() - started)
    rate = attempted / elapsed if elapsed > 0 else 0.0
    return AuditResult(
        path=path,
        attack=attack,
        found=password is not None,
        password=password,
        attempted=attempted,
        elapsed=elapsed,
        rate=rate,
    )


def run_wordlist(
    path: Path,
    wordlist: Path,
    *,
    verifier: PasswordVerifier = verify_password,
    clock: Clock = perf_counter,
) -> AuditResult:
    return run_attack(
        path,
        wordlist_candidates(wordlist),
        attack="wordlist",
        verifier=verifier,
        clock=clock,
    )
