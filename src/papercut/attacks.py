from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from time import perf_counter

from .backends.hashcat import (
    HashcatError,
    hashcat_available,
    run_bruteforce_hashcat,
    run_mask_hashcat,
    run_wordlist_hashcat,
)
from .candidates import (
    DEFAULT_SEARCH_LIMIT,
    bruteforce_candidate_count,
    bruteforce_candidates,
    expand_mutations,
    mask_candidate_count,
    mask_candidates,
    wordlist_candidates,
)
from .hash_extract import UnsupportedEncryptionError
from .models import AuditResult, Progress
from .pdf import inspect_pdf, verify_password

PasswordVerifier = Callable[[Path, str], bool]
Clock = Callable[[], float]
ProgressCallback = Callable[[Progress], None]


class AttackInputError(RuntimeError):
    """Raised when the target is unsuitable for a password audit."""


def calculate_progress(
    attempted: int, total: int | None, started: float, now: float
) -> Progress:
    elapsed = max(0.0, now - started)
    rate = attempted / elapsed if elapsed > 0 else 0.0
    eta = None
    if total is not None and rate > 0:
        eta = max(0.0, total - attempted) / rate
    return Progress(
        attempted=attempted,
        total=total,
        elapsed=elapsed,
        rate=rate,
        eta=eta,
    )


def run_attack(
    path: Path,
    candidates: Iterable[str],
    *,
    attack: str,
    total: int | None = None,
    progress: ProgressCallback | None = None,
    progress_interval: float = 1.0,
    verifier: PasswordVerifier = verify_password,
    clock: Clock = perf_counter,
) -> AuditResult:
    """Test a candidate stream sequentially and stop at the first match."""
    info = inspect_pdf(path)
    if not info.encrypted:
        raise AttackInputError(f"target PDF is not encrypted: {path}")

    attempted = 0
    started = clock()
    last_report = started
    password: str | None = None
    for candidate in candidates:
        attempted += 1
        if verifier(path, candidate):
            password = candidate
            break
        if progress is not None:
            now = clock()
            if now - last_report >= progress_interval:
                progress(calculate_progress(attempted, total, started, now))
                last_report = now

    final_progress = calculate_progress(attempted, total, started, clock())
    return AuditResult(
        path=path,
        attack=attack,
        found=password is not None,
        password=password,
        attempted=attempted,
        elapsed=final_progress.elapsed,
        rate=final_progress.rate,
        backend="python",
    )


def _prefer_hashcat() -> bool:
    return hashcat_available()


def run_wordlist(
    path: Path,
    wordlist: Path,
    *,
    mutate: bool = False,
    progress: ProgressCallback | None = None,
    progress_interval: float = 1.0,
    verifier: PasswordVerifier = verify_password,
    clock: Clock = perf_counter,
    prefer_hashcat: bool | None = None,
) -> AuditResult:
    use_hashcat = _prefer_hashcat() if prefer_hashcat is None else prefer_hashcat
    if use_hashcat:
        try:
            return run_wordlist_hashcat(path, wordlist, mutate=mutate, clock=clock)
        except UnsupportedEncryptionError:
            # Certificate / unknown handlers cannot use Hashcat or useful PDF password tests.
            raise AttackInputError(
                "PDF encryption is not supported for Hashcat-backed auditing"
            )
        except HashcatError:
            # Fall back to the built-in Python verifier path.
            pass

    candidates = wordlist_candidates(wordlist)
    if mutate:
        candidates = expand_mutations(candidates)
    return run_attack(
        path,
        candidates,
        attack="wordlist+mutations" if mutate else "wordlist",
        progress=progress,
        progress_interval=progress_interval,
        verifier=verifier,
        clock=clock,
    )


def run_mask(
    path: Path,
    mask: str,
    *,
    max_candidates: int = DEFAULT_SEARCH_LIMIT,
    progress: ProgressCallback | None = None,
    progress_interval: float = 1.0,
    verifier: PasswordVerifier = verify_password,
    clock: Clock = perf_counter,
    prefer_hashcat: bool | None = None,
) -> AuditResult:
    use_hashcat = _prefer_hashcat() if prefer_hashcat is None else prefer_hashcat
    if use_hashcat:
        try:
            return run_mask_hashcat(
                path,
                mask,
                max_candidates=max_candidates,
                clock=clock,
            )
        except UnsupportedEncryptionError as exc:
            raise AttackInputError(str(exc)) from exc
        except HashcatError:
            pass

    total = mask_candidate_count(mask)
    candidates = mask_candidates(mask, max_candidates=max_candidates)
    return run_attack(
        path,
        candidates,
        attack="mask",
        total=total,
        progress=progress,
        progress_interval=progress_interval,
        verifier=verifier,
        clock=clock,
    )


def run_bruteforce(
    path: Path,
    charset: str,
    min_length: int,
    max_length: int,
    *,
    max_candidates: int = DEFAULT_SEARCH_LIMIT,
    progress: ProgressCallback | None = None,
    progress_interval: float = 1.0,
    verifier: PasswordVerifier = verify_password,
    clock: Clock = perf_counter,
    prefer_hashcat: bool | None = None,
) -> AuditResult:
    use_hashcat = _prefer_hashcat() if prefer_hashcat is None else prefer_hashcat
    if use_hashcat:
        try:
            return run_bruteforce_hashcat(
                path,
                charset,
                min_length,
                max_length,
                max_candidates=max_candidates,
                clock=clock,
            )
        except UnsupportedEncryptionError as exc:
            raise AttackInputError(str(exc)) from exc
        except HashcatError:
            pass

    total = bruteforce_candidate_count(charset, min_length, max_length)
    candidates = bruteforce_candidates(
        charset,
        min_length,
        max_length,
        max_candidates=max_candidates,
    )
    return run_attack(
        path,
        candidates,
        attack="bruteforce",
        total=total,
        progress=progress,
        progress_interval=progress_interval,
        verifier=verifier,
        clock=clock,
    )
