from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from ..candidates import (
    CHARSETS,
    COMMON_SYMBOLS,
    SearchSpaceLimitError,
    bruteforce_candidate_count,
    expand_mutations,
    mask_candidate_count,
    wordlist_candidates,
)
from ..hash_extract import (
    HashExtractionError,
    UnsupportedEncryptionError,
    extract_pdf_hash,
    hashcat_mode_for_hash,
)
from ..models import AuditResult

Clock = Callable[[], float]
Runner = Callable[[list[str], Path], "HashcatProcessResult"]


class HashcatError(RuntimeError):
    """Raised when Hashcat cannot be used for an attack."""


@dataclass(frozen=True)
class HashcatProcessResult:
    returncode: int
    stdout: str
    stderr: str


_HASHCAT_NAMES = ("hashcat", "hashcat.bin")
_SPEED_RE = re.compile(
    r"Speed\.Dev.#\d+\.+:\s*([\d.]+)\s*([kKmMgGtT]?)H/s"
)
_PROGRESS_RE = re.compile(r"Progress\.+:\s*(\d+)/(\d+)")


def find_hashcat() -> Path | None:
    for name in _HASHCAT_NAMES:
        located = shutil.which(name)
        if located:
            return Path(located)
    return None


def hashcat_available() -> bool:
    return find_hashcat() is not None


def _parse_rate(text: str) -> float | None:
    match = _SPEED_RE.search(text)
    if not match:
        return None
    value = float(match.group(1))
    suffix = match.group(2).lower()
    multipliers = {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}
    return value * multipliers.get(suffix, 1.0)


def _parse_attempted(text: str) -> int | None:
    match = _PROGRESS_RE.search(text)
    if not match:
        return None
    return int(match.group(1))


def _read_recovered_password(outfile: Path) -> str | None:
    if not outfile.exists():
        return None
    for line in outfile.read_text(encoding="utf-8", errors="replace").splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if candidate.startswith("$pdf$") and ":" in candidate:
            return candidate.rsplit(":", maxsplit=1)[-1]
        return candidate
    return None


def _default_runner(command: list[str], workdir: Path) -> HashcatProcessResult:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        cwd=str(workdir),
    )
    return HashcatProcessResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def translate_papercut_mask(mask: str) -> tuple[list[str], str]:
    """Map Papercut mask tokens to Hashcat, keeping ?s bounded to COMMON_SYMBOLS."""
    extras: list[str] = []
    translated: list[str] = []
    index = 0
    custom_symbols = False
    while index < len(mask):
        if mask[index] != "?":
            translated.append(mask[index])
            index += 1
            continue
        if index + 1 >= len(mask):
            raise HashcatError("mask cannot end with '?'")
        token = mask[index + 1]
        if token == "s":
            if not custom_symbols:
                extras.extend(["-1", COMMON_SYMBOLS])
                custom_symbols = True
            translated.append("?1")
        elif token in {"l", "u", "d"}:
            translated.append(f"?{token}")
        else:
            raise HashcatError(
                f"unsupported mask token '?{token}'; use ?l, ?u, ?d, or ?s"
            )
        index += 2
    return extras, "".join(translated)


def bruteforce_mask_args(
    charset: str, min_length: int, max_length: int
) -> tuple[list[str], str]:
    if charset not in CHARSETS:
        raise HashcatError(f"unsupported character set '{charset}'")
    if min_length < 1 or max_length < min_length:
        raise HashcatError("invalid brute-force length bounds")

    extras: list[str] = [
        "--increment",
        f"--increment-min={min_length}",
        f"--increment-max={max_length}",
    ]
    if charset == "digits":
        token = "?d"
    elif charset == "lowercase":
        token = "?l"
    elif charset == "uppercase":
        token = "?u"
    elif charset == "letters":
        extras.extend(["-1", "?l?u"])
        token = "?1"
    elif charset == "alnum":
        extras.extend(["-1", "?l?u?d"])
        token = "?1"
    else:  # symbols
        extras.extend(["-1", COMMON_SYMBOLS])
        token = "?1"
    return extras, token * max_length


def build_hashcat_command(
    *,
    hashcat: Path,
    mode: int,
    attack_mode: int,
    hash_file: Path,
    outfile: Path,
    session: str,
    wordlist: Path | None = None,
    mask: str | None = None,
    extra: list[str] | None = None,
) -> list[str]:
    command = [
        str(hashcat),
        "-m",
        str(mode),
        "-a",
        str(attack_mode),
        "--quiet",
        "--potfile-disable",
        "--restore-disable",
        f"--session={session}",
        "-o",
        str(outfile),
        "--outfile-format=2",
    ]
    if extra:
        command.extend(extra)
    command.append(str(hash_file))
    if attack_mode == 0:
        if wordlist is None:
            raise HashcatError("wordlist attack requires a wordlist path")
        command.append(str(wordlist))
    elif attack_mode == 3:
        if mask is None:
            raise HashcatError("mask attack requires a mask")
        command.append(mask)
    else:
        raise HashcatError(f"unsupported Hashcat attack mode {attack_mode}")
    return command


def _write_hash_file(directory: Path, pdf_hash: str) -> Path:
    path = directory / "target.hash"
    # Hash files intentionally contain no plaintext passwords.
    path.write_text(pdf_hash + "\n", encoding="utf-8")
    return path


def _materialize_candidates(
    directory: Path, candidates: Iterable[str]
) -> Path:
    path = directory / "candidates.wordlist"
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for candidate in candidates:
            stream.write(candidate)
            stream.write("\n")
    return path


def _run_hashcat_job(
    *,
    path: Path,
    attack: str,
    total: int | None,
    build_command: Callable[[Path, Path, Path, str, int], list[str]],
    runner: Runner = _default_runner,
    clock: Clock = perf_counter,
) -> AuditResult:
    hashcat = find_hashcat()
    if hashcat is None:
        raise HashcatError(
            "Hashcat was not found on PATH; install Hashcat or rely on the Python fallback"
        )

    try:
        pdf_hash = extract_pdf_hash(path)
        mode = hashcat_mode_for_hash(pdf_hash)
    except UnsupportedEncryptionError:
        raise
    except HashExtractionError as exc:
        raise HashcatError(str(exc)) from exc

    with tempfile.TemporaryDirectory(prefix="papercut-hashcat-") as tmp:
        workdir = Path(tmp)
        hash_file = _write_hash_file(workdir, pdf_hash)
        outfile = workdir / "recovered.txt"
        session = f"papercut_{uuid.uuid4().hex[:12]}"
        command = build_command(hashcat, hash_file, outfile, session, mode)

        started = clock()
        try:
            process = runner(command, workdir)
        except OSError as exc:
            raise HashcatError(f"could not execute Hashcat: {exc}") from exc
        elapsed = max(0.0, clock() - started)

        if process.returncode not in {0, 1}:
            detail = (process.stderr or process.stdout or "unknown error").strip()
            raise HashcatError(f"Hashcat failed (exit {process.returncode}): {detail}")

        password = _read_recovered_password(outfile)
        combined = f"{process.stdout}\n{process.stderr}"
        attempted = _parse_attempted(combined)
        if attempted is None:
            if password is not None:
                attempted = 1
            elif total is not None:
                attempted = total
            else:
                attempted = 0
        rate = _parse_rate(combined)
        if rate is None:
            rate = attempted / elapsed if elapsed > 0 else 0.0

        return AuditResult(
            path=path,
            attack=attack,
            found=password is not None,
            password=password,
            attempted=attempted,
            elapsed=elapsed,
            rate=rate,
            backend="hashcat",
        )


def run_wordlist_hashcat(
    path: Path,
    wordlist: Path,
    *,
    mutate: bool = False,
    runner: Runner = _default_runner,
    clock: Clock = perf_counter,
) -> AuditResult:
    attack = "wordlist+mutations" if mutate else "wordlist"

    def build(
        hashcat: Path, hash_file: Path, outfile: Path, session: str, mode: int
    ) -> list[str]:
        workdir = hash_file.parent
        if mutate:
            candidates = expand_mutations(wordlist_candidates(wordlist))
            candidate_file = _materialize_candidates(workdir, candidates)
        else:
            candidate_file = wordlist
        return build_hashcat_command(
            hashcat=hashcat,
            mode=mode,
            attack_mode=0,
            hash_file=hash_file,
            outfile=outfile,
            session=session,
            wordlist=candidate_file,
        )

    return _run_hashcat_job(
        path=path,
        attack=attack,
        total=None,
        build_command=build,
        runner=runner,
        clock=clock,
    )


def run_mask_hashcat(
    path: Path,
    mask: str,
    *,
    max_candidates: int,
    runner: Runner = _default_runner,
    clock: Clock = perf_counter,
) -> AuditResult:
    total = mask_candidate_count(mask)
    if total > max_candidates:
        raise SearchSpaceLimitError(
            f"search space has {total:,} candidates; "
            f"increase --max-candidates above the configured limit of {max_candidates:,}"
        )
    extras, translated = translate_papercut_mask(mask)

    def build(
        hashcat: Path, hash_file: Path, outfile: Path, session: str, mode: int
    ) -> list[str]:
        return build_hashcat_command(
            hashcat=hashcat,
            mode=mode,
            attack_mode=3,
            hash_file=hash_file,
            outfile=outfile,
            session=session,
            mask=translated,
            extra=extras,
        )

    return _run_hashcat_job(
        path=path,
        attack="mask",
        total=total,
        build_command=build,
        runner=runner,
        clock=clock,
    )


def run_bruteforce_hashcat(
    path: Path,
    charset: str,
    min_length: int,
    max_length: int,
    *,
    max_candidates: int,
    runner: Runner = _default_runner,
    clock: Clock = perf_counter,
) -> AuditResult:
    total = bruteforce_candidate_count(charset, min_length, max_length)
    if total > max_candidates:
        raise SearchSpaceLimitError(
            f"search space has {total:,} candidates; "
            f"increase --max-candidates above the configured limit of {max_candidates:,}"
        )
    extras, mask = bruteforce_mask_args(charset, min_length, max_length)

    def build(
        hashcat: Path, hash_file: Path, outfile: Path, session: str, mode: int
    ) -> list[str]:
        return build_hashcat_command(
            hashcat=hashcat,
            mode=mode,
            attack_mode=3,
            hash_file=hash_file,
            outfile=outfile,
            session=session,
            mask=mask,
            extra=extras,
        )

    return _run_hashcat_job(
        path=path,
        attack="bruteforce",
        total=total,
        build_command=build,
        runner=runner,
        clock=clock,
    )
