from __future__ import annotations

from pathlib import Path

import pytest
from pypdf import PdfWriter

from papercut.attacks import (
    calculate_progress,
    run_attack,
    run_bruteforce,
    run_mask,
)
from papercut.candidates import (
    CandidateOptionError,
    SearchSpaceLimitError,
    bruteforce_candidate_count,
    bruteforce_candidates,
    mask_candidate_count,
    mask_candidates,
)
from papercut.cli import main


def make_encrypted_pdf(path: Path, password: str) -> Path:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt(password)
    with path.open("wb") as stream:
        writer.write(stream)
    return path


def test_mask_generation_and_count() -> None:
    candidates = list(mask_candidates("A?d?s", max_candidates=100))

    assert mask_candidate_count("A?d?s") == 80
    assert candidates[:3] == ["A0!", "A0@", "A0#"]
    assert candidates[-1] == "A9*"


def test_mask_attack_recovers_password(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "Summer01")

    result = run_mask(pdf, "Summer?d?d")

    assert result.found is True
    assert result.password == "Summer01"
    assert result.attempted == 2


def test_bruteforce_generation_is_bounded_and_ordered() -> None:
    candidates = list(
        bruteforce_candidates("digits", 1, 2, max_candidates=110)
    )

    assert bruteforce_candidate_count("digits", 1, 2) == 110
    assert candidates[:3] == ["0", "1", "2"]
    assert candidates[10:13] == ["00", "01", "02"]
    assert candidates[-1] == "99"


def test_bruteforce_attack_recovers_password(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "3")

    result = run_bruteforce(pdf, "digits", 1, 1)

    assert result.found is True
    assert result.password == "3"
    assert result.attempted == 4


@pytest.mark.parametrize("mask", ["?", "?x", "prefix?"])
def test_invalid_masks_are_rejected(mask: str) -> None:
    with pytest.raises(CandidateOptionError):
        mask_candidates(mask)


@pytest.mark.parametrize(
    ("charset", "min_length", "max_length"),
    [
        ("unknown", 1, 2),
        ("digits", 0, 2),
        ("digits", 3, 2),
    ],
)
def test_invalid_bruteforce_options_are_rejected(
    charset: str, min_length: int, max_length: int
) -> None:
    with pytest.raises(CandidateOptionError):
        bruteforce_candidates(charset, min_length, max_length)


def test_search_space_limit_requires_explicit_increase() -> None:
    with pytest.raises(SearchSpaceLimitError, match="100 candidates"):
        mask_candidates("?d?d", max_candidates=99)

    assert len(list(mask_candidates("?d?d", max_candidates=100))) == 100


def test_bruteforce_search_space_limit_is_enforced() -> None:
    with pytest.raises(SearchSpaceLimitError, match="110 candidates"):
        bruteforce_candidates("digits", 1, 2, max_candidates=100)


def test_progress_statistics_include_eta() -> None:
    progress = calculate_progress(attempted=25, total=100, started=10.0, now=15.0)

    assert progress.attempted == 25
    assert progress.elapsed == 5.0
    assert progress.rate == 5.0
    assert progress.eta == 15.0


def test_attack_runner_reports_periodic_progress(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "secret")
    times = iter([0.0, 1.0, 2.0, 2.5])
    updates = []

    result = run_attack(
        pdf,
        ["a", "b"],
        attack="test",
        total=2,
        progress=updates.append,
        progress_interval=1.0,
        verifier=lambda _path, _candidate: False,
        clock=lambda: next(times),
    )

    assert result.attempted == 2
    assert [update.attempted for update in updates] == [1, 2]
    assert updates[-1].eta == 0.0


def test_mask_and_bruteforce_cli_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mask_pdf = make_encrypted_pdf(tmp_path / "mask.pdf", "Code1")
    brute_pdf = make_encrypted_pdf(tmp_path / "brute.pdf", "2")

    mask_exit = main(["mask", str(mask_pdf), "Code?d"])
    mask_output = capsys.readouterr()
    brute_exit = main(
        [
            "bruteforce",
            str(brute_pdf),
            "--charset",
            "digits",
            "--min-length",
            "1",
            "--max-length",
            "1",
        ]
    )
    brute_output = capsys.readouterr()

    assert mask_exit == 0
    assert "Papercut mask: SUCCESS" in mask_output.out
    assert brute_exit == 0
    assert "Papercut bruteforce: SUCCESS" in brute_output.out
