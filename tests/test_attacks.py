from __future__ import annotations

from pathlib import Path

import pytest
from pypdf import PdfWriter

from papercut.attacks import run_wordlist
from papercut.candidates import CandidateSourceError
from papercut.cli import main
from papercut.models import AuditResult
from papercut.pdf import PdfInspectionError


def make_encrypted_pdf(path: Path, password: str = "client-secret") -> Path:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt(password)
    with path.open("wb") as stream:
        writer.write(stream)
    return path


def test_wordlist_recovers_password_and_stops(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("incorrect\nclient-secret\nnever-tested\n", encoding="utf-8")

    result = run_wordlist(pdf, wordlist)

    assert isinstance(result, AuditResult)
    assert result.found is True
    assert result.password == "client-secret"
    assert result.attempted == 2
    assert result.elapsed >= 0
    assert result.rate >= 0


def test_wordlist_exhaustion_returns_failure(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("first\nsecond\nthird\n", encoding="utf-8")

    result = run_wordlist(pdf, wordlist)

    assert result.found is False
    assert result.password is None
    assert result.attempted == 3


def test_wordlist_rejects_malformed_utf8(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_bytes(b"password\n\xff")

    with pytest.raises(CandidateSourceError, match="could not read wordlist"):
        run_wordlist(pdf, wordlist)


def test_empty_wordlist_returns_zero_attempts(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("", encoding="utf-8")

    result = run_wordlist(pdf, wordlist)

    assert result.found is False
    assert result.attempted == 0
    assert result.rate == 0


def test_wordlist_reports_missing_pdf(tmp_path: Path) -> None:
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("password\n", encoding="utf-8")

    with pytest.raises(PdfInspectionError, match="could not read"):
        run_wordlist(tmp_path / "missing.pdf", wordlist)


def test_wordlist_reports_missing_wordlist(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")

    with pytest.raises(CandidateSourceError, match="could not read wordlist"):
        run_wordlist(pdf, tmp_path / "missing.txt")


def test_wordlist_cli_prints_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("wrong\nclient-secret\n", encoding="utf-8")

    exit_code = main(["wordlist", str(pdf), str(wordlist)])

    output = capsys.readouterr()
    assert exit_code == 0
    assert "Papercut wordlist: SUCCESS" in output.out
    assert "Password: client-secret" in output.out
    assert "Attempted: 2" in output.out


def test_wordlist_cli_prints_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("wrong\n", encoding="utf-8")

    exit_code = main(["wordlist", str(pdf), str(wordlist)])

    output = capsys.readouterr()
    assert exit_code == 1
    assert "Papercut wordlist: NOT FOUND" in output.out
    assert "Attempted: 1" in output.out


def test_wordlist_cli_reports_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")

    exit_code = main(["wordlist", str(pdf), str(tmp_path / "missing.txt")])

    output = capsys.readouterr()
    assert exit_code == 2
    assert "Papercut: error:" in output.err
