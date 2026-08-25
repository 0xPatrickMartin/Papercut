from __future__ import annotations

from pathlib import Path

import pytest
from pypdf import PdfWriter

from papercut.pdf import PdfInspectionError, inspect_pdf, verify_password


def make_pdf(path: Path, password: str | None = None) -> Path:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if password is not None:
        writer.encrypt(password)
    with path.open("wb") as stream:
        writer.write(stream)
    return path


def test_inspect_unencrypted_pdf(tmp_path: Path) -> None:
    path = make_pdf(tmp_path / "plain.pdf")

    info = inspect_pdf(path)

    assert info.path == path
    assert info.encrypted is False
    assert info.handler is None


def test_inspect_encrypted_pdf(tmp_path: Path) -> None:
    path = make_pdf(tmp_path / "protected.pdf", "client-secret")

    info = inspect_pdf(path)

    assert info.encrypted is True
    assert info.handler == "/Standard"
    assert info.revision is not None
    assert info.key_bits is not None
    assert info.permissions is not None


def test_inspect_invalid_pdf(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pdf"
    path.write_bytes(b"not a PDF")

    with pytest.raises(PdfInspectionError, match="could not read"):
        inspect_pdf(path)


def test_verify_correct_password(tmp_path: Path) -> None:
    path = make_pdf(tmp_path / "protected.pdf", "correct-horse")

    assert verify_password(path, "correct-horse") is True


def test_verify_incorrect_password(tmp_path: Path) -> None:
    path = make_pdf(tmp_path / "protected.pdf", "correct-horse")

    assert verify_password(path, "wrong-password") is False


def test_verify_password_rejects_unencrypted_pdf(tmp_path: Path) -> None:
    path = make_pdf(tmp_path / "plain.pdf")

    assert verify_password(path, "") is False


def test_verify_password_handles_invalid_pdf(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pdf"
    path.write_bytes(b"not a PDF")

    assert verify_password(path, "anything") is False
