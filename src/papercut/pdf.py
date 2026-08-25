from __future__ import annotations

from pathlib import Path
from typing import Any

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .models import EncryptionInfo


class PdfInspectionError(RuntimeError):
    """Raised when a target cannot be inspected as a PDF."""


def _plain_value(value: Any) -> Any:
    try:
        value = value.get_object()
    except AttributeError:
        pass
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, str)):
        return value
    return str(value) if value is not None else None


def inspect_pdf(path: Path) -> EncryptionInfo:
    try:
        reader = PdfReader(path, strict=False)
        encrypted = reader.is_encrypted
        if not encrypted:
            return EncryptionInfo(path=path, encrypted=False)

        encryption = reader.trailer.get("/Encrypt")
        if encryption is None:
            return EncryptionInfo(path=path, encrypted=True)
        encryption = encryption.get_object()
        length = _plain_value(encryption.get("/Length"))
        return EncryptionInfo(
            path=path,
            encrypted=True,
            handler=_plain_value(encryption.get("/Filter")),
            subfilter=_plain_value(encryption.get("/SubFilter")),
            version=_plain_value(encryption.get("/V")),
            revision=_plain_value(encryption.get("/R")),
            key_bits=int(length) if length is not None else 40,
            permissions=_plain_value(encryption.get("/P")),
            encrypt_metadata=_plain_value(encryption.get("/EncryptMetadata", True)),
        )
    except (OSError, PdfReadError, ValueError, TypeError) as exc:
        raise PdfInspectionError(f"could not read {path}: {exc}") from exc


def verify_password(path: Path, password: str) -> bool:
    try:
        reader = PdfReader(path, strict=False)
        return bool(reader.is_encrypted and reader.decrypt(password))
    except (OSError, PdfReadError, ValueError, TypeError):
        return False
