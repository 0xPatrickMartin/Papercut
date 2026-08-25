from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .pdf import PdfInspectionError, inspect_pdf

# Hashcat modes for Standard security-handler revisions.
# Certificate-based / public-key encryption is unsupported.
HASHCAT_PDF_MODES = {
    (1, 2): 10400,  # PDF 1.1–1.3 / RC4-40
    (2, 3): 10500,  # PDF 1.4–1.6 / RC4-128
    (2, 4): 10500,
    (4, 4): 10600,  # PDF 1.7 Level 3 / AES-128
    (5, 5): 10700,  # PDF 1.7 Level 8 / AES-256
    (5, 6): 10700,
}

_PDF2JOHN_NAMES = ("pdf2john.py", "pdf2john", "pdf2john.pl")
_HASH_RE = re.compile(r"(\$pdf\$\S+)")


class HashExtractionError(RuntimeError):
    """Raised when a PDF hash cannot be extracted for Hashcat."""


class UnsupportedEncryptionError(HashExtractionError):
    """Raised when PDF encryption is outside Papercut's Hashcat support."""


def find_pdf2john() -> Path | None:
    for name in _PDF2JOHN_NAMES:
        located = shutil.which(name)
        if located:
            return Path(located)
    return None


def _signed_permissions(value: int) -> int:
    if value > 0x7FFFFFFF:
        return struct.unpack("i", struct.pack("I", value & 0xFFFFFFFF))[0]
    return value


def _as_bytes(value: object) -> bytes:
    original = getattr(value, "original_bytes", None)
    if isinstance(original, (bytes, bytearray)):
        return bytes(original)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1")
    raise HashExtractionError(f"unsupported PDF binary field type: {type(value)!r}")


def hashcat_mode_for_hash(pdf_hash: str) -> int:
    if not pdf_hash.startswith("$pdf$"):
        raise UnsupportedEncryptionError("hash is not in $pdf$ format")
    try:
        body = pdf_hash[len("$pdf$") :]
        version_s, revision_s, *_rest = body.split("*")
        version = int(version_s)
        revision = int(revision_s)
    except (TypeError, ValueError) as exc:
        raise UnsupportedEncryptionError(f"could not parse PDF hash: {pdf_hash}") from exc

    mode = HASHCAT_PDF_MODES.get((version, revision))
    if mode is None:
        raise UnsupportedEncryptionError(
            f"unsupported PDF encryption V={version} R={revision} for Hashcat; "
            "supported revisions map to modes 10400/10500/10600/10700"
        )
    return mode


def _assert_supported_encryption(path: Path) -> None:
    info = inspect_pdf(path)
    if not info.encrypted:
        raise HashExtractionError(f"target PDF is not encrypted: {path}")

    handler = (info.handler or "").replace("/", "")
    subfilter = (info.subfilter or "").lower()
    if handler and handler != "Standard":
        raise UnsupportedEncryptionError(
            f"unsupported security handler {info.handler!r}; "
            "Papercut Hashcat support covers the Standard handler only"
        )
    if "pkcs7" in subfilter or "adbe.pkcs7" in subfilter:
        raise UnsupportedEncryptionError(
            "certificate/public-key PDF encryption is not supported"
        )


def _extract_with_pdf2john(path: Path, tool: Path) -> str:
    command = [str(tool), str(path)]
    if tool.suffix == ".py":
        command = ["python3", str(tool), str(path)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise HashExtractionError(f"could not run {tool}: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        raise HashExtractionError(f"pdf2john failed for {path}: {detail}")

    for line in completed.stdout.splitlines():
        match = _HASH_RE.search(line.strip())
        if match:
            return match.group(1)
    raise HashExtractionError(f"pdf2john produced no $pdf$ hash for {path}")


def _extract_with_pypdf(path: Path) -> str:
    """Format a John/Hashcat $pdf$ hash using pypdf (pdf2john-compatible layout)."""
    try:
        reader = PdfReader(path, strict=False)
        if not reader.is_encrypted:
            raise HashExtractionError(f"target PDF is not encrypted: {path}")

        encryption = reader.trailer.get("/Encrypt")
        if encryption is None:
            raise HashExtractionError(f"encrypted PDF is missing /Encrypt: {path}")
        encryption = encryption.get_object()

        version = int(encryption.get("/V", 0))
        revision = int(encryption["/R"])
        length = int(encryption.get("/Length", 40))
        permissions = _signed_permissions(int(encryption["/P"]))
        encrypt_metadata = encryption.get("/EncryptMetadata", True)
        if hasattr(encrypt_metadata, "get_object"):
            encrypt_metadata = encrypt_metadata.get_object()
        encrypt_metadata_flag = 1 if bool(encrypt_metadata) else 0

        document_ids = reader.trailer.get("/ID")
        if not document_ids:
            encryption_state = getattr(reader, "_encryption", None)
            document_id = getattr(encryption_state, "id1_entry", None)
            if not document_id:
                raise HashExtractionError(f"encrypted PDF is missing /ID: {path}")
            document_id_bytes = _as_bytes(document_id)
        else:
            document_id_bytes = _as_bytes(document_ids[0])

        user = _as_bytes(encryption["/U"])
        owner = _as_bytes(encryption["/O"])
        max_len = 48 if revision >= 5 else 32
        user = user[:max_len]
        owner = owner[:max_len]

        parts = [
            f"$pdf${version}",
            str(revision),
            str(length),
            str(permissions),
            str(encrypt_metadata_flag),
            str(len(document_id_bytes)),
            document_id_bytes.hex(),
            str(len(user)),
            user.hex(),
            str(len(owner)),
            owner.hex(),
        ]

        if revision >= 5:
            for key in ("/OE", "/UE"):
                if key not in encryption:
                    raise HashExtractionError(
                        f"revision {revision} PDF is missing required {key}"
                    )
                value = _as_bytes(encryption[key])[:32]
                parts.extend([str(len(value)), value.hex()])

        return "*".join(parts)
    except (OSError, PdfReadError, KeyError, TypeError, ValueError) as exc:
        raise HashExtractionError(f"could not extract hash from {path}: {exc}") from exc


def extract_pdf_hash(path: Path) -> str:
    """Return a $pdf$ hash string suitable for Hashcat."""
    try:
        _assert_supported_encryption(path)
    except PdfInspectionError as exc:
        raise HashExtractionError(str(exc)) from exc

    tool = find_pdf2john()
    if tool is not None:
        pdf_hash = _extract_with_pdf2john(path, tool)
    else:
        pdf_hash = _extract_with_pypdf(path)

    # Validate that Hashcat has a mode for this hash before returning it.
    hashcat_mode_for_hash(pdf_hash)
    return pdf_hash
