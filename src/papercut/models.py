from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EncryptionInfo:
    path: Path
    encrypted: bool
    handler: str | None = None
    subfilter: str | None = None
    version: int | None = None
    revision: int | None = None
    key_bits: int | None = None
    permissions: int | None = None
    encrypt_metadata: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        return data


@dataclass(frozen=True)
class Progress:
    attempted: int
    total: int | None
    elapsed: float
    rate: float
    eta: float | None


@dataclass(frozen=True)
class AuditResult:
    path: Path
    attack: str
    found: bool
    password: str | None
    attempted: int
    elapsed: float
    rate: float
    resumed_from: int = 0
    backend: str = "python"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["path"] = str(self.path)
        return data
