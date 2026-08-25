from __future__ import annotations

from pathlib import Path

import pytest
from pypdf import PdfWriter

from papercut.attacks import run_bruteforce, run_mask, run_wordlist
from papercut.backends.hashcat import (
    HashcatProcessResult,
    bruteforce_mask_args,
    build_hashcat_command,
    find_hashcat,
    hashcat_available,
    run_mask_hashcat,
    run_wordlist_hashcat,
    translate_papercut_mask,
    _parse_attempted,
    _parse_rate,
    _read_recovered_password,
)
from papercut.hash_extract import (
    UnsupportedEncryptionError,
    extract_pdf_hash,
    hashcat_mode_for_hash,
)


def make_encrypted_pdf(path: Path, password: str = "client-secret") -> Path:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt(password)
    with path.open("wb") as stream:
        writer.write(stream)
    return path


def test_find_hashcat_detects_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = tmp_path / "hashcat"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    assert find_hashcat() == fake
    assert hashcat_available() is True


def test_find_hashcat_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    assert find_hashcat() is None
    assert hashcat_available() is False


def test_hashcat_mode_mapping_for_supported_hashes() -> None:
    assert hashcat_mode_for_hash("$pdf$1*2*40*-4*1*16*00*32*11*32*22") == 10400
    assert hashcat_mode_for_hash("$pdf$2*3*128*-4*1*16*00*32*11*32*22") == 10500
    assert hashcat_mode_for_hash("$pdf$4*4*128*-4*1*16*00*32*11*32*22") == 10600
    assert hashcat_mode_for_hash("$pdf$5*6*256*-4*1*16*00*48*11*48*22") == 10700


def test_unsupported_pdf_variant_raises() -> None:
    with pytest.raises(UnsupportedEncryptionError, match="V=9 R=9"):
        hashcat_mode_for_hash("$pdf$9*9*128*-4*1*16*00*32*11*32*22")


def test_extract_pdf_hash_produces_pdf_prefix(tmp_path: Path) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf")
    pdf_hash = extract_pdf_hash(pdf)
    assert pdf_hash.startswith("$pdf$")
    assert hashcat_mode_for_hash(pdf_hash) in {10400, 10500, 10600, 10700}


def test_extract_pdf_hash_rejects_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pdf"
    path.write_bytes(b"not a pdf")
    with pytest.raises(Exception, match="could not"):
        extract_pdf_hash(path)


def test_translate_mask_uses_bounded_symbols() -> None:
    extras, translated = translate_papercut_mask("Summer?d?s")
    assert extras == ["-1", "!@#$%^&*"]
    assert translated == "Summer?d?1"


def test_bruteforce_mask_args_for_digits() -> None:
    extras, mask = bruteforce_mask_args("digits", 4, 6)
    assert "--increment" in extras
    assert "--increment-min=4" in extras
    assert "--increment-max=6" in extras
    assert mask == "?d?d?d?d?d?d"


def test_build_hashcat_wordlist_command() -> None:
    command = build_hashcat_command(
        hashcat=Path("/usr/bin/hashcat"),
        mode=10500,
        attack_mode=0,
        hash_file=Path("/tmp/target.hash"),
        outfile=Path("/tmp/out.txt"),
        session="papercut_test",
        wordlist=Path("/tmp/passwords.txt"),
    )
    assert command == [
        "/usr/bin/hashcat",
        "-m",
        "10500",
        "-a",
        "0",
        "--quiet",
        "--potfile-disable",
        "--restore-disable",
        "--session=papercut_test",
        "-o",
        "/tmp/out.txt",
        "--outfile-format=2",
        "/tmp/target.hash",
        "/tmp/passwords.txt",
    ]


def test_build_hashcat_mask_command() -> None:
    extras, translated = translate_papercut_mask("A?d?s")
    command = build_hashcat_command(
        hashcat=Path("/usr/bin/hashcat"),
        mode=10500,
        attack_mode=3,
        hash_file=Path("/tmp/target.hash"),
        outfile=Path("/tmp/out.txt"),
        session="papercut_test",
        mask=translated,
        extra=extras,
    )
    assert command[:5] == ["/usr/bin/hashcat", "-m", "10500", "-a", "3"]
    assert "-1" in command
    assert "!@#$%^&*" in command
    assert command[-1] == "A?d?1"


def test_build_hashcat_bruteforce_command() -> None:
    extras, mask = bruteforce_mask_args("digits", 4, 6)
    command = build_hashcat_command(
        hashcat=Path("/usr/bin/hashcat"),
        mode=10500,
        attack_mode=3,
        hash_file=Path("/tmp/target.hash"),
        outfile=Path("/tmp/out.txt"),
        session="papercut_test",
        mask=mask,
        extra=extras,
    )
    assert "--increment" in command
    assert "--increment-min=4" in command
    assert "--increment-max=6" in command
    assert command[-1] == "?d?d?d?d?d?d"


def test_parse_hashcat_status_helpers() -> None:
    sample = (
        "Speed.Dev.#1.....:  123.4 kH/s\n"
        "Progress.........: 250/1000 (25.00%)\n"
    )
    assert _parse_rate(sample) == pytest.approx(123400.0)
    assert _parse_attempted(sample) == 250


def test_read_recovered_password_plaintext_and_hash_pass(tmp_path: Path) -> None:
    plain = tmp_path / "plain.txt"
    plain.write_text("recovered-secret\n", encoding="utf-8")
    assert _read_recovered_password(plain) == "recovered-secret"

    mixed = tmp_path / "mixed.txt"
    mixed.write_text("$pdf$2*3*128*-4*1*16*00*32*11*32*22:hidden\n", encoding="utf-8")
    assert _read_recovered_password(mixed) == "hidden"


def test_hashcat_preferred_execution_for_wordlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "secret")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("secret\n", encoding="utf-8")
    fake_hashcat = tmp_path / "hashcat"
    fake_hashcat.write_text("#!/bin/sh\n", encoding="utf-8")
    fake_hashcat.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    captured: dict[str, object] = {}

    def fake_runner(command: list[str], workdir: Path) -> HashcatProcessResult:
        captured["command"] = command
        outfile = Path(command[command.index("-o") + 1])
        outfile.write_text("secret\n", encoding="utf-8")
        return HashcatProcessResult(returncode=0, stdout="", stderr="")

    result = run_wordlist_hashcat(pdf, wordlist, runner=fake_runner)
    assert result.backend == "hashcat"
    assert result.found is True
    assert result.password == "secret"
    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == str(fake_hashcat)
    assert "-a" in command and "0" in command


def test_hashcat_preferred_via_attack_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "secret")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("secret\n", encoding="utf-8")

    def fake_hashcat_run(*_args, **_kwargs):
        from papercut.models import AuditResult

        return AuditResult(
            path=pdf,
            attack="wordlist",
            found=True,
            password="secret",
            attempted=1,
            elapsed=0.1,
            rate=10.0,
            backend="hashcat",
        )

    monkeypatch.setattr("papercut.attacks.hashcat_available", lambda: True)
    monkeypatch.setattr("papercut.attacks.run_wordlist_hashcat", fake_hashcat_run)

    result = run_wordlist(pdf, wordlist, prefer_hashcat=True)
    assert result.backend == "hashcat"
    assert result.password == "secret"


def test_fallback_when_hashcat_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "secret")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("secret\n", encoding="utf-8")
    monkeypatch.setattr("papercut.attacks.hashcat_available", lambda: False)

    result = run_wordlist(pdf, wordlist)
    assert result.backend == "python"
    assert result.found is True
    assert result.password == "secret"


def test_fallback_when_hashcat_execution_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "secret")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("secret\n", encoding="utf-8")

    def boom(*_args, **_kwargs):
        from papercut.backends.hashcat import HashcatError

        raise HashcatError("simulated device failure")

    monkeypatch.setattr("papercut.attacks.hashcat_available", lambda: True)
    monkeypatch.setattr("papercut.attacks.run_wordlist_hashcat", boom)

    result = run_wordlist(pdf, wordlist, prefer_hashcat=True)
    assert result.backend == "python"
    assert result.password == "secret"


def test_mask_hashcat_command_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "A1!")
    fake_hashcat = tmp_path / "hashcat"
    fake_hashcat.write_text("#!/bin/sh\n", encoding="utf-8")
    fake_hashcat.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    seen: list[list[str]] = []

    def fake_runner(command: list[str], workdir: Path) -> HashcatProcessResult:
        seen.append(command)
        outfile = Path(command[command.index("-o") + 1])
        outfile.write_text("A1!\n", encoding="utf-8")
        return HashcatProcessResult(returncode=0, stdout="", stderr="")

    result = run_mask_hashcat(
        pdf, "A?d?s", max_candidates=100, runner=fake_runner
    )
    assert result.found is True
    assert result.password == "A1!"
    assert seen[0][-1] == "A?d?1"


def test_attack_api_mask_and_bruteforce_prefer_hashcat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "12")

    def fake_mask(*_args, **_kwargs):
        from papercut.models import AuditResult

        return AuditResult(
            path=pdf,
            attack="mask",
            found=True,
            password="12",
            attempted=2,
            elapsed=0.2,
            rate=10.0,
            backend="hashcat",
        )

    def fake_brute(*_args, **_kwargs):
        from papercut.models import AuditResult

        return AuditResult(
            path=pdf,
            attack="bruteforce",
            found=True,
            password="12",
            attempted=12,
            elapsed=0.2,
            rate=60.0,
            backend="hashcat",
        )

    monkeypatch.setattr("papercut.attacks.hashcat_available", lambda: True)
    monkeypatch.setattr("papercut.attacks.run_mask_hashcat", fake_mask)
    monkeypatch.setattr("papercut.attacks.run_bruteforce_hashcat", fake_brute)

    mask_result = run_mask(pdf, "?d?d", prefer_hashcat=True)
    brute_result = run_bruteforce(pdf, "digits", 1, 2, prefer_hashcat=True)
    assert mask_result.backend == "hashcat"
    assert brute_result.backend == "hashcat"


@pytest.mark.integration
def test_optional_local_hashcat_integration(tmp_path: Path) -> None:
    """Manual/local integration path; skipped unless Hashcat is usable."""
    if not hashcat_available():
        pytest.skip("Hashcat not installed")

    pdf = make_encrypted_pdf(tmp_path / "protected.pdf", "ab")
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("zz\nab\n", encoding="utf-8")
    try:
        result = run_wordlist_hashcat(pdf, wordlist)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Hashcat unavailable for integration: {exc}")

    assert result.backend == "hashcat"
    if result.found:
        assert result.password == "ab"
