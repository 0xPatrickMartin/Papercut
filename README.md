# Papercut

Papercut is a Python CLI for authorized PDF password-strength auditing. It
inspects PDF encryption settings and tests whether passwords are realistically
guessable using wordlists, bounded mutations, masks, and bounded brute force.

When [Hashcat](https://hashcat.net/) is on `PATH`, Papercut uses it
automatically for supported encrypted PDFs. If Hashcat is missing or cannot
run, Papercut falls back to its built-in Python verifier. There is no
user-facing backend flag.

## Authorized use only

Use Papercut only on documents you own or have explicit permission to assess.
You are responsible for complying with applicable contracts, policies, and
laws. Papercut is intended for defensive security reviews of client PDFs.

## Requirements

* Python 3.10 or newer
* Runtime dependency: `pypdf>=5.0`
* Optional for high performance: Hashcat (`hashcat` or `hashcat.bin` on `PATH`)
* Optional for hash extraction: `pdf2john`, `pdf2john.py`, or `pdf2john.pl` on
  `PATH` (if absent, Papercut builds a John/Hashcat-compatible `$pdf$` hash
  with `pypdf`)

## Installation

From the project directory:

```console
python -m pip install .
```

Development install and tests:

```console
python -m pip install -e ".[dev]"
pytest
```

The default test run excludes optional Hashcat integration tests:

```console
pytest -m integration
```

## Commands

```console
papercut --help
papercut {inspect,wordlist,mask,bruteforce} --help
```

### `inspect`

Report whether a PDF is encrypted and print security-handler details when
available:

```console
papercut inspect path/to/document.pdf
```

Printed fields for encrypted PDFs include security handler, subfilter,
algorithm version, security revision, key length, permissions, and whether
metadata is encrypted.

### `wordlist`

Test candidates from a UTF-8 wordlist (one password per line). The wordlist is
read line-by-line and is not loaded entirely into memory.

```console
papercut wordlist path/to/document.pdf path/to/passwords.txt
papercut wordlist path/to/document.pdf path/to/passwords.txt --mutate
```

| Option | Description |
| --- | --- |
| `pdf` | Target PDF path |
| `wordlist` | UTF-8 wordlist path |
| `--mutate` | Expand each base candidate with Papercut’s bounded mutation set |

With `--mutate`, each base candidate yields a deterministic unique set that
includes:

* the original candidate
* first-letter capitalization
* uppercase and lowercase forms
* numeric suffixes: `1`, `12`, `123`, `1234`
* year suffixes: `2024`, `2025`, `2026`
* substitutions: `a→@`, `e→3`, `i→1`, `o→0`, `s→$` (single and combined)

### `mask`

Generate candidates from a mask pattern:

```console
papercut mask path/to/document.pdf 'Summer?d?d?d?d'
papercut mask path/to/document.pdf 'A?d?s' --max-candidates 1000000
```

| Option | Description |
| --- | --- |
| `pdf` | Target PDF path |
| `mask` | Pattern using literal characters plus `?l`, `?u`, `?d`, `?s` |
| `--max-candidates` | Search-space safety limit (default: `1000000`) |

Mask tokens:

| Token | Character set |
| --- | --- |
| `?l` | lowercase letters `a–z` |
| `?u` | uppercase letters `A–Z` |
| `?d` | digits `0–9` |
| `?s` | common symbols `!@#$%^&*` |

Other `?` tokens are rejected. Spaces larger than `--max-candidates` are refused
until the operator raises the limit.

### `bruteforce`

Run a bounded character-set search over a length range:

```console
papercut bruteforce path/to/document.pdf \
  --charset digits \
  --min-length 4 \
  --max-length 6
```

| Option | Description |
| --- | --- |
| `pdf` | Target PDF path |
| `--charset` | Required. One of `digits`, `lowercase`, `uppercase`, `letters`, `alnum`, `symbols` |
| `--min-length` | Required. Minimum password length (`>= 1`) |
| `--max-length` | Required. Maximum password length (`>= --min-length`) |
| `--max-candidates` | Search-space safety limit (default: `1000000`) |

Charset contents:

| Name | Characters |
| --- | --- |
| `digits` | `0–9` |
| `lowercase` | `a–z` |
| `uppercase` | `A–Z` |
| `letters` | `a–zA–Z` |
| `alnum` | `a–zA–Z0–9` |
| `symbols` | `!@#$%^&*` |

## Attack behavior

* Attacks stop immediately when a password succeeds.
* Progress is printed periodically to stderr with attempted count, elapsed
  time, attempts/sec, and ETA when the candidate count is known.
* Final stdout includes status, engine (`Hashcat` or `Python`), recovered
  password (if any), attempted count, elapsed time, and rate.
* Exit codes:
  * `0` — password recovered
  * `1` — candidates exhausted / not found
  * `2` — input or configuration error

## Backend selection

Papercut chooses the engine automatically:

1. If `hashcat` / `hashcat.bin` is found on `PATH`, Papercut extracts a `$pdf$`
   hash and runs Hashcat for wordlist, wordlist+mutations, mask, and
   brute-force workflows.
2. Prefer `pdf2john` / `pdf2john.py` / `pdf2john.pl` for hash extraction when
   present; otherwise format the hash with `pypdf`.
3. If Hashcat is missing, fails to start, or returns a runtime error, Papercut
   falls back to the sequential Python verifier (`pypdf` password checks).
4. Operators never select a backend.

Hashcat PDF modes currently mapped:

| PDF encryption | Hashcat mode |
| --- | --- |
| V=1, R=2 | `10400` |
| V=2, R=3 or R=4 | `10500` |
| V=4, R=4 | `10600` |
| V=5, R=5 or R=6 | `10700` |

Unsupported for Hashcat-backed auditing:

* Non-`/Standard` security handlers
* Certificate / public-key encryption (`adbe.pkcs7*` SubFilters)
* Encryption revisions outside the modes above

Temporary Hashcat hash/output files are cleaned up after each run. Mutated
wordlists are expanded into a temporary candidate file when using Hashcat; the
operator wordlist is used in place for plain wordlist attacks.

## Current limitations

* Python fallback is sequential; multiprocessing is not implemented yet.
* No user-selectable backend flags, GPU tuning, distributed cracking, advanced
  Hashcat rule packs, checkpoint/resume, configuration files, or plugins.
* Mutation rules are intentionally small and deterministic.
* A working Hashcat install (including any required OpenCL/device support) is
  needed for the high-performance path; the default test suite mocks Hashcat
  and does not require a GPU.
