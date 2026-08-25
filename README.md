# Papercut

Papercut is a Python CLI for authorized PDF password-strength auditing. It
inspects encryption settings and tests passwords with wordlists, bounded
mutations, masks, and bounded brute force.

When [Hashcat](https://hashcat.net/) is installed and available on `PATH`,
Papercut uses it automatically for supported encrypted PDFs. If Hashcat is
missing or cannot run, Papercut falls back to its built-in Python verifier.
Operators do not select a backend.

## Authorized use only

Use Papercut only on documents you own or have explicit permission to assess.
You are responsible for complying with applicable contracts, policies, and
laws. Papercut is intended for defensive security reviews of client PDFs.

## Installation

Papercut requires Python 3.10 or newer. From the project directory:

```console
python -m pip install .
```

For development and testing:

```console
python -m pip install -e ".[dev]"
pytest
```

Optional high-performance path:

* Install Hashcat and ensure `hashcat` is on your `PATH`.
* Optionally install `pdf2john` / `pdf2john.py` for hash extraction. If it is
  absent, Papercut formats a John/Hashcat-compatible `$pdf$` hash with `pypdf`.

## Usage

Inspect a PDF:

```console
papercut inspect path/to/document.pdf
```

Wordlist attack:

```console
papercut wordlist path/to/document.pdf path/to/passwords.txt
papercut wordlist path/to/document.pdf path/to/passwords.txt --mutate
```

Mask attack (`?l` lowercase, `?u` uppercase, `?d` digits, `?s` = `!@#$%^&*`):

```console
papercut mask protected.pdf 'Summer?d?d?d?d'
```

Bounded brute force:

```console
papercut bruteforce protected.pdf \
  --charset digits \
  --min-length 4 \
  --max-length 6
```

Character-set choices are `digits`, `lowercase`, `uppercase`, `letters`,
`alnum`, and `symbols`.

Mask and brute-force attacks default to a safety limit of 1,000,000 candidates.
Raise it explicitly with `--max-candidates` when needed. Successful recovery
exits `0`, exhaustion `1`, and input errors `2`. Attack output includes which
engine handled the run (`Hashcat` or `Python`).

## Automatic engine selection

1. If Hashcat is detected, Papercut extracts a `$pdf$` hash and runs Hashcat.
2. If Hashcat is unavailable, fails to start, or returns a runtime error,
   Papercut falls back to the Python candidate tester.
3. Unsupported encryption (non-Standard handlers, certificate/public-key
   SubFilters, or PDF revisions outside Hashcat modes 10400/10500/10600/10700)
   is reported clearly.

## Proof-of-concept limitations

* Sequential Python fallback only; no multiprocessing yet.
* No backend flags, GPU tuning, distributed cracking, advanced Hashcat rules,
  checkpoints, configuration files, or plugins.
* Mutation rules remain a small deterministic set.
* Local Hashcat still depends on a working Hashcat/OpenCL (or compatible)
  install; the default test suite mocks Hashcat and does not require a GPU.

Optional local Hashcat check:

```console
pytest -m integration
```
