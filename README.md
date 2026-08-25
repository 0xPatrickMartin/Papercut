# Papercut

Papercut is a Python CLI for assessing the password protection used by PDF
documents. It can inspect PDF encryption settings and test passwords from a
wordlist.

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

## Usage

Inspect a PDF:

```console
papercut inspect path/to/document.pdf
```

Test an encrypted PDF with a UTF-8 wordlist containing one candidate per line:

```console
papercut wordlist path/to/document.pdf path/to/passwords.txt
```

Papercut reads the wordlist incrementally, stops at the first matching
password, and reports attempts, elapsed time, and attempts per second. A
successful match exits with status `0`, exhaustion with `1`, and an input error
with `2`.

Use `--mutate` to test a small, deterministic set of common capitalization,
numeric suffix, year suffix, and character-substitution variants for each
wordlist entry:

```console
papercut wordlist path/to/document.pdf path/to/passwords.txt --mutate
```

Show command help:

```console
papercut --help
papercut inspect --help
papercut wordlist --help
```
