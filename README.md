# Papercut

Papercut is a Python CLI for assessing the password protection used by PDF
documents. The current milestone inspects a PDF and reports whether it is
encrypted, along with the available security-handler and encryption details.

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

Show command help:

```console
papercut --help
papercut inspect --help
```

Password-testing attack modes are not included in this milestone.
