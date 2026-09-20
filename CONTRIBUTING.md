# Contributing

## Running the tests

```
python -m pip install pytest
pytest tests/ -v
```

Tests spin up the toy server (`server.py`) on an ephemeral local port as a
background thread, so the suite never touches real internet DNS and runs
the same way locally and in CI.

CI (`.github/workflows/tests.yml`) runs the same command across the
supported Python versions on every push and pull request. Please make sure
`pytest tests/ -v` is green before opening a PR.

## Code style

This project matches the style already in `dns_protocol.py`, `resolver.py`,
`server.py`, and `resolve.py`:

- Pure standard library only (`socket`, `struct`, `argparse`, `json`,
  `threading`, `dataclasses`). No third-party DNS libraries — hand-rolling
  the wire format is the point of the project.
- `from __future__ import annotations` at the top of each module, with
  type hints on public functions.
- Specific exception types (`DNSFormatError`, `DNSTimeoutError`,
  `NXDomainError`, `DNSQueryError`, ...) rather than bare `Exception` or
  generic `ValueError`s bubbling up to a user-facing CLI.
- Docstrings on modules and non-trivial functions explaining *why*, not
  just *what* — see the module docstrings in `resolver.py` and
  `dns_protocol.py` for the expected level of detail.
- Tests use `unittest.TestCase` classes (run via `pytest`), grouped by the
  behavior under test (e.g. `TestNameEncoding`, `TestTimeoutHandling`), with
  descriptive method names that state the expected behavior.

## Submitting changes

1. Fork the repo and create a branch for your change.
2. Keep changes focused — one logical change per commit/PR.
3. Add or update tests for any behavior change. New wire-format edge cases
   (compression, truncation, unusual record types, etc.) are especially
   welcome, since hand-parsing DNS packets is where subtle bugs hide.
4. Run `pytest tests/ -v` and confirm everything passes.
5. Open a pull request describing what changed and why.
