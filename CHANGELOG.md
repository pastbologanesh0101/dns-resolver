# Changelog

## [0.1.0] - Initial release

The first commit of the from-scratch DNS resolver and toy authoritative
server:

- `dns_protocol.py` — hand-rolled RFC 1035 wire-format encoding/decoding:
  header, question section, and A/AAAA/CNAME/NS/MX/TXT resource records,
  plus name compression (pointer following, with loop protection) on
  decode. No third-party DNS library used.
- `server.py` — a toy authoritative UDP DNS server that loads a JSON zone
  file, answers queries with real wire-format responses, returns NXDOMAIN
  for unknown names, follows a single CNAME hop server-side, and survives
  malformed incoming packets without crashing.
- `resolver.py` — a UDP-socket resolver with `query_server()` for a single
  request/response round trip and `resolve()` for iterative resolution
  (follows NS/glue referrals up to a hop limit, with loop detection), plus
  specific exceptions (`DNSTimeoutError`, `NXDomainError`, `DNSQueryError`)
  instead of raw socket/parse errors.
- `resolve.py` — CLI entry point (`python resolve.py <name> --server
  host:port [--type TYPE] [--timeout SECONDS]`) with distinct exit codes
  for success, NXDOMAIN, timeout, and other errors.
- `zones/example.json` — sample zone data used by the demo and tests.
- `tests/` — unit tests for wire-format round trips, name compression,
  and each supported record type, plus integration tests that start the
  toy server on an ephemeral local port and exercise successful
  resolution, NXDOMAIN, timeouts, and malformed-packet handling.
- `.github/workflows/tests.yml` — CI running the test suite on Python
  3.11 and 3.12.
- `README.md` and `LICENSE` (MIT).
