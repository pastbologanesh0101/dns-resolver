# DNS Resolver

A DNS resolver and toy authoritative DNS server, both built from scratch in
pure Python: raw UDP sockets (`socket`) and hand-rolled DNS wire-format
encoding/decoding (`struct`). No `dnspython` or any other DNS library is
used — parsing the packet format by hand is the whole point of the project.

## What's in here

- `dns_protocol.py` — DNS message encoding/decoding per RFC 1035: header,
  question section, resource records (A, AAAA, CNAME, NS, MX, TXT), and
  name compression (pointer following) on decode.
- `server.py` — a toy authoritative DNS server. Loads a JSON zone file and
  answers UDP DNS queries with real wire-format responses, including
  NXDOMAIN for unknown names.
- `resolver.py` — an iterative-style resolver: queries a starting server,
  returns answers directly when given one (as our authoritative toy server
  does), or follows NS/glue referrals when given a genuine referral chain.
  Raises clean, specific errors for NXDOMAIN and timeouts.
- `resolve.py` — CLI entry point: `python resolve.py <name> --server host:port`.
- `zones/example.json` — the toy server's zone data.
- `tests/` — unit + integration tests that spin up the toy server on an
  ephemeral local port, so nothing here depends on real internet DNS.

## DNS wire format, briefly

Every DNS message (query or response) is a single UDP payload with this
layout:

```
+---------------------+
|        Header        |  12 bytes: ID, flags (QR/opcode/AA/TC/RD/RA/RCODE),
+---------------------+   and 4 counts (QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT)
|       Question        |  QNAME (labels) + QTYPE + QCLASS, one per question
+---------------------+
|        Answer         |  RRs answering the question
+---------------------+
|       Authority       |  RRs pointing at authoritative nameservers
+---------------------+
|       Additional      |  RRs with "glue" data (e.g. an NS's own A record)
+---------------------+
```

**Names** are encoded as a sequence of length-prefixed labels
(`3www7example3com0` for `www.example.com`), terminated by a zero-length
label. To avoid repeating the same name bytes over and over in a packet,
DNS allows **compression pointers**: a 2-byte pointer (top two bits set,
`0xC0`) that says "the rest of this name is identical to the name starting
at byte offset N in this packet." `dns_protocol.decode_name()` follows
these pointers (with loop protection), which is the trickiest part of
writing a DNS parser by hand.

**Resource records** (answers) each carry an owner name, TYPE, CLASS, TTL,
and a length-prefixed RDATA blob whose interpretation depends on TYPE — an
A record's RDATA is 4 raw bytes, a CNAME's RDATA is itself a (possibly
compressed) name, an MX's RDATA is a 2-byte preference plus a name, and so
on. `dns_protocol.py` implements packing/unpacking for A, AAAA, CNAME, NS,
MX, and TXT.

## How the resolver and toy server work together

`server.py` is authoritative for whatever is in `zones/example.json` — for
any query it either answers directly or returns NXDOMAIN. `resolver.py`
sends a query, and:

- if the response has answers, it returns them (following a single CNAME
  hop if needed);
- if the response is NXDOMAIN, it raises `NXDomainError`;
- if the response is a **referral** (empty answers, but NS records in the
  authority section and glue A records in additional), it follows the
  referral to the next server and re-queries — this is real iterative
  resolution, the same mechanism a full resolver uses walking from the
  root down through TLD and authoritative servers. Our toy server never
  emits referrals (it's authoritative for everything it knows), so against
  it the resolver always finishes in one hop; the referral-following path
  is exercised by the code but not required for the default demo.

By default `resolve.py` points at `1.1.1.1:53` (a well-known public
resolver) so it's usable against the real internet too, but every
automated test — and the recommended demo — points it at a toy server
running locally, so nothing requires real network access.

## Running the demo

Start the toy server (in one terminal):

```
python server.py --port 5353 --zone zones/example.json
```

Query it (in another terminal):

```
$ python resolve.py example.com --server 127.0.0.1:5353
Resolved example.com (A) via 127.0.0.1:5353:
  example.com                       300  A      93.184.216.34

$ python resolve.py example.com --type MX --server 127.0.0.1:5353
Resolved example.com (MX) via 127.0.0.1:5353:
  example.com                       300  MX     (10, 'mail.example.com')

$ python resolve.py www.example.com --server 127.0.0.1:5353
Resolved www.example.com (A) via 127.0.0.1:5353:
  www.example.com                   300  CNAME  example.com
  example.com                       300  A      93.184.216.34

$ python resolve.py nosuchdomain.invalid --server 127.0.0.1:5353
NXDOMAIN: nosuchdomain.invalid does not exist (NXDOMAIN)

$ python resolve.py example.com --server 127.0.0.1:5353 --short
93.184.216.34
```

`--short` prints just the resolved value(s), one per line, with no
name/ttl/type columns or summary line — handy for scripting, similar to
`dig +short`.

## Running the tests

```
python -m pip install pytest
pytest tests/ -v
```

Tests start the toy server on an ephemeral local port as a background
thread for each test class, then exercise the resolver against it —
covering wire-format round trips, name compression, each supported record
type, successful resolution, NXDOMAIN, timeouts (against a closed local
port), and malformed-packet handling (the server must keep running).

CI (`.github/workflows/tests.yml`) runs the same suite on Python 3.11,
3.12, and 3.13 on every push and pull request.

## Troubleshooting / FAQ

**I get a `TIMEOUT` instead of `NXDOMAIN` — what's the difference?**
They mean different things and it's worth not confusing them. `NXDOMAIN`
means a server *responded* and authoritatively said the name doesn't
exist. `TIMEOUT` means nothing answered at all within `--timeout` seconds
— wrong host/port, a firewall dropping the UDP packet, or the toy server
not actually running. Since DNS-over-UDP is connectionless, the client
has no way to distinguish "no such server" from "server is slow" from
"reply got lost in transit" — they all look like silence, so `resolve.py`
reports them all as `TIMEOUT` (exit code 2). If you're expecting
`NXDOMAIN` and getting `TIMEOUT` instead, double check `--server` points
at a server that's actually listening (`python server.py --port ...`
must be running first).

**Why doesn't the referral-following code path ever seem to run against the default server?**
Pointing `resolve.py` at a real public resolver like `1.1.1.1:53` (the
default) or at our own `server.py` both return final, direct answers —
a real public resolver does its own recursion internally and only hands
you the finished result, and our toy server is authoritative for
everything it knows, so it never emits a referral either. The
NS/glue-referral-following loop in `resolver.py`'s `resolve()` is real,
tested code, but you'd only see it actually take a hop if you ran two
toy servers and configured one to refer to the other, which the test
suite deliberately doesn't set up (see Limitations below).

**Why do I get raw bytes instead of a readable value for some record?**
`dns_protocol.py` only interprets A, AAAA, CNAME, NS, MX, and TXT rdata.
Any other RTYPE it encounters while decoding (e.g. SOA, SRV, PTR) is
returned as the raw RDATA bytes rather than raising, so the message still
parses instead of crashing — it's just up to the caller to know what to
do with those bytes. Extending `_decode_rdata()` for a new type is a good
first contribution (see `CONTRIBUTING.md`).

**`server.py` fails with `OSError: [Errno 48] Address already in use`.**
Something (often a previous, still-running `server.py`) is already bound
to that UDP port. Pick a different `--port`, or find and stop the
existing process.

## Limitations

This is a learning/portfolio project, not a production resolver: no
caching, no DNSSEC, no TCP fallback for large responses, no EDNS0. The
referral-following path in `resolver.py` is implemented and tested at the
unit level via the toy server's direct-answer path, but isn't exercised
against a multi-server referral chain since that would require running
several toy servers together.
