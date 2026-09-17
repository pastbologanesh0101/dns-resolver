#!/usr/bin/env python3
"""
resolve.py
==========

CLI for the from-scratch DNS resolver.

Usage:
    python resolve.py example.com --server 127.0.0.1:5353
    python resolve.py example.com --type MX --server 127.0.0.1:5353
    python resolve.py example.com                      # uses default public resolver

Exit codes:
    0  success (records printed)
    1  NXDOMAIN
    2  timeout
    3  other resolver/query error
"""

from __future__ import annotations

import argparse
import sys

from dns_protocol import NAME_TO_TYPE, TYPE_A
from resolver import (
    DEFAULT_PORT,
    DEFAULT_START_SERVER,
    DNSQueryError,
    DNSTimeoutError,
    NXDomainError,
    parse_server_arg,
    resolve,
)


def main():
    parser = argparse.ArgumentParser(description="From-scratch DNS resolver CLI")
    parser.add_argument("name", help="Domain name to resolve, e.g. example.com")
    parser.add_argument(
        "--type",
        default="A",
        choices=sorted(NAME_TO_TYPE.keys()),
        help="Record type to query (default A)",
    )
    parser.add_argument(
        "--server",
        default=f"{DEFAULT_START_SERVER}:{DEFAULT_PORT}",
        help="Nameserver to query as host:port (default: %(default)s). "
             "Point this at your toy server, e.g. 127.0.0.1:5353",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Query timeout in seconds (default 3)")
    args = parser.parse_args()

    host, port = parse_server_arg(args.server)
    qtype = NAME_TO_TYPE[args.type]

    try:
        answers = resolve(args.name, qtype=qtype, start_server=host, start_port=port, timeout=args.timeout)
    except NXDomainError as e:
        print(f"NXDOMAIN: {e}", file=sys.stderr)
        sys.exit(1)
    except DNSTimeoutError as e:
        print(f"TIMEOUT: {e}", file=sys.stderr)
        sys.exit(2)
    except DNSQueryError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(3)

    if not answers:
        print(f"No {args.type} records found for {args.name} (NOERROR, no data)")
        return

    print(f"Resolved {args.name} ({args.type}) via {host}:{port}:")
    for ans in answers:
        print(f"  {ans.name:30s} {ans.ttl:6d}  {ans.rtype:6s} {ans.value}")


if __name__ == "__main__":
    main()
