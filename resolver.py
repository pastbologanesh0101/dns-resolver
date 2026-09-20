"""
resolver.py
===========

A DNS resolver built on raw UDP sockets and the hand-rolled wire format
in dns_protocol.py.

Two modes of operation:

  - query_server(): send a single query to one nameserver and return its
    response (used directly against our toy authoritative server, or as
    the building block for iterative resolution).

  - resolve(): an "iterative" resolver. If the configured start server
    already gives a final answer (as our toy server does -- it's
    authoritative for everything it knows), that answer is returned
    directly. If the response is a referral (answers empty, but
    authority/additional sections point at other nameservers), the
    resolver follows the referral chain by querying those nameservers
    in turn, up to a maximum number of hops. This mirrors how a real
    iterative resolver walks from the root down to the authoritative
    server, without requiring real internet access -- point it at your
    own toy server (or a chain of them) for fully offline testing.

NXDOMAIN and timeouts are surfaced as clean, specific exceptions rather
than generic socket errors.
"""

from __future__ import annotations

import random
import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

from dns_protocol import (
    DNSFormatError,
    DNSMessage,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_CNAME,
    TYPE_NAMES,
    build_query,
)

DEFAULT_TIMEOUT = 3.0
MAX_REFERRAL_HOPS = 8

# A well-known public resolver, used only as the *default* starting point.
# Tests never rely on this being reachable -- they always point resolve()
# at a locally started toy server instead.
DEFAULT_START_SERVER = "1.1.1.1"
DEFAULT_PORT = 53


class DNSResolverError(Exception):
    """Base class for resolver errors."""


class DNSTimeoutError(DNSResolverError):
    """Raised when no response is received from a server within the timeout."""


class NXDomainError(DNSResolverError):
    """Raised when a server authoritatively reports the name does not exist."""


class DNSQueryError(DNSResolverError):
    """Raised for other non-success RCODEs or malformed responses."""


@dataclass
class ResolvedAnswer:
    name: str
    rtype: str
    ttl: int
    value: object


def parse_server_arg(server: str) -> Tuple[str, int]:
    """Parse a "host:port" or bare "host" string into (host, port).

    Raises ValueError with a specific, user-facing message if a port is
    present but isn't a valid UDP port number (not an integer, or out of
    the 0-65535 range) -- e.g. a typo like "127.0.0.1:53a" or a missing
    host like ":5353".
    """
    if ":" in server:
        host, port_str = server.rsplit(":", 1)
        if not host:
            raise ValueError(f"invalid --server value {server!r}: missing host before ':'")
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"invalid --server value {server!r}: {port_str!r} is not a valid port number")
        if not (0 <= port <= 65535):
            raise ValueError(f"invalid --server value {server!r}: port {port} is out of range (0-65535)")
        return host, port
    return server, DEFAULT_PORT


def query_server(
    qname: str,
    qtype: int,
    server_host: str,
    server_port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    query_id: Optional[int] = None,
) -> DNSMessage:
    """Send one DNS query over UDP to a specific server and return the
    parsed response message.

    Raises DNSTimeoutError on timeout, DNSFormatError on unparsable
    responses.
    """
    if query_id is None:
        query_id = random.randint(0, 0xFFFF)

    query = build_query(qname, qtype=qtype, query_id=query_id)
    packet = query.pack()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, (server_host, server_port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            raise DNSTimeoutError(
                f"no response from {server_host}:{server_port} within {timeout}s"
            )
    finally:
        sock.close()

    response = DNSMessage.unpack(data)
    if response.header.id != query_id:
        raise DNSQueryError("response ID does not match query ID")
    return response


def resolve(
    name: str,
    qtype: int = TYPE_A,
    start_server: str = DEFAULT_START_SERVER,
    start_port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_hops: int = MAX_REFERRAL_HOPS,
) -> List[ResolvedAnswer]:
    """Resolve `name` to records of type `qtype`, starting from
    `start_server`.

    For an authoritative toy server, this is a single round trip. If the
    server instead returns a referral (empty answers, but NS records in
    the authority section plus glue A records in additional), the
    resolver follows the chain to the next server and re-queries, up to
    `max_hops` times.
    """
    current_host, current_port = start_server, start_port
    current_name = name
    hops = 0
    seen_servers = set()

    while True:
        hops += 1
        if hops > max_hops:
            raise DNSQueryError(f"exceeded max referral hops ({max_hops}) resolving {name}")

        response = query_server(current_name, qtype, current_host, current_port, timeout=timeout)

        if response.header.rcode == RCODE_NXDOMAIN:
            raise NXDomainError(f"{current_name} does not exist (NXDOMAIN)")
        if response.header.rcode != RCODE_NOERROR:
            raise DNSQueryError(f"server returned rcode={response.header.rcode} for {current_name}")

        if response.answers:
            results = []
            cname_target = None
            for rec in response.answers:
                type_name = TYPE_NAMES.get(rec.rtype, str(rec.rtype))
                results.append(ResolvedAnswer(name=rec.name, rtype=type_name, ttl=rec.ttl, value=rec.rdata))
                if rec.rtype == TYPE_CNAME and qtype != TYPE_CNAME:
                    cname_target = rec.rdata

            # If we only got a CNAME and were looking for something else,
            # follow it against the same server (our toy server already
            # inlines this, but a referral-following resolver might not).
            has_requested_type = any(
                TYPE_NAMES.get(qtype) == r.rtype for r in results
            )
            if cname_target and not has_requested_type:
                current_name = cname_target
                continue

            return results

        # No answers: look for a referral (NS in authority + glue in additional).
        referral_ns = [rec for rec in response.authorities if rec.rtype == 2]  # NS
        if not referral_ns:
            # Authoritative NOERROR/NODATA: name exists, but no records of
            # this type. Return empty list rather than raising.
            return []

        glue = {rec.name: rec.rdata for rec in response.additionals if rec.rtype == TYPE_A}
        next_ns_name = referral_ns[0].rdata
        if next_ns_name in glue:
            next_host = glue[next_ns_name]
        else:
            # No glue record; resolve the nameserver's address using the
            # same starting server as a fallback (best-effort).
            ns_answers = resolve(next_ns_name, TYPE_A, start_server, start_port, timeout, max_hops - hops)
            if not ns_answers:
                raise DNSQueryError(f"could not resolve address of nameserver {next_ns_name}")
            next_host = ns_answers[0].value

        server_key = (next_host, current_port)
        if server_key in seen_servers:
            raise DNSQueryError("referral loop detected")
        seen_servers.add(server_key)
        current_host = next_host
        # current_name stays the same; we re-ask the referred server.
