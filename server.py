#!/usr/bin/env python3
"""
server.py
=========

A toy authoritative DNS server. It loads a JSON "zone file" mapping
domain names to record type -> value(s), listens on a UDP port, and
answers DNS queries using hand-rolled wire-format encoding from
dns_protocol.py.

Usage:
    python server.py --port 5353 --zone zones/example.json

The server understands A, AAAA, CNAME, NS, MX, and TXT records in the
zone file and returns NXDOMAIN for anything it doesn't have.
Malformed incoming packets are logged and ignored (the server keeps
running rather than crashing).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from typing import Dict, Optional

from dns_protocol import (
    CLASS_IN,
    DNSFormatError,
    DNSHeader,
    DNSMessage,
    DNSRecord,
    NAME_TO_TYPE,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NAMES,
    TYPE_NS,
    TYPE_TXT,
)

DEFAULT_TTL = 300


def load_zone(path: str) -> Dict[str, Dict[str, list]]:
    with open(path, "r") as f:
        raw = json.load(f)
    # Normalize domain names to lowercase, no trailing dot.
    zone = {}
    for name, records in raw.items():
        zone[name.rstrip(".").lower()] = records
    return zone


def _build_record(name: str, rtype: int, value: object) -> DNSRecord:
    if rtype == TYPE_MX:
        preference, exchange = value
        rdata = (preference, exchange)
    else:
        rdata = value
    return DNSRecord(name=name, rtype=rtype, rclass=CLASS_IN, ttl=DEFAULT_TTL, rdata=rdata)


class ToyDNSServer:
    """A minimal authoritative DNS server over UDP."""

    def __init__(self, zone: Dict[str, Dict[str, list]], host: str = "127.0.0.1", port: int = 5353):
        self.zone = zone
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    def _answer(self, query: DNSMessage) -> DNSMessage:
        header = DNSHeader(
            id=query.header.id,
            qr=1,
            opcode=query.header.opcode,
            aa=1,
            rd=query.header.rd,
            ra=0,
            rcode=RCODE_NOERROR,
        )
        response = DNSMessage(header=header, questions=list(query.questions))

        if not query.questions:
            header.rcode = RCODE_SERVFAIL
            return response

        question = query.questions[0]
        qname = question.qname.rstrip(".").lower()
        type_name = TYPE_NAMES.get(question.qtype)

        if qname not in self.zone:
            header.rcode = RCODE_NXDOMAIN
            return response

        records = self.zone[qname]

        # Follow a single CNAME hop if the queried type isn't a direct
        # match but a CNAME exists (like a real authoritative server would
        # include the CNAME + then the target's records if known locally).
        answers = []
        if type_name and type_name in records:
            for value in records[type_name]:
                answers.append(_build_record(qname, question.qtype, value))
        elif "CNAME" in records:
            cname_target = records["CNAME"][0]
            answers.append(_build_record(qname, TYPE_CNAME, cname_target))
            target = cname_target.rstrip(".").lower()
            if type_name and target in self.zone and type_name in self.zone[target]:
                for value in self.zone[target][type_name]:
                    answers.append(_build_record(target, question.qtype, value))

        if not answers:
            # Name exists but no records of the requested type: NOERROR
            # with an empty answer section (like real DNS "NODATA").
            header.rcode = RCODE_NOERROR
            response.answers = []
            return response

        response.answers = answers
        return response

    def _serve_forever(self) -> None:
        assert self._sock is not None
        self._sock.settimeout(0.5)
        while self._running.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                query = DNSMessage.unpack(data)
                response = self._answer(query)
                self._sock.sendto(response.pack(), addr)
            except DNSFormatError as e:
                # Malformed packet: log and ignore, don't crash the server.
                sys.stderr.write(f"[server] dropped malformed packet from {addr}: {e}\n")
                continue
            except Exception as e:  # pragma: no cover - defensive catch-all
                sys.stderr.write(f"[server] unexpected error handling packet from {addr}: {e}\n")
                continue

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        # If port 0 was requested, find out what we actually got.
        self.port = self._sock.getsockname()[1]
        self._running.set()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()

    def wait_forever(self) -> None:
        try:
            while self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=0.5)
        except KeyboardInterrupt:
            self.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Toy authoritative DNS server")
    parser.add_argument("--port", type=int, default=5353, help="UDP port to listen on (default 5353)")
    parser.add_argument("--host", default="127.0.0.1", help="Host/IP to bind (default 127.0.0.1)")
    parser.add_argument("--zone", default="zones/example.json", help="Path to zone JSON file")
    args = parser.parse_args()

    zone = load_zone(args.zone)
    server = ToyDNSServer(zone, host=args.host, port=args.port)
    server.start()
    print(f"Toy DNS server listening on {args.host}:{server.port}, zone={args.zone}")
    server.wait_forever()


if __name__ == "__main__":
    main()
