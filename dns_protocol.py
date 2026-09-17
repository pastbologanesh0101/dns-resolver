"""
dns_protocol.py
================

A from-scratch implementation of DNS message encoding/decoding
(RFC 1035), including:

  - Header section
  - Question section
  - Resource record section (A, AAAA, CNAME, NS, MX, TXT)
  - DNS name compression (pointer) handling on decode
  - DNS name compression is NOT used on encode (we always write full
    labels), which is valid per RFC 1035 and simplifies the encoder.

No third-party DNS libraries are used -- only Python's standard
library (struct, socket, dataclasses).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# QTYPE / TYPE values we support (RFC 1035 section 3.2.2, plus AAAA RFC 3596)
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
}
NAME_TO_TYPE = {v: k for k, v in TYPE_NAMES.items()}

CLASS_IN = 1

# RCODE values
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# Pointer marker: top two bits of a length byte set == 0xC0
POINTER_FLAG = 0xC0


class DNSFormatError(Exception):
    """Raised when a packet cannot be parsed as a valid DNS message."""


# ---------------------------------------------------------------------------
# Name encoding / decoding
# ---------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format (sequence of length-prefixed
    labels terminated by a zero-length label). No compression is applied.
    """
    name = name.strip(".")
    if name == "":
        return b"\x00"

    out = bytearray()
    for label in name.split("."):
        label_bytes = label.encode("ascii")
        if len(label_bytes) == 0 or len(label_bytes) > 63:
            raise DNSFormatError(f"invalid label length in name: {name!r}")
        out.append(len(label_bytes))
        out.extend(label_bytes)
    out.append(0)
    return bytes(out)


def decode_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """Decode a domain name starting at `offset` within `packet`, following
    compression pointers as needed.

    Returns (name, new_offset) where new_offset is the offset immediately
    after the encoded name *as it appears at the original position* (i.e.
    after following the first pointer, if any -- subsequent bytes are not
    part of the record that referenced this name).
    """
    labels: List[str] = []
    pos = offset
    end_offset: Optional[int] = None  # offset to return to caller
    visited = set()  # loop protection

    while True:
        if pos >= len(packet):
            raise DNSFormatError("name extends past end of packet")
        length = packet[pos]

        if length == 0:
            # end of name
            pos += 1
            if end_offset is None:
                end_offset = pos
            break

        if (length & POINTER_FLAG) == POINTER_FLAG:
            if pos + 1 >= len(packet):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[pos + 1]
            if end_offset is None:
                end_offset = pos + 2
            if pointer in visited:
                raise DNSFormatError("compression pointer loop detected")
            visited.add(pointer)
            if pointer >= len(packet):
                raise DNSFormatError("compression pointer out of range")
            pos = pointer
            continue

        if (length & 0xC0) != 0:
            raise DNSFormatError("invalid label length byte")

        pos += 1
        if pos + length > len(packet):
            raise DNSFormatError("label extends past end of packet")
        label = packet[pos:pos + length]
        try:
            labels.append(label.decode("ascii"))
        except UnicodeDecodeError:
            raise DNSFormatError("non-ascii label")
        pos += length

    name = ".".join(labels)
    return name, end_offset


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

@dataclass
class DNSHeader:
    id: int = 0
    qr: int = 0          # 0 = query, 1 = response
    opcode: int = 0
    aa: int = 0           # authoritative answer
    tc: int = 0           # truncated
    rd: int = 1           # recursion desired
    ra: int = 0           # recursion available
    rcode: int = 0
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def pack(self) -> bytes:
        flags = (
            (self.qr & 0x1) << 15
            | (self.opcode & 0xF) << 11
            | (self.aa & 0x1) << 10
            | (self.tc & 0x1) << 9
            | (self.rd & 0x1) << 8
            | (self.ra & 0x1) << 7
            | (self.rcode & 0xF)
        )
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def unpack(cls, packet: bytes) -> "DNSHeader":
        if len(packet) < 12:
            raise DNSFormatError("packet shorter than DNS header (12 bytes)")
        id_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
        return cls(
            id=id_,
            qr=(flags >> 15) & 0x1,
            opcode=(flags >> 11) & 0xF,
            aa=(flags >> 10) & 0x1,
            tc=(flags >> 9) & 0x1,
            rd=(flags >> 8) & 0x1,
            ra=(flags >> 7) & 0x1,
            rcode=flags & 0xF,
            qdcount=qd,
            ancount=an,
            nscount=ns,
            arcount=ar,
        )


# ---------------------------------------------------------------------------
# Question
# ---------------------------------------------------------------------------

@dataclass
class DNSQuestion:
    qname: str
    qtype: int = TYPE_A
    qclass: int = CLASS_IN

    def pack(self) -> bytes:
        return encode_name(self.qname) + struct.pack("!HH", self.qtype, self.qclass)

    @classmethod
    def unpack(cls, packet: bytes, offset: int) -> Tuple["DNSQuestion", int]:
        name, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise DNSFormatError("truncated question section")
        qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
        return cls(qname=name, qtype=qtype, qclass=qclass), offset + 4


# ---------------------------------------------------------------------------
# Resource Record
# ---------------------------------------------------------------------------

@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: object  # interpreted value: str (A/AAAA/CNAME/NS/MX target), tuple (MX), or str (TXT)

    def pack(self) -> bytes:
        header = encode_name(self.name) + struct.pack("!HHI", self.rtype, self.rclass, self.ttl)
        rdata_bytes = self._pack_rdata()
        return header + struct.pack("!H", len(rdata_bytes)) + rdata_bytes

    def _pack_rdata(self) -> bytes:
        if self.rtype == TYPE_A:
            return _pack_ipv4(self.rdata)
        if self.rtype == TYPE_AAAA:
            return _pack_ipv6(self.rdata)
        if self.rtype in (TYPE_CNAME, TYPE_NS):
            return encode_name(self.rdata)
        if self.rtype == TYPE_MX:
            preference, exchange = self.rdata
            return struct.pack("!H", preference) + encode_name(exchange)
        if self.rtype == TYPE_TXT:
            text_bytes = self.rdata.encode("ascii")
            if len(text_bytes) > 255:
                raise DNSFormatError("TXT record too long for single string")
            return bytes([len(text_bytes)]) + text_bytes
        raise DNSFormatError(f"cannot encode unsupported rtype {self.rtype}")

    @classmethod
    def unpack(cls, packet: bytes, offset: int) -> Tuple["DNSRecord", int]:
        name, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise DNSFormatError("truncated resource record header")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata_start = offset
        if rdata_start + rdlength > len(packet):
            raise DNSFormatError("truncated resource record data")
        rdata_end = rdata_start + rdlength

        rdata = _decode_rdata(packet, rtype, rdata_start, rdata_end)
        return cls(name=name, rtype=rtype, rclass=rclass, ttl=ttl, rdata=rdata), rdata_end


def _pack_ipv4(addr: str) -> bytes:
    parts = addr.split(".")
    if len(parts) != 4:
        raise DNSFormatError(f"invalid IPv4 address: {addr!r}")
    try:
        return bytes(int(p) for p in parts)
    except ValueError:
        raise DNSFormatError(f"invalid IPv4 address: {addr!r}")


def _unpack_ipv4(data: bytes) -> str:
    if len(data) != 4:
        raise DNSFormatError("invalid A record length")
    return ".".join(str(b) for b in data)


def _pack_ipv6(addr: str) -> bytes:
    import socket as _socket
    return _socket.inet_pton(_socket.AF_INET6, addr)


def _unpack_ipv6(data: bytes) -> str:
    import socket as _socket
    if len(data) != 16:
        raise DNSFormatError("invalid AAAA record length")
    return _socket.inet_ntop(_socket.AF_INET6, data)


def _decode_rdata(packet: bytes, rtype: int, start: int, end: int):
    data = packet[start:end]
    if rtype == TYPE_A:
        return _unpack_ipv4(data)
    if rtype == TYPE_AAAA:
        return _unpack_ipv6(data)
    if rtype in (TYPE_CNAME, TYPE_NS):
        name, _ = decode_name(packet, start)
        return name
    if rtype == TYPE_MX:
        if len(data) < 2:
            raise DNSFormatError("truncated MX record")
        preference = struct.unpack("!H", data[:2])[0]
        exchange, _ = decode_name(packet, start + 2)
        return (preference, exchange)
    if rtype == TYPE_TXT:
        if len(data) == 0:
            return ""
        strlen = data[0]
        if 1 + strlen > len(data):
            raise DNSFormatError("truncated TXT record")
        return data[1:1 + strlen].decode("ascii", errors="replace")
    # Unsupported/unknown type: return raw bytes so callers can still
    # see *something* rather than crashing.
    return data


# ---------------------------------------------------------------------------
# Full message
# ---------------------------------------------------------------------------

@dataclass
class DNSMessage:
    header: DNSHeader
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    authorities: List[DNSRecord] = field(default_factory=list)
    additionals: List[DNSRecord] = field(default_factory=list)

    def pack(self) -> bytes:
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authorities)
        self.header.arcount = len(self.additionals)

        out = bytearray(self.header.pack())
        for q in self.questions:
            out.extend(q.pack())
        for r in self.answers:
            out.extend(r.pack())
        for r in self.authorities:
            out.extend(r.pack())
        for r in self.additionals:
            out.extend(r.pack())
        return bytes(out)

    @classmethod
    def unpack(cls, packet: bytes) -> "DNSMessage":
        header = DNSHeader.unpack(packet)
        offset = 12

        questions = []
        for _ in range(header.qdcount):
            q, offset = DNSQuestion.unpack(packet, offset)
            questions.append(q)

        answers = []
        for _ in range(header.ancount):
            r, offset = DNSRecord.unpack(packet, offset)
            answers.append(r)

        authorities = []
        for _ in range(header.nscount):
            r, offset = DNSRecord.unpack(packet, offset)
            authorities.append(r)

        additionals = []
        for _ in range(header.arcount):
            r, offset = DNSRecord.unpack(packet, offset)
            additionals.append(r)

        return cls(
            header=header,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )


def build_query(qname: str, qtype: int = TYPE_A, query_id: int = 0, recursion_desired: bool = True) -> DNSMessage:
    """Convenience constructor for a single-question DNS query message."""
    header = DNSHeader(id=query_id, qr=0, opcode=0, rd=1 if recursion_desired else 0)
    question = DNSQuestion(qname=qname, qtype=qtype, qclass=CLASS_IN)
    return DNSMessage(header=header, questions=[question])
