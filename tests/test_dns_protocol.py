"""Unit tests for dns_protocol.py: encoding/decoding round trips,
name compression, and record parsing.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_protocol import (
    CLASS_IN,
    DNSFormatError,
    DNSHeader,
    DNSMessage,
    DNSQuestion,
    DNSRecord,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_TXT,
    build_query,
    decode_name,
    encode_name,
)


class TestNameEncoding(unittest.TestCase):
    def test_encode_decode_simple_name_round_trip(self):
        encoded = encode_name("example.com")
        decoded, new_offset = decode_name(encoded, 0)
        self.assertEqual(decoded, "example.com")
        self.assertEqual(new_offset, len(encoded))

    def test_encode_root_name(self):
        encoded = encode_name("")
        self.assertEqual(encoded, b"\x00")
        decoded, offset = decode_name(encoded, 0)
        self.assertEqual(decoded, "")
        self.assertEqual(offset, 1)

    def test_decode_name_with_compression_pointer(self):
        # Build a packet where a second name is just a pointer back to the
        # first name's encoding, exactly as real DNS packets compress names.
        first = encode_name("example.com")
        pointer_offset = 0
        # Pointer bytes: 0xC0 | high bits of offset, low bits of offset.
        pointer = bytes([0xC0 | (pointer_offset >> 8), pointer_offset & 0xFF])
        packet = first + pointer

        decoded, new_offset = decode_name(packet, len(first))
        self.assertEqual(decoded, "example.com")
        self.assertEqual(new_offset, len(first) + 2)

    def test_decode_name_pointer_loop_raises(self):
        # A pointer that points at itself must not hang the decoder.
        packet = bytes([0xC0, 0x00])
        with self.assertRaises(DNSFormatError):
            decode_name(packet, 0)


class TestHeaderRoundTrip(unittest.TestCase):
    def test_header_pack_unpack_round_trip(self):
        header = DNSHeader(id=0x1234, qr=1, opcode=0, aa=1, rd=1, ra=1, rcode=0,
                            qdcount=1, ancount=2, nscount=0, arcount=0)
        packed = header.pack()
        self.assertEqual(len(packed), 12)
        unpacked = DNSHeader.unpack(packed)
        self.assertEqual(unpacked, header)


class TestMessageRoundTrip(unittest.TestCase):
    def test_query_message_round_trip(self):
        query = build_query("example.com", qtype=TYPE_A, query_id=42)
        packed = query.pack()
        decoded = DNSMessage.unpack(packed)

        self.assertEqual(decoded.header.id, 42)
        self.assertEqual(decoded.header.qr, 0)
        self.assertEqual(decoded.header.qdcount, 1)
        self.assertEqual(decoded.questions[0].qname, "example.com")
        self.assertEqual(decoded.questions[0].qtype, TYPE_A)
        self.assertEqual(decoded.questions[0].qclass, CLASS_IN)

    def test_response_message_round_trip_with_answer(self):
        header = DNSHeader(id=99, qr=1, aa=1, rcode=0, qdcount=1, ancount=1)
        question = DNSQuestion(qname="example.com", qtype=TYPE_A, qclass=CLASS_IN)
        record = DNSRecord(name="example.com", rtype=TYPE_A, rclass=CLASS_IN, ttl=300, rdata="93.184.216.34")
        message = DNSMessage(header=header, questions=[question], answers=[record])

        packed = message.pack()
        decoded = DNSMessage.unpack(packed)

        self.assertEqual(decoded.header.id, 99)
        self.assertEqual(decoded.header.qr, 1)
        self.assertEqual(len(decoded.answers), 1)
        self.assertEqual(decoded.answers[0].name, "example.com")
        self.assertEqual(decoded.answers[0].rtype, TYPE_A)
        self.assertEqual(decoded.answers[0].rdata, "93.184.216.34")

    def test_message_with_multiple_records_uses_name_compression_safe_decode(self):
        # Two answers both referencing the same owner name; even though we
        # don't compress on encode, the decoder must still handle each
        # name occurrence independently and correctly.
        header = DNSHeader(id=7, qr=1, aa=1, qdcount=1, ancount=2)
        question = DNSQuestion(qname="example.com", qtype=TYPE_A)
        rec1 = DNSRecord(name="example.com", rtype=TYPE_A, rclass=CLASS_IN, ttl=60, rdata="1.2.3.4")
        rec2 = DNSRecord(name="example.com", rtype=TYPE_A, rclass=CLASS_IN, ttl=60, rdata="5.6.7.8")
        message = DNSMessage(header=header, questions=[question], answers=[rec1, rec2])

        decoded = DNSMessage.unpack(message.pack())
        values = sorted(r.rdata for r in decoded.answers)
        self.assertEqual(values, ["1.2.3.4", "5.6.7.8"])


class TestRecordParsing(unittest.TestCase):
    def test_a_record_value(self):
        rec = DNSRecord(name="host.example.com", rtype=TYPE_A, rclass=CLASS_IN, ttl=100, rdata="10.20.30.40")
        packed = rec.pack()
        decoded, offset = DNSRecord.unpack(packed, 0)
        self.assertEqual(decoded.rdata, "10.20.30.40")
        self.assertEqual(offset, len(packed))

    def test_aaaa_record_value(self):
        rec = DNSRecord(name="host.example.com", rtype=TYPE_AAAA, rclass=CLASS_IN, ttl=100,
                         rdata="2606:2800:220:1:248:1893:25c8:1946")
        decoded, _ = DNSRecord.unpack(rec.pack(), 0)
        self.assertEqual(decoded.rdata, "2606:2800:220:1:248:1893:25c8:1946")

    def test_cname_record_value(self):
        rec = DNSRecord(name="www.example.com", rtype=TYPE_CNAME, rclass=CLASS_IN, ttl=100, rdata="example.com")
        decoded, _ = DNSRecord.unpack(rec.pack(), 0)
        self.assertEqual(decoded.rdata, "example.com")

    def test_mx_record_value(self):
        rec = DNSRecord(name="example.com", rtype=TYPE_MX, rclass=CLASS_IN, ttl=100, rdata=(10, "mail.example.com"))
        decoded, _ = DNSRecord.unpack(rec.pack(), 0)
        self.assertEqual(decoded.rdata, (10, "mail.example.com"))

    def test_txt_record_value(self):
        rec = DNSRecord(name="example.com", rtype=TYPE_TXT, rclass=CLASS_IN, ttl=100, rdata="v=spf1 -all")
        decoded, _ = DNSRecord.unpack(rec.pack(), 0)
        self.assertEqual(decoded.rdata, "v=spf1 -all")

    def test_ns_record_value(self):
        rec = DNSRecord(name="example.com", rtype=TYPE_NS, rclass=CLASS_IN, ttl=100, rdata="ns1.example.com")
        decoded, _ = DNSRecord.unpack(rec.pack(), 0)
        self.assertEqual(decoded.rdata, "ns1.example.com")


if __name__ == "__main__":
    unittest.main()
