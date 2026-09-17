"""Integration-style tests for server.py + resolver.py.

These tests start the toy authoritative server on an ephemeral local
port as a background thread and query it through the resolver, so they
never touch real internet DNS servers.
"""

import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_protocol import DNSMessage, TYPE_A, TYPE_MX, TYPE_TXT
from resolver import (
    DNSTimeoutError,
    NXDomainError,
    query_server,
    resolve,
)
from server import ToyDNSServer, load_zone

ZONE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zones", "example.json")


class ToyServerTestCase(unittest.TestCase):
    """Base class that spins up a real toy server on 127.0.0.1:<ephemeral>."""

    @classmethod
    def setUpClass(cls):
        zone = load_zone(ZONE_PATH)
        cls.server = ToyDNSServer(zone, host="127.0.0.1", port=0)
        cls.server.start()
        cls.port = cls.server.port

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()


class TestToyServerAnswers(ToyServerTestCase):
    def test_resolves_a_record_for_known_zone_entry(self):
        answers = resolve("example.com", qtype=TYPE_A, start_server="127.0.0.1", start_port=self.port, timeout=2.0)
        self.assertEqual(len(answers), 1)
        self.assertEqual(answers[0].value, "93.184.216.34")
        self.assertEqual(answers[0].rtype, "A")

    def test_resolves_multiple_a_records(self):
        answers = resolve("toylab.dev", qtype=TYPE_A, start_server="127.0.0.1", start_port=self.port, timeout=2.0)
        values = sorted(a.value for a in answers)
        self.assertEqual(values, ["10.0.0.1", "10.0.0.2"])

    def test_resolves_mx_record(self):
        answers = resolve("example.com", qtype=TYPE_MX, start_server="127.0.0.1", start_port=self.port, timeout=2.0)
        self.assertEqual(len(answers), 1)
        self.assertEqual(answers[0].value, (10, "mail.example.com"))

    def test_resolves_txt_record(self):
        answers = resolve("api.toylab.dev", qtype=TYPE_TXT, start_server="127.0.0.1", start_port=self.port, timeout=2.0)
        self.assertEqual(answers[0].value, "hello from the toy zone")

    def test_cname_chain_resolves_to_a_record(self):
        answers = resolve("www.example.com", qtype=TYPE_A, start_server="127.0.0.1", start_port=self.port, timeout=2.0)
        rtypes = [a.rtype for a in answers]
        values = [a.value for a in answers]
        self.assertIn("CNAME", rtypes)
        self.assertIn("93.184.216.34", values)

    def test_nxdomain_for_unknown_domain(self):
        with self.assertRaises(NXDomainError):
            resolve("this-domain-does-not-exist-in-our-zone.invalid",
                     qtype=TYPE_A, start_server="127.0.0.1", start_port=self.port, timeout=2.0)

    def test_raw_query_server_returns_well_formed_response(self):
        response = query_server("example.com", TYPE_A, "127.0.0.1", self.port, timeout=2.0)
        self.assertEqual(response.header.qr, 1)
        self.assertEqual(response.header.aa, 1)
        self.assertEqual(len(response.answers), 1)


class TestTimeoutHandling(unittest.TestCase):
    def test_timeout_when_server_unreachable(self):
        # Bind a socket to grab a genuinely free port, then close it so
        # nothing is listening there -- queries against it should time out
        # (or in some environments, fail fast with a connection error,
        # which we also treat as acceptable since we don't control the
        # OS's ICMP behavior). We assert on timeout specifically by using
        # a very short timeout and a non-routable-but-not-refusing address
        # is unreliable across CI hosts, so instead we close a bound
        # ephemeral port to guarantee no responder exists.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        unused_port = probe.getsockname()[1]
        probe.close()

        with self.assertRaises(DNSTimeoutError):
            resolve("example.com", qtype=TYPE_A, start_server="127.0.0.1", start_port=unused_port, timeout=0.5)


class TestMalformedPacketHandling(ToyServerTestCase):
    def test_server_survives_malformed_packet_and_keeps_answering(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            # Send garbage that is shorter than a DNS header.
            sock.sendto(b"\x00\x01\x02", ("127.0.0.1", self.port))
            # Send garbage that looks header-sized but is nonsense.
            sock.sendto(os.urandom(20), ("127.0.0.1", self.port))
        finally:
            sock.close()

        # The server must still be alive and answer a legitimate query
        # afterward.
        answers = resolve("example.com", qtype=TYPE_A, start_server="127.0.0.1", start_port=self.port, timeout=2.0)
        self.assertEqual(answers[0].value, "93.184.216.34")


if __name__ == "__main__":
    unittest.main()
