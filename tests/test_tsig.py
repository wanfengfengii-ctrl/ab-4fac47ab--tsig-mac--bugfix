import struct
import time
import unittest

from app import dnsclient as dc
from app import dnswire as w


class TestTsigWire(unittest.TestCase):
    def test_time_48bit_roundtrip(self):
        for when in (0, 1, 1700000000, 0xFFFFFFFF, 0x1_FFFFFFFF):
            q = dc.build_tsig_query(0x1234, "example.", w.TYPE_AXFR,
                                    "key.", b"k" * 32, when=when, fudge=300)
            parsed = w.parse_query(q)
            self.assertEqual(parsed["tsig"]["time"], when, when)
            self.assertEqual(parsed["tsig"]["fudge"], 300)

    def test_current_time_roundtrip(self):
        now = int(time.time())
        q = dc.build_tsig_query(1, "example.", w.TYPE_SOA, "key.",
                                b"k" * 32)
        parsed = w.parse_query(q)
        self.assertLessEqual(abs(parsed["tsig"]["time"] - now), 2)

    def test_time_verification(self):
        now = 1000000
        self.assertTrue(w.verify_tsig_time(now, 300, now))
        self.assertTrue(w.verify_tsig_time(now + 300, 300, now))
        self.assertFalse(w.verify_tsig_time(now + 301, 300, now))
        self.assertFalse(w.verify_tsig_time(now - 100000, 300, now))
        self.assertFalse(w.verify_tsig_time(now, 99999, now))  # fudge cap

    def test_request_mac_deterministic(self):
        q1 = dc.build_tsig_query(1, "example.", w.TYPE_AXFR, "k.",
                                 b"k" * 32, when=1000)
        q2 = dc.build_tsig_query(1, "example.", w.TYPE_AXFR, "k.",
                                 b"k" * 32, when=1000)
        self.assertEqual(q1, q2)
        p1, p2 = w.parse_query(q1), w.parse_query(q2)
        self.assertEqual(p1["tsig"]["mac"], p2["tsig"]["mac"])


if __name__ == "__main__":
    unittest.main()
