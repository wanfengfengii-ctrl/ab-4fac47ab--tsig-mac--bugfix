import json
import unittest

from app import canonical as c
from app.errors import ApiError
from app import dnswire


class TestCanonical(unittest.TestCase):
    def test_zone_case_and_absolute(self):
        self.assertEqual(c.canonical_zone("EXAMPLE.COM."), "example.com.")
        with self.assertRaises(ApiError):
            c.canonical_zone("example.com")  # must be absolute

    def test_owner_name_relative_and_case(self):
        self.assertEqual(c.canonical_name("WWW", "example.com."),
                         "www.example.com.")
        self.assertEqual(c.canonical_name("WWW.Example.COM.", "example.com."),
                         "www.example.com.")

    def test_out_of_zone_boundary(self):
        with self.assertRaises(ApiError) as ctx:
            c.canonical_name("evil-example.com.", "example.com.")
        self.assertEqual(ctx.exception.code, "NAME_OUT_OF_ZONE")
        with self.assertRaises(ApiError):
            c.canonical_name("other.test.", "example.com.")

    def test_rdata_canonical_aaaa(self):
        text, wire = c.canonical_rdata(
            "AAAA", {"address": "2001:DB8:0:0::1"}, "example.com.")
        self.assertEqual(json.loads(text)["address"], "2001:db8::1")
        self.assertEqual(len(wire), 16)

    def test_txt_roundtrip(self):
        text, wire = c.canonical_rdata("TXT", {"text": "hi"}, "example.com.")
        self.assertTrue(wire.endswith(b"hi"))

    def test_soa_wire(self):
        _, wire = c.canonical_rdata("SOA", {
            "mname": "a.example.", "rname": "b.example.", "serial": 1,
            "refresh": 2, "retry": 3, "expire": 4, "minimum": 5},
            "example.com.")
        self.assertEqual(len(wire), len(dnswire.encode_name("a.example."))
                         + len(dnswire.encode_name("b.example.")) + 20)

    def test_bad_ipv4(self):
        with self.assertRaises(ApiError):
            c.canonical_rdata("A", {"address": "999.1.1.1"}, "example.com.")


if __name__ == "__main__":
    unittest.main()
