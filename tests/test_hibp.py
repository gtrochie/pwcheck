import unittest
from pwcheck.hibp import sha1_hex, split_hash, parse_range_response

PASSWORD_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


class TestHashing(unittest.TestCase):
    def test_sha1_known_value(self):
        self.assertEqual(sha1_hex("password"), PASSWORD_HASH)


class TestSplit(unittest.TestCase):
    def test_split(self):
        prefix, suffix = split_hash(PASSWORD_HASH)
        self.assertEqual(prefix, "5BAA6")
        self.assertEqual(len(suffix), 35)
        self.assertEqual(prefix + suffix, PASSWORD_HASH)

class TestParsing(unittest.TestCase):
    def test_parses_counts(self):
        body = "AAAA:3\r\nbbbb:12\r\n"
        self.assertEqual(parse_range_response(body), {"AAAA": 3, "BBBB": 12})


if __name__ == "__main__":
    unittest.main()