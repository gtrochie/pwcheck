import unittest
from pwcheck.hibp import sha1_hex, split_hash, parse_range_response,BreachCheckError,breach_count

PASSWORD_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"

class FakeAPI:
    """Pretends to be HIBP and remembers what it was sent."""

    def __init__(self, body: str = ""):
        self.body = body
        self.requests: list[str] = []

    def __call__(self, prefix: str) -> str:
        self.requests.append(prefix)
        return self.body


class TestBreachCount(unittest.TestCase):
    def test_found(self):
        _, suffix = split_hash(PASSWORD_HASH)
        api = FakeAPI(f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:9545824\r\n")
        self.assertEqual(breach_count("password", api), 9545824)

    def test_not_found(self):
        api = FakeAPI("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n")
        self.assertEqual(breach_count("password", api), 0)


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

    def test_skips_padding(self):
        body = "AAAA:3\r\nBBBB:0\r\n"
        self.assertEqual(parse_range_response(body), {"AAAA": 3})

    def test_malformed_line_raises(self):
        with self.assertRaises(BreachCheckError):
            parse_range_response("AAAA-3")

class TestKAnonymity(unittest.TestCase):
    def test_only_five_char_prefix_is_sent(self):
        api = FakeAPI()
        breach_count("password", api)
        self.assertEqual(api.requests, ["5BAA6"])

    def test_password_never_sent(self):
        api = FakeAPI()
        breach_count("hunter2", api)
        for sent in api.requests:
            self.assertNotIn("hunter2", sent)
            self.assertEqual(len(sent), 5)

if __name__ == "__main__":
    unittest.main()