import unittest
from pwcheck.hibp import sha1_hex

PASSWORD_HASH = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


class TestHashing(unittest.TestCase):
    def test_sha1_known_value(self):
        self.assertEqual(sha1_hex("password"), PASSWORD_HASH)


if __name__ == "__main__":
    unittest.main()