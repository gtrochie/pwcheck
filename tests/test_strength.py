import unittest
from pwcheck.strength import charset_size


class TestCharset(unittest.TestCase):
    def test_lowercase_only(self):
        self.assertEqual(charset_size("abc"), 26)

    def test_all_types(self):
        self.assertEqual(charset_size("aB1!"), 95)


if __name__ == "__main__":
    unittest.main()