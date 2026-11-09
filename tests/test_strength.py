import unittest
from pwcheck.strength import charset_size,entropy_bits, find_warnings


class TestCharset(unittest.TestCase):
    def test_lowercase_only(self):
        self.assertEqual(charset_size("abc"), 26)

    def test_all_types(self):
        self.assertEqual(charset_size("aB1!"), 95)

class TestEntropy(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(entropy_bits(""), 0.0)

    def test_longer_is_stronger(self):
        self.assertGreater(entropy_bits("abcdefghij"), entropy_bits("abcde"))

class TestWarnings(unittest.TestCase):
    def test_short(self):
        self.assertIn("Shorter than 8 characters.", find_warnings("aB1!"))

    def test_common_word(self):
        warnings = find_warnings("MyPassword2026")
        self.assertTrue(any("common" in w for w in warnings))

if __name__ == "__main__":
    unittest.main()