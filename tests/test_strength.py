import unittest
from pwcheck.strength import charset_size,entropy_bits, find_warnings,has_sequence, analyse

if __name__ == "__main__":
    unittest.main()


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
    
    def test_sequence(self):
        self.assertTrue(has_sequence("Xyabcd99!!"))
        self.assertTrue(has_sequence("zz4321zz"))
        self.assertTrue(has_sequence("myqwerpass"))
        self.assertFalse(has_sequence("Tq8#mZ2!"))

    def test_repeats(self):
        warnings = find_warnings("aaa-Secure-99")
        self.assertTrue(any("repeated" in w for w in warnings))

class TestAnalyse(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        report = analyse("password")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.label, "Very weak")

    def test_passphrase_is_strong(self):
        report = analyse("Correct-Horse-Battery-Staple-Mopane-7")
        self.assertGreaterEqual(report.score, 3)
        self.assertEqual(report.warnings, [])

if __name__ == "__main__":
    unittest.main()