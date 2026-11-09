import unittest

from pwcheck import cli
from pwcheck.hibp import split_hash
from tests.test_hibp import PASSWORD_HASH, FakeAPI


class TestCLI(unittest.TestCase):
    def test_breached_password(self):
        _, suffix = split_hash(PASSWORD_HASH)
        result = cli.check_one("password", fetch=FakeAPI(f"{suffix}:5\r\n"))
        self.assertEqual(result["breaches"], 5)
        self.assertIn("DO NOT USE", cli.verdict(result))
        self.assertEqual(cli.exit_code(result), cli.EXIT_BREACHED)


if __name__ == "__main__":
    unittest.main()