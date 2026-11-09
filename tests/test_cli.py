import unittest
import io, os, tempfile
from contextlib import redirect_stdout
from pwcheck import cli
from pwcheck.hibp import split_hash
from tests.test_hibp import PASSWORD_HASH, FakeAPI
from pwcheck.hibp import BreachCheckError

class TestCLI(unittest.TestCase):
    def test_breached_password(self):
        _, suffix = split_hash(PASSWORD_HASH)
        result = cli.check_one("password", fetch=FakeAPI(f"{suffix}:5\r\n"))
        self.assertEqual(result["breaches"], 5)
        self.assertIn("DO NOT USE", cli.verdict(result))
        self.assertEqual(cli.exit_code(result), cli.EXIT_BREACHED)
    
    def test_offline_skips_network(self):
        api = FakeAPI()
        result = cli.check_one("whatever", offline=True, fetch=api)
        self.assertIsNone(result["breaches"])
        self.assertEqual(api.requests, [])

    def test_file_mode_never_prints_passwords(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as fh:
            fh.write("SuperSecretValue123\nanotherOne!\n")
            path = fh.name
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.main(["--file", path], fetch=FakeAPI())
            out = buf.getvalue()
            self.assertNotIn("SuperSecretValue123", out)
            self.assertIn("line 1", out)
            self.assertEqual(code, cli.EXIT_OK)
        finally:
            os.unlink(path)

    def test_network_failure_is_reported_not_crashed(self):
        def broken(prefix):
            raise BreachCheckError("network down")

        result = cli.check_one("whatever", fetch=broken)
        self.assertIsNone(result["breaches"])
        self.assertIn("network down", result["error"])
        self.assertNotIn("not found", cli.render(result))
        self.assertEqual(cli.exit_code(result), cli.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main()