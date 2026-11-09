import hashlib
import urllib.error
import urllib.request
from typing import Callable

PREFIX_LEN = 5

class BreachCheckError(Exception):
    """Raised when the breach API can't be reached or returns bad data."""


def split_hash(full_hash: str) -> tuple[str, str]:
    """Split a hash into (prefix sent to API, suffix kept locally)."""
    return full_hash[:PREFIX_LEN], full_hash[PREFIX_LEN:]


def sha1_hex(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of a password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def parse_range_response(body: str) -> dict[str, int]:
    """Parse 'SUFFIX:COUNT' lines into {suffix: count}."""
    results: dict[str, int] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        suffix, sep, count = line.partition(":")
        if not sep or not count.strip().isdigit():
            raise BreachCheckError(f"malformed API line: {line!r}")
        n = int(count)
        if n > 0:
            results[suffix.strip().upper()] = n
    return results

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "pwcheck-student-project/1.0"


def http_fetch(prefix: str, timeout: float = 10.0) -> str:
    """Fetch breached hash suffixes for a 5-char prefix from HIBP."""
    if len(prefix) != PREFIX_LEN:
        raise ValueError("prefix must be exactly 5 characters")
    req = urllib.request.Request(
        API_URL.format(prefix=prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise BreachCheckError(f"could not reach breach API: {exc}") from exc
    
def breach_count(password: str, fetch: Callable[[str], str] = http_fetch) -> int:
    """Return how many times this password appears in known breaches (0 = none)."""
    prefix, suffix = split_hash(sha1_hex(password))
    matches = parse_range_response(fetch(prefix))
    return matches.get(suffix, 0)