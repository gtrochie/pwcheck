import hashlib
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