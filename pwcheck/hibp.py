import hashlib


def sha1_hex(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of a password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()