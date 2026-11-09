import hashlib
PREFIX_LEN = 5


def split_hash(full_hash: str) -> tuple[str, str]:
    """Split a hash into (prefix sent to API, suffix kept locally)."""
    return full_hash[:PREFIX_LEN], full_hash[PREFIX_LEN:]


def sha1_hex(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of a password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()