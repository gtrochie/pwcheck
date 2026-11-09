import string
import math

def charset_size(password: str) -> int:
    """Estimate how many possible characters the password draws from."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation or c == " " for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):
        size += 100  # rough allowance for non-ASCII characters
    return size

def entropy_bits(password: str) -> float:
    """Naive entropy: length * log2(pool size)."""
    pool = charset_size(password)
    if not password or pool == 0:
        return 0.0
    return len(password) * math.log2(pool)

