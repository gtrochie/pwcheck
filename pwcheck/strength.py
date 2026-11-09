import string


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

