import string
import math
import re

COMMON_WORDS = {
    "password", "passw0rd", "qwerty", "letmein", "welcome", "admin",
    "iloveyou", "monkey", "dragon", "football", "baseball", "sunshine",
    "princess", "master", "login", "abc123", "123456", "111111",
}

KEYBOARD_RUNS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def has_sequence(password: str, run: int = 4) -> bool:
    """Detect runs like 'abcd', '4321' or keyboard rows like 'qwer'."""
    p = password.lower()
    for i in range(len(p) - run + 1):
        chunk = p[i : i + run]
        steps = {ord(chunk[j + 1]) - ord(chunk[j]) for j in range(run - 1)}
        if steps in ({1}, {-1}):
            return True
        for row in KEYBOARD_RUNS:
            if chunk in row or chunk in row[::-1]:
                return True
    return False


def find_warnings(password: str) -> list[str]:
    """Return human-readable warnings about weaknesses in the password."""
    warnings: list[str] = []
    lowered = password.lower()

    if len(password) < 8:
        warnings.append("Shorter than 8 characters.")
    elif len(password) < 12:
        warnings.append("Under 12 characters; longer is much harder to crack.")

    if any(word in lowered for word in COMMON_WORDS):
        warnings.append("Contains a very common password or word.")

    if re.search(r"(.)\1{2,}", password):
        warnings.append("Has a character repeated 3+ times in a row.")
    if has_sequence(password):
        warnings.append("Contains a sequence or keyboard pattern (e.g. 'abcd', 'qwer').")
    if password.isdigit():
        warnings.append("Only digits.")
    elif password.isalpha():
        warnings.append("Only letters.")

    return warnings

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

