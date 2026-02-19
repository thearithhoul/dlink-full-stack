from secrets import choice


CODE_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def generate_7_digit_code() -> str:
    """Return a random 7-character Base62 short code."""
    return "".join(choice(CODE_ALPHABET) for _ in range(7))
