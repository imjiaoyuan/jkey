import secrets
import string

_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?/"


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    char_sets = []
    if lowercase:
        char_sets.append(string.ascii_lowercase)
    if uppercase:
        char_sets.append(string.ascii_uppercase)
    if digits:
        char_sets.append(string.digits)
    if symbols:
        char_sets.append(_SYMBOLS)
    if not char_sets:
        raise ValueError("At least one character set must be selected.")
    all_chars = "".join(char_sets)
    mandatory = [secrets.choice(cs) for cs in char_sets]
    if length < len(mandatory):
        raise ValueError("Length too small to include all required character types.")
    remaining = length - len(mandatory)
    extra = [secrets.choice(all_chars) for _ in range(remaining)]
    password_list = mandatory + extra
    secrets.SystemRandom().shuffle(password_list)
    return "".join(password_list)
