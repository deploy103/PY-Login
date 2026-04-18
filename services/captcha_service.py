import random
import string


SPECIALS = "!@#$%^&*()"
CAPTCHA_CHARACTERS = string.ascii_uppercase + string.ascii_lowercase + string.digits + SPECIALS


def generate_captcha(length=8):
    characters = []
    for _ in range(length):
        characters.append(random.choice(CAPTCHA_CHARACTERS))
    return "".join(characters)
