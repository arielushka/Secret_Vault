"""Password hashing using scrypt from the project's existing crypto package."""

import base64
import hmac

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

_SALT_SIZE = 16
_HASH_SIZE = 32
_COST = {"N": 2**14, "r": 8, "p": 1}


def hash_password(password):
    salt = get_random_bytes(_SALT_SIZE)
    digest = scrypt(password.encode("utf-8"), salt, _HASH_SIZE, **_COST)
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"scrypt$1${salt_text}${digest_text}"


def verify_password(saved_hash, password):
    try:
        algorithm, version, salt_text, digest_text = saved_hash.split("$")
        if algorithm != "scrypt" or version != "1":
            return False
        salt = base64.b64decode(salt_text, altchars=b"-_", validate=True)
        expected = base64.b64decode(digest_text, altchars=b"-_", validate=True)
        actual = scrypt(password.encode("utf-8"), salt, _HASH_SIZE, **_COST)
        return hmac.compare_digest(actual, expected)
    except ValueError:
        return False
