from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_password_hasher = PasswordHasher()


def hash_password(password):
    return _password_hasher.hash(password)


def verify_password(saved_hash, password):
    try:
        return _password_hasher.verify(saved_hash, password)
    except (InvalidHashError, VerificationError):
        return False
