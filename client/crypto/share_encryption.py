"""RSA-OAEP wrapping for the small Shamir shares sent through JSON."""

import base64

from client.crypto.rsa_manager import RSAEncryption


def encrypt_share(share, public_key):
    max_size = public_key.key_size // 8 - 2 * 32 - 2  # OAEP with SHA-256
    if len(share) > max_size:
        raise ValueError("Share is too large for RSA")
    ciphertext = RSAEncryption.encrypt(share, public_key)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_share(encoded, private_key):
    ciphertext = base64.b64decode(encoded, validate=True)
    return RSAEncryption.decrypt(ciphertext, private_key)
