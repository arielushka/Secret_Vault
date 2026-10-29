"""RSA-OAEP wrapping for the small Shamir shares sent through JSON."""

import base64


def encrypt_share(share, public_key, rsa_manager):
    message = share.encode("utf-8")
    max_size = public_key.key_size // 8 - 2 * 32 - 2  # OAEP with SHA-256
    if len(message) > max_size:
        raise ValueError("Share is too large for RSA")
    return base64.b64encode(rsa_manager.encrypt(message, public_key)).decode("ascii")


def decrypt_share(encoded, private_key, rsa_manager):
    ciphertext = base64.b64decode(encoded, validate=True)
    return rsa_manager.decrypt(ciphertext, private_key).decode("utf-8")


class ShareEncryption:
    encrypt_share = staticmethod(encrypt_share)
    decrypt_share = staticmethod(decrypt_share)
