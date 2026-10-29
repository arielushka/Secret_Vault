"""Short AES-GCM wrapper around PyCryptodome."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AESEncryption:
    def __init__(self, key=None):
        self.key = get_random_bytes(16) if key is None else key
        if len(self.key) not in (16, 32):
            raise ValueError("AES keys must be 16 or 32 bytes")

    def encrypt(self, data: bytes):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=get_random_bytes(12))
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, ciphertext + tag

    def decrypt(self, ciphertext: bytes, nonce: bytes):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
