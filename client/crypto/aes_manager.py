import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESEncryption:

    def __init__(self, key=None):
        if key is None:
            self.key = AESGCM.generate_key(bit_length=256)
        else:
            self.key = key

    def encrypt(self, data: bytes):
        nonce = os.urandom(12)
        aes_cipher = AESGCM(self.key)
        ciphertext = aes_cipher.encrypt(nonce, data, None)
        return nonce, ciphertext

    def decrypt(self, ciphertext: bytes, nonce: bytes):
        aes_cipher = AESGCM(self.key)
        plaintext = aes_cipher.decrypt(nonce, ciphertext, None)
        return plaintext

