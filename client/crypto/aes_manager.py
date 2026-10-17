import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESEncryption:

    def __init__(self, key=None):
        if key is None:
            # New uploads get a random 256-bit key; downloads pass in a recovered key.
            self.key = AESGCM.generate_key(bit_length=256)
        else:
            self.key = key

    def encrypt(self, data: bytes):
        # AES-GCM uses a fresh nonce for every file encryption.
        nonce = os.urandom(12)
        aes_cipher = AESGCM(self.key)
        # AES-GCM returns ciphertext with an authentication tag attached.
        ciphertext = aes_cipher.encrypt(nonce, data, None)
        return nonce, ciphertext

    def decrypt(self, ciphertext: bytes, nonce: bytes):
        # AES-GCM verifies integrity as well as decrypting the data.
        aes_cipher = AESGCM(self.key)
        # Invalid ciphertext or a wrong key raises an authentication error here.
        plaintext = aes_cipher.decrypt(nonce, ciphertext, None)
        return plaintext

