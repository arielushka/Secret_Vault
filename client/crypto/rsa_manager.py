"""RSA key storage and OAEP operations backed by the compact PyCryptodome API."""

import os
import tempfile
from pathlib import Path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class RSAEncryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        self.private_key = RSA.generate(4096)
        self.public_key = self.private_key.public_key()

    @staticmethod
    def encrypt(message, public_key):
        return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)

    @staticmethod
    def decrypt(encrypted_message, private_key):
        return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(encrypted_message)

    def serialize_public_key(self):
        if self.public_key is None:
            raise ValueError("Public key is not loaded")
        return self.public_key.export_key().decode("ascii")

    @staticmethod
    def read_public_key(public_key_text):
        key = RSA.import_key(public_key_text)
        if key.has_private() or key.size_in_bits() != 4096:
            raise ValueError("Use an RSA-4096 public key")
        return key

    def prepare_private_key(self, password):
        if self.private_key is None:
            raise ValueError("Private key is not loaded")
        folder = self.key_folder()
        folder.mkdir(parents=True, exist_ok=True)
        # Keep the private key password-encrypted with PKCS#8 and scrypt/AES-256.
        key_bytes = self.private_key.export_key(
            passphrase=password,
            pkcs=8,
            protection="scryptAndAES256-CBC",
        )
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="pending_", suffix=".pem", dir=folder,
            delete=False
        ) as file:
            file.write(key_bytes)
            path = Path(file.name)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

    @staticmethod
    def install_prepared_private_key(prepared_path, user_id):
        final_path = RSAEncryption.key_folder() / f"user_{user_id}_private_key.pem"
        os.link(prepared_path, final_path)
        Path(prepared_path).unlink()
        return final_path

    def load_private_key(self, password, user_id):
        path = self.key_folder() / f"user_{user_id}_private_key.pem"
        self.private_key = RSA.import_key(path.read_bytes(), passphrase=password)
        if not self.private_key.has_private():
            raise ValueError("Not an RSA private key")
        self.public_key = self.private_key.public_key()

    @staticmethod
    def key_folder():
        folder = os.environ.get("SECRET_VAULT_KEY_DIR")
        return Path(folder) if folder else Path.home() / ".secret_vault" / "keys"
