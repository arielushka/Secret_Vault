import hashlib
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class RSAEncryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def make_oaep_padding(self):
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message, public_key=None):
        if public_key is None:
            public_key = self.public_key
        if public_key is None:
            raise ValueError("Public key is not loaded")
        return public_key.encrypt(message, self.make_oaep_padding())

    def decrypt(self, encrypted_message, private_key=None):
        if private_key is None:
            private_key = self.private_key
        if private_key is None:
            raise ValueError("Private key is not loaded")
        return private_key.decrypt(encrypted_message, self.make_oaep_padding())

    def serialize_public_key(self):
        if self.public_key is None:
            raise ValueError("Public key is not loaded")
        public_bytes = self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes.decode("utf-8")

    @staticmethod
    def read_public_key(public_key_text):
        public_key = serialization.load_pem_public_key(public_key_text.encode("utf-8"))
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 4096:
            raise ValueError("Use an RSA-4096 public key")
        return public_key

    @staticmethod
    def fingerprint(public_key_text):
        public_key = RSAEncryption.read_public_key(public_key_text)
        public_bytes = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_bytes).hexdigest()

    def prepare_private_key(self, password):
        if self.private_key is None:
            raise ValueError("Private key is not loaded")
        folder = self.key_folder()
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / ("pending_" + uuid.uuid4().hex + ".pem")
        encrypted_key = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password)
        )
        with open(path, "xb") as file:
            file.write(encrypted_key)
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
        with open(path, "rb") as file:
            key_bytes = file.read()
        self.private_key = serialization.load_pem_private_key(key_bytes, password=password)
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Not an RSA private key")
        self.public_key = self.private_key.public_key()

    @staticmethod
    def key_folder():
        folder = os.environ.get("SECRET_VAULT_KEY_DIR")
        if folder:
            return Path(folder)
        return Path.home() / ".secret_vault" / "keys"



