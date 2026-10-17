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
        # OAEP with SHA-256 safely wraps the small Shamir share payloads.
        return padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    def generate_keys(self):
        # Use a large RSA key because the public key is shared with other users.
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message, public_key=None):
        # Use the supplied recipient key, or this object's public key by default.
        if public_key is None:
            public_key = self.public_key
        if public_key is None:
            raise ValueError("Public key is not loaded")
        return public_key.encrypt(message, self.make_oaep_padding())

    def decrypt(self, encrypted_message, private_key=None):
        # Use the supplied private key, or the locally loaded key by default.
        if private_key is None:
            private_key = self.private_key
        if private_key is None:
            raise ValueError("Private key is not loaded")
        return private_key.decrypt(encrypted_message, self.make_oaep_padding())

    def serialize_public_key(self):
        # Public keys are sent as PEM text so they fit in the JSON protocol.
        if self.public_key is None:
            raise ValueError("Public key is not loaded")
        public_bytes = self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes.decode("utf-8")

    @staticmethod
    def read_public_key(public_key_text):
        # Parsing PEM alone is insufficient; also enforce the project's RSA size.
        public_key = serialization.load_pem_public_key(public_key_text.encode("utf-8"))
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 4096:
            raise ValueError("Use an RSA-4096 public key")
        return public_key

    @staticmethod
    def fingerprint(public_key_text):
        # Hash the normalized public-key bytes, not formatting differences in PEM.
        public_key = RSAEncryption.read_public_key(public_key_text)
        public_bytes = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(public_bytes).hexdigest()

    def prepare_private_key(self, password):
        # Prepare the encrypted key first; registration installs it only on success.
        if self.private_key is None:
            raise ValueError("Private key is not loaded")
        folder = self.key_folder()
        # Keep local key files in a dedicated directory and avoid overwriting one.
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / ("pending_" + uuid.uuid4().hex + ".pem")
        encrypted_key = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password)
        )
        with open(path, "xb") as file:
            # Exclusive creation prevents replacing an existing pending key file.
            file.write(encrypted_key)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return path

    @staticmethod
    def install_prepared_private_key(prepared_path, user_id):
        # Link into the final name only after registration succeeds.
        final_path = RSAEncryption.key_folder() / f"user_{user_id}_private_key.pem"
        os.link(prepared_path, final_path)
        Path(prepared_path).unlink()
        return final_path

    def load_private_key(self, password, user_id):
        # The account password decrypts the private key stored on this computer.
        path = self.key_folder() / f"user_{user_id}_private_key.pem"
        with open(path, "rb") as file:
            # Read the protected bytes before asking the crypto library to unlock them.
            key_bytes = file.read()
        self.private_key = serialization.load_pem_private_key(key_bytes, password=password)
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Not an RSA private key")
        self.public_key = self.private_key.public_key()

    @staticmethod
    def key_folder():
        # Allow tests or users to choose a custom key directory with an environment variable.
        folder = os.environ.get("SECRET_VAULT_KEY_DIR")
        if folder:
            return Path(folder)
        return Path.home() / ".secret_vault" / "keys"



