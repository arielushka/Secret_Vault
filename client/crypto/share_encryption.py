
import base64


class ShareEncryption:

    @staticmethod
    def encrypt_share(share: str, public_key, rsa_manager):
        share_bytes = share.encode("utf-8")

        key_size_in_bytes = public_key.key_size // 8
        sha256_size = 32
        oaep_overhead = (2 * sha256_size) + 2
        max_message_size = key_size_in_bytes - oaep_overhead

        if len(share_bytes) > max_message_size:
            raise ValueError("Share is too large for RSA")

        encrypted = rsa_manager.encrypt(share_bytes, public_key)

        encoded_bytes = base64.b64encode(encrypted)
        encoded_text = encoded_bytes.decode("ascii")
        return encoded_text

    @staticmethod
    def decrypt_share(encrypted_share: str, private_key, rsa_manager):
        encrypted_bytes = base64.b64decode(
            encrypted_share,
            validate=True
        )

        decrypted = rsa_manager.decrypt(encrypted_bytes, private_key)

        share = decrypted.decode("utf-8")
        return share
