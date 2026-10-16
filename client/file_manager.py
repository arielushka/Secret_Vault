import base64

from client.crypto.aes_manager import AESEncryption
from client.crypto.rsa_manager import RSAEncryption
from client.crypto.shamir_manager import ShamirManager
from client.crypto.share_encryption import ShareEncryption

def prepare_upload(file_path, recipients, threshold):
    if not isinstance(recipients, list):
        raise ValueError("Recipients must be a list")

    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise ValueError("Threshold must be an integer")

    recipient_count = len(recipients)

    if threshold < 2:
        raise ValueError("Invalid threshold or recipient count")

    if threshold > recipient_count:
        raise ValueError("Invalid threshold or recipient count")

    if recipient_count > 16:
        raise ValueError("Invalid threshold or recipient count")

    aes = AESEncryption()

    with open(file_path, "rb") as input_file:
        file_data = input_file.read()

    nonce, ciphertext = aes.encrypt(file_data)
    encrypted_file_bytes = nonce + ciphertext
    encrypted_file = base64.b64encode(encrypted_file_bytes).decode("ascii")

    shares = ShamirManager.split_secret(
        aes.key,
        threshold,
        recipient_count
    )
    rsa_manager = RSAEncryption()
    encrypted_shares = []
    seen_user_ids = set()

    for index in range(recipient_count):
        recipient = recipients[index]

        if not isinstance(recipient, dict):
            raise ValueError("Invalid recipient")

        user_id = recipient.get("user_id")
        public_key_text = recipient.get("public_key")

        if isinstance(user_id, bool) or not isinstance(user_id, int):
            raise ValueError("Invalid recipient ID")

        if user_id < 1:
            raise ValueError("Invalid recipient ID")

        if user_id in seen_user_ids:
            raise ValueError("Duplicate recipients")

        seen_user_ids.add(user_id)

        public_key = RSAEncryption.read_public_key(public_key_text)
        share = shares[index]
        encrypted_share = ShareEncryption.encrypt_share(
            share,
            public_key,
            rsa_manager
        )

        encrypted_shares.append({
            "user_id": user_id,
            "encrypted_share": encrypted_share
        })

    return encrypted_file, encrypted_shares


def decrypt_file(encrypted_file_text, aes_key, output_path):
    encrypted_file_bytes = base64.b64decode(encrypted_file_text, validate=True)
    if len(encrypted_file_bytes) < 12 + 16:
        raise ValueError("Encrypted file is incomplete")

    nonce = encrypted_file_bytes[:12]
    ciphertext = encrypted_file_bytes[12:]
    aes_manager = AESEncryption(aes_key)
    file_data = aes_manager.decrypt(ciphertext, nonce)

    with open(output_path, "xb") as output_file:
        output_file.write(file_data)

    return output_path
