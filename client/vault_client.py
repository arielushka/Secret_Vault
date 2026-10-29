import json
import os
import socket
from pathlib import Path
import ssl

from common.protocol import send_message, recv_message
from client.crypto.rsa_manager import RSAEncryption
from client.crypto.share_encryption import ShareEncryption
from client.crypto.shamir_manager import ShamirManager
from client.file_manager import decrypt_file, prepare_upload


class VaultClient:
    def __init__(self, host=None, port=None):
        self.host = host or os.environ.get("SECRET_VAULT_HOST", "127.0.0.1")
        self.port = port or int(os.environ.get("SECRET_VAULT_PORT", "5000"))
        self.sock = None
        self.user_id = None
        self.rsa_manager = None

    def connect(self):
        # Verify the server certificate and require TLS 1.3 for the connection.
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        context.load_verify_locations("server.crt")

        # Establish TCP first, then wrap that socket with certificate-verified TLS.
        sock = socket.create_connection(
            (self.host, self.port),
            timeout=10
        )

        try:
            self.sock = context.wrap_socket(
                sock,
                server_hostname=self.host
            )
        except Exception:
            sock.close()
            raise

        self.sock.settimeout(None)

    def disconnect(self):
        if self.sock is not None:
            # Close the socket and clear account state when leaving the client.
            self.sock.close()
            self.sock = None
        self.user_id = None
        self.rsa_manager = None

    def request(self, action, data=None):
        # All client/server actions use the same length-prefixed JSON protocol.
        if self.sock is None:
            raise RuntimeError("Not connected to server")
        if data is None:
            data = {}
        # Keep action and payload together in one protocol message.
        send_message(self.sock, {"action": action, "data": data})
        response = recv_message(self.sock)
        if response is None:
            raise ConnectionError("Server disconnected")
        return response

    def register(self, username, password):
        # Generate and protect the private key locally before registering its public key.
        self.rsa_manager = RSAEncryption()
        self.rsa_manager.generate_keys()
        # Encrypt the private key locally using the password before contacting server.
        prepared_path = self.rsa_manager.prepare_private_key(
            password.encode("utf-8"))
        response = self.request("REGISTER", {
            "username": username,
            "password": password,
            "public_key": self.rsa_manager.serialize_public_key()
        })
        if response.get("status") != "OK":
            # Registration failed, so remove the temporary key and clear its memory copy.
            Path(prepared_path).unlink(missing_ok=True)
            self.rsa_manager = None
            return response
        self.user_id = response["data"]["user_id"]
        # Install the local key only once the server has created the account.
        RSAEncryption.install_prepared_private_key(prepared_path, self.user_id)
        self.save_trusted_key(
            self.user_id, self.rsa_manager.serialize_public_key())
        return response

    def login(self, username, password):
        # Load the local private key only after the server accepts the login.
        response = self.request(
            "LOGIN", {"username": username, "password": password})
        if response.get("status") != "OK":
            return response
        self.user_id = response["data"]["user_id"]
        self.rsa_manager = RSAEncryption()
        try:
            self.rsa_manager.load_private_key(
                password.encode("utf-8"), self.user_id
            )
            users_response = self.get_users()
            if users_response.get("status") != "OK":
                raise ValueError("Could not check your public key")
            found_own_key = False
            for user in users_response["data"]["users"]:
                if user["user_id"] == self.user_id:
                    # Compare the private key's public half with the server's copy.
                    found_own_key = True
                    saved_key = self.rsa_manager.serialize_public_key()
                    if RSAEncryption.fingerprint(saved_key) != RSAEncryption.fingerprint(user["public_key"]):
                        raise ValueError(
                            "Your public key on the server does not match your private key")
                    self.save_trusted_key(self.user_id, saved_key)
                    break
            if not found_own_key:
                raise ValueError("Your account was not found on the server")
        except Exception:
            try:
                self.request("LOGOUT")
            except Exception:
                pass
            self.user_id = None
            self.rsa_manager = None
            raise
        return response

    def logout(self):
        response = self.request("LOGOUT")
        if response.get("status") == "OK":
            self.user_id = None
            self.rsa_manager = None
        return response

    def key_file(self):
        return RSAEncryption.key_folder().parent / "trusted_keys.json"

    def read_trusted_keys(self):
        path = self.key_file()
        if not path.exists():
            return {}
        # The trust file contains only key fingerprints, never private keys.
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    def save_trusted_key(self, user_id, public_key_text):
        # Refuse key replacement so a changed identity cannot be trusted silently.
        path = self.key_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        trusted = self.read_trusted_keys()
        user_key = str(user_id)
        # A fingerprint change may signal key replacement, so never overwrite it quietly.
        fingerprint = RSAEncryption.fingerprint(public_key_text)
        if user_key in trusted and trusted[user_key] != fingerprint:
            raise ValueError(
                "This user's public key changed; refusing to replace it")
        trusted[user_key] = fingerprint
        with open(path, "w", encoding="utf-8") as file:
            json.dump(trusted, file, indent=2)

    def public_key_status(self, user):
        fingerprint = RSAEncryption.fingerprint(user["public_key"])
        # The current user's key can be verified directly against the loaded private key.
        if user["user_id"] == self.user_id and self.rsa_manager is not None:
            own_key = self.rsa_manager.serialize_public_key()
            if RSAEncryption.fingerprint(own_key) != fingerprint:
                return "changed", fingerprint
            self.save_trusted_key(self.user_id, own_key)
            return "trusted", fingerprint
        trusted = self.read_trusted_keys()
        # Distinguish a first-seen key from a previously trusted key that changed.
        old_fingerprint = trusted.get(str(user["user_id"]))
        if old_fingerprint == fingerprint:
            return "trusted", fingerprint
        if old_fingerprint is not None:
            return "changed", fingerprint
        return "new", fingerprint

    def get_users(self):
        return self.request("GET_USERS")

    def upload_file_path(self, file_path, recipients, threshold):
        # Require every recipient key to be trusted before encrypting for them.
        for recipient in recipients:
            status, fingerprint = self.public_key_status(recipient)
            if status != "trusted":
                raise ValueError(
                    "Verify each recipient public key before uploading")
        encrypted_file, encrypted_shares = prepare_upload(
            file_path, recipients, threshold)
        # Send only ciphertext and recipient-encrypted shares to the server.
        return self.request("UPLOAD_FILE", {
            "filename": Path(file_path).name,
            "threshold": threshold,
            "encrypted_file": encrypted_file,
            "recipients": encrypted_shares
        })

    def my_files(self):
        return self.request("MY_FILES")

    def shared_files(self):
        return self.request("SHARED_FILES")

    def file_info(self, file_id):
        return self.request("FILE_INFO", {"file_id": file_id})

    def approve_share(self, info):
        if self.rsa_manager is None:
            raise RuntimeError("Load your private key first")
        share = ShareEncryption.decrypt_share(
            info["my_encrypted_share"], self.rsa_manager.private_key, self.rsa_manager
        )
        encrypted_shares = []
        # Re-encrypt this user's share separately for every authorized recipient.
        for recipient in info["recipients"]:
            status, fingerprint = self.public_key_status(recipient)
            if status != "trusted":
                raise ValueError(
                    "Verify each recipient public key before approving")
            public_key = RSAEncryption.read_public_key(recipient["public_key"])
            encrypted_share = ShareEncryption.encrypt_share(
                share, public_key, self.rsa_manager
            )
            encrypted_shares.append({
                "user_id": recipient["user_id"],
                "encrypted_share": encrypted_share
            })
        return self.request("APPROVE_SHARE", {
            "file_id": info["file_id"],
            "shares": encrypted_shares
        })

    def revoke_approval(self, file_id):
        return self.request("REVOKE_APPROVAL", {"file_id": file_id})

    def download_file(self, file_id, output_path):
        # The client decrypts the shares and file; the server returns ciphertext only.
        if self.rsa_manager is None:
            raise RuntimeError("Load your private key first")
        response = self.request("DOWNLOAD_FILE", {"file_id": file_id})
        if response.get("status") != "OK":
            return response
        data = response["data"]
        # Rebuild the AES key from this user's encrypted Shamir contributions.
        shares = []
        for encrypted_share in data["encrypted_shares"]:
            shares.append(ShareEncryption.decrypt_share(
                encrypted_share, self.rsa_manager.private_key, self.rsa_manager
            ))
        aes_key = ShamirManager.recover_secret(shares)
        # Decryption and local file writing happen on the client computer.
        saved_path = decrypt_file(data["encrypted_file"], aes_key, output_path)
        return {"status": "OK", "data": {"path": str(saved_path), "filename": data["filename"]}}

    def delete_file(self, file_id):
        return self.request("DELETE_FILE", {"file_id": file_id})
