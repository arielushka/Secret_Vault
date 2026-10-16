"""Smoke checks for a full local Secret-Vault checkout.

Start the TLS server first, then run:
    python -m unittest test_installation -v
"""

import importlib
import ssl
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class InstallationSmokeTests(unittest.TestCase):
    def test_both_server_and_client_sources_are_present(self):
        for relative_path in (
            "server/server.py",
            "server/handlers.py",
            "client/client.py",
            "client/vault_client.py",
            "common/protocol.py",
            "test_installation.py",
        ):
            with self.subTest(path=relative_path):
                self.assertTrue((ROOT / relative_path).is_file(), relative_path)

    def test_both_sides_dependencies_are_importable(self):
        for module_name in ("argon2", "cryptography", "shamir_mnemonic"):
            with self.subTest(module=module_name):
                importlib.import_module(module_name)

    def test_server_certificate_and_private_key_match(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(ROOT / "server.crt", ROOT / "server.key")

    def test_tls_13_and_request_protocol_with_local_server(self):
        from client.vault_client import VaultClient

        # The installation test runs against the server on this same computer,
        # even if SECRET_VAULT_HOST points regular clients to another LAN host.
        client = VaultClient(host="127.0.0.1", port=5000)
        try:
            try:
                client.connect()
            except OSError as error:
                self.fail(
                    "Could not connect to 127.0.0.1:5000. Start the server first. "
                    f"Details: {error}"
                )

            self.assertEqual(client.sock.version(), "TLSv1.3")
            response = client.request("GET_USERS")
            self.assertEqual(response.get("status"), "ERROR")
            self.assertEqual(response.get("error"), "Login required")
        finally:
            client.disconnect()


if __name__ == "__main__":
    unittest.main()
