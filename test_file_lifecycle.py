"""Tests for approval, file opening, access, and automatic expiry."""

import base64
from contextlib import closing
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from server import database


TEST_TEMP_DIR = Path(__file__).resolve().parent / ".smoke_tmp"
TEST_TEMP_DIR.mkdir(exist_ok=True)


class FileLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir=TEST_TEMP_DIR)
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = Path(self.temp_dir.name) / "vault.db"
        self.db_patch = patch.object(database, "DB_PATH", self.db_path)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        # Each test starts with a separate database and four minimal accounts.
        database.create_tables()
        with closing(database.connect()) as conn:
            with conn:
                conn.executemany(
                    "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
                    [(f"user{n}", "unused", "unused") for n in range(1, 5)]
                )
        self.ciphertext_path = Path(self.temp_dir.name) / "file.enc"
        self.ciphertext_path.write_bytes(b"x" * 28)
        self.recipients = [
            {"user_id": user_id, "encrypted_share": base64.b64encode(
                bytes([user_id]) * 512).decode("ascii")}
            for user_id in (1, 2, 3)
        ]
        self.file_id = database.save_file(
            4, "secret.bin", self.ciphertext_path, 2, self.recipients
        )
        self.encrypted_shares = [
            {"user_id": recipient["user_id"],
             "encrypted_share": recipient["encrypted_share"]}
            for recipient in self.recipients
        ]

    def approve(self, user_id):
        # Use the same complete encrypted-share list for each approval in these tests.
        database.set_approval(
            self.file_id, user_id, True, self.encrypted_shares
        )

    def test_waiting_file_does_not_expire_and_approval_has_no_deadline(self):
        # A file does not start its short expiry period until the threshold is reached.
        database.delete_expired_files(now=time.time() + 3600)
        self.assertEqual(len(database.list_files(1)), 1)
        self.approve(1)
        self.assertIsNone(database.file_info(self.file_id, 1)["opened_at"])

    def test_threshold_opens_file_for_approvers_only(self):
        # Two approvals meet this test file's threshold of two.
        self.approve(1)
        self.approve(2)

        info = database.file_info(self.file_id, 1)
        self.assertIsNotNone(info["opened_at"])
        self.assertTrue(info["your_approval"])
        self.assertEqual(len(database.download_file(self.file_id, 1)["encrypted_shares"]), 2)
        self.assertEqual(database.list_files(3), [])
        with self.assertRaisesRegex(ValueError, "not allowed to view"):
            database.file_info(self.file_id, 3)
        with self.assertRaisesRegex(ValueError, "Only users who approved"):
            database.download_file(self.file_id, 3)
        with self.assertRaisesRegex(ValueError, "already open"):
            database.set_approval(self.file_id, 2, False)

    def test_existing_database_gets_opened_at_column(self):
        # Simulate a database created before the opened_at column was introduced.
        self.approve(1)
        self.approve(2)
        with closing(database.connect()) as conn:
            with conn:
                conn.execute("ALTER TABLE files DROP COLUMN opened_at")

        database.create_tables()
        info = database.file_info(self.file_id, 1)
        self.assertIsNotNone(info["opened_at"])

    def test_expiry_removes_file_ciphertext_and_cascaded_shares(self):
        # Once opened, an expired file and its related data should all be removed.
        self.approve(1)
        self.approve(2)
        with closing(database.connect()) as conn:
            with conn:
                conn.execute(
                    "UPDATE files SET opened_at=? WHERE id=?",
                    (time.time() - database.OPEN_FILE_SECONDS - 1, self.file_id)
                )
        self.assertEqual(database.delete_expired_files(), 1)
        self.assertFalse(self.ciphertext_path.exists())
        with closing(database.connect()) as conn:
            # Keep the SELECT statements simple and check the returned IDs here.
            file_ids = [row[0] for row in conn.execute("SELECT id FROM files")]
            recipient_file_ids = [
                row[0] for row in conn.execute("SELECT file_id FROM file_recipients")
            ]
            share_file_ids = [
                row[0] for row in conn.execute("SELECT file_id FROM active_shares")
            ]
            self.assertNotIn(self.file_id, file_ids)
            self.assertNotIn(self.file_id, recipient_file_ids)
            self.assertNotIn(self.file_id, share_file_ids)


if __name__ == "__main__":
    unittest.main()
