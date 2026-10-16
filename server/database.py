import base64
import binascii
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "vault.db"
OPEN_FILE_SECONDS = 60


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                threshold INTEGER NOT NULL CHECK (threshold >= 2),
                opened_at REAL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_recipients (
                file_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                encrypted_share TEXT NOT NULL,
                approved INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (file_id, user_id),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        file_columns = [row[1] for row in conn.execute("PRAGMA table_info(files)")]
        if "opened_at" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN opened_at REAL")
        old_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='file_shares'"
        ).fetchone()
        if old_table is not None:
            conn.execute("""
                INSERT OR IGNORE INTO file_recipients (file_id, user_id, encrypted_share)
                SELECT file_id, user_id, encrypted_share FROM file_shares
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_shares (
                file_id INTEGER NOT NULL,
                share_owner_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                encrypted_share TEXT NOT NULL,
                PRIMARY KEY (file_id, share_owner_id, recipient_id),
                FOREIGN KEY (file_id, share_owner_id)
                    REFERENCES file_recipients(file_id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        """)
        # Remove tables used only by the old temporary approval process.
        conn.execute("DROP TABLE IF EXISTS opening_key_envelopes")
        conn.execute("DROP TABLE IF EXISTS opening_contributions")
        conn.execute("DROP TABLE IF EXISTS opening_votes")
        conn.execute("DROP TABLE IF EXISTS opening_sessions")
        conn.execute("DROP TABLE IF EXISTS file_shares")
        conn.execute("""
            UPDATE files SET opened_at=?
            WHERE opened_at IS NULL AND
                  (SELECT COUNT(*) FROM file_recipients r
                   WHERE r.file_id=files.id AND r.approved=1) >= files.threshold
        """, (time.time(),))
        conn.commit()
    finally:
        conn.close()


def delete_expired_files(now=None):
    """Delete files, their cascading shares, and ciphertext after the open window."""
    if now is None:
        now = time.time()
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, storage_path FROM files WHERE opened_at IS NOT NULL AND opened_at <= ?",
            (now - OPEN_FILE_SECONDS,)
        ).fetchall()
        if rows:
            conn.executemany("DELETE FROM files WHERE id=?", [(row[0],) for row in rows])
            conn.commit()
    finally:
        conn.close()
    for _, storage_path in rows:
        try:
            Path(storage_path).unlink(missing_ok=True)
        except OSError:
            pass
    return len(rows)


def get_users():
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, username, public_key FROM users ORDER BY id"
        ).fetchall()
        users = []
        for row in rows:
            users.append({
                "user_id": row[0],
                "username": row[1],
                "public_key": row[2]
            })
        return users
    finally:
        conn.close()


def save_file(owner_id, filename, path, threshold, recipients):
    conn = connect()
    try:
        cursor = conn.execute(
            "INSERT INTO files (owner_id, filename, storage_path, threshold) VALUES (?, ?, ?, ?)",
            (owner_id, filename, str(path), threshold)
        )
        file_id = cursor.lastrowid
        for recipient in recipients:
            conn.execute(
                "INSERT INTO file_recipients (file_id, user_id, encrypted_share) VALUES (?, ?, ?)",
                (file_id, recipient["user_id"], recipient["encrypted_share"])
            )
        conn.commit()
        return file_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_files(user_id, owner_only=False):
    delete_expired_files()
    conn = connect()
    try:
        if owner_only:
            rows = conn.execute(
                """SELECT f.id, f.filename, f.threshold, u.username, f.owner_id
                   FROM files f JOIN users u ON u.id=f.owner_id
                   WHERE f.owner_id=?
                     AND (f.opened_at IS NULL OR EXISTS (
                         SELECT 1 FROM file_recipients r
                         WHERE r.file_id=f.id AND r.user_id=? AND r.approved=1
                     ))
                   ORDER BY f.id""", (user_id, user_id)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT f.id, f.filename, f.threshold, u.username, f.owner_id
                   FROM files f JOIN users u ON u.id=f.owner_id
                   JOIN file_recipients r ON r.file_id=f.id
                   WHERE r.user_id=? AND f.owner_id!=?
                     AND (f.opened_at IS NULL OR r.approved=1)
                   ORDER BY f.id""",
                (user_id, user_id)
            ).fetchall()
        files = []
        for row in rows:
            files.append({
                "file_id": row[0], "filename": row[1],
                "threshold": row[2], "owner": row[3], "owner_id": row[4]
            })
        return files
    finally:
        conn.close()

def file_info(file_id, user_id):
    delete_expired_files()
    conn = connect()
    try:
        row = conn.execute(
            """SELECT f.filename, f.threshold, f.owner_id, u.username,
                      r.approved,
                      (SELECT COUNT(*) FROM file_recipients
                       WHERE file_id=f.id AND approved=1),
                      f.opened_at
               FROM files f JOIN users u ON u.id=f.owner_id
               LEFT JOIN file_recipients r
                 ON r.file_id=f.id AND r.user_id=?
               WHERE f.id=? AND (f.owner_id=? OR r.user_id IS NOT NULL)
                 AND (f.opened_at IS NULL OR r.approved=1)""",
            (user_id, file_id, user_id)
        ).fetchone()
        if row is None:
            raise ValueError("You are not allowed to view this file")
        recipient_rows = conn.execute(
            """SELECT r.user_id, u.username, u.public_key, r.encrypted_share
               FROM file_recipients r JOIN users u ON u.id=r.user_id
               WHERE r.file_id=? ORDER BY r.user_id""", (file_id,)
        ).fetchall()
        recipients = []
        my_share = None
        for recipient_row in recipient_rows:
            recipients.append({
                "user_id": recipient_row[0],
                "username": recipient_row[1],
                "public_key": recipient_row[2]
            })
            if recipient_row[0] == user_id:
                my_share = recipient_row[3]
        return {
            "file_id": file_id, "filename": row[0], "threshold": row[1],
            "owner_id": row[2], "owner": row[3],
            "your_approval": bool(row[4]), "approval_count": row[5],
            "opened_at": row[6],
            "my_encrypted_share": my_share, "recipients": recipients
        }
    finally:
        conn.close()

def set_approval(file_id, share_owner_id, approved, encrypted_shares=None):
    delete_expired_files()
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        recipient = conn.execute(
            """SELECT r.approved, f.opened_at
               FROM file_recipients r JOIN files f ON f.id=r.file_id
               WHERE r.file_id=? AND r.user_id=?""",
            (file_id, share_owner_id)
        ).fetchone()
        if recipient is None:
            raise ValueError("You are not allowed to approve this file")
        if recipient[1] is not None:
            raise ValueError("The file is already open")
        if approved:
            if not isinstance(encrypted_shares, list):
                raise ValueError("Encrypted shares are required")
            allowed = conn.execute(
                "SELECT user_id FROM file_recipients WHERE file_id=? ORDER BY user_id",
                (file_id,)
            ).fetchall()
            allowed_ids = []
            for row in allowed:
                allowed_ids.append(row[0])
            seen = []
            for item in encrypted_shares:
                if not isinstance(item, dict):
                    raise ValueError("Invalid encrypted share")
                target_id = item.get("user_id")
                share_text = item.get("encrypted_share")
                if isinstance(target_id, bool) or not isinstance(target_id, int):
                    raise ValueError("Invalid share recipient")
                if target_id not in allowed_ids or not isinstance(share_text, str):
                    raise ValueError("Invalid share recipient")
                try:
                    share_bytes = base64.b64decode(share_text, validate=True)
                except (ValueError, binascii.Error):
                    raise ValueError("Invalid encrypted share")
                if len(share_bytes) != 512:
                    raise ValueError("Invalid encrypted share size")
                seen.append(target_id)
            if sorted(seen) != allowed_ids or len(set(seen)) != len(seen):
                raise ValueError("A share is required for each authorized user")
            conn.execute(
                "DELETE FROM active_shares WHERE file_id=? AND share_owner_id=?",
                (file_id, share_owner_id)
            )
            for item in encrypted_shares:
                conn.execute(
                    "INSERT INTO active_shares VALUES (?, ?, ?, ?)",
                    (file_id, share_owner_id, item["user_id"], item["encrypted_share"])
                )
            conn.execute(
                "UPDATE file_recipients SET approved=1 WHERE file_id=? AND user_id=?",
                (file_id, share_owner_id)
            )
            conn.execute(
                """UPDATE files SET opened_at=COALESCE(opened_at, ?)
                   WHERE id=? AND (SELECT COUNT(*) FROM file_recipients
                                   WHERE file_id=? AND approved=1) >= threshold""",
                (time.time(), file_id, file_id)
            )
        else:
            conn.execute(
                "UPDATE file_recipients SET approved=0 WHERE file_id=? AND user_id=?",
                (file_id, share_owner_id)
            )
            conn.execute(
                "DELETE FROM active_shares WHERE file_id=? AND share_owner_id=?",
                (file_id, share_owner_id)
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def download_file(file_id, user_id):
    delete_expired_files()
    conn = connect()
    try:
        file_row = conn.execute(
            """SELECT f.filename, f.storage_path, f.threshold, f.opened_at, r.approved
               FROM files f JOIN file_recipients r ON r.file_id=f.id
               WHERE f.id=? AND r.user_id=?""", (file_id, user_id)
        ).fetchone()
        if file_row is None:
            raise ValueError("You are not allowed to download this file")
        if file_row[3] is None:
            raise ValueError("The file is not open yet")
        if not file_row[4]:
            raise ValueError("Only users who approved this file can access it")
        count = conn.execute(
            "SELECT COUNT(*) FROM file_recipients WHERE file_id=? AND approved=1",
            (file_id,)
        ).fetchone()[0]
        if count < file_row[2]:
            raise ValueError("Not enough active approvals")
        rows = conn.execute(
            """SELECT s.encrypted_share FROM active_shares s
               JOIN file_recipients r ON r.file_id=s.file_id AND r.user_id=s.share_owner_id
               WHERE s.file_id=? AND s.recipient_id=? AND r.approved=1
               ORDER BY s.share_owner_id""", (file_id, user_id)
        ).fetchall()
        if len(rows) < file_row[2]:
            raise ValueError("Not enough encrypted shares are available")
        with open(file_row[1], "rb") as file:
            encrypted_file = file.read()
        return {
            "filename": file_row[0],
            "encrypted_file": base64.b64encode(encrypted_file).decode("ascii"),
            "encrypted_shares": [row[0] for row in rows[:file_row[2]]]
        }
    finally:
        conn.close()


def delete_file(file_id, owner_id):
    delete_expired_files()
    conn = connect()
    try:
        row = conn.execute(
            """SELECT f.storage_path, f.opened_at,
                      EXISTS(SELECT 1 FROM file_recipients r
                             WHERE r.file_id=f.id AND r.user_id=? AND r.approved=1)
               FROM files f WHERE f.id=? AND f.owner_id=?""",
            (owner_id, file_id, owner_id)
        ).fetchone()
        if row is None:
            raise ValueError("Only the owner can delete this file")
        if row[1] is not None and not row[2]:
            raise ValueError("Only users who approved this file can access it")
        conn.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.commit()
        try:
            Path(row[0]).unlink(missing_ok=True)
        except OSError:
            pass
    finally:
        conn.close()








