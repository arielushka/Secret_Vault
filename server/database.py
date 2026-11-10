
import base64
import binascii
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "vault.db"
OPEN_FILE_SECONDS = 60


def connect():
    # Enable cascading foreign-key behavior for dependent file/share rows.
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _approval_count(conn, file_id):
    return conn.execute(
        "SELECT COUNT(*) FROM file_recipients WHERE file_id=? AND approved=1",
        (file_id,)
    ).fetchone()[0]


def _recipient_row(conn, file_id, user_id):
    # Return this user's share and approval state for the requested file.
    return conn.execute(
        "SELECT user_id, encrypted_share, approved FROM file_recipients "
        "WHERE file_id=? AND user_id=?",
        (file_id, user_id)
    ).fetchone()


def _file_row(conn, file_id):
    # Return a file record in the same column order expected by callers.
    return conn.execute(
        "SELECT id, owner_id, filename, storage_path, threshold, opened_at "
        "FROM files WHERE id=?",
        (file_id,)
    ).fetchone()


def _username(conn, user_id):
    row = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    return row[0] if row else None


def create_tables():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                threshold INTEGER NOT NULL CHECK (threshold >= 2),
                opened_at REAL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS file_recipients (
                file_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                encrypted_share TEXT NOT NULL,
                approved INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (file_id, user_id),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS active_shares (
                file_id INTEGER NOT NULL,
                share_owner_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                encrypted_share TEXT NOT NULL,
                PRIMARY KEY (file_id, share_owner_id, recipient_id),
                FOREIGN KEY (file_id, share_owner_id)
                    REFERENCES file_recipients(file_id, user_id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            );
        """)
    finally:
        conn.close()


def delete_expired_files(now=None):
    """Remove expired ciphertext and their database rows."""
    if now is None:
        now = time.time()
    conn = connect()
    try:
        expired = conn.execute(
            "SELECT id, storage_path FROM files "
            "WHERE opened_at IS NOT NULL AND opened_at<=?",
            (now - OPEN_FILE_SECONDS,)
        ).fetchall()
        if expired:
            conn.executemany(
                "DELETE FROM files WHERE id=?",
                [(file_id,) for file_id, _ in expired]
            )
            conn.commit()
    finally:
        conn.close()
    for _, storage_path in expired:
        try:
            Path(storage_path).unlink(missing_ok=True)
        except OSError:
            pass
    return len(expired)


def get_users():
    conn = connect()
    try:
        return [
            {"user_id": user_id, "username": username, "public_key": public_key}
            for user_id, username, public_key in conn.execute(
                "SELECT id, username, public_key FROM users ORDER BY id"
            )
        ]
    finally:
        conn.close()


def save_file(owner_id, filename, path, threshold, recipients):
    # Insert the file and all recipient shares in one transaction.
    conn = connect()
    try:
        cursor = conn.execute(
            "INSERT INTO files (owner_id, filename, storage_path, threshold) "
            "VALUES (?, ?, ?, ?)",
            (owner_id, filename, str(path), threshold)
        )
        # The generated row ID connects each recipient share to this new file.
        file_id = cursor.lastrowid
        for recipient in recipients:
            conn.execute(
                "INSERT INTO file_recipients (file_id, user_id, encrypted_share) "
                "VALUES (?, ?, ?)",
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
        access = "f.owner_id=?" if owner_only else "f.owner_id<>? AND r.user_id IS NOT NULL"
        rows = conn.execute(
            "SELECT f.id, f.filename, f.threshold, u.username, f.owner_id "
            "FROM files f JOIN users u ON u.id=f.owner_id "
            "LEFT JOIN file_recipients r ON r.file_id=f.id AND r.user_id=? "
            f"WHERE {access} AND (f.opened_at IS NULL OR r.approved=1) "
            "ORDER BY f.id",
            (user_id, user_id)
        )
        return [
            {"file_id": file_id, "filename": filename, "threshold": threshold,
             "owner": username, "owner_id": owner_id}
            for file_id, filename, threshold, username, owner_id in rows
        ]
    finally:
        conn.close()


def file_info(file_id, user_id):
    delete_expired_files()
    conn = connect()
    try:
        file_row = _file_row(conn, file_id)
        if file_row is None:
            raise ValueError("You are not allowed to view this file")
        _, owner_id, filename, _, threshold, opened_at = file_row
        own_recipient = _recipient_row(conn, file_id, user_id)
        approved = own_recipient is not None and own_recipient[2] == 1
        # An unopened file is visible to its owner and authorized recipients.
        if (owner_id != user_id and own_recipient is None) or (opened_at is not None and not approved):
            raise ValueError("You are not allowed to view this file")

        recipient_rows = conn.execute(
            "SELECT r.user_id, u.username, u.public_key "
            "FROM file_recipients r JOIN users u ON u.id=r.user_id "
            "WHERE r.file_id=? ORDER BY r.user_id",
            (file_id,)
        )
        recipients = [
            {"user_id": recipient_id, "username": username, "public_key": public_key}
            for recipient_id, username, public_key in recipient_rows
        ]
        return {
            "file_id": file_id,
            "filename": filename,
            "threshold": threshold,
            "owner_id": owner_id,
            "owner": _username(conn, owner_id),
            "your_approval": approved,
            "opened_at": opened_at,
            "my_encrypted_share": own_recipient[1] if own_recipient else None,
            "recipients": recipients,
            "approval_count": _approval_count(conn, file_id),
        }
    finally:
        conn.close()


def set_approval(file_id, share_owner_id, approved, encrypted_shares=None):
    # Serialize the approval update and threshold decision in a transaction.
    delete_expired_files()
    conn = connect()
    try:
        # Serialize approval changes and threshold checks across client threads.
        conn.execute("BEGIN IMMEDIATE")
        recipient = _recipient_row(conn, file_id, share_owner_id)
        file_row = _file_row(conn, file_id)
        if recipient is None or file_row is None:
            raise ValueError("You are not allowed to approve this file")
        if file_row[5] is not None:
            raise ValueError("The file is already open")
        if approved:
            # Validate the full share set before changing approval state.
            if not isinstance(encrypted_shares, list):
                raise ValueError("Encrypted shares are required")
            allowed_ids = [row[0] for row in conn.execute(
                "SELECT user_id FROM file_recipients WHERE file_id=? ORDER BY user_id",
                (file_id,)
            )]
            allowed_id_set = set(allowed_ids)
            submitted_ids = []
            for item in encrypted_shares:
                if not isinstance(item, dict):
                    raise ValueError("Invalid encrypted share")
                target_id = item.get("user_id")
                share_text = item.get("encrypted_share")
                if isinstance(target_id, bool) or not isinstance(target_id, int):
                    raise ValueError("Invalid share recipient")
                if target_id not in allowed_id_set or not isinstance(share_text, str):
                    raise ValueError("Invalid share recipient")
                try:
                    share_bytes = base64.b64decode(share_text, validate=True)
                except (ValueError, binascii.Error):
                    raise ValueError("Invalid encrypted share")
                if len(share_bytes) != 512:
                    raise ValueError("Invalid encrypted share size")
                submitted_ids.append(target_id)
            if sorted(submitted_ids) != allowed_ids:
                raise ValueError(
                    "A share is required for each authorized user")
            conn.execute(
                "DELETE FROM active_shares WHERE file_id=? AND share_owner_id=?",
                (file_id, share_owner_id)
            )
            for item in encrypted_shares:
                # Store a copy of this user's share encrypted for every file recipient.
                conn.execute(
                    "INSERT INTO active_shares VALUES (?, ?, ?, ?)",
                    (file_id, share_owner_id,
                     item["user_id"], item["encrypted_share"])
                )
            conn.execute(
                "UPDATE file_recipients SET approved=1 WHERE file_id=? AND user_id=?",
                (file_id, share_owner_id)
            )
            if _approval_count(conn, file_id) >= file_row[4]:
                conn.execute(
                    "UPDATE files SET opened_at=? WHERE id=?",
                    (time.time(), file_id)
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
    # Check access and gather only shares belonging to currently approved users.
    delete_expired_files()
    conn = connect()
    try:
        file_row = _file_row(conn, file_id)
        recipient = _recipient_row(conn, file_id, user_id)
        if file_row is None or recipient is None:
            raise ValueError("You are not allowed to download this file")
        _, _, filename, storage_path, threshold, opened_at = file_row
        if opened_at is None:
            raise ValueError("The file is not open yet")
        if recipient[2] != 1:
            raise ValueError("Only users who approved this file can access it")
        if _approval_count(conn, file_id) < threshold:
            raise ValueError("Not enough active approvals")

        selected = [row[0] for row in conn.execute(
            "SELECT a.encrypted_share FROM active_shares a "
            "JOIN file_recipients r ON r.file_id=a.file_id "
            "AND r.user_id=a.share_owner_id "
            "WHERE a.file_id=? AND a.recipient_id=? AND r.approved=1 "
            "ORDER BY a.share_owner_id LIMIT ?",
            (file_id, user_id, threshold)
        )]
        if len(selected) < threshold:
            raise ValueError("Not enough encrypted shares are available")
        # Read the encrypted file only after all access and threshold checks pass.
        with open(storage_path, "rb") as file:
            encrypted_file = file.read()
        return {
            "filename": filename,
            "encrypted_file": base64.b64encode(encrypted_file).decode("ascii"),
            "encrypted_shares": selected[:threshold],
        }
    finally:
        conn.close()


def delete_file(file_id, owner_id):
    # Only the owner may remove a file, subject to the open-file approval rule.
    delete_expired_files()
    conn = connect()
    try:
        file_row = _file_row(conn, file_id)
        if file_row is None or file_row[1] != owner_id:
            raise ValueError("Only the owner can delete this file")
        opened_at = file_row[5]
        own_recipient = _recipient_row(conn, file_id, owner_id)
        approved = own_recipient is not None and own_recipient[2] == 1
        if opened_at is not None and not approved:
            raise ValueError("Only users who approved this file can access it")
        # Cascading foreign keys remove recipient and active-share rows with the file.
        conn.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.commit()
        try:
            Path(file_row[3]).unlink(missing_ok=True)
        except OSError:
            pass
    finally:
        conn.close()
