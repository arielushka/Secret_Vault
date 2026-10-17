
"""Secret-Vault persistence layer.

Queries fetch rows with simple SELECT statements; approval counts, access
decisions, timeouts, filtering and sorting are calculated in Python.
"""
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
    """Count approvals in Python instead of using a SQL aggregate/filter."""
    # This reads every recipient row; keeping the selection simple suits this small app.
    rows = conn.execute(
        "SELECT file_id, approved FROM file_recipients"
    ).fetchall()
    count = 0
    for row_file_id, approved in rows:
        if row_file_id == file_id and approved == 1:
            count += 1
    return count


def _recipient_row(conn, file_id, user_id):
    # Return this user's share and approval state for the requested file.
    rows = conn.execute(
        "SELECT file_id, user_id, encrypted_share, approved FROM file_recipients"
    ).fetchall()
    for row in rows:
        if row[0] == file_id and row[1] == user_id:
            return row[1:]
    return None


def _file_row(conn, file_id):
    # Return a file record in the same column order expected by callers.
    rows = conn.execute(
        "SELECT id, owner_id, filename, storage_path, threshold, opened_at FROM files"
    ).fetchall()
    for row in rows:
        if row[0] == file_id:
            return row
    return None


def _username(conn, user_id):
    rows = conn.execute("SELECT id, username FROM users").fetchall()
    for row_id, username in rows:
        if row_id == user_id:
            return username
    return None


def create_tables():
    # Create the database directory on first run.
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        # Each table stores one kind of record: users, files, or file recipients.
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
        # Upgrade older databases that do not have the file-open timestamp yet.
        file_columns = [row[1]
                        for row in conn.execute("PRAGMA table_info(files)")]
        if "opened_at" not in file_columns:
            # Older database files need this field to track the expiry timer.
            conn.execute("ALTER TABLE files ADD COLUMN opened_at REAL")
        # Read table names first, then decide in Python whether the old table exists.
        table_rows = conn.execute("SELECT name FROM sqlite_master").fetchall()
        old_table_exists = any(row[0] == "file_shares" for row in table_rows)
        if old_table_exists:
            # Copy old shares into the current recipient table before removing the old table.
            old_shares = conn.execute(
                "SELECT file_id, user_id, encrypted_share FROM file_shares"
            ).fetchall()
            for file_id, user_id, encrypted_share in old_shares:
                # Avoid a conflict clause by checking for an existing row in Python.
                recipient_rows = conn.execute(
                    "SELECT file_id, user_id FROM file_recipients"
                ).fetchall()
                already_added = False
                for row_file_id, row_user_id in recipient_rows:
                    if row_file_id == file_id and row_user_id == user_id:
                        already_added = True
                        break
                if not already_added:
                    conn.execute(
                        "INSERT INTO file_recipients "
                        "(file_id, user_id, encrypted_share) VALUES (?, ?, ?)",
                        (file_id, user_id, encrypted_share)
                    )
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
        # Remove obsolete tables left by the earlier opening-session design.
        conn.execute("DROP TABLE IF EXISTS opening_key_envelopes")
        conn.execute("DROP TABLE IF EXISTS opening_contributions")
        conn.execute("DROP TABLE IF EXISTS opening_votes")
        conn.execute("DROP TABLE IF EXISTS opening_sessions")
        conn.execute("DROP TABLE IF EXISTS file_shares")

        # Migrate preexisting files that already met their threshold.
        files = conn.execute("SELECT id, threshold, opened_at FROM files").fetchall()
        current_time = time.time()
        for file_id, threshold, opened_at in files:
            if opened_at is None and _approval_count(conn, file_id) >= threshold:
                conn.execute(
                    "UPDATE files SET opened_at=? WHERE id=?",
                    (current_time, file_id)
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_expired_files(now=None):
    """Remove expired ciphertext and database rows using Python time comparisons."""
    if now is None:
        now = time.time()
    conn = connect()
    try:
        # Fetch rows first; Python decides expiration using the supplied clock.
        files = conn.execute(
            "SELECT id, storage_path, opened_at FROM files"
        ).fetchall()
        expired = []
        for file_id, storage_path, opened_at in files:
            if opened_at is not None and now - opened_at >= OPEN_FILE_SECONDS:
                expired.append((file_id, storage_path))
        if expired:
            # Remove database rows first; the file paths are removed after closing the DB.
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
        rows = conn.execute(
            "SELECT id, username, public_key FROM users"
        ).fetchall()
        # Keep output stable without putting ORDER BY in SQL.
        rows.sort(key=lambda row: row[0])
        users = []
        for user_id, username, public_key in rows:
            users.append({
                "user_id": user_id,
                "username": username,
                "public_key": public_key,
            })
        return users
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
    # Expire old files before returning the current visible list.
    delete_expired_files()
    conn = connect()
    try:
        files_rows = conn.execute(
            "SELECT id, owner_id, filename, threshold, opened_at FROM files"
        ).fetchall()
        files_rows.sort(key=lambda row: row[0])
        recipient_rows = conn.execute(
            "SELECT file_id, user_id, approved FROM file_recipients"
        ).fetchall()
        approvals = {}
        for file_id, recipient_id, approved in recipient_rows:
            approvals[(file_id, recipient_id)] = approved
        users = {}
        for user_id_from_db, username in conn.execute(
            "SELECT id, username FROM users"
        ).fetchall():
            users[user_id_from_db] = username

        result = []
        # Apply visibility rules in Python using the loaded file and approval rows.
        for file_id, owner_id, filename, threshold, opened_at in files_rows:
            approved = approvals.get((file_id, user_id), 0) == 1
            if owner_only:
                allowed = owner_id == user_id and (
                    opened_at is None or approved)
            else:
                allowed = (
                    owner_id != user_id
                    and (file_id, user_id) in approvals
                    and (opened_at is None or approved)
                )
            if allowed:
                result.append({
                    "file_id": file_id,
                    "filename": filename,
                    "threshold": threshold,
                    "owner": users[owner_id],
                    "owner_id": owner_id,
                })
        return result
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
            "SELECT file_id, user_id, encrypted_share, approved FROM file_recipients"
        ).fetchall()
        matching_recipients = []
        for row in recipient_rows:
            if row[0] == file_id:
                matching_recipients.append(row)
        recipient_rows = matching_recipients
        recipient_rows.sort(key=lambda row: row[1])
        user_rows = conn.execute(
            "SELECT id, username, public_key FROM users"
        ).fetchall()
        users = {}
        for user_id_from_db, username, public_key in user_rows:
            users[user_id_from_db] = (username, public_key)
        recipients = []
        my_share = None
        for _, recipient_id, encrypted_share, _ in recipient_rows:
            # Include the public identity for each recipient, but expose only this user's share.
            username, public_key = users[recipient_id]
            recipients.append({
                "user_id": recipient_id,
                "username": username,
                "public_key": public_key,
            })
            if recipient_id == user_id:
                my_share = encrypted_share
        approval_count = 0
        for _, _, _, is_approved in recipient_rows:
            if is_approved == 1:
                approval_count += 1
        return {
            "file_id": file_id,
            "filename": filename,
            "threshold": threshold,
            "owner_id": owner_id,
            "owner": users[owner_id][0],
            "your_approval": approved,
            "approval_count": approval_count,
            "opened_at": opened_at,
            "my_encrypted_share": my_share,
            "recipients": recipients,
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
            allowed_rows = conn.execute(
                "SELECT file_id, user_id FROM file_recipients"
            ).fetchall()
            allowed_ids = []
            for row_file_id, recipient_id in allowed_rows:
                if row_file_id == file_id:
                    allowed_ids.append(recipient_id)
            allowed_ids.sort()
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
            # The SQL update only writes; counting and the threshold decision are Python.
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

        # Fetch contributions and approvals; Python decides which contributions count.
        all_shares = conn.execute(
            "SELECT file_id, share_owner_id, recipient_id, encrypted_share "
            "FROM active_shares"
        ).fetchall()
        shares = []
        for share_file_id, owner_id, recipient_id, encrypted_share in all_shares:
            if share_file_id == file_id and recipient_id == user_id:
                shares.append((owner_id, encrypted_share))
        shares.sort(key=lambda row: row[0])

        all_approvals = conn.execute(
            "SELECT file_id, user_id, approved FROM file_recipients"
        ).fetchall()
        approvals = {}
        for approval_file_id, approver_id, is_approved in all_approvals:
            if approval_file_id == file_id:
                approvals[approver_id] = is_approved
        selected = []
        for owner_id, encrypted_share in shares:
            if approvals.get(owner_id) == 1:
                selected.append(encrypted_share)
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
