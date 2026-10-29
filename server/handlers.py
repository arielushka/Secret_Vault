import binascii
import sqlite3

from Crypto.PublicKey import RSA

from common.protocol import send_message
from server.database import (
    connect, get_users, list_files, file_info,
    set_approval, download_file, delete_file
)
from server.file_handler import handle_upload
from server.passwords import hash_password, verify_password
from server.session import Session

def send_error(sock, message):
    send_message(sock, {"status": "ERROR", "error": message})

def handle_request(sock, request, session):
    # Validate the outer message before choosing an action.
    if not isinstance(request, dict):
        send_error(sock, "Invalid request")
        return
    action = request.get("action")
    data = request.get("data", {})
    # Every action expects its parameters inside a dictionary payload.
    if not isinstance(data, dict):
        send_error(sock, "Invalid data")
        return
    try:
        # Handle authentication actions and logout before checking protected actions.
        if action == "REGISTER":
            result = register(data, session)
        elif action == "LOGIN":
            result = login(data, session)
        elif action == "LOGOUT":
            session.logout()
            result = {"status": "OK", "message": "Logged out"}
        # Every operation after registration and login requires an active session.
        elif not session.is_authenticated():
            raise ValueError("Login required")
        elif action == "GET_USERS":
            result = {"status": "OK", "data": {"users": get_users()}}
        elif action == "UPLOAD_FILE":
            upload_result = handle_upload(data, session.user_id)
            result = {"status": "OK", "data": upload_result}
        elif action == "MY_FILES":
            result = {"status": "OK", "data": {"files": list_files(session.user_id, True)}}
        elif action == "SHARED_FILES":
            result = {"status": "OK", "data": {"files": list_files(session.user_id)}}
        elif action == "FILE_INFO":
            result = {"status": "OK", "data": file_info(data.get("file_id"), session.user_id)}
        elif action == "APPROVE_SHARE":
            set_approval(data.get("file_id"), session.user_id, True, data.get("shares"))
            result = {"status": "OK", "message": "Share approved"}
        elif action == "REVOKE_APPROVAL":
            set_approval(data.get("file_id"), session.user_id, False)
            result = {"status": "OK", "message": "Approval revoked"}
        elif action == "DOWNLOAD_FILE":
            result = {"status": "OK", "data": download_file(data.get("file_id"), session.user_id)}
        elif action == "DELETE_FILE":
            delete_file(data.get("file_id"), session.user_id)
            result = {"status": "OK", "message": "File deleted"}
        else:
            raise ValueError("Unknown action")
    except (ValueError, KeyError, TypeError) as error:
        result = {"status": "ERROR", "error": str(error)}
    except sqlite3.Error as error:
        print("Database error:", error)
        result = {"status": "ERROR", "error": "Database error"}
    except (OSError, binascii.Error) as error:
        result = {"status": "ERROR", "error": str(error)}
    send_message(sock, result)


def register(data, session):
    # Validate credentials and key format before inserting the new account.
    username = data.get("username")
    password = data.get("password")
    public_key_text = data.get("public_key")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Enter a username")
    if not isinstance(password, str) or not password:
        raise ValueError("Enter a password")
    if not isinstance(public_key_text, str):
        raise ValueError("Public key is missing")
    # Parse the PEM first, then accept only the required RSA key type and size.
    public_key = RSA.import_key(public_key_text)
    if public_key.has_private() or public_key.size_in_bits() != 4096:
        raise ValueError("Use an RSA-4096 public key")
    conn = connect()
    try:
        # Hash before inserting; the database never receives the plain password.
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username.strip(), hash_password(password), public_key_text)
        )
        conn.commit()
        session.login(cursor.lastrowid)
        return {"status": "OK", "data": {"user_id": session.user_id}}
    except sqlite3.IntegrityError:
        conn.rollback()
        raise ValueError("Username already exists")
    finally:
        conn.close()


def login(data, session):
    # Read the stored hash, then verify or upgrade it outside the database.
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("Enter username and password")
    conn = connect()
    try:
        # Fetch rows simply, then find the requested account in Python.
        user_rows = conn.execute(
            "SELECT id, username, password_hash FROM users"
        ).fetchall()
        row = None
        for user_id, saved_username, password_hash in user_rows:
            if saved_username == username.strip():
                row = (user_id, password_hash)
                break
    finally:
        conn.close()
    if row is None:
        raise ValueError("Incorrect username or password")
    valid, replacement_hash = verify_password(row[1], password)
    if not valid:
        raise ValueError("Incorrect username or password")
    if replacement_hash:
        conn = connect()
        try:
            with conn:
                conn.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (replacement_hash, row[0])
                )
        finally:
            conn.close()
    # Mark the connection as authenticated only after the password verifies.
    session.login(row[0])
    return {"status": "OK", "data": {"user_id": row[0]}}









