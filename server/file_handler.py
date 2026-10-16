import base64
import binascii
import uuid
from pathlib import Path

from server.database import save_file, get_users

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
MAX_FILE_SIZE = 10 * 1024 * 1024


def handle_upload(data, owner_id):
    if not isinstance(data, dict):
        raise ValueError("Invalid upload")
    filename = data.get("filename")
    encrypted_text = data.get("encrypted_file")
    threshold = data.get("threshold")
    recipients = data.get("recipients")
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Invalid filename")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise ValueError("Invalid threshold")
    if not isinstance(recipients, list) or threshold < 2 or threshold > len(recipients):
        raise ValueError("Invalid recipients or threshold")
    if len(recipients) > 16 or not isinstance(encrypted_text, str):
        raise ValueError("Invalid upload data")
    try:
        encrypted_file = base64.b64decode(encrypted_text, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid encrypted file")
    if len(encrypted_file) < 28 or len(encrypted_file) > MAX_FILE_SIZE:
        raise ValueError("Invalid file size")
    known_ids = []
    for user in get_users():
        known_ids.append(user["user_id"])
    recipient_ids = []
    for item in recipients:
        if not isinstance(item, dict):
            raise ValueError("Invalid recipient")
        user_id = item.get("user_id")
        share = item.get("encrypted_share")
        if user_id not in known_ids or not isinstance(share, str):
            raise ValueError("Invalid recipient share")
        try:
            share_bytes = base64.b64decode(share, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid share encoding")
        if len(share_bytes) != 512:
            raise ValueError("Invalid RSA share size")
        recipient_ids.append(user_id)
    if len(set(recipient_ids)) != len(recipient_ids):
        raise ValueError("Duplicate recipients")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    path = UPLOAD_DIR / (uuid.uuid4().hex + ".enc")
    with open(path, "wb") as file:
        file.write(encrypted_file)
    try:
        file_id = save_file(owner_id, filename, path, threshold, recipients)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {"file_id": file_id}
