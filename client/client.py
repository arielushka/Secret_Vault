import getpass
from pathlib import Path

from client.vault_client import VaultClient


def show_response(response):
    if response is None:
        print("Server disconnected")
    elif response.get("status") != "OK":
        print("Error:", response.get("error", "Unknown error"))
    else:
        print(response.get("message", response.get("data", "Done")))


def verify_users(client, users):
    for user in users:
        status, fingerprint = client.public_key_status(user)
        if status == "trusted":
            continue
        if status == "changed":
            raise ValueError(
                "A saved public key changed. The action was stopped.")
        print("\nPublic key fingerprint for", user["username"])
        print(fingerprint)
        print("Compare this with the fingerprint the user gives you through another trusted method.")
        answer = input("Do they match? [y/N]: ").strip().lower()
        if answer != "y":
            raise ValueError("Public key was not trusted")
        client.save_trusted_key(user["user_id"], user["public_key"])


def register_or_login(client):
    while True:
        print("\nSECRET-VAULT")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("> ").strip()
        if choice == "3":
            return False
        if choice not in ("1", "2"):
            print("Choose 1, 2, or 3")
            continue
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        try:
            if choice == "1":
                response = client.register(username, password)
            else:
                response = client.login(username, password)
            show_response(response)
            if response and response.get("status") == "OK":
                return True
        except Exception as error:
            print("Could not continue:", error)


def read_number(message):
    value = input(message).strip()
    if not value.isdigit():
        raise ValueError("Enter a number")
    return int(value)


def upload_file(client):
    path = input("File path: ").strip().strip('"')
    if not Path(path).is_file():
        print("File does not exist")
        return
    response = client.get_users()
    if response.get("status") != "OK":
        show_response(response)
        return
    users = response["data"]["users"]
    for user in users:
        print(f"{user['user_id']}: {user['username']}")
    raw_ids = input("Recipient IDs separated by commas: ")
    recipient_ids = []
    for value in raw_ids.split(","):
        value = value.strip()
        if not value.isdigit():
            raise ValueError("Enter recipient IDs as numbers")
        recipient_ids.append(int(value))
    recipients = []
    for recipient_id in recipient_ids:
        found = None
        for user in users:
            if user["user_id"] == recipient_id:
                found = user
                break
        if found is None:
            raise ValueError("Recipient not found")
        recipients.append(found)
    verify_users(client, recipients)
    threshold = read_number("Required shares: ")
    response = client.upload_file_path(path, recipients, threshold)
    show_response(response)


def show_files(client, action):
    while True:
        response = client.request(action)
        if response.get("status") != "OK":
            show_response(response)
            return
        files = response["data"]["files"]
        if not files:
            print("No files found")
        else:
            for file in files:
                print(
                    f"{file['file_id']}: {file['filename']} (threshold {file['threshold']}) — {file['owner']}")
        print("f. Refresh")
        file_id = input("File ID, f to refresh, or 0 to go back: ").strip().lower()
        if file_id == "0":
            return
        if file_id == "f":
            continue
        if not file_id.isdigit():
            print("Enter a file ID, f, or 0")
            continue
        selected_id = int(file_id)
        if selected_id and any(item["file_id"] == selected_id for item in files):
            show_file(client, selected_id)
        elif selected_id:
            print("File not found in this list")

def show_file(client, file_id):
    response = client.file_info(file_id)
    if response.get("status") != "OK":
        show_response(response)
        return
    info = response["data"]
    while True:
        print(f"\nFile: {info['filename']}")
        print(f"Owner: {info['owner']}")
        print(f"Approvals: {info['approval_count']}/{info['threshold']}")
        print("Your approval:", "Active" if info["your_approval"] else "Inactive")
        opened = info["opened_at"] is not None
        print("Status:", "Open" if opened else "Waiting for approvals")
        actions = []
        if not opened and info["my_encrypted_share"] is not None:
            if info["your_approval"]:
                actions.append(("r", "Revoke approval"))
            else:
                actions.append(("a", "Approve share"))
        if opened and info["your_approval"]:
            actions.append(("o", "Download file"))
        if info["owner_id"] == client.user_id and (not opened or info["your_approval"]):
            actions.append(("d", "Delete file"))
        actions.append(("f", "Refresh"))
        actions.append(("b", "Back"))
        for key, label in actions:
            print(f"{key}. {label}")
        choice = input("> ").strip().lower()
        if choice == "b":
            return
        if choice == "f":
            response = client.file_info(file_id)
            if response.get("status") != "OK":
                show_response(response)
                return
            info = response["data"]
            continue
        selected = None
        for key, label in actions:
            if key == choice:
                selected = key
        if selected is None or selected in ("f", "b"):
            print("Choose one of the listed options")
            continue
        try:
            if selected == "a":
                verify_users(client, info["recipients"])
                show_response(client.approve_share(info))
            elif selected == "r":
                show_response(client.revoke_approval(file_id))
            elif selected == "o":
                output_path = input(
                    "Save decrypted file to: ").strip().strip('"')
                if not output_path:
                    raise ValueError("Enter an output path")
                show_response(client.download_file(file_id, output_path))
            elif selected == "d":
                answer = input("Delete this file? [y/N]: ").strip().lower()
                if answer == "y":
                    show_response(client.delete_file(file_id))
                    return
            response = client.file_info(file_id)
            if response.get("status") != "OK":
                show_response(response)
                return
            info = response["data"]
        except Exception as error:
            print("Could not complete action:", error)

def logged_in_menu(client):
    while client.user_id is not None:
        print("\n1. Upload file")
        print("2. My files")
        print("3. Shared with me")
        print("4. Logout")
        choice = input("> ").strip()
        try:
            if choice == "1":
                upload_file(client)
            elif choice == "2":
                show_files(client, "MY_FILES")
            elif choice == "3":
                show_files(client, "SHARED_FILES")
            elif choice == "4":
                show_response(client.logout())
            else:
                print("Choose 1, 2, 3, or 4")
        except Exception as error:
            print("Action failed:", error)


def main():
    client = VaultClient()
    try:
        client.connect()
        while register_or_login(client):
            logged_in_menu(client)
    except (ConnectionError, OSError) as error:
        print("Could not connect to the server:", error)
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
