import socket
import threading
import ssl
import os
import sqlite3
import time
from common.protocol import recv_message, send_message
from server.database import create_tables, delete_expired_files
from server.handlers import handle_request
from server.session import Session

# Listen on all interfaces for private-LAN clients; restrict access with the host firewall.
HOST = os.environ.get("SECRET_VAULT_BIND_HOST", "0.0.0.0")
PORT = int(os.environ.get("SECRET_VAULT_PORT", "5000"))


def handle_client(sock, address):
    session = Session()
    print("Connected:", address)
    try:
        while True:
            request = recv_message(sock)
            if request is None:
                break
            handle_request(sock, request, session)
    except (ConnectionError, OSError, ValueError) as error:
        print("Client error:", error)
    finally:
        sock.close()
        print("Disconnected:", address)


def handle_secure_client(client, address, context):
    try:
        client.settimeout(10)

        secure_client = context.wrap_socket(
            client,
            server_side=True
        )

        secure_client.settimeout(None)

        handle_client(secure_client, address)

    except (ssl.SSLError, OSError) as error:
        print("Connection error:", error)

    finally:
        client.close()


def expire_open_files():
    while True:
        try:
            delete_expired_files()
        except (OSError, sqlite3.Error) as error:
            print("File cleanup error:", error)
        time.sleep(0.5)


def main():
    create_tables()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("server.crt", "server.key")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    threading.Thread(target=expire_open_files, daemon=True).start()

    print(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            client, address = server.accept()

            thread = threading.Thread(
                target=handle_secure_client,
                args=(client, address, context)
            )
            thread.start()

    except KeyboardInterrupt:
        print("Server shutting down")

    finally:
        server.close()


if __name__ == "__main__":
    main()
