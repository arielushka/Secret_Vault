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
    # Each connection gets an independent login session.
    session = Session()
    print("Connected:", address)
    try:
        while True:
            request = recv_message(sock)
            # A closed connection returns None and ends this client's request loop.
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
        # Apply a timeout during the TLS handshake to avoid stalled connections.
        client.settimeout(10)

        secure_client = context.wrap_socket(
            client,
            server_side=True
        )

        secure_client.settimeout(None)

        # Reuse the normal request loop after TLS has been established.
        handle_client(secure_client, address)

    except (ssl.SSLError, OSError) as error:
        print("Connection error:", error)

    finally:
        client.close()


def expire_open_files():
    # Periodically remove ciphertext after the file's access window expires.
    while True:
        try:
            delete_expired_files()
        except (OSError, sqlite3.Error) as error:
            print("File cleanup error:", error)
        time.sleep(0.5)


def main():
    # Ensure the schema exists before accepting client requests.
    create_tables()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # Load the certificate and private key used to identify this server to clients.
    context.load_cert_chain("server.crt", "server.key")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    # Cleanup runs in the background while the main thread accepts connections.
    threading.Thread(target=expire_open_files, daemon=True).start()

    print(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            client, address = server.accept()

            # Handle clients separately so one connection does not block others.
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
