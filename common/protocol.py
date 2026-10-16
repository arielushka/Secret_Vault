import json
import struct

MAX_MESSAGE_SIZE = 16 * 1024 * 1024


def send_message(sock, message):
    message_bytes = json.dumps(message).encode("utf-8")
    if len(message_bytes) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large")
    length = struct.pack("!I", len(message_bytes))
    sock.sendall(length + message_bytes)


def receive_bytes(sock, amount):
    data = b""
    while len(data) < amount:
        part = sock.recv(amount - len(data))
        if not part:
            return None
        data += part
    return data


def recv_message(sock):
    length_bytes = receive_bytes(sock, 4)
    if length_bytes is None:
        return None
    message_length = struct.unpack("!I", length_bytes)[0]
    if message_length == 0 or message_length > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid message size")
    message_bytes = receive_bytes(sock, message_length)
    if message_bytes is None:
        return None
    return json.loads(message_bytes.decode("utf-8"))
