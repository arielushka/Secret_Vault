"""Length-prefixed JSON messages shared by the client and server."""

import struct

import orjson

MAX_MESSAGE_SIZE = 16 * 1024 * 1024


def send_message(sock, message):
    body = orjson.dumps(message)
    if not body or len(body) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large")
    sock.sendall(struct.pack("!I", len(body)) + body)


def receive_bytes(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            return None
        chunks.extend(part)
    return bytes(chunks)


def recv_message(sock):
    header = receive_bytes(sock, 4)
    if header is None:
        return None
    size, = struct.unpack("!I", header)
    if not 0 < size <= MAX_MESSAGE_SIZE:
        raise ValueError("Invalid message size")
    body = receive_bytes(sock, size)
    return None if body is None else orjson.loads(body)
