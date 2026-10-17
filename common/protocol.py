import json
import struct

# Both sides enforce the same limit before accepting a message body.
MAX_MESSAGE_SIZE = 16 * 1024 * 1024


def send_message(sock, message):
    # Prefix each JSON message with its byte length so TCP boundaries are clear.
    # Convert the message to bytes before measuring its network size.
    message_bytes = json.dumps(message).encode("utf-8")
    # Refuse oversized data before sending any part of the message.
    if len(message_bytes) > MAX_MESSAGE_SIZE:
        raise ValueError("Message is too large")
    # Network byte order makes the four-byte length consistent across computers.
    length = struct.pack("!I", len(message_bytes))
    sock.sendall(length + message_bytes)


def receive_bytes(sock, amount):
    # recv() may return only part of the requested data, so keep reading.
    data = b""
    while len(data) < amount:
        # Ask only for the bytes still missing from this message part.
        part = sock.recv(amount - len(data))
        if not part:
            return None
        data += part
    return data


def recv_message(sock):
    # Read the four-byte size header before reading the message body.
    length_bytes = receive_bytes(sock, 4)
    if length_bytes is None:
        return None
    message_length = struct.unpack("!I", length_bytes)[0]
    # Check the declared size before allocating and reading the body.
    if message_length == 0 or message_length > MAX_MESSAGE_SIZE:
        raise ValueError("Invalid message size")
    message_bytes = receive_bytes(sock, message_length)
    if message_bytes is None:
        return None
    # Decode only after the complete message body has arrived.
    return json.loads(message_bytes.decode("utf-8"))
