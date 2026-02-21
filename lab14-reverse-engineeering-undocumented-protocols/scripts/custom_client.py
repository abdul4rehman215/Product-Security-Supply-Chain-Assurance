#!/usr/bin/env python3
import socket
import struct


def parse_message(buf):
    """
    Parse one protocol message from a buffer.
    Returns: (msg_dict, remaining_bytes) or (None, buf) if incomplete.
    """
    if len(buf) < 4 + 1 + 1 + 2 + 1:
        return None, buf

    magic, version, msg_type, length = struct.unpack("!4sBBH", buf[:8])

    total_len = 8 + length + 1
    if len(buf) < total_len:
        return None, buf

    data = buf[8:8 + length]
    checksum = buf[8 + length]

    # Validate checksum
    calc = sum(data) % 256
    valid = (calc == checksum)

    msg = {
        "magic": magic.decode(errors="ignore"),
        "version": version,
        "type": msg_type,
        "length": length,
        "data": data.decode(errors="ignore"),
        "checksum": checksum,
        "checksum_valid": valid
    }

    remaining = buf[total_len:]
    return msg, remaining


def connect_to_server():
    """
    Connect to server on localhost:8888
    Receive and display messages
    Handle connection errors gracefully
    """
    host = "127.0.0.1"
    port = 8888

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        print(f"[+] Connected to {host}:{port}")

        buffer = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buffer += chunk

                # Parse all complete messages in buffer
                while True:
                    msg, buffer = parse_message(buffer)
                    if msg is None:
                        break
                    print("\n--- Message Received ---")
                    print(f"Magic: {msg['magic']}")
                    print(f"Version: {msg['version']}")
                    print(f"Type: {msg['type']}")
                    print(f"Length: {msg['length']}")
                    print(f"Data: {msg['data']}")
                    print(f"Checksum: {msg['checksum']} (valid={msg['checksum_valid']})")

            except socket.timeout:
                break

    except ConnectionRefusedError:
        print("[-] Connection refused. Is the server running?")
    except Exception as e:
        print(f"[-] Client error: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass
        print("[*] Client finished")


if __name__ == "__main__":
    connect_to_server()
