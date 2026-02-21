#!/usr/bin/env python3
import socket
import struct
import threading
import time


class CustomProtocolServer:
    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port
        self.magic = b"CPRO"          # 4 bytes
        self.version = 1              # 1 byte

    def create_message(self, msg_type, data):
        """
        Create a custom protocol message.
        Protocol format: [MAGIC(4)][VERSION(1)][TYPE(1)][LENGTH(2)][DATA][CHECKSUM(1)]

        Implement message creation with proper field packing
        Calculate checksum as sum of data bytes % 256
        """
        if isinstance(data, str):
            data = data.encode()

        if data is None:
            data = b""

        length = len(data)

        # Header: MAGIC(4), VERSION(1), TYPE(1), LENGTH(2) big-endian
        header = struct.pack("!4sBBH", self.magic, self.version, int(msg_type), int(length))

        # Checksum: sum(data bytes) % 256
        checksum = sum(data) % 256
        checksum_byte = struct.pack("!B", checksum)

        return header + data + checksum_byte

    def handle_client(self, client_socket, addr):
        """
        Send welcome message (type 1)
        Send status message (type 2)
        Send data message (type 3) with flag
        Implement proper error handling
        """
        try:
            client_socket.settimeout(10)

            # Type 1 - Welcome
            welcome = self.create_message(1, "WELCOME: Custom Protocol Server Ready")
            client_socket.sendall(welcome)
            time.sleep(0.2)

            # Type 2 - Status
            status = self.create_message(2, "STATUS: OK; UPTIME=1; MODE=TEST")
            client_socket.sendall(status)
            time.sleep(0.2)

            # Type 3 - Data (contains "flag" keyword to demonstrate information disclosure in plaintext)
            data_msg = self.create_message(3, "DATA: flag{demo_plaintext_flag}; value=12345")
            client_socket.sendall(data_msg)

            # Optionally read client data (not required for capture)
            try:
                incoming = client_socket.recv(4096)
                if incoming:
                    # Keep the protocol simple; we do not parse client traffic here
                    pass
            except socket.timeout:
                pass

        except Exception as e:
            # In a real server, log to file
            try:
                err = self.create_message(2, f"STATUS: ERROR; reason={str(e)}")
                client_socket.sendall(err)
            except Exception:
                pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def start(self):
        """
        Bind socket and listen for connections
        Accept clients and spawn handler threads
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind((self.host, self.port))
        server_socket.listen(5)

        print(f"[+] CustomProtocolServer listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"[+] Client connected from {addr}")
                t = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\n[!] Server stopped by user")
        finally:
            try:
                server_socket.close()
            except Exception:
                pass


if __name__ == "__main__":
    server = CustomProtocolServer()
    server.start()
