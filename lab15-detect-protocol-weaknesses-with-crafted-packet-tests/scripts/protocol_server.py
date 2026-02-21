#!/usr/bin/env python3
import socket
import threading
import struct

class VulnerableProtocolServer:
    """
    A deliberately vulnerable protocol server for testing.
    Protocol format: [Magic:2][Version:2][Command:2][Length:2][Payload:N]
    """

    def __init__(self, host='127.0.0.1', port=8888):
        self.host = host
        self.port = port

    def handle_client(self, client_socket, address):
        try:
            data = client_socket.recv(1024)
            if len(data) < 8:
                client_socket.close()
                return

            magic, version, command, length = struct.unpack('!HHHH', data[:8])
            payload = data[8:]

            # Check magic number
            if magic != 0xDEAD:
                response = struct.pack('!HHHH', 0xBEEF, version, 0xFFFF, 0)
                client_socket.send(response)
                client_socket.close()
                return

            # Buffer overflow simulation
            if length > 1000:
                response_payload = b"BUFFER_OVERFLOW_DETECTED"
                response = struct.pack('!HHHH', 0xBEEF, version, command, len(response_payload)) + response_payload
                client_socket.send(response)
                client_socket.close()
                return

            # Command handlers
            if command == 1:
                # Echo
                response_payload = payload
            elif command == 2:
                response_payload = b"STATUS_OK"
            elif command == 999:
                # Intentional vulnerability
                response_payload = b"ADMIN:root PASSWORD:supersecret"
            else:
                response_payload = b"UNKNOWN_COMMAND"

            response = struct.pack('!HHHH', 0xBEEF, version, command, len(response_payload)) + response_payload
            client_socket.send(response)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"[+] Server listening on {self.host}:{self.port}")

        while True:
            client_socket, addr = server.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            client_thread.daemon = True
            client_thread.start()

if __name__ == "__main__":
    server = VulnerableProtocolServer()
    server.start()
