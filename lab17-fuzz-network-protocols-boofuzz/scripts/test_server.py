#!/usr/bin/env python3

import socket
import threading
import logging


class CustomProtocolServer:
    """Simple server for fuzzing demonstration"""

    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.running = True
        logging.info(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                thread.start()
            except Exception as e:
                logging.error(f"Accept error: {e}")

    def handle_client(self, client_socket, address):
        logging.info(f"Connection from {address}")
        try:
            data = client_socket.recv(4096)
            if not data:
                return

            response = self.process_message(data)
            client_socket.sendall(response)

        except Exception as e:
            logging.error(f"Client error: {e}")
        finally:
            client_socket.close()

    def process_message(self, data):
        try:
            message = data.decode(errors="ignore").strip()

            if message.startswith("HELLO"):
                return b"Hello Client\n"

            elif message.startswith("GET"):
                return b"Resource Data\n"

            elif message.startswith("SET"):
                return b"Value Stored\n"

            elif message.startswith("QUIT"):
                return b"Goodbye\n"

            else:
                return b"Unknown Command\n"

        except Exception:
            return b"Error Processing Message\n"

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()


if __name__ == "__main__":
    server = CustomProtocolServer()

    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop_server()
