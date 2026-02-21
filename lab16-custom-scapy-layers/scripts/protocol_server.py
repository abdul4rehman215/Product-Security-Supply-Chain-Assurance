#!/usr/bin/env python3

import socket
import struct
import threading


class ProtocolTestServer:
    """
    Simple UDP server to test SecureComm protocol
    """

    def __init__(self, port=9999):
        self.port = port
        self.running = False
        self.sock = None

    def start_server(self):
        """
        Start the UDP server.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", self.port))

        self.running = True
        print(f"[+] SecureComm UDP test server listening on 127.0.0.1:{self.port}")

        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self.process_packet(data, addr)
            except KeyboardInterrupt:
                print("\n[!] Server stopping...")
                self.running = False
            except Exception as e:
                print(f"[!] Error: {e}")

        if self.sock:
            self.sock.close()

    def process_packet(self, data, addr):
        """
        Process received SecureComm packets.
        """
        # SecureComm header = 14 bytes
        if len(data) < 14:
            print(f"[-] Packet too short from {addr}")
            return

        try:
            magic, version, msg_type, sequence, payload_len, checksum = struct.unpack(
                "!IBBIHH", data[:14]
            )
        except Exception as e:
            print(f"[-] Failed to unpack header from {addr}: {e}")
            return

        if magic != 0x53434D4D:
            print(f"[-] Invalid magic from {addr}: 0x{magic:08X}")
            return

        payload = data[14:]
        print(
            f"[+] SecureComm packet from {addr} | "
            f"ver={version} type={msg_type} seq={sequence} len={payload_len}"
        )

        # Send ACK response
        ack = self.create_ack(sequence)
        self.sock.sendto(ack, addr)
        print(f"[>] Sent ACK to {addr} for seq={sequence}")

    def create_ack(self, sequence):
        """
        Create ACK response packet.
        """
        magic = 0x53434D4D
        version = 1
        msg_type = 3  # ACK
        payload = b""
        payload_len = len(payload)

        header = struct.pack("!IBBIHH", magic, version, msg_type, sequence, payload_len, 0)

        checksum = (sum(header + payload) & 0xFFFF)

        header = struct.pack("!IBBIHH", magic, version, msg_type, sequence, payload_len, checksum)
        return header + payload


if __name__ == "__main__":
    server = ProtocolTestServer()
    server.start_server()
