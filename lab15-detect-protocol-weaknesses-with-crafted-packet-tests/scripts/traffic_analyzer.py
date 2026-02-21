#!/usr/bin/env python3
from scapy.all import *
import struct
from collections import Counter

class ProtocolTrafficAnalyzer:

    def __init__(self, interface='lo', target_port=8888):
        self.interface = interface
        self.target_port = target_port
        self.packets = []

    def packet_callback(self, packet):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == self.target_port or tcp.sport == self.target_port:
                if packet.haslayer(Raw):
                    data = packet[Raw].load
                    if len(data) >= 8:
                        try:
                            magic, version, command, length = struct.unpack('!HHHH', data[:8])
                            self.packets.append((magic, command, length))
                        except:
                            pass

    def start_capture(self, duration=30):
        sniff(
            iface=self.interface,
            filter=f"tcp port {self.target_port}",
            prn=self.packet_callback,
            timeout=duration
        )

    def analyze_patterns(self):
        commands = [pkt[1] for pkt in self.packets]
        magic_numbers = [pkt[0] for pkt in self.packets]
        lengths = [pkt[2] for pkt in self.packets]

        print("Command Frequency:", Counter(commands))
        print("Magic Numbers Seen:", Counter(magic_numbers))
        if lengths:
            print("Max Payload Size:", max(lengths))

if __name__ == "__main__":
    analyzer = ProtocolTrafficAnalyzer()
    analyzer.start_capture(30)
    analyzer.analyze_patterns()
