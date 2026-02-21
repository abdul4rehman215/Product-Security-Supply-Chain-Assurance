#!/usr/bin/env python3
from scapy.all import *
import time
from collections import Counter


class PacketCapture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.captured_packets = []

    def packet_handler(self, packet):
        """
        Process each captured packet.

        Args:
            packet: Captured packet object
        """
        ts = time.time()

        # IP details
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = "N/A"
            dst_ip = "N/A"

        # Protocol details
        proto = "OTHER"
        dst_port = None

        if packet.haslayer(TCP):
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        # Print live output
        print(f"[{ts:.3f}] {proto} {src_ip} -> {dst_ip}", end="")
        if dst_port is not None:
            print(f" dport={dst_port}")
        else:
            print("")

        # Store packet
        self.captured_packets.append(packet)

    def start_capture(self, count=20, timeout=30):
        """
        Start capturing packets.

        Args:
            count: Number of packets to capture
            timeout: Maximum capture time in seconds
        """
        print(f"Starting capture on {self.interface}")

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=count,
                timeout=timeout,
                store=False
            )
        except KeyboardInterrupt:
            print("\nCapture interrupted by user.")

        print(f"Capture complete. Total packets captured: {len(self.captured_packets)}")

    def analyze_packets(self):
        """
        Analyze captured packets and generate statistics.
        """
        proto_counts = Counter()
        src_counts = Counter()
        dst_ports = Counter()

        for pkt in self.captured_packets:
            if pkt.haslayer(TCP):
                proto_counts["TCP"] += 1
                src_counts[pkt[IP].src if pkt.haslayer(IP) else "N/A"] += 1
                dst_ports[pkt[TCP].dport] += 1
            elif pkt.haslayer(UDP):
                proto_counts["UDP"] += 1
                src_counts[pkt[IP].src if pkt.haslayer(IP) else "N/A"] += 1
                dst_ports[pkt[UDP].dport] += 1
            elif pkt.haslayer(ICMP):
                proto_counts["ICMP"] += 1
                src_counts[pkt[IP].src if pkt.haslayer(IP) else "N/A"] += 1
            else:
                proto_counts["OTHER"] += 1

        print("\n=== Analysis Results ===")
        print("Packets by protocol:")
        for k, v in proto_counts.most_common():
            print(f"  {k}: {v}")

        print("\nTop source IPs:")
        for ip, c in src_counts.most_common(5):
            print(f"  {ip}: {c}")

        print("\nTop destination ports:")
        for p, c in dst_ports.most_common(5):
            print(f"  {p}: {c}")

    def save_capture(self, filename="captured.pcap"):
        """
        Save captured packets to file.

        Args:
            filename: Output PCAP filename
        """
        wrpcap(filename, self.captured_packets)
        print(f"[+] Saved capture to {filename}")


def main():
    # Show available interfaces
    interfaces = get_if_list()
    print("Available interfaces:")
    for i in interfaces:
        print(f"  - {i}")

    # Prefer eth0, otherwise fall back to first available
    interface = "eth0"
    if interface not in interfaces and len(interfaces) > 0:
        interface = interfaces[0]
        print(f"\n[!] Default interface eth0 not found. Using: {interface}")

    cap = PacketCapture(interface=interface)

    cap.start_capture(count=20, timeout=30)
    cap.analyze_packets()
    cap.save_capture("captured.pcap")

    print("Capture complete")


if __name__ == "__main__":
    main()
