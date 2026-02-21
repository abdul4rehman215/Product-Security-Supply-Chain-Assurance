#!/usr/bin/env python3
from scapy.all import *
import struct


class ProtocolAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []

    def load_packets(self):
        """
        Load packets from PCAP file using rdpcap()
        Filter for TCP packets with Raw payload
        """
        pkts = rdpcap(self.pcap_file)
        filtered = []
        for p in pkts:
            if p.haslayer(TCP) and p.haslayer(Raw):
                filtered.append(p)
        self.packets = filtered
        print(f"[+] Loaded {len(pkts)} packets; {len(self.packets)} TCP packets with Raw payload")

    def extract_payloads(self):
        """
        Extract TCP payload data from packets
        Return list of payload byte strings
        """
        payloads = []
        for p in self.packets:
            data = bytes(p[Raw].load)
            if data:
                payloads.append(data)
        print(f"[+] Extracted {len(payloads)} payloads")
        return payloads

    def analyze_structure(self, payloads):
        """
        Identify common patterns in first bytes (magic)
        Analyze payload length distribution
        Look for fixed-position fields
        Print hex and ASCII representation
        """
        if not payloads:
            print("[-] No payloads to analyze")
            return

        print("\n=== Structure Analysis ===")
        # Common magic bytes (first 4 bytes)
        magic_counts = {}
        lengths = []
        for pl in payloads:
            if len(pl) >= 4:
                m = pl[:4]
                magic_counts[m] = magic_counts.get(m, 0) + 1
            lengths.append(len(pl))

        print("\n[Magic Byte Frequency]")
        for m, c in sorted(magic_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {m} -> {c} times")

        print("\n[Payload Length Distribution]")
        print(f"  Min: {min(lengths)}")
        print(f"  Max: {max(lengths)}")
        print(f"  Avg: {sum(lengths) / len(lengths):.2f}")

        # Look for fixed-position fields by parsing a few samples
        print("\n[Sample Payloads Hex/ASCII]")
        for i, pl in enumerate(payloads[:5], 1):
            print(f"\n--- Payload #{i} ({len(pl)} bytes) ---")
            print(self.hexdump_ascii(pl))
            fields = self.identify_fields(pl)
            if fields:
                print("\n[Parsed Fields]")
                for k, v in fields.items():
                    print(f"  {k}: {v}")

    def identify_fields(self, payload):
        """
        Parse potential magic bytes (first 4 bytes)
        Extract version field (byte 5)
        Extract message type (byte 6)
        Parse length field (bytes 7-8, big-endian)
        Extract data based on length field
        Identify checksum (last byte)
        """
        if len(payload) < 9:
            return None

        try:
            magic = payload[:4]
            version = payload[4]
            msg_type = payload[5]
            length = struct.unpack("!H", payload[6:8])[0]

            expected_total = 8 + length + 1
            if len(payload) < expected_total:
                return {
                    "magic": magic,
                    "version": version,
                    "type": msg_type,
                    "length": length,
                    "error": f"Incomplete payload (expected {expected_total} bytes)"
                }

            data = payload[8:8 + length]
            checksum = payload[8 + length]
            calc = sum(data) % 256
            checksum_valid = (calc == checksum)

            return {
                "magic": magic,
                "version": version,
                "type": msg_type,
                "length": length,
                "data_ascii": data.decode(errors="ignore"),
                "checksum": checksum,
                "checksum_valid": checksum_valid
            }
        except Exception as e:
            return {"error": str(e)}

    def hexdump_ascii(self, data, width=16):
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
        return "\n".join(lines)


if __name__ == "__main__":
    analyzer = ProtocolAnalyzer("protocol_capture.pcap")
    analyzer.load_packets()
    payloads = analyzer.extract_payloads()
    analyzer.analyze_structure(payloads)
