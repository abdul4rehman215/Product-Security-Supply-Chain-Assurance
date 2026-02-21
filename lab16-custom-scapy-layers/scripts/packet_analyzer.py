#!/usr/bin/env python3

from scapy.all import *
import struct


class CustomProtocolAnalyzer:
    """
    Analyze custom protocol packets from pcap files
    """

    def __init__(self):
        self.protocols_found = {}
        self.anomalies = []
        self.total_packets = 0
        self.securecomm_packets = 0

    def analyze_pcap(self, filename):
        print("=" * 60)
        print(f"Loading PCAP: {filename}")
        print("=" * 60)

        try:
            packets = rdpcap(filename)
        except FileNotFoundError:
            print(f"[!] File not found: {filename}")
            return
        except Exception as e:
            print(f"[!] Failed to read pcap: {e}")
            return

        self.total_packets = len(packets)
        print(f"[+] Total packets loaded: {self.total_packets}")

        for i, pkt in enumerate(packets, start=1):
            self.analyze_packet(pkt, i)

    def analyze_packet(self, pkt, pkt_num):
        if UDP in pkt:
            udp = pkt[UDP]
            if udp.dport == 9999 or udp.sport == 9999:
                self.securecomm_packets += 1
                raw_payload = bytes(udp.payload)
                self.protocols_found["SecureComm"] = (
                    self.protocols_found.get("SecureComm", 0) + 1
                )

                if len(raw_payload) < 14:
                    self.anomalies.append(
                        (pkt_num, "SecureComm", "Payload too short (<14 bytes)")
                    )
                    return

                self.validate_packet(raw_payload, pkt_num)

    def validate_packet(self, payload, pkt_num):
        try:
            magic, version, msg_type, sequence, payload_len, checksum = struct.unpack(
                "!IBBIHH", payload[:14]
            )
        except Exception as e:
            self.anomalies.append(
                (pkt_num, "SecureComm", f"Header unpack failed: {e}")
            )
            return

        if magic != 0x53434D4D:
            self.anomalies.append(
                (pkt_num, "SecureComm", f"Invalid magic: 0x{magic:08X}")
            )
            return

        if version != 1:
            self.anomalies.append(
                (pkt_num, "SecureComm", f"Invalid version: {version}")
            )

        if msg_type not in [1, 2, 3, 4]:
            self.anomalies.append(
                (pkt_num, "SecureComm", f"Invalid msg_type: {msg_type}")
            )

        actual_payload = payload[14:]
        actual_len = len(actual_payload)

        if payload_len != actual_len:
            self.anomalies.append(
                (
                    pkt_num,
                    "SecureComm",
                    f"Payload length mismatch: header={payload_len}, actual={actual_len}",
                )
            )

        calc = (
            sum(payload[:12] + struct.pack("!H", checksum) + actual_payload)
            & 0xFFFF
        )

        if calc != checksum:
            alt_calc = (
                sum(payload[:12] + b"\x00\x00" + actual_payload) & 0xFFFF
            )
            if alt_calc != checksum:
                self.anomalies.append(
                    (
                        pkt_num,
                        "SecureComm",
                        f"Checksum mismatch: got=0x{checksum:04X}, "
                        f"calc=0x{calc:04X}, alt=0x{alt_calc:04X}",
                    )
                )

    def generate_report(self):
        print("\n" + "=" * 60)
        print("Custom Protocol PCAP Analysis Report")
        print("=" * 60)

        print(f"Total packets in capture: {self.total_packets}")
        print(f"SecureComm packets detected: {self.securecomm_packets}")

        print("\n--- Packets per Protocol ---")
        if not self.protocols_found:
            print("No custom protocols detected.")
        else:
            for proto, count in self.protocols_found.items():
                print(f"{proto}: {count}")

        print("\n--- Anomalies Found ---")
        if not self.anomalies:
            print("No anomalies detected.")
        else:
            for pkt_num, proto, issue in self.anomalies:
                print(f"Packet #{pkt_num:04d} [{proto}] -> {issue}")

        print("\n--- Statistics ---")
        if self.securecomm_packets > 0:
            anomaly_rate = (
                len(self.anomalies) / self.securecomm_packets
            ) * 100
            print(f"SecureComm anomaly rate: {anomaly_rate:.2f}%")
        else:
            print("No SecureComm packets to calculate anomaly rate.")


if __name__ == "__main__":
    analyzer = CustomProtocolAnalyzer()
    analyzer.analyze_pcap("custom_protocols.pcap")
    analyzer.generate_report()
