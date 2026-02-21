#!/usr/bin/env python3
import struct
from scapy.all import rdpcap, TCP, Raw
from collections import Counter


class ProtocolDissector:
    def __init__(self):
        self.message_types = {
            1: "WELCOME",
            2: "STATUS",
            3: "DATA"
        }

    def dissect_message(self, payload):
        """
        Dissect a protocol message into its components.

        Returns dict with fields:
        - magic: 4-byte identifier
        - version: protocol version
        - type: message type code
        - type_name: human-readable type
        - length: data length
        - data: message data
        - checksum: integrity check value
        - checksum_valid: boolean validation result
        """
        try:
            if len(payload) < 9:
                return {"error": "Payload too short to parse", "raw_len": len(payload)}

            magic, version, msg_type, length = struct.unpack("!4sBBH", payload[:8])

            total_len = 8 + length + 1
            if len(payload) < total_len:
                return {
                    "magic": magic,
                    "version": version,
                    "type": msg_type,
                    "type_name": self.message_types.get(msg_type, "UNKNOWN"),
                    "length": length,
                    "error": f"Incomplete message: expected {total_len} bytes, got {len(payload)}"
                }

            data = payload[8:8 + length]
            checksum = payload[8 + length]
            calc = sum(data) % 256
            valid = (calc == checksum)

            return {
                "magic": magic.decode(errors="ignore"),
                "version": version,
                "type": msg_type,
                "type_name": self.message_types.get(msg_type, "UNKNOWN"),
                "length": length,
                "data": data.decode(errors="ignore"),
                "checksum": checksum,
                "checksum_valid": valid
            }

        except Exception as e:
            return {"error": str(e)}

    def analyze_all_messages(self, payloads):
        """
        Dissect all payloads
        Count message types
        Identify patterns and anomalies
        """
        parsed = []
        type_counts = Counter()
        checksum_fail = 0
        unknown_types = 0

        for p in payloads:
            msg = self.dissect_message(p)
            parsed.append(msg)
            if "type" in msg and isinstance(msg["type"], int):
                type_counts[msg["type_name"]] += 1
                if msg.get("type_name") == "UNKNOWN":
                    unknown_types += 1
            if msg.get("checksum_valid") is False:
                checksum_fail += 1

        print("\n=== Dissector Summary ===")
        print("Message type counts:")
        for t, c in type_counts.most_common():
            print(f"  {t}: {c}")

        print(f"\nChecksum failures: {checksum_fail}")
        print(f"Unknown types: {unknown_types}")

        return {
            "messages": parsed,
            "type_counts": dict(type_counts),
            "checksum_failures": checksum_fail,
            "unknown_types": unknown_types
        }


def load_payloads_from_pcap(pcap_file):
    pkts = rdpcap(pcap_file)
    payloads = []
    for p in pkts:
        if p.haslayer(TCP) and p.haslayer(Raw):
            data = bytes(p[Raw].load)
            if data:
                payloads.append(data)
    return payloads


if __name__ == "__main__":
    payloads = load_payloads_from_pcap("protocol_capture.pcap")
    dissector = ProtocolDissector()
    results = dissector.analyze_all_messages(payloads)

    # Save parsed messages for later tasks
    import json
    with open("dissector_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n[+] Saved dissector_results.json")
