#!/usr/bin/env python3
from scapy.all import rdpcap, TCP, Raw
from collections import Counter
import json
import math
import hashlib
from datetime import datetime


class AutomatedProtocolAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.results = {
            "patterns": {},
            "vulnerabilities": [],
            "statistics": {}
        }
        self.payloads = []
        self.timestamps = []

    def load_payloads(self):
        """
        Load TCP Raw payloads from a PCAP file using Scapy.
        Also capture packet timestamps when available.
        """
        pkts = rdpcap(self.pcap_file)
        for p in pkts:
            if p.haslayer(TCP) and p.haslayer(Raw):
                data = bytes(p[Raw].load)
                if data:
                    self.payloads.append(data)
                    try:
                        self.timestamps.append(float(p.time))
                    except Exception:
                        pass

    def calculate_entropy(self, data):
        """
        Calculate Shannon entropy for a byte string.
        Entropy range for bytes is typically 0 to 8.
        """
        if not data:
            return 0.0
        freq = Counter(data)
        n = len(data)
        ent = 0.0
        for c in freq.values():
            p = c / n
            ent -= p * math.log2(p)
        return ent

    def extract_patterns(self):
        """
        Identify common protocol signatures:
        - first 4 bytes (magic)
        - first 8 bytes (header prefix)
        """
        if not self.payloads:
            return

        magic_counts = Counter()
        prefix_counts = Counter()

        for p in self.payloads:
            if len(p) >= 4:
                magic_counts[p[:4]] += 1
            if len(p) >= 8:
                prefix_counts[p[:8]] += 1

        self.results["patterns"]["top_magic"] = [
            (k.hex(), v) for k, v in magic_counts.most_common(10)
        ]
        self.results["patterns"]["top_prefix8"] = [
            (k.hex(), v) for k, v in prefix_counts.most_common(10)
        ]

    def statistical_analysis(self):
        """
        Compute statistics:
        - payload lengths (min/max/avg)
        - entropy (min/max/avg)
        - timing deltas if timestamps exist
        """
        if not self.payloads:
            return

        lengths = [len(p) for p in self.payloads]
        entropies = [self.calculate_entropy(p) for p in self.payloads]

        stats = {
            "payload_count": len(self.payloads),
            "min_length": min(lengths),
            "max_length": max(lengths),
            "avg_length": sum(lengths) / len(lengths),
            "min_entropy": min(entropies),
            "max_entropy": max(entropies),
            "avg_entropy": sum(entropies) / len(entropies),
        }

        if len(self.timestamps) >= 2:
            sorted_ts = sorted(self.timestamps)
            deltas = [
                sorted_ts[i + 1] - sorted_ts[i]
                for i in range(len(sorted_ts) - 1)
            ]
            stats["timing_min_delta"] = min(deltas)
            stats["timing_max_delta"] = max(deltas)
            stats["timing_avg_delta"] = sum(deltas) / len(deltas)

        self.results["statistics"] = stats

        # Simple inference: low entropy often indicates plaintext traffic
        if stats["avg_entropy"] < 4.0:
            self.results["vulnerabilities"].append(
                "Low entropy suggests plaintext protocol traffic (no encryption)."
            )

    def generate_protocol_signature(self):
        """
        Generate a stable fingerprint for this protocol based on observed traits.
        """
        sig = {
            "pcap_file": self.pcap_file,
            "observed_magic": self.results.get("patterns", {}).get("top_magic", []),
            "avg_len": self.results.get("statistics", {}).get("avg_length"),
            "avg_entropy": self.results.get("statistics", {}).get("avg_entropy"),
        }

        raw = json.dumps(sig, sort_keys=True).encode()
        fingerprint = hashlib.sha256(raw).hexdigest()

        self.results["protocol_signature"] = {
            "fingerprint_sha256": fingerprint,
            "signature_input": sig,
            "detection_hint": "Look for TCP payloads starting with magic bytes 0x4350524f ('CPRO')."
        }

    def export_results(self, output_file="analysis_results.json"):
        """
        Save analysis results to JSON.
        """
        self.results["timestamp"] = datetime.utcnow().isoformat() + "Z"
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Saved {output_file}")

    def run_full_analysis(self):
        """
        Run the complete analysis pipeline.
        """
        self.load_payloads()
        self.extract_patterns()
        self.statistical_analysis()
        self.generate_protocol_signature()


if __name__ == "__main__":
    analyzer = AutomatedProtocolAnalyzer("protocol_capture.pcap")
    analyzer.run_full_analysis()
    analyzer.export_results()
