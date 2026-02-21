#!/usr/bin/env python3
from scapy.all import *
import threading
import time
import json
from datetime import datetime
from collections import Counter


class PacketAutomation:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.captured_packets = []
        self.sent_packets = []
        self.capturing = False
        self.capture_thread = None

    def start_background_capture(self):
        """
        Start packet capture in background thread.
        """

        def capture_worker():
            self.capturing = True

            def handler(pkt):
                self.captured_packets.append(pkt)

            # stop_filter returns True to stop sniffing
            sniff(
                iface=self.interface,
                prn=handler,
                store=False,
                stop_filter=lambda x: not self.capturing
            )

        self.capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self.capture_thread.start()
        time.sleep(1)

    def stop_background_capture(self):
        """
        Stop background capture thread.
        """
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=3)

    def send_ping_sequence(self, target_ip, count=5):
        """
        Send multiple ICMP echo request packets.
        """
        for i in range(count):
            pkt = IP(dst=target_ip) / ICMP(id=0x1234, seq=i)
            send(pkt, verbose=False)
            self.sent_packets.append(pkt)
            time.sleep(0.5)

    def send_port_scan(self, target_ip, ports):
        """
        Send TCP SYN packets to multiple ports.
        """
        for p in ports:
            pkt = IP(dst=target_ip) / TCP(
                dport=int(p),
                sport=RandShort(),
                flags="S",
                seq=RandInt()
            )
            send(pkt, verbose=False)
            self.sent_packets.append(pkt)
            time.sleep(0.2)

    def analyze_responses(self):
        """
        Correlate sent packets with captured responses.
        """
        icmp_replies = 0
        tcp_synack = 0
        tcp_rst = 0

        for pkt in self.captured_packets:
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 0:
                icmp_replies += 1

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                # SYN-ACK (0x12)
                if flags == 0x12:
                    tcp_synack += 1
                # RST or RST-ACK
                if "R" in str(flags) or flags in [0x14, 0x04]:
                    tcp_rst += 1

        print("\n=== Correlation Statistics ===")
        print(f"Sent packets: {len(self.sent_packets)}")
        print(f"Captured packets: {len(self.captured_packets)}")
        print(f"ICMP echo replies observed: {icmp_replies}")
        print(f"TCP SYN-ACK responses observed: {tcp_synack}")
        print(f"TCP RST responses observed: {tcp_rst}")

        return {
            "icmp_echo_replies": icmp_replies,
            "tcp_synack": tcp_synack,
            "tcp_rst": tcp_rst
        }

    def generate_report(self):
        """
        Generate JSON report of traffic analysis.
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "sent_count": len(self.sent_packets),
            "captured_count": len(self.captured_packets),
            "protocols": {},
            "top_ips": {}
        }

        proto_counts = Counter()
        src_counts = Counter()

        for pkt in self.captured_packets:
            if pkt.haslayer(TCP):
                proto_counts["TCP"] += 1
            elif pkt.haslayer(UDP):
                proto_counts["UDP"] += 1
            elif pkt.haslayer(ICMP):
                proto_counts["ICMP"] += 1
            else:
                proto_counts["OTHER"] += 1

            if pkt.haslayer(IP):
                src_counts[pkt[IP].src] += 1

        report["protocols"] = dict(proto_counts)
        report["top_ips"] = dict(src_counts.most_common(10))
        return report

    def save_results(self, base_filename="automation"):
        """
        Save packets and report to files.
        """
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        sent_pcap = f"{base_filename}_sent_{ts}.pcap"
        cap_pcap = f"{base_filename}_captured_{ts}.pcap"
        report_json = f"{base_filename}_report_{ts}.json"

        wrpcap(sent_pcap, self.sent_packets)
        wrpcap(cap_pcap, self.captured_packets)

        report = self.generate_report()
        with open(report_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        print("\n=== Saved Results ===")
        print(f"Sent PCAP: {sent_pcap}")
        print(f"Captured PCAP: {cap_pcap}")
        print(f"Report JSON: {report_json}")


def run_automated_test():
    # NOTE: In your environment, eth0 was not present; you used lo/ens5.
    # Change interface to "lo" (for localhost testing) or "ens5" (for real traffic).
    pa = PacketAutomation(interface="eth0")

    pa.start_background_capture()

    pa.send_ping_sequence("127.0.0.1", count=5)
    pa.send_port_scan("127.0.0.1", ports=[22, 80, 443])

    time.sleep(3)

    pa.stop_background_capture()
    pa.analyze_responses()
    pa.save_results(base_filename="automation")


def main():
    print("Starting automated packet operations")
    run_automated_test()
    print("Automation complete")


if __name__ == "__main__":
    main()
