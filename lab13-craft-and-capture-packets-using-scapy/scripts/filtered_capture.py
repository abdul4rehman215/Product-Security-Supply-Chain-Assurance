#!/usr/bin/env python3
from scapy.all import *
import time


def capture_tcp_only(interface, count=10):
    """
    Capture only TCP packets.

    Args:
        interface: Network interface name
        count: Number of packets to capture

    Returns:
        List of captured packets
    """
    captured = []

    def handler(pkt):
        captured.append(pkt)
        print(pkt.summary())

    sniff(
        iface=interface,
        filter="tcp",
        prn=handler,
        count=count,
        timeout=20,
        store=False
    )

    return captured


def capture_http_traffic(interface, count=10):
    """
    Capture HTTP traffic on port 80.

    Args:
        interface: Network interface name
        count: Number of packets to capture

    Returns:
        List of captured packets
    """
    captured = []

    def handler(pkt):
        captured.append(pkt)

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            try:
                preview = payload[:120].decode(errors="ignore")
            except Exception:
                preview = str(payload[:120])
            print(f"[HTTP Payload Preview] {preview}")
        else:
            print(pkt.summary())

    sniff(
        iface=interface,
        filter="tcp port 80",
        prn=handler,
        count=count,
        timeout=20,
        store=False
    )

    return captured


def capture_dns_queries(interface, count=10):
    """
    Capture DNS queries and responses.

    Args:
        interface: Network interface name
        count: Number of packets to capture

    Returns:
        List of captured packets
    """
    captured = []

    def handler(pkt):
        captured.append(pkt)

        if pkt.haslayer(DNS):
            # DNS query
            if pkt.haslayer(DNSQR) and pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode(errors="ignore")
                print(f"[DNS Query] {qname}")

            # DNS answer
            if pkt[DNS].an:
                try:
                    ans = pkt[DNS].an.rdata
                    print(f"[DNS Answer] {ans}")
                except Exception:
                    pass
        else:
            print(pkt.summary())

    sniff(
        iface=interface,
        filter="udp port 53",
        prn=handler,
        count=count,
        timeout=20,
        store=False
    )

    return captured


def main():
    # NOTE: In your lab run, eth0 didn’t exist and you used lo/ens5.
    # Keep eth0 as default for portability, but you can change it to "ens5".
    interface = "eth0"

    print("\n=== Capturing TCP packets ===")
    tcp_packets = capture_tcp_only(interface, count=10)
    wrpcap("tcp_only.pcap", tcp_packets)
    print("[+] Saved tcp_only.pcap")

    print("\n=== Capturing HTTP traffic (port 80) ===")
    http_packets = capture_http_traffic(interface, count=10)
    wrpcap("http_traffic.pcap", http_packets)
    print("[+] Saved http_traffic.pcap")

    print("\n=== Capturing DNS traffic (port 53) ===")
    dns_packets = capture_dns_queries(interface, count=10)
    wrpcap("dns_traffic.pcap", dns_packets)
    print("[+] Saved dns_traffic.pcap")

    print("Filtered capture complete")


if __name__ == "__main__":
    main()
