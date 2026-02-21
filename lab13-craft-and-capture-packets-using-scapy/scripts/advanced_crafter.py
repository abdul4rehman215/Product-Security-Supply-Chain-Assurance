#!/usr/bin/env python3
from scapy.all import *


def create_port_scan_packets(target_ip, port_list):
    """
    Create TCP SYN packets for multiple ports.

    Args:
        target_ip: Target IP address
        port_list: List of ports to scan

    Returns:
        List of packet objects
    """
    packets = []
    for port in port_list:
        pkt = IP(dst=target_ip) / TCP(
            dport=int(port),
            sport=RandShort(),
            flags="S",
            seq=RandInt()
        )
        packets.append(pkt)
    return packets


def create_fragmented_packet(target_ip, payload_size):
    """
    Create and fragment a large packet.

    Args:
        target_ip: Destination IP
        payload_size: Size of payload in bytes

    Returns:
        List of fragmented packets
    """
    payload = b"A" * int(payload_size)
    pkt = IP(dst=target_ip) / UDP(dport=4444, sport=RandShort()) / Raw(load=payload)

    # Split packet into fragments
    fragments = fragment(pkt, fragsize=1480)
    return fragments


def create_custom_fields_packet(src_ip, dst_ip, ttl_value):
    """
    Create packet with custom IP header fields.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        ttl_value: Time-to-live value

    Returns:
        Packet with custom fields
    """
    ip_layer = IP(src=src_ip, dst=dst_ip, ttl=int(ttl_value))
    icmp_layer = ICMP(type="echo-request")
    return ip_layer / icmp_layer


def main():
    target = "127.0.0.1"

    # Port scan packets
    port_scan_packets = create_port_scan_packets(target, [22, 80, 443])
    print(f"[+] Created {len(port_scan_packets)} port scan packets")

    # Fragmented packet
    fragments = create_fragmented_packet(target, 2000)
    print(f"[+] Created {len(fragments)} fragmented packets")

    # Custom TTL packet
    custom_ttl_packet = create_custom_fields_packet("127.0.0.1", target, 32)
    print("[+] Created custom TTL packet")

    # Save all packets
    all_packets = []
    all_packets.extend(port_scan_packets)
    all_packets.extend(fragments)
    all_packets.append(custom_ttl_packet)

    wrpcap("advanced_packets.pcap", all_packets)
    print("[+] Saved all packets to advanced_packets.pcap")

    print("Advanced packet crafting complete")


if __name__ == "__main__":
    main()
