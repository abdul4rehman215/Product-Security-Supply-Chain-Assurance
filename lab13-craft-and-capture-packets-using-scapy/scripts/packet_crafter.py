#!/usr/bin/env python3
from scapy.all import *


def craft_icmp_packet(target_ip):
    """
    Craft an ICMP echo request packet.

    Args:
        target_ip: Destination IP address

    Returns:
        Scapy packet object
    """
    ip_layer = IP(dst=target_ip)
    icmp_layer = ICMP(type="echo-request")
    packet = ip_layer / icmp_layer
    return packet


def craft_tcp_syn_packet(target_ip, target_port):
    """
    Craft a TCP SYN packet for connection initiation.

    Args:
        target_ip: Destination IP address
        target_port: Destination port number

    Returns:
        Scapy packet object
    """
    ip_layer = IP(dst=target_ip)
    tcp_layer = TCP(dport=int(target_port), flags="S", sport=RandShort(), seq=RandInt())
    packet = ip_layer / tcp_layer
    return packet


def craft_udp_packet(target_ip, target_port, payload):
    """
    Craft a UDP packet with custom payload.

    Args:
        target_ip: Destination IP address
        target_port: Destination port
        payload: Data to send

    Returns:
        Scapy packet object
    """
    ip_layer = IP(dst=target_ip)
    udp_layer = UDP(dport=int(target_port), sport=RandShort())
    packet = ip_layer / udp_layer / Raw(load=payload)
    return packet


def display_packet_details(packet):
    """
    Display detailed information about a packet.

    Args:
        packet: Scapy packet object
    """
    print("\n--- Packet Summary ---")
    print(packet.summary())

    print("\n--- Packet Detailed View ---")
    packet.show()


def main():
    target = "127.0.0.1"

    icmp_pkt = craft_icmp_packet(target)
    print("\n[+] Crafted ICMP packet")
    display_packet_details(icmp_pkt)

    tcp_syn_pkt = craft_tcp_syn_packet(target, 80)
    print("\n[+] Crafted TCP SYN packet")
    display_packet_details(tcp_syn_pkt)

    udp_pkt = craft_udp_packet(target, 53, b"Hello from Scapy")
    print("\n[+] Crafted UDP packet")
    display_packet_details(udp_pkt)

    wrpcap("crafted_packets.pcap", [icmp_pkt, tcp_syn_pkt, udp_pkt])
    print("\n[+] Saved packets to crafted_packets.pcap")

    print("Packet crafting complete")


if __name__ == "__main__":
    main()
