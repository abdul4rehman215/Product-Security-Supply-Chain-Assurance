#!/usr/bin/env python3
from scapy.all import *


def send_and_receive_icmp(target_ip, timeout=2):
    """
    Send ICMP echo-request and wait for echo-reply.

    Args:
        target_ip: Target IP address
        timeout: Response timeout in seconds

    Returns:
        Response packet or None
    """
    pkt = IP(dst=target_ip) / ICMP(type="echo-request")
    resp = sr1(pkt, timeout=timeout, verbose=False)

    if resp is None:
        return None
    return resp


def send_and_receive_tcp(target_ip, target_port, timeout=2):
    """
    Send TCP SYN and wait for a response (SYN-ACK or RST).

    Args:
        target_ip: Target IP address
        target_port: Target port number
        timeout: Response timeout in seconds

    Returns:
        Response packet or None
    """
    syn = IP(dst=target_ip) / TCP(
        dport=int(target_port),
        sport=RandShort(),
        flags="S",
        seq=RandInt()
    )

    resp = sr1(syn, timeout=timeout, verbose=False)
    if resp is None:
        return None

    return resp


def batch_send_receive(target_ip, ports):
    """
    Send TCP SYN packets to multiple ports and collect responses.

    Args:
        target_ip: Target IP address
        ports: List of ports to test

    Returns:
        Tuple(answered, unanswered)
    """
    pkts = [
        IP(dst=target_ip) / TCP(dport=int(p), sport=RandShort(), flags="S", seq=RandInt())
        for p in ports
    ]

    answered, unanswered = sr(pkts, timeout=2, verbose=False)
    return answered, unanswered


def main():
    target = "127.0.0.1"

    # ICMP test
    print("\n=== ICMP Test ===")
    icmp_resp = send_and_receive_icmp(target, timeout=2)
    if icmp_resp:
        print("[+] ICMP response received:")
        print(icmp_resp.summary())
    else:
        print("[-] No ICMP response received")

    # TCP test (single port)
    print("\n=== TCP Test (port 80) ===")
    tcp_resp = send_and_receive_tcp(target, 80, timeout=2)
    if tcp_resp:
        print("[+] TCP response received:")
        print(tcp_resp.summary())
        if tcp_resp.haslayer(TCP):
            print(f"    TCP Flags: {tcp_resp[TCP].flags}")
    else:
        print("[-] No TCP response received")

    # Batch TCP test
    print("\n=== Batch TCP Test (ports 22, 80, 443) ===")
    ans, unans = batch_send_receive(target, [22, 80, 443])

    print(f"[+] Answered count: {len(ans)}")
    for s, r in ans:
        print(f"    {s[IP].dst}:{s[TCP].dport} -> {r.summary()}")

    print(f"[-] Unanswered count: {len(unans)}")
    for pkt in unans:
        if pkt.haslayer(TCP):
            print(f"    {pkt[IP].dst}:{pkt[TCP].dport} (no response)")

    print("Send/receive tests complete")


if __name__ == "__main__":
    main()
