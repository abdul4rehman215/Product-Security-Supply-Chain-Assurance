#!/usr/bin/env python3

from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet
import struct


class SecureCommHeader(Packet):
    """
    Custom SecureComm Protocol Layer
    """

    name = "SecureComm"

    fields_desc = [
        XIntField("magic", 0x53434D4D),
        ByteField("version", 1),
        ByteEnumField("msg_type", 1, {
            1: "HELLO",
            2: "DATA",
            3: "ACK",
            4: "CLOSE"
        }),
        IntField("sequence", 0),
        ShortField("payload_len", 0),
        XShortField("checksum", 0)
    ]

    def post_build(self, pkt, pay):
        # Update payload_len if needed
        if self.payload_len == 0 and pay:
            payload_length = len(pay)
            pkt = pkt[:10] + struct.pack("!H", payload_length) + pkt[12:]

        # Calculate checksum
        total_bytes = pkt + pay
        checksum = sum(total_bytes) & 0xFFFF
        pkt = pkt[:-2] + struct.pack("!H", checksum)

        return pkt + pay


# Bind to UDP port 9999
bind_layers(UDP, SecureCommHeader, dport=9999)


def test_protocol():
    print("=" * 60)
    print("Testing SecureComm Protocol")
    print("=" * 60)

    hello_pkt = IP(dst="127.0.0.1") / UDP(dport=9999) / SecureCommHeader(
        msg_type=1,
        sequence=1
    ) / b"Hello Server"

    data_pkt = IP(dst="127.0.0.1") / UDP(dport=9999) / SecureCommHeader(
        msg_type=2,
        sequence=2
    ) / b"Sample Data"

    print("\n--- HELLO Packet ---")
    hello_pkt.show()

    print("\n--- DATA Packet ---")
    data_pkt.show()

    send(hello_pkt, verbose=False)
    send(data_pkt, verbose=False)

    print("\nPackets sent to localhost:9999")


if __name__ == "__main__":
    test_protocol()
