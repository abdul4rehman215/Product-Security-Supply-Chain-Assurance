#!/usr/bin/env python3

from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet


def explore_tcp_layer():
    """
    Explore the TCP layer structure to understand Scapy's architecture.
    """

    print("=" * 60)
    print("Exploring TCP Layer Structure")
    print("=" * 60)

    # Create a TCP packet
    tcp_pkt = TCP()

    print("\n--- TCP Packet Structure (show) ---")
    tcp_pkt.show()

    # Iterate through fields_desc
    print("\n--- TCP fields_desc Details ---")
    for field in tcp_pkt.fields_desc:
        print(f"Field Name: {field.name} | Type: {type(field).__name__}")

    # Create sample IP/TCP packet
    sample_pkt = IP(dst="127.0.0.1") / TCP(dport=80)
    print("\n--- Sample IP/TCP Packet Layers ---")
    sample_pkt.show()

    print("\n--- Packet Summary ---")
    print(sample_pkt.summary())


def explore_field_types():
    """
    Examine different Scapy field types.
    """

    print("\n" + "=" * 60)
    print("Exploring Field Types")
    print("=" * 60)

    class FieldTest(Packet):
        name = "FieldTest"
        fields_desc = [
            ByteField("byte_field", 10),
            ShortField("short_field", 1000),
            IntField("int_field", 123456),
            XIntField("xint_field", 0x1234ABCD),
            StrField("str_field", "hello"),
            StrFixedLenField("fixed_str", "test", length=8),
        ]

    pkt = FieldTest()

    print("\n--- FieldTest Packet Structure ---")
    pkt.show()

    print("\n--- Raw Bytes ---")
    print(bytes(pkt))


if __name__ == "__main__":
    explore_tcp_layer()
    explore_field_types()
