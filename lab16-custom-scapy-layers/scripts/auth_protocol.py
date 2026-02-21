#!/usr/bin/env python3

from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet
import time
import hashlib
import struct
import zlib


class AuthProtocolHeader(Packet):
    """
    Advanced Authentication Protocol
    """

    name = "AuthProtocol"

    fields_desc = [
        XIntField("magic", 0x41555448),  # "AUTH"
        ByteField("version", 1),

        ByteEnumField("cmd", 1, {
            1: "AUTH_REQUEST",
            2: "AUTH_RESPONSE",
            3: "SESSION_DATA",
            4: "LOGOUT"
        }),

        ByteField("flags", 0),
        IntField("session_id", 0),
        IntField("timestamp", 0),

        StrFixedLenField("token", b"\x00" * 16, length=16),

        ShortField("data_len", 0),
        XShortField("crc", 0)
    ]

    def post_build(self, pkt, pay):
        """
        Post-build processing:
        - Auto-set timestamp if 0
        - Auto-update data_len
        - Calculate CRC (zlib.crc32)
        """

        # Timestamp offset = 11 bytes
        if self.timestamp == 0:
            ts = int(time.time())
            pkt = pkt[:11] + struct.pack("!I", ts) + pkt[15:]

        # Data length offset = 31 bytes
        if pay is not None:
            dl = len(pay)
            pkt = pkt[:31] + struct.pack("!H", dl) + pkt[33:]

        # CRC calculation
        pkt_wo_crc = pkt[:-2] + struct.pack("!H", 0)
        crc_full = zlib.crc32(pkt_wo_crc + pay) & 0xFFFFFFFF
        crc_16 = crc_full & 0xFFFF
        pkt = pkt[:-2] + struct.pack("!H", crc_16)

        return pkt + pay


class AuthData(Packet):
    """
    Authentication data payload
    """

    name = "AuthData"

    fields_desc = [
        FieldLenField("username_len", None, length_of="username", fmt="B"),
        StrLenField("username", b"", length_from=lambda pkt: pkt.username_len),

        FieldLenField("password_len", None, length_of="password", fmt="B"),
        StrLenField("password", b"", length_from=lambda pkt: pkt.password_len),

        IntField("client_id", 0)
    ]


# Bind to TCP port 8888
bind_layers(TCP, AuthProtocolHeader, dport=8888)
bind_layers(TCP, AuthProtocolHeader, sport=8888)

# Bind AuthData when cmd=1 (AUTH_REQUEST)
bind_layers(AuthProtocolHeader, AuthData, cmd=1)


def create_auth_session():
    """
    Create authentication session packets.
    """

    print("=" * 60)
    print("Creating AuthProtocol Session Packets")
    print("=" * 60)

    username = "user1"
    password = "pass123"
    client_id = 1001
    session_id = 0xABCDEF01

    # AUTH_REQUEST
    auth_req = IP(dst="127.0.0.1") / TCP(dport=8888, sport=44444, flags="PA") / AuthProtocolHeader(
        cmd=1,
        flags=0x01,
        session_id=session_id,
        timestamp=0,
        token=b"\x00" * 16
    ) / AuthData(username=username.encode(), password=password.encode(), client_id=client_id)

    # Create token for response
    token_src = f"{username}:{password}:{int(time.time())}".encode()
    token = hashlib.md5(token_src).digest()

    # AUTH_RESPONSE
    auth_resp = IP(dst="127.0.0.1") / TCP(dport=8888, sport=44444, flags="PA") / AuthProtocolHeader(
        cmd=2,
        flags=0x02,
        session_id=session_id,
        timestamp=0,
        token=token
    ) / Raw(b"AUTH_OK")

    # SESSION_DATA
    session_data = IP(dst="127.0.0.1") / TCP(dport=8888, sport=44444, flags="PA") / AuthProtocolHeader(
        cmd=3,
        flags=0x00,
        session_id=session_id,
        timestamp=0,
        token=token
    ) / Raw(b"PING")

    print("\n--- AUTH_REQUEST Packet ---")
    auth_req.show()

    print("\n--- AUTH_RESPONSE Packet ---")
    auth_resp.show()

    print("\n--- SESSION_DATA Packet ---")
    session_data.show()

    print("\nNOTE: These packets are built for demonstration and analysis.")
    print("If you have a listener on TCP/8888, you can send them using send().")


if __name__ == "__main__":
    create_auth_session()
