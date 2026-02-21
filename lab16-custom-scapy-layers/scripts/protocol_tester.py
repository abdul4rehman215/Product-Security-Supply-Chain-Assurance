#!/usr/bin/env python3

from scapy.all import *
from secure_comm_protocol import SecureCommHeader
import time


class ProtocolTester:
    """
    Test custom protocols against target systems
    """

    def __init__(self):
        self.results = []

    def test_secure_comm(self, target_ip="127.0.0.1", port=9999):
        """
        Test SecureComm protocol.
        """
        print("=" * 60)
        print("Testing SecureComm Protocol")
        print("=" * 60)

        tests = [
            ("HELLO", 1, b"Hello"),
            ("DATA", 2, b"TestData"),
            ("ACK", 3, b""),
            ("CLOSE", 4, b"Bye"),
        ]

        seq = 1
        for name, msg_type, payload in tests:
            pkt = (
                IP(dst=target_ip)
                / UDP(dport=port, sport=RandShort())
                / SecureCommHeader(msg_type=msg_type, sequence=seq)
                / payload
            )

            print(f"\n[>] Sending {name} (type={msg_type}) seq={seq}")
            resp = sr1(pkt, timeout=2, verbose=False)

            if resp is None:
                print("[-] No response")
                self.results.append((name, False, "No response"))
            else:
                print("[+] Response received:")
                resp.show()
                self.results.append((name, True, "Response received"))

            seq += 1
            time.sleep(0.5)

    def fuzz_test(self, target_ip="127.0.0.1"):
        """
        Perform fuzzing tests.
        """
        print("\n" + "=" * 60)
        print("Fuzz Testing SecureComm Protocol")
        print("=" * 60)

        port = 9999

        pkt1 = IP(dst=target_ip) / UDP(dport=port) / SecureCommHeader(
            magic=0xDEADBEEF, version=1, msg_type=1, sequence=999
        ) / b"BadMagic"

        pkt2 = IP(dst=target_ip) / UDP(dport=port) / SecureCommHeader(
            version=99, msg_type=2, sequence=1000
        ) / b"BadVersion"

        pkt3 = IP(dst=target_ip) / UDP(dport=port) / SecureCommHeader(
            msg_type=99, sequence=1001
        ) / b"UnknownType"

        pkt4 = IP(dst=target_ip) / UDP(dport=port) / SecureCommHeader(
            msg_type=2, sequence=1002
        ) / (b"A" * 1500)

        fuzz_packets = [
            ("Invalid Magic", pkt1),
            ("Invalid Version", pkt2),
            ("Unknown Msg Type", pkt3),
            ("Large Payload", pkt4),
        ]

        for name, pkt in fuzz_packets:
            print(f"\n[>] Sending fuzz case: {name}")
            resp = sr1(pkt, timeout=2, verbose=False)

            if resp is None:
                print("[-] No response (expected in some fuzz cases)")
                self.results.append((f"FUZZ: {name}", False, "No response"))
            else:
                print("[+] Response received:")
                resp.show()
                self.results.append((f"FUZZ: {name}", True, "Response received"))

            time.sleep(0.5)

    def generate_report(self):
        """
        Generate test report.
        """
        print("\n" + "=" * 60)
        print("Test Report")
        print("=" * 60)

        if not self.results:
            print("No results recorded.")
            return

        total = len(self.results)
        success = sum(1 for r in self.results if r[1])
        fail = total - success
        rate = (success / total) * 100

        print(f"Total Tests: {total}")
        print(f"Success: {success}")
        print(f"Fail: {fail}")
        print(f"Success Rate: {rate:.2f}%")

        print("\n--- Detailed Results ---")
        for test_name, ok, detail in self.results:
            status = "PASS" if ok else "FAIL"
            print(f"{status:4} | {test_name:25} | {detail}")


if __name__ == "__main__":
    tester = ProtocolTester()
    tester.test_secure_comm()
    tester.fuzz_test()
    tester.generate_report()
