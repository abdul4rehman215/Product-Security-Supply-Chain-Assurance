#!/usr/bin/env python3
import socket
import random
import struct
import time
import json
from datetime import datetime


class ProtocolFuzzer:
    def __init__(self, target_host='127.0.0.1', target_port=8888):
        self.target_host = target_host
        self.target_port = target_port
        self.crash_cases = []
        self.magic = b"CPRO"
        self.version = 1

    def checksum(self, data):
        return sum(data) % 256

    def build_packet(self, magic, version, msg_type, length, data, checksum=None):
        header = struct.pack(
            "!4sBBH",
            magic,
            int(version) & 0xFF,
            int(msg_type) & 0xFF,
            int(length) & 0xFFFF
        )
        if checksum is None:
            checksum = self.checksum(data)
        return header + data + struct.pack("!B", checksum & 0xFF)

    def monitor_server_response(self, test_case):
        """
        Send fuzzed packet
        Monitor for crashes or errors
        Record anomalous behavior
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.target_host, self.target_port))

            # Read banner messages (ignore content)
            try:
                s.recv(4096)
                s.recv(4096)
                s.recv(4096)
            except Exception:
                pass

            s.sendall(test_case["packet"])
            time.sleep(0.1)

            try:
                resp = s.recv(512)
                test_case["response_preview"] = resp[:120].decode(errors="ignore")
            except Exception as e:
                test_case["response_preview"] = f"recv_error: {str(e)}"

            return True, test_case

        except Exception as e:
            test_case["error"] = str(e)
            return False, test_case
        finally:
            try:
                s.close()
            except Exception:
                pass

    def fuzz_magic_bytes(self):
        """
        Generate random magic byte variations
        Test server response to invalid magic
        """
        cases = []
        for _ in range(10):
            bad_magic = bytes(random.randint(0, 255) for _ in range(4))
            data = b"FUZZ"
            pkt = self.build_packet(bad_magic, self.version, 3, len(data), data)
            cases.append({
                "category": "magic_bytes",
                "magic": bad_magic.hex(),
                "packet": pkt
            })
        return cases

    def fuzz_length_field(self):
        """
        Send mismatched length values
        Test extreme values
        """
        cases = []

        data = b"LENFUZZ"

        # Length too large
        pkt1 = self.build_packet(self.magic, self.version, 3, 5000, data)
        cases.append({"category": "length_field", "case": "mismatch_large", "packet": pkt1})

        # Length too small
        pkt2 = self.build_packet(self.magic, self.version, 3, 1, data)
        cases.append({"category": "length_field", "case": "mismatch_small", "packet": pkt2})

        # Maximum uint16 length
        pkt3 = self.build_packet(self.magic, self.version, 3, 65535, b"A" * 20)
        cases.append({"category": "length_field", "case": "max_uint16", "packet": pkt3})

        # Simulated negative wrap (-1 → 65535)
        pkt4 = self.build_packet(self.magic, self.version, 3, 0xFFFF, b"B" * 10)
        cases.append({"category": "length_field", "case": "negative_wrap", "packet": pkt4})

        return cases

    def fuzz_data_field(self):
        """
        Send random and malformed data patterns
        """
        cases = []

        # Random bytes
        rand_data = bytes(random.randint(0, 255) for _ in range(64))
        pkt1 = self.build_packet(self.magic, self.version, 3, len(rand_data), rand_data)
        cases.append({"category": "data_field", "case": "random_bytes", "packet": pkt1})

        # Special characters
        special = b"%%%%%s%s%s\x00\x00\n\r\t"
        pkt2 = self.build_packet(self.magic, self.version, 3, len(special), special)
        cases.append({"category": "data_field", "case": "special_chars", "packet": pkt2})

        # Long repetitive payload
        long_data = b"A" * 2000
        pkt3 = self.build_packet(self.magic, self.version, 3, len(long_data), long_data)
        cases.append({"category": "data_field", "case": "long_payload", "packet": pkt3})

        return cases

    def run_fuzzing_campaign(self, iterations=50):
        """
        Execute fuzzing tests
        Track crash cases
        Generate fuzzing report
        """
        all_cases = []
        all_cases.extend(self.fuzz_magic_bytes())
        all_cases.extend(self.fuzz_length_field())
        all_cases.extend(self.fuzz_data_field())

        results = []
        count = 0

        for case in all_cases:
            if count >= iterations:
                break
            count += 1

            ok, result_case = self.monitor_server_response(case)
            result_case["success"] = ok
            results.append(result_case)

            if not ok:
                self.crash_cases.append(result_case)

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target": f"{self.target_host}:{self.target_port}",
            "iterations": count,
            "crash_cases_count": len(self.crash_cases),
            "crash_cases": self.crash_cases,
            "all_results": results
        }

        with open("fuzzing_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print("[+] Saved fuzzing_report.json")
        print(f"Crash/anomaly cases recorded: {len(self.crash_cases)}")


# WARNING: Only fuzz authorized test systems
if __name__ == "__main__":
    print("[*] Fuzzing - authorized systems only (localhost test server).")
    print("[*] Start custom_server.py first before fuzzing.")

    fuzzer = ProtocolFuzzer()
    fuzzer.run_fuzzing_campaign(iterations=50)
