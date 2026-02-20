#!/usr/bin/env python3

import requests
import json
import sys
import time

class SpiderFootScanner:
    def __init__(self, base_url="http://127.0.0.1:5001"):
        self.base_url = base_url
        self.session = requests.Session()

    def start_scan(self, target, scan_name="OSINT_Scan"):
        modules = [
            "sfp_dnsresolve",
            "sfp_sslcert",
            "sfp_webframework",
            "sfp_subdomain_enum"
        ]

        scan_data = {
            "scanname": scan_name,
            "scantarget": target,
            "modulelist": ",".join(modules),
            "typelist": "DOMAIN_NAME"
        }

        response = self.session.post(
            f"{self.base_url}/startscan",
            data=scan_data
        )

        if response.status_code == 200:
            print("[+] Scan started successfully")
            return True
        else:
            print("[-] Failed to start scan")
            return False

    def get_scan_results(self):
        response = self.session.get(f"{self.base_url}/scans")
        if response.status_code == 200:
            return response.text
        return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 spiderfoot_scanner.py <target_domain>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = SpiderFootScanner()

    print(f"Starting scan for: {target}")
    if scanner.start_scan(target):
        print("[+] Waiting for scan to initialize...")
        time.sleep(10)
        results = scanner.get_scan_results()
        if results:
            print(results)


if __name__ == "__main__":
    main()
