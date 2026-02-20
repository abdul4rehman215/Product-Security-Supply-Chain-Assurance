#!/usr/bin/env python3

# ==========================================================
# Lab 4 - Advanced Nmap Automation Script
# ==========================================================
# Performs:
#   - Basic port scan
#   - Detailed service enumeration
#   - Vulnerability scanning (NSE vuln scripts)
#   - Stealth scanning
# Saves output in JSON format
# ==========================================================

import nmap
import json
import datetime


class AdvancedNmapScanner:

    def __init__(self, target="localhost"):
        self.target = target
        self.nm = nmap.PortScanner()

    # ----------------------------------------------------------
    # Vulnerability Scan
    # ----------------------------------------------------------
    def vulnerability_scan(self):
        print("[+] Performing vulnerability scan...")
        try:
            result = self.nm.scan(self.target, arguments='--script vuln')
            return result
        except Exception as e:
            print(f"Vulnerability scan error: {e}")
            return None

    # ----------------------------------------------------------
    # Detailed Service Enumeration
    # ----------------------------------------------------------
    def service_enumeration_scan(self):
        print("[+] Performing detailed service enumeration...")
        try:
            result = self.nm.scan(
                self.target,
                arguments='-sV --script=banner,http-title,ssh-hostkey'
            )
            return result
        except Exception as e:
            print(f"Service enumeration error: {e}")
            return None

    # ----------------------------------------------------------
    # Stealth Scan
    # ----------------------------------------------------------
    def stealth_scan(self):
        print("[+] Performing stealth scan...")
        try:
            result = self.nm.scan(self.target, arguments='-sS -T2')
            return result
        except Exception as e:
            print(f"Stealth scan error: {e}")
            return None

    # ----------------------------------------------------------
    # Run All Scans
    # ----------------------------------------------------------
    def comprehensive_scan(self):

        results = {}

        print("==================================================")
        print("Running Advanced Nmap Scans")
        print("==================================================")

        # Basic scan (ports 1–1000)
        print("[+] Running basic scan...")
        results['basic'] = self.nm.scan(self.target, '1-1000')

        # Detailed service scan
        results['service_enumeration'] = self.service_enumeration_scan()

        # Vulnerability scan
        results['vulnerability'] = self.vulnerability_scan()

        # Stealth scan
        results['stealth'] = self.stealth_scan()

        return results


# ----------------------------------------------------------
# Execution Block
# ----------------------------------------------------------
if __name__ == "__main__":

    scanner = AdvancedNmapScanner()
    results = scanner.comprehensive_scan()

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"advanced_scan_{timestamp}.json"

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print("==================================================")
    print("Advanced scanning completed successfully!")
    print(f"Results saved to: {output_file}")
    print("==================================================")
