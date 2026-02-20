#!/usr/bin/env python3

# ==========================================================
# Lab 4 - Automated Service Enumeration Script
# ==========================================================
# Combines:
#   - Nmap scanning (TCP, service detection, scripts)
#   - Netstat analysis
#   - Structured parsing
#   - JSON and TXT reporting
# ==========================================================

import nmap
import subprocess
import json
import datetime
import os
import sys


class ServiceEnumerator:

    def __init__(self, target="localhost"):
        self.target = target
        self.nm = nmap.PortScanner()
        self.results = {}
        self.output_dir = "enumeration_results"

        # Create output directory if not exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    # ----------------------------------------------------------
    # Nmap Scanning
    # ----------------------------------------------------------
    def nmap_scan(self):
        print(f"Starting nmap scan of {self.target}...")

        try:
            # Full TCP SYN scan
            print("[+] Performing TCP SYN scan...")
            tcp_scan = self.nm.scan(self.target, '1-65535', '-sS')

            # Service version detection
            print("[+] Performing service version detection...")
            service_scan = self.nm.scan(self.target, arguments='-sV')

            # Default script scan
            print("[+] Performing script scan...")
            script_scan = self.nm.scan(self.target, arguments='-sC')

            self.results['nmap'] = {
                'tcp_scan': tcp_scan,
                'service_scan': service_scan,
                'script_scan': script_scan
            }

            return True

        except Exception as e:
            print(f"Error during nmap scan: {e}")
            return False

    # ----------------------------------------------------------
    # Netstat Analysis
    # ----------------------------------------------------------
    def netstat_analysis(self):
        print("[+] Performing netstat analysis...")

        try:
            listening_result = subprocess.run(
                ["netstat", "-ln"],
                capture_output=True,
                text=True
            )

            active_result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True
            )

            process_result = subprocess.run(
                ["netstat", "-lnp"],
                capture_output=True,
                text=True
            )

            self.results['netstat'] = {
                'listening_ports': listening_result.stdout,
                'active_connections': active_result.stdout,
                'process_info': process_result.stdout
            }

            return True

        except Exception as e:
            print(f"Error during netstat analysis: {e}")
            return False

    # ----------------------------------------------------------
    # Parse Results
    # ----------------------------------------------------------
    def parse_results(self):

        print("[+] Parsing results...")

        parsed_results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'target': self.target,
            'open_ports': [],
            'listening_ports': [],
            'active_connections': 0
        }

        # Parse nmap results
        try:
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():

                        state = self.nm[host][proto][port]['state']

                        if state == 'open':
                            service_info = {
                                'port': port,
                                'protocol': proto,
                                'service': self.nm[host][proto][port].get('name', 'unknown'),
                                'version': self.nm[host][proto][port].get('version', 'unknown')
                            }

                            parsed_results['open_ports'].append(service_info)

        except Exception:
            pass

        # Parse netstat results
        if 'netstat' in self.results:

            listening_lines = self.results['netstat']['listening_ports'].split('\n')

            for line in listening_lines:
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        parsed_results['listening_ports'].append(parts[3])

            active_lines = self.results['netstat']['active_connections'].split('\n')
            active_count = sum(1 for line in active_lines if "ESTABLISHED" in line)
            parsed_results['active_connections'] = active_count

        return parsed_results

    # ----------------------------------------------------------
    # Report Generation
    # ----------------------------------------------------------
    def generate_report(self, parsed_results):

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        json_file = f"{self.output_dir}/enumeration_report_{timestamp}.json"
        txt_file = f"{self.output_dir}/enumeration_report_{timestamp}.txt"

        # Save JSON
        with open(json_file, 'w') as jf:
            json.dump(parsed_results, jf, indent=2)

        # Save Text
        with open(txt_file, 'w') as tf:

            tf.write("SERVICE ENUMERATION REPORT\n")
            tf.write("=" * 60 + "\n")
            tf.write(f"Target: {parsed_results['target']}\n")
            tf.write(f"Timestamp: {parsed_results['timestamp']}\n\n")

            tf.write("Open Ports:\n")
            tf.write("-" * 30 + "\n")

            for port_info in parsed_results['open_ports']:
                tf.write(
                    f"Port {port_info['port']}/{port_info['protocol']} - "
                    f"{port_info['service']} ({port_info['version']})\n"
                )

            tf.write("\nListening Ports (netstat):\n")
            tf.write("-" * 30 + "\n")

            for port in parsed_results['listening_ports']:
                tf.write(f"{port}\n")

            tf.write("\nActive Connections:\n")
            tf.write("-" * 30 + "\n")
            tf.write(str(parsed_results['active_connections']) + "\n")

        print("Reports generated:")
        print(f"  JSON: {json_file}")
        print(f"  TEXT: {txt_file}")

    # ----------------------------------------------------------
    # Main Workflow
    # ----------------------------------------------------------
    def run_enumeration(self):

        print("==================================================")
        print("Starting Automated Service Enumeration")
        print("==================================================")

        if not self.nmap_scan():
            print("nmap scan failed.")
            return False

        if not self.netstat_analysis():
            print("netstat analysis failed.")
            return False

        parsed_results = self.parse_results()
        self.generate_report(parsed_results)

        print("\nEnumeration completed successfully.")
        print(f"Open Ports Found: {len(parsed_results['open_ports'])}")
        print(f"Listening Ports Found: {len(parsed_results['listening_ports'])}")
        print(f"Active Connections: {parsed_results['active_connections']}")

        return True


# ----------------------------------------------------------
# Entry Point
# ----------------------------------------------------------
def main():
    enumerator = ServiceEnumerator()
    success = enumerator.run_enumeration()

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
