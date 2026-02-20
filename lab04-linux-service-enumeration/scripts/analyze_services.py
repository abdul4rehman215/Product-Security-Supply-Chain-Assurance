#!/usr/bin/env python3

# ==========================================================
# Lab 4 - Service Analysis & Categorization Script
# ==========================================================
# Reads enumeration JSON reports
# Identifies common services
# Provides basic security recommendations
# ==========================================================

import json
import glob


def analyze_common_services():
    """Analyze and categorize discovered services"""

    common_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }

    # Locate enumeration JSON reports
    json_files = glob.glob("*/enumeration_report_*.json")

    if not json_files:
        print("No enumeration report JSON files found.")
        return

    for json_file in json_files:

        print("==================================================")
        print(f"Analyzing: {json_file}")
        print("==================================================")

        with open(json_file, 'r') as f:
            data = json.load(f)

        print("Identified Services:")
        print("--------------------")

        for port_info in data.get('open_ports', []):
            port = int(port_info['port'])
            detected_service = port_info.get('service', 'unknown')
            service_name = common_services.get(port, "Unknown")

            print(f"Port {port}: {service_name} ({detected_service})")

            # Security Recommendations
            if port == 23:
                print("  WARNING: Telnet is insecure. Use SSH instead.")
            elif port == 21:
                print("  WARNING: FTP is insecure. Use SFTP or FTPS.")
            elif port == 80:
                print("  INFO: HTTP detected. Ensure HTTPS is also enabled.")
            elif port == 22:
                print("  INFO: Ensure SSH uses key-based authentication and strong ciphers.")

        print()


if __name__ == "__main__":
    analyze_common_services()
