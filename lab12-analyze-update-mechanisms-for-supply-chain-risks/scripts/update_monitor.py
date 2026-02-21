#!/usr/bin/env python3
"""
Update Network Traffic Monitor
"""

import subprocess
import json
import time
import threading
from datetime import datetime
import re


class UpdateNetworkMonitor:
    def __init__(self):
        self.connections = []
        self.monitoring = False
        self.suspicious_activity = []

    def start_monitoring(self):
        """Start network traffic monitoring"""
        self.monitoring = True
        t = threading.Thread(target=self.monitor_connections, daemon=True)
        t.start()

    def monitor_connections(self):
        """Monitor active network connections"""

        while self.monitoring:
            try:
                result = subprocess.run(
                    ["netstat", "-tunp"],
                    capture_output=True,
                    text=True
                )

                output = result.stdout.splitlines()

                for line in output:
                    if "ESTABLISHED" in line:
                        conn = self.parse_netstat_line(line)
                        if conn:
                            conn["timestamp"] = datetime.now().isoformat()
                            self.connections.append(conn)

                            assessment = self.analyze_connection(conn)
                            if assessment.get("flagged"):
                                self.suspicious_activity.append(assessment)

            except Exception as e:
                self.connections.append({
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                })

            time.sleep(2)

    def parse_netstat_line(self, line):
        parts = line.split()
        if len(parts) < 7:
            return None

        proto = parts[0]
        local_addr = parts[3]
        remote_addr = parts[4]
        state = parts[5]
        pid_prog = parts[6]

        local_ip, local_port = self.split_host_port(local_addr)
        remote_ip, remote_port = self.split_host_port(remote_addr)

        return {
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "process": pid_prog
        }

    def split_host_port(self, addr):
        if addr.startswith("[") and "]" in addr:
            host = addr.split("]")[0].lstrip("[")
            port = addr.split("]:")[-1] if "]:" in addr else ""
            return host, port

        if ":" in addr:
            host, port = addr.rsplit(":", 1)
            return host, port

        return addr, ""

    def analyze_connection(self, connection):
        flagged = False
        issues = []

        if str(connection.get("remote_port")) == "80":
            flagged = True
            issues.append("Unencrypted HTTP connection detected (port 80)")

        remote_ip = connection.get("remote_ip", "")
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", remote_ip):
            issues.append("Remote destination is an IP address (not a domain)")

        suspicious_ports = {"1337", "4444", "5555", "6666", "31337"}
        if str(connection.get("remote_port")) in suspicious_ports:
            flagged = True
            issues.append(f"Suspicious remote port detected: {connection.get('remote_port')}")

        severity = "LOW"
        if any("Unencrypted HTTP" in i for i in issues) or any("Suspicious remote port" in i for i in issues):
            severity = "HIGH"
        elif any("IP address" in i for i in issues):
            severity = "MEDIUM"

        return {
            "timestamp": datetime.now().isoformat(),
            "connection": connection,
            "issues": issues,
            "severity": severity,
            "flagged": flagged
        }

    def simulate_update(self):
        print("Starting network monitoring...")
        self.start_monitoring()

        print("Simulating update check (apt list --upgradable)...")
        try:
            subprocess.run(
                ["bash", "-lc", "apt list --upgradable 2>/dev/null | head -n 25"],
                check=False
            )
        except Exception as e:
            print(f"Error running apt list --upgradable: {e}")

        print("Capturing traffic for 10 seconds...")
        time.sleep(10)

        self.monitoring = False
        print("Monitoring stopped.")

        print("Analyzing captured connections...")

    def generate_traffic_report(self):
        unique_destinations = set()
        for c in self.connections:
            if isinstance(c, dict) and "remote_ip" in c and "remote_port" in c:
                unique_destinations.add(f"{c['remote_ip']}:{c['remote_port']}")

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_connections_captured": len(self.connections),
            "unique_destinations": sorted(list(unique_destinations)),
            "suspicious_activity_count": len(self.suspicious_activity),
            "suspicious_activity": self.suspicious_activity,
            "connections": self.connections[:500]
        }

        with open("update_traffic_report.json", "w") as f:
            json.dump(report, f, indent=4)

        print("\n=== Network Traffic Report ===")
        print(f"Total connections captured: {report['total_connections_captured']}")
        print(f"Unique destinations: {len(report['unique_destinations'])}")
        print(f"Suspicious activity found: {report['suspicious_activity_count']}")
        print("Report saved to update_traffic_report.json")


def main():
    monitor = UpdateNetworkMonitor()
    monitor.simulate_update()
    monitor.generate_traffic_report()


if __name__ == "__main__":
    main()
