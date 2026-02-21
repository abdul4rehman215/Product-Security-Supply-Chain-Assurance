#!/usr/bin/env python3
"""
Comprehensive Supply Chain Security Auditor
Integrates package security, network monitoring, and TLS evaluation into one report.
"""

import json
import subprocess
import time
import os
from datetime import datetime, timezone

# ----------------------------
# Embedded Package Analyzer
# ----------------------------
import re
from urllib.parse import urlparse


class PackageSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.security_score = 100

    def analyze_apt_sources(self):
        print("=== Analyzing APT Sources ===")

        sources_files = ['/etc/apt/sources.list']
        sources_dir = '/etc/apt/sources.list.d/'

        if os.path.isdir(sources_dir):
            for file in os.listdir(sources_dir):
                if file.endswith(".list"):
                    sources_files.append(os.path.join(sources_dir, file))

        for filepath in sources_files:
            if not os.path.exists(filepath):
                continue

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("deb"):
                            issue = self.check_source_line(filepath, line_num, line)
                            if issue:
                                self.vulnerabilities.append(issue)
            except PermissionError:
                self.vulnerabilities.append({
                    "file": filepath,
                    "line": None,
                    "issue": "Permission denied reading APT source file (run with sudo if needed)",
                    "severity": "MEDIUM",
                    "source": None
                })

    def check_source_line(self, filepath, line_num, line):
        parts = line.split()
        if len(parts) < 2:
            return None

        url = parts[1]
        parsed = urlparse(url)
        issues = []

        if parsed.scheme == "http":
            issues.append(("HIGH", "Source uses HTTP instead of HTTPS"))

        hostname = parsed.hostname or ""
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            issues.append(("MEDIUM", "Source uses IP address instead of domain"))

        if hostname.endswith((".tk", ".ml", ".ga")):
            issues.append(("MEDIUM", "Suspicious TLD used in repository URL"))

        if issues:
            severity, description = issues[0]
            return {
                "file": filepath,
                "line": line_num,
                "issue": description,
                "severity": severity,
                "source": line
            }

        return None

    def analyze_pip_config(self):
        print("\n=== Analyzing Pip Configuration ===")

        config_paths = [
            os.path.expanduser('~/.pip/pip.conf'),
            '/etc/pip.conf'
        ]

        for path in config_paths:
            if not os.path.exists(path):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        raw = line.strip()
                        if not raw or raw.startswith("#"):
                            continue
                        if raw.startswith("index-url") and "http://" in raw:
                            self.vulnerabilities.append({
                                "file": path,
                                "line": None,
                                "issue": "pip index-url uses HTTP",
                                "severity": "HIGH",
                                "source": raw
                            })
                        if raw.startswith("trusted-host"):
                            self.vulnerabilities.append({
                                "file": path,
                                "line": None,
                                "issue": "pip trusted-host bypasses SSL verification",
                                "severity": "MEDIUM",
                                "source": raw
                            })
            except PermissionError:
                self.vulnerabilities.append({
                    "file": path,
                    "line": None,
                    "issue": "Permission denied reading pip config (run with sudo if needed)",
                    "severity": "LOW",
                    "source": None
                })

    def calculate_risk_score(self):
        self.security_score = 100
        for vuln in self.vulnerabilities:
            sev = vuln.get("severity", "LOW")
            if sev == "HIGH":
                self.security_score -= 20
            elif sev == "MEDIUM":
                self.security_score -= 10
            elif sev == "LOW":
                self.security_score -= 5

        self.security_score = max(self.security_score, 0)
        return self.security_score

    def remediation_recommendations(self, grouped):
        recs = []
        if grouped.get("HIGH"):
            recs.append("Replace all HTTP APT/pip sources with HTTPS to prevent MITM attacks.")
        if grouped.get("MEDIUM"):
            recs.append("Remove unnecessary third-party repositories and avoid IP-based sources.")
            recs.append("Avoid pip 'trusted-host' unless absolutely necessary; prefer proper CA validation.")
        if not (grouped.get("HIGH") or grouped.get("MEDIUM") or grouped.get("LOW")):
            recs.append("No obvious package manager misconfigurations detected.")
        return recs

    def generate_report(self):
        grouped = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for v in self.vulnerabilities:
            grouped.setdefault(v.get("severity", "LOW"), []).append(v)

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_issues": len(self.vulnerabilities),
            "security_score": self.security_score,
            "by_severity": grouped,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": self.remediation_recommendations(grouped)
        }

        with open("package_security_report.json", "w") as f:
            json.dump(report, f, indent=4)

        return report


# ----------------------------
# Embedded Network Monitor
# ----------------------------
import threading


class UpdateNetworkMonitor:
    def __init__(self):
        self.connections = []
        self.monitoring = False
        self.suspicious_activity = []

    def start_monitoring(self):
        self.monitoring = True
        t = threading.Thread(target=self.monitor_connections, daemon=True)
        t.start()

    def monitor_connections(self):
        while self.monitoring:
            try:
                # Prefer ss (available by default) but keep the lab intent
                data = self.get_connections_ss()
                for c in data:
                    self.connections.append(c)
                    assessment = self.analyze_connection(c)
                    if assessment.get("flagged"):
                        self.suspicious_activity.append(assessment)

            except Exception as e:
                self.connections.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": str(e)
                })

            time.sleep(2)

    def get_connections_ss(self):
        res = subprocess.run(["ss", "-tunp"], capture_output=True, text=True)
        lines = res.stdout.splitlines()
        conns = []

        for line in lines:
            if "ESTAB" not in line:
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            proto = parts[0]
            state = parts[1]
            local = parts[4]
            remote = parts[5]
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""

            local_ip, local_port = self.split_host_port(local)
            remote_ip, remote_port = self.split_host_port(remote)

            conns.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "proto": proto,
                "state": state,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process": proc
            })

        return conns

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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
            subprocess.run(["bash", "-lc", "apt list --upgradable 2>/dev/null | head -n 25"], check=False)
        except Exception as e:
            print(f"Error running apt list --upgradable: {e}")

        print("Capturing traffic for 10 seconds...")
        time.sleep(10)

        self.monitoring = False
        print("Monitoring stopped.")

    def generate_traffic_report(self):
        unique_destinations = set()
        for c in self.connections:
            if isinstance(c, dict) and "remote_ip" in c and "remote_port" in c:
                unique_destinations.add(f"{c['remote_ip']}:{c['remote_port']}")

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_connections_captured": len(self.connections),
            "unique_destinations": sorted(list(unique_destinations)),
            "suspicious_activity_count": len(self.suspicious_activity),
            "suspicious_activity": self.suspicious_activity,
            "connections": self.connections[:500]
        }

        with open("update_traffic_report.json", "w") as f:
            json.dump(report, f, indent=4)

        return report


# ----------------------------
# Embedded TLS Analyzer
# ----------------------------
import ssl
import socket


class TLSSecurityAnalyzer:
    def __init__(self):
        self.results = []
        self.update_servers = [
            'archive.ubuntu.com',
            'security.ubuntu.com',
            'pypi.org',
            'github.com'
        ]

    def analyze_server(self, hostname, port=443):
        result = {
            "hostname": hostname,
            "port": port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tls_version": None,
            "cipher": None,
            "certificate": {},
            "issues": [],
            "severity": "LOW",
            "status": "UNKNOWN"
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    result["tls_version"] = tls_version
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "secret_bits": cipher[2]
                    }

                    result["certificate"] = {
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "issuer": cert.get("issuer", []),
                        "subject": cert.get("subject", []),
                        "subjectAltName": cert.get("subjectAltName", [])
                    }

                    expiry = self.check_certificate_expiry(cert)
                    if expiry.get("issue"):
                        result["issues"].append(expiry["issue"])

                    tv = self.evaluate_tls_version(tls_version)
                    if tv.get("issue"):
                        result["issues"].append(tv["issue"])

                    cs = self.evaluate_cipher_suite(result["cipher"])
                    if cs.get("issue"):
                        result["issues"].append(cs["issue"])

                    severities = [x.get("severity") for x in [expiry, tv, cs] if x.get("severity")]
                    if "HIGH" in severities:
                        result["severity"] = "HIGH"
                    elif "MEDIUM" in severities:
                        result["severity"] = "MEDIUM"
                    else:
                        result["severity"] = "LOW"

                    result["status"] = "OK"

        except ssl.SSLError as e:
            result["status"] = "SSL_ERROR"
            result["severity"] = "HIGH"
            result["issues"].append(f"SSL error: {str(e)}")
        except socket.timeout:
            result["status"] = "TIMEOUT"
            result["severity"] = "MEDIUM"
            result["issues"].append("Connection timed out")
        except Exception as e:
            result["status"] = "ERROR"
            result["severity"] = "MEDIUM"
            result["issues"].append(f"General error: {str(e)}")

        return result

    def check_certificate_expiry(self, cert):
        not_after = cert.get("notAfter")
        if not not_after:
            return {"severity": "MEDIUM", "issue": "Certificate missing notAfter field"}

        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.utcnow()
            days_left = (expiry - now).days

            if days_left < 0:
                return {"severity": "HIGH", "issue": f"Certificate expired ({abs(days_left)} days ago)"}
            if days_left <= 30:
                return {"severity": "MEDIUM", "issue": f"Certificate expires soon ({days_left} days left)"}
            return {"severity": "LOW", "issue": None}
        except Exception:
            return {"severity": "MEDIUM", "issue": "Unable to parse certificate expiration date"}

    def evaluate_tls_version(self, version):
        if not version:
            return {"severity": "MEDIUM", "issue": "TLS version could not be determined"}

        insecure = {"TLSv1", "TLSv1.1"}
        if version in insecure:
            return {"severity": "HIGH", "issue": f"Insecure TLS version detected: {version}"}

        allowed = {"TLSv1.2", "TLSv1.3"}
        if version not in allowed:
            return {"severity": "MEDIUM", "issue": f"Unexpected/unknown TLS version: {version}"}

        return {"severity": "LOW", "issue": None}

    def evaluate_cipher_suite(self, cipher):
        if not cipher:
            return {"severity": "MEDIUM", "issue": "Cipher suite could not be determined"}

        name = cipher.get("name", "")
        secret_bits = cipher.get("secret_bits", 0)

        weak_patterns = ["RC4", "DES", "3DES", "NULL", "MD5"]
        if any(pat in name.upper() for pat in weak_patterns):
            return {"severity": "HIGH", "issue": f"Weak cipher detected: {name}"}

        if secret_bits < 128:
            return {"severity": "MEDIUM", "issue": f"Weak key length: {secret_bits} bits"}

        if not re.search(r"(ECDHE|DHE)", name.upper()):
            return {"severity": "MEDIUM", "issue": f"Cipher may not provide forward secrecy: {name}"}

        return {"severity": "LOW", "issue": None}

    def analyze_all_servers(self):
        for host in self.update_servers:
            self.results.append(self.analyze_server(host, 443))

    def generate_tls_report(self):
        high = [r for r in self.results if r.get("severity") == "HIGH"]
        medium = [r for r in self.results if r.get("severity") == "MEDIUM"]
        low = [r for r in self.results if r.get("severity") == "LOW"]

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "servers_analyzed": len(self.results),
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "all_results": self.results
        }

        with open("tls_security_report.json", "w") as f:
            json.dump(report, f, indent=4)

        return report


# ----------------------------
# Integrated Auditor
# ----------------------------
class SupplyChainAuditor:
    def __init__(self):
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'package_security': {},
            'network_security': {},
            'tls_security': {},
            'overall_score': 0,
            'risk_level': 'UNKNOWN'
        }

    def run_full_audit(self):
        pkg = PackageSecurityAnalyzer()
        pkg.analyze_apt_sources()
        pkg.analyze_pip_config()
        pkg_score = pkg.calculate_risk_score()
        pkg_report = pkg.generate_report()

        self.audit_results["package_security"] = {
            "score": pkg_score,
            "report_file": "package_security_report.json",
            "summary": {
                "total_issues": pkg_report.get("total_issues"),
                "high": len(pkg_report.get("by_severity", {}).get("HIGH", [])),
                "medium": len(pkg_report.get("by_severity", {}).get("MEDIUM", [])),
                "low": len(pkg_report.get("by_severity", {}).get("LOW", []))
            }
        }

        net = UpdateNetworkMonitor()
        net.simulate_update()
        net_report = net.generate_traffic_report()
        net_score = self.estimate_network_score(net_report)

        self.audit_results["network_security"] = {
            "score": net_score,
            "report_file": "update_traffic_report.json",
            "summary": {
                "total_connections_captured": net_report.get("total_connections_captured"),
                "unique_destinations": len(net_report.get("unique_destinations", [])),
                "suspicious_activity_count": net_report.get("suspicious_activity_count")
            }
        }

        tls = TLSSecurityAnalyzer()
        tls.analyze_all_servers()
        tls_report = tls.generate_tls_report()
        tls_score = self.estimate_tls_score(tls_report)

        self.audit_results["tls_security"] = {
            "score": tls_score,
            "report_file": "tls_security_report.json",
            "summary": {
                "servers_analyzed": tls_report.get("servers_analyzed"),
                "high_issues": len(tls_report.get("high_severity", [])),
                "medium_issues": len(tls_report.get("medium_severity", []))
            }
        }

    def estimate_network_score(self, net_report):
        score = 100
        suspicious_count = net_report.get("suspicious_activity_count", 0)
        score -= min(60, suspicious_count * 10)

        for item in net_report.get("suspicious_activity", []):
            if item.get("severity") == "HIGH":
                score -= 10

        return max(score, 0)

    def estimate_tls_score(self, tls_report):
        score = 100
        score -= len(tls_report.get("high_severity", [])) * 20
        score -= len(tls_report.get("medium_severity", [])) * 10
        return max(score, 0)

    def calculate_overall_score(self):
        pkg = self.audit_results.get("package_security", {}).get("score", 0)
        net = self.audit_results.get("network_security", {}).get("score", 0)
        tls = self.audit_results.get("tls_security", {}).get("score", 0)

        weighted = (pkg * 0.40) + (net * 0.30) + (tls * 0.30)
        self.audit_results["overall_score"] = round(weighted, 2)

        self.audit_results["risk_level"] = self.determine_risk_level(self.audit_results["overall_score"])

    def determine_risk_level(self, score):
        if score >= 90:
            return "LOW"
        if score >= 70:
            return "MEDIUM"
        if score >= 50:
            return "HIGH"
        return "CRITICAL"

    def generate_recommendations(self):
        recs = []

        pkg = self.audit_results.get("package_security", {}).get("summary", {})
        if pkg.get("high", 0) > 0:
            recs.append("Replace any HTTP APT/pip sources with HTTPS and remove insecure repositories.")
        if pkg.get("medium", 0) > 0:
            recs.append("Audit third-party repos, avoid IP-based sources, and reduce pip trusted-host usage.")

        net = self.audit_results.get("network_security", {}).get("summary", {})
        if net.get("suspicious_activity_count", 0) > 0:
            recs.append("Investigate flagged network connections and enforce HTTPS-only update endpoints where possible.")

        tls = self.audit_results.get("tls_security", {}).get("summary", {})
        if tls.get("high_issues", 0) > 0:
            recs.append("Fix TLS issues immediately: disable weak TLS versions/ciphers and address certificate problems.")
        if tls.get("medium_issues", 0) > 0:
            recs.append("Improve TLS posture: ensure forward secrecy, strong ciphers, and monitor certificate expiry.")

        if not recs:
            recs.append("No major issues detected. Continue regular audits and monitoring.")

        self.audit_results["recommendations"] = recs

    def export_audit_report(self):
        with open("supply_chain_audit_report.json", "w") as f:
            json.dump(self.audit_results, f, indent=4)

        lines = []
        lines.append("Comprehensive Supply Chain Security Audit Report")
        lines.append("=" * 55)
        lines.append(f"Timestamp: {self.audit_results.get('timestamp')}")
        lines.append(f"Overall Score: {self.audit_results.get('overall_score')}")
        lines.append(f"Risk Level: {self.audit_results.get('risk_level')}")
        lines.append("")
        lines.append("Category Scores")
        lines.append("-" * 55)
        lines.append(f"Package Security Score: {self.audit_results.get('package_security', {}).get('score')}")
        lines.append(f"Network Security Score: {self.audit_results.get('network_security', {}).get('score')}")
        lines.append(f"TLS Security Score: {self.audit_results.get('tls_security', {}).get('score')}")
        lines.append("")
        lines.append("Recommendations")
        lines.append("-" * 55)
        for r in self.audit_results.get("recommendations", []):
            lines.append(f"- {r}")
        lines.append("")
        lines.append("Report Files Generated")
        lines.append("-" * 55)
        lines.append("- package_security_report.json")
        lines.append("- update_traffic_report.json")
        lines.append("- tls_security_report.json")
        lines.append("- supply_chain_audit_report.json")
        lines.append("")

        with open("supply_chain_audit_report.txt", "w") as f:
            f.write("\n".join(lines))

    def run(self):
        self.run_full_audit()
        self.calculate_overall_score()
        self.generate_recommendations()
        self.export_audit_report()


def main():
    auditor = SupplyChainAuditor()
    auditor.run()
    print("\nAudit complete! Review the generated reports.")


if __name__ == "__main__":
    main()
