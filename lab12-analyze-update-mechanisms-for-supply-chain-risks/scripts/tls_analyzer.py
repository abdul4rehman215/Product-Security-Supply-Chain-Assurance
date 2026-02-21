#!/usr/bin/env python3
"""
TLS Security Analyzer for Update Servers
"""

import ssl
import socket
import json
from datetime import datetime, timezone
import re


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
                        "subject": cert.get("subject", []),
                        "issuer": cert.get("issuer", []),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "subjectAltName": cert.get("subjectAltName", [])
                    }

                    expiry_status = self.check_certificate_expiry(cert)
                    if expiry_status.get("issue"):
                        result["issues"].append(expiry_status["issue"])

                    tls_eval = self.evaluate_tls_version(tls_version)
                    if tls_eval.get("issue"):
                        result["issues"].append(tls_eval["issue"])

                    cipher_eval = self.evaluate_cipher_suite(result["cipher"])
                    if cipher_eval.get("issue"):
                        result["issues"].append(cipher_eval["issue"])

                    severities = [
                        i.get("severity")
                        for i in [expiry_status, tls_eval, cipher_eval]
                        if i.get("severity")
                    ]

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
        print("=== TLS Analysis ===")
        for host in self.update_servers:
            print(f"Analyzing: {host}")
            res = self.analyze_server(host, 443)
            self.results.append(res)

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

        print("\n=== TLS Security Report ===")
        print(f"Servers analyzed: {report['servers_analyzed']}")
        print(f"HIGH severity issues: {len(high)}")
        print(f"MEDIUM severity issues: {len(medium)}")
        print(f"LOW severity issues: {len(low)}")
        print("Report saved to tls_security_report.json")


def main():
    analyzer = TLSSecurityAnalyzer()
    analyzer.analyze_all_servers()
    analyzer.generate_tls_report()


if __name__ == "__main__":
    main()
