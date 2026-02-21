#!/usr/bin/env python3
"""
Package Manager Security Analyzer
"""

import os
import re
import json
from urllib.parse import urlparse


class PackageSecurityAnalyzer:
    def __init__(self):
        self.vulnerabilities = []
        self.security_score = 100

    def analyze_apt_sources(self):
        """Analyze APT sources for security issues"""
        print("=== Analyzing APT Sources ===")

        sources_files = ['/etc/apt/sources.list']
        sources_dir = '/etc/apt/sources.list.d/'

        # Find all .list files
        if os.path.isdir(sources_dir):
            for file in os.listdir(sources_dir):
                if file.endswith(".list"):
                    sources_files.append(os.path.join(sources_dir, file))

        # Iterate through each source file
        for filepath in sources_files:
            if not os.path.exists(filepath):
                continue

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line.startswith("deb"):
                        issue = self.check_source_line(filepath, line_num, line)
                        if issue:
                            self.vulnerabilities.append(issue)

    def check_source_line(self, filepath, line_num, line):
        """Check individual source line for security issues"""

        parts = line.split()
        if len(parts) < 2:
            return None

        url = parts[1]
        parsed = urlparse(url)
        issues = []

        # Detect HTTP sources
        if parsed.scheme == "http":
            issues.append(("HIGH", "Source uses HTTP instead of HTTPS"))

        # Detect IP address usage
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.hostname or ""):
            issues.append(("MEDIUM", "Source uses IP address instead of domain"))

        # Suspicious TLDs
        if parsed.hostname and parsed.hostname.endswith((".tk", ".ml", ".ga")):
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
        """Analyze pip configuration for security risks"""
        print("\n=== Analyzing Pip Configuration ===")

        config_paths = [
            os.path.expanduser('~/.pip/pip.conf'),
            '/etc/pip.conf'
        ]

        for path in config_paths:
            if not os.path.exists(path):
                continue

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("index-url"):
                        if "http://" in line:
                            self.vulnerabilities.append({
                                "file": path,
                                "issue": "pip index-url uses HTTP",
                                "severity": "HIGH"
                            })
                    if line.startswith("trusted-host"):
                        self.vulnerabilities.append({
                            "file": path,
                            "issue": "pip trusted-host bypasses SSL verification",
                            "severity": "MEDIUM"
                        })

    def calculate_risk_score(self):
        """Calculate overall security risk score"""
        for vuln in self.vulnerabilities:
            if vuln["severity"] == "HIGH":
                self.security_score -= 20
            elif vuln["severity"] == "MEDIUM":
                self.security_score -= 10
            elif vuln["severity"] == "LOW":
                self.security_score -= 5

        self.security_score = max(self.security_score, 0)
        return self.security_score

    def generate_report(self):
        """Generate security assessment report"""

        print("\n=== Security Report ===")
        print(f"Total Issues Found: {len(self.vulnerabilities)}")
        print(f"Security Score: {self.security_score}/100")

        report = {
            "total_issues": len(self.vulnerabilities),
            "security_score": self.security_score,
            "vulnerabilities": self.vulnerabilities
        }

        with open("package_security_report.json", "w") as f:
            json.dump(report, f, indent=4)

        print("Report saved to package_security_report.json")


def main():
    analyzer = PackageSecurityAnalyzer()
    analyzer.analyze_apt_sources()
    analyzer.analyze_pip_config()
    analyzer.calculate_risk_score()
    analyzer.generate_report()


if __name__ == "__main__":
    main()
