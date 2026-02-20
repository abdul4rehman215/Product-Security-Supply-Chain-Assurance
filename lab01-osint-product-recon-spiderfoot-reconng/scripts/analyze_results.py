#!/usr/bin/env python3
# File: ~/osint-lab/analyze_results.py

import json
import sys
from collections import Counter


class ResultAnalyzer:
    def __init__(self, report_file):
        self.report_file = report_file
        self.data = {}

    def load_report(self):
        with open(self.report_file, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        return self.data

    def analyze_subdomains(self):
        findings = self.data.get("findings", {})
        sub_info = findings.get("subdomains", {})
        discovered = sub_info.get("discovered", [])

        risky_patterns = ["admin", "test", "dev", "staging"]
        risky = []
        labels = []

        for sub in discovered:
            first = sub.split(".")[0] if "." in sub else sub
            labels.append(first)

            for rp in risky_patterns:
                if sub.startswith(f"{rp}.") or f".{rp}." in sub:
                    risky.append(sub)
                    break

        counts = Counter(labels)

        return {
            "total_discovered": len(discovered),
            "risky_subdomains": sorted(set(risky)),
            "label_counts": dict(counts)
        }

    def calculate_risk_score(self):
        risk_score = 0
        risk_factors = []

        findings = self.data.get("findings", {})
        sub_info = findings.get("subdomains", {})
        discovered = sub_info.get("discovered", [])

        admin_like = [s for s in discovered if s.startswith("admin.") or ".admin." in s]
        if admin_like:
            risk_factors.append(
                f"Admin-like subdomains exposed: {', '.join(sorted(set(admin_like)))}"
            )
            risk_score += 30

        dev_like = [
            s for s in discovered
            if s.startswith(("dev.", "test.", "staging."))
            or ".dev." in s
            or ".test." in s
            or ".staging." in s
        ]
        if dev_like:
            risk_factors.append(
                f"Dev/Test/Staging subdomains exposed: {', '.join(sorted(set(dev_like)))}"
            )
            risk_score += 25

        if len(discovered) >= 5:
            risk_factors.append(f"High subdomain exposure: {len(discovered)} discovered")
            risk_score += 20
        elif len(discovered) >= 2:
            risk_factors.append(f"Moderate subdomain exposure: {len(discovered)} discovered")
            risk_score += 10

        dns = findings.get("dns", {})
        mx = dns.get("MX", [])
        if mx:
            risk_factors.append("MX records present (email infrastructure exposed)")
            risk_score += 10

        if risk_score > 100:
            risk_score = 100

        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return risk_score, risk_level, risk_factors

    def generate_summary(self):
        sub_analysis = self.analyze_subdomains()
        risk_score, risk_level, risk_factors = self.calculate_risk_score()

        summary_lines = []
        summary_lines.append("Executive Summary")
        summary_lines.append("=================")
        summary_lines.append(f"Target: {self.data.get('target', 'N/A')}")
        summary_lines.append(f"Timestamp: {self.data.get('timestamp', 'N/A')}")
        summary_lines.append("")
        summary_lines.append(f"Discovered Subdomains: {sub_analysis['total_discovered']}")
        summary_lines.append(f"Risk Score: {risk_score}")
        summary_lines.append(f"Risk Level: {risk_level}")
        summary_lines.append("")
        summary_lines.append("Risk Factors:")

        if risk_factors:
            for rf in risk_factors:
                summary_lines.append(f"- {rf}")
        else:
            summary_lines.append("- No major risk factors detected from the OSINT dataset.")

        summary_lines.append("")
        summary_lines.append("Top Recommendations:")
        recs = []
        if sub_analysis["risky_subdomains"]:
            recs.append(
                "Restrict access to risky subdomains (admin/dev/test/staging) and enforce authentication."
            )
        recs.append("Perform periodic OSINT monitoring and remove/decommission unused DNS records.")
        recs.append("Validate external exposure controls (WAF, rate limiting, security headers).")

        for r in recs:
            summary_lines.append(f"- {r}")

        return "\n".join(summary_lines)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_results.py <report_file.json>")
        sys.exit(1)

    analyzer = ResultAnalyzer(sys.argv[1])
    analyzer.load_report()
    summary = analyzer.generate_summary()
    print(summary)


if __name__ == "__main__":
    main()
