#!/usr/bin/env python3
# File: ~/osint-lab/osint_master.py

import os
import sys
import json
import subprocess
from datetime import datetime


class OSINTMaster:
    def __init__(self, target_domain, output_dir="results"):
        self.target = target_domain
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "target": target_domain,
            "timestamp": self.timestamp,
            "findings": {}
        }
        os.makedirs(output_dir, exist_ok=True)

    def _run_cmd(self, cmd_list, timeout=30):
        try:
            p = subprocess.run(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "Command timed out"

    def run_dns_enumeration(self):
        dns_data = {
            "A": [],
            "MX": [],
            "NS": [],
            "SOA": [],
        }

        rc, out, err = self._run_cmd(["dig", self.target, "A", "+short"])
        if rc == 0 and out:
            dns_data["A"] = [line.strip() for line in out.splitlines() if line.strip()]
        else:
            dns_data["A_error"] = err if err else "No A records found"

        rc, out, err = self._run_cmd(["dig", self.target, "MX", "+short"])
        if rc == 0 and out:
            dns_data["MX"] = [line.strip() for line in out.splitlines() if line.strip()]
        else:
            dns_data["MX_error"] = err if err else "No MX records found"

        rc, out, err = self._run_cmd(["dig", self.target, "NS", "+short"])
        if rc == 0 and out:
            dns_data["NS"] = [line.strip() for line in out.splitlines() if line.strip()]
        else:
            dns_data["NS_error"] = err if err else "No NS records found"

        rc, out, err = self._run_cmd(["dig", self.target, "SOA", "+short"])
        if rc == 0 and out:
            dns_data["SOA"] = [line.strip() for line in out.splitlines() if line.strip()]
        else:
            dns_data["SOA_error"] = err if err else "No SOA record found"

        self.results["findings"]["dns"] = dns_data
        return dns_data

    def discover_subdomains(self):
        common_prefixes = [
            "www", "mail", "ftp", "api", "admin",
            "test", "dev", "staging", "blog"
        ]

        discovered = []
        details = {}

        for pref in common_prefixes:
            sub = f"{pref}.{self.target}"
            rc, out, err = self._run_cmd(["dig", "+short", sub, "A"])
            if rc == 0 and out:
                ips = [line.strip() for line in out.splitlines() if line.strip()]
                discovered.append(sub)
                details[sub] = {"A": ips}
            else:
                details[sub] = {"A": [], "error": err if err else "No record"}

        self.results["findings"]["subdomains"] = {
            "discovered": discovered,
            "checked": details
        }
        return discovered

    def run_spiderfoot(self):
        spiderfoot_script = os.path.expanduser("~/osint-lab/spiderfoot_scanner.py")
        if not os.path.exists(spiderfoot_script):
            self.results["findings"]["spiderfoot_error"] = "spiderfoot_scanner.py not found"
            return None

        rc, out, err = self._run_cmd(["python3", spiderfoot_script, self.target], timeout=120)
        self.results["findings"]["spiderfoot"] = {
            "returncode": rc,
            "stdout": out,
            "stderr": err
        }
        return self.results["findings"]["spiderfoot"]

    def run_reconng(self):
        recon_script = os.path.expanduser("~/osint-lab/reconng_scanner.py")
        if not os.path.exists(recon_script):
            self.results["findings"]["reconng_error"] = "reconng_scanner.py not found"
            return None

        rc, out, err = self._run_cmd(["python3", recon_script, self.target], timeout=180)
        self.results["findings"]["reconng"] = {
            "returncode": rc,
            "stdout": out,
            "stderr": err
        }
        return self.results["findings"]["reconng"]

    def analyze_results(self):
        analysis = {
            "risk_score": 0,
            "risk_level": "LOW",
            "findings": [],
            "recommendations": []
        }

        risky_keywords = ["admin", "test", "dev", "staging"]
        discovered = []

        if "subdomains" in self.results["findings"]:
            discovered = self.results["findings"]["subdomains"].get("discovered", [])

        risky_found = []
        for sub in discovered:
            for kw in risky_keywords:
                if sub.startswith(f"{kw}.") or f".{kw}." in sub:
                    risky_found.append(sub)
                    break

        if risky_found:
            analysis["findings"].append(
                f"Risky subdomains discovered: {', '.join(sorted(set(risky_found)))}"
            )
            analysis["recommendations"].append(
                "Restrict access to admin/test/dev/staging endpoints (VPN/IP allowlist/auth)."
            )
            analysis["risk_score"] += 30

        sub_count = len(discovered)
        if sub_count >= 5:
            analysis["findings"].append(
                f"High subdomain exposure: {sub_count} subdomains discovered."
            )
            analysis["recommendations"].append(
                "Review DNS records and decommission unused subdomains."
            )
            analysis["risk_score"] += 20
        elif sub_count >= 2:
            analysis["findings"].append(
                f"Moderate subdomain exposure: {sub_count} subdomains discovered."
            )
            analysis["risk_score"] += 10

        dns_data = self.results["findings"].get("dns", {})
        mx = dns_data.get("MX", [])
        if mx:
            analysis["findings"].append(
                f"MX records present (email infrastructure exposed): {len(mx)} entries."
            )
            analysis["recommendations"].append(
                "Ensure email security controls (SPF/DKIM/DMARC) are configured."
            )
            analysis["risk_score"] += 10

        if analysis["risk_score"] > 100:
            analysis["risk_score"] = 100

        if analysis["risk_score"] >= 70:
            analysis["risk_level"] = "HIGH"
        elif analysis["risk_score"] >= 40:
            analysis["risk_level"] = "MEDIUM"
        else:
            analysis["risk_level"] = "LOW"

        return analysis

    def generate_report(self):
        report_file = os.path.join(
            self.output_dir,
            f"osint_report_{self.target}_{self.timestamp}.json"
        )

        summary_file = os.path.join(
            self.output_dir,
            f"osint_report_{self.target}_{self.timestamp}.txt"
        )

        self.results["analysis"] = self.analyze_results()

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)

        analysis = self.results["analysis"]
        lines = []
        lines.append("OSINT Reconnaissance Report")
        lines.append("==========================")
        lines.append(f"Target: {self.results['target']}")
        lines.append(f"Timestamp: {self.results['timestamp']}")
        lines.append("")
        lines.append(f"Risk Score: {analysis['risk_score']}")
        lines.append(f"Risk Level: {analysis['risk_level']}")
        lines.append("")
        lines.append("Key Findings:")
        if analysis["findings"]:
            for fnd in analysis["findings"]:
                lines.append(f"- {fnd}")
        else:
            lines.append("- No major risks identified from collected OSINT.")

        lines.append("")
        lines.append("Recommendations:")
        if analysis["recommendations"]:
            for rec in analysis["recommendations"]:
                lines.append(f"- {rec}")
        else:
            lines.append("- Continue periodic OSINT monitoring and hardening.")

        lines.append("")
        lines.append("DNS Records:")
        dns = self.results["findings"].get("dns", {})
        for k in ["A", "MX", "NS", "SOA"]:
            vals = dns.get(k, [])
            if vals:
                lines.append(f"- {k}:")
                for v in vals:
                    lines.append(f"  - {v}")

        lines.append("")
        lines.append("Subdomains Discovered:")
        subs = self.results["findings"].get("subdomains", {}).get("discovered", [])
        if subs:
            for s in subs:
                lines.append(f"- {s}")
        else:
            lines.append("- None discovered from basic prefix checks.")

        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        print(f"[+] JSON report written to: {report_file}")
        print(f"[+] Text summary written to: {summary_file}")

    def run_full_scan(self):
        print(f"[+] Starting OSINT reconnaissance for {self.target}")

        self.run_dns_enumeration()
        self.discover_subdomains()
        self.run_spiderfoot()
        self.run_reconng()

        self.generate_report()

        print(f"[+] Reconnaissance complete. Results in {self.output_dir}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 osint_master.py <target_domain>")
        sys.exit(1)

    target = sys.argv[1]
    osint = OSINTMaster(target)
    osint.run_full_scan()


if __name__ == "__main__":
    main()
