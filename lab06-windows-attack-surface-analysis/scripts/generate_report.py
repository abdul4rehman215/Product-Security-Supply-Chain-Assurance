#!/usr/bin/env python3
import json
from datetime import datetime
from pathlib import Path

class ReportGenerator:
    def __init__(self):
        self.report_data = {}

    def load_analysis_results(self):
        """
        Load results from previous analysis files.

        - Read attack_surface_report.json
        - Parse and store data
        """
        with open("attack_surface_report.json", "r", encoding="utf-8") as f:
            attack_surface = json.load(f)

        vulnerability_report = {}
        if Path("vulnerability_report.json").is_file():
            with open("vulnerability_report.json", "r", encoding="utf-8") as f:
                vulnerability_report = json.load(f)

        self.report_data = {
            "generated_at": datetime.now().isoformat(),
            "attack_surface": attack_surface,
            "vulnerability_scan": vulnerability_report
        }

    def create_executive_summary(self):
        """
        Create executive summary section.

        - Summarize key findings
        - Highlight critical vulnerabilities
        - Provide risk level assessment
        """
        attack = self.report_data.get("attack_surface", {})
        vulns = self.report_data.get("vulnerability_scan", {}).get("vulnerabilities", [])

        risk_total = attack.get("risk_score", {}).get("total", 0)
        listeners = attack.get("network_exposure", {}).get("total_listeners", 0)

        high_vulns = [v for v in vulns if v.get("severity", "").upper() == "HIGH"]
        med_vulns = [v for v in vulns if v.get("severity", "").upper() == "MEDIUM"]

        if risk_total >= 70:
            level = "HIGH"
        elif risk_total >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        summary = {
            "risk_score": risk_total,
            "risk_level": level,
            "open_listeners": listeners,
            "high_vuln_count": len(high_vulns),
            "medium_vuln_count": len(med_vulns),
            "key_findings": []
        }

        if listeners > 0:
            summary["key_findings"].append(f"{listeners} listening network ports detected.")
        if len(high_vulns) > 0:
            summary["key_findings"].append(f"{len(high_vulns)} HIGH severity vulnerabilities identified.")
        if len(med_vulns) > 0:
            summary["key_findings"].append(f"{len(med_vulns)} MEDIUM severity vulnerabilities identified.")
        if not summary["key_findings"]:
            summary["key_findings"].append("No significant issues identified by automated checks.")

        self.report_data["executive_summary"] = summary

    def create_detailed_findings(self):
        """
        Create detailed findings section.

        - List all vulnerabilities with details
        - Include evidence and impact
        - Provide remediation steps
        """
        details = {
            "attack_surface_vulnerabilities": self.report_data.get("attack_surface", {}).get("vulnerabilities", []),
            "vulnerability_scanner_findings": self.report_data.get("vulnerability_scan", {}).get("vulnerabilities", []),
            "recommendations": self.report_data.get("vulnerability_scan", {}).get("recommendations", [])
        }
        self.report_data["detailed_findings"] = details

    def export_html_report(self, filename='security_report.html'):
        """
        Export report as HTML file.

        - Create HTML structure
        - Add CSS styling
        - Include tables
        - Write to file
        """
        summary = self.report_data.get("executive_summary", {})
        attack = self.report_data.get("attack_surface", {})
        vulnscan = self.report_data.get("vulnerability_scan", {})

        risk_level = summary.get("risk_level", "LOW")
        risk_score = summary.get("risk_score", 0)

        if risk_level == "HIGH":
            badge = "#dc2626"
        elif risk_level == "MEDIUM":
            badge = "#f59e0b"
        else:
            badge = "#16a34a"

        listeners = attack.get("network_exposure", {}).get("listening_ports", [])
        a_vulns = attack.get("vulnerabilities", [])
        v_vulns = vulnscan.get("vulnerabilities", [])
        recs = vulnscan.get("recommendations", [])

        def esc(s):
            return (str(s)
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#39;"))

        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>")
        html.append("<title>Security Assessment Report</title>")
        html.append("<style>")
        html.append("""
        body{font-family:Arial, sans-serif; background:#f5f7fb; margin:0; color:#111827;}
        header{background:#111827; color:#fff; padding:22px;}
        .container{max-width:1100px; margin:0 auto; padding:16px;}
        .card{background:#fff; border-radius:10px; padding:16px; margin:14px 0; box-shadow:0 2px 8px rgba(0,0,0,0.06);}
        h1,h2,h3{margin:0 0 10px 0;}
        table{width:100%; border-collapse:collapse; margin-top:10px;}
        th,td{padding:10px; border-bottom:1px solid #e5e7eb; text-align:left; vertical-align:top;}
        th{background:#f3f4f6;}
        .badge{display:inline-block; padding:6px 10px; border-radius:999px; color:#fff; font-weight:bold; font-size:12px;}
        .muted{color:#6b7280; font-size:13px;}
        .sevHIGH{color:#dc2626; font-weight:bold;}
        .sevMEDIUM{color:#f59e0b; font-weight:bold;}
        .sevLOW{color:#374151; font-weight:bold;}
        pre{white-space:pre-wrap; word-wrap:break-word;}
        """)
        html.append("</style></head><body>")

        html.append("<header><div class='container'>")
        html.append("<h1>Security Assessment Report</h1>")
        html.append(f"<p class='muted'>Generated: {esc(self.report_data.get('generated_at',''))}</p>")
        html.append(f"<p><span class='badge' style='background:{badge}'>Risk Level: {esc(risk_level)} | Score: {esc(risk_score)}/100</span></p>")
        html.append("</div></header>")

        html.append("<div class='container'>")

        html.append("<div class='card'><h2>Executive Summary</h2>")
        html.append("<ul>")
        for kf in summary.get("key_findings", []):
            html.append(f"<li>{esc(kf)}</li>")
        html.append("</ul></div>")

        html.append("<div class='card'><h2>Network Exposure</h2>")
        html.append(f"<p><b>Total listeners:</b> {esc(attack.get('network_exposure',{}).get('total_listeners',0))}</p>")
        html.append("<table><tr><th>IP</th><th>Port</th><th>Process</th><th>User</th><th>Hint</th></tr>")
        for l in listeners[:50]:
            html.append("<tr>")
            html.append(f"<td>{esc(l.get('ip'))}</td>")
            html.append(f"<td>{esc(l.get('port'))}</td>")
            html.append(f"<td>{esc(l.get('process'))}</td>")
            html.append(f"<td>{esc(l.get('user'))}</td>")
            html.append(f"<td>{esc(l.get('service_hint'))}</td>")
            html.append("</tr>")
        html.append("</table></div>")

        html.append("<div class='card'><h2>Vulnerabilities</h2>")
        html.append("<h3>Attack Surface Analyzer Findings</h3>")
        if not a_vulns:
            html.append("<p class='muted'>No vulnerabilities reported by analyzer heuristics.</p>")
        else:
            html.append("<table><tr><th>Severity</th><th>Type</th><th>Detail</th></tr>")
            for v in a_vulns[:100]:
                sev = esc(v.get("severity","LOW")).upper()
                html.append("<tr>")
                html.append(f"<td class='sev{sev}'>{sev}</td>")
                html.append(f"<td>{esc(v.get('type'))}</td>")
                html.append(f"<td>{esc(v.get('detail'))}</td>")
                html.append("</tr>")
            html.append("</table>")

        html.append("<h3>Vulnerability Scanner Findings</h3>")
        if not v_vulns:
            html.append("<p class='muted'>No vulnerabilities reported by scanner checks.</p>")
        else:
            html.append("<table><tr><th>Severity</th><th>Component</th><th>Name</th><th>Description</th><th>Evidence</th></tr>")
            for v in v_vulns[:100]:
                sev = esc(v.get("severity","LOW")).upper()
                html.append("<tr>")
                html.append(f"<td class='sev{sev}'>{sev}</td>")
                html.append(f"<td>{esc(v.get('component'))}</td>")
                html.append(f"<td>{esc(v.get('name'))}</td>")
                html.append(f"<td>{esc(v.get('description'))}</td>")
                html.append(f"<td><pre class='muted'>{esc(v.get('evidence',''))}</pre></td>")
                html.append("</tr>")
            html.append("</table>")

        html.append("</div>")

        html.append("<div class='card'><h2>Recommendations</h2>")
        if not recs:
            html.append("<p class='muted'>No recommendations available.</p>")
        else:
            html.append("<ul>")
            for r in recs:
                sev = esc(r.get("severity","LOW")).upper()
                txt = esc(r.get("recommendation",""))
                html.append(f"<li><span class='sev{sev}'>[{sev}]</span> {txt}</li>")
            html.append("</ul>")
        html.append("</div>")

        html.append("</div></body></html>")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(html))

        print(f"[+] HTML report exported: {filename}")

def main():
    rg = ReportGenerator()
    rg.load_analysis_results()
    rg.create_executive_summary()
    rg.create_detailed_findings()
    rg.export_html_report("security_report.html")

if __name__ == "__main__":
    main()
