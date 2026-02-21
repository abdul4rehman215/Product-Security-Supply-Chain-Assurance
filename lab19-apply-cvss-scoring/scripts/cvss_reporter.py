#!/usr/bin/env python3
"""
CVSS Report Generator
Generates JSON, HTML, and CSV reports based on CVSS scoring results.
"""

import json
import csv
import argparse
from datetime import datetime
from typing import Dict, List

from cvss_calculator import CVSSCalculator


class CVSSReporter:
    """Generate comprehensive CVSS reports"""

    def __init__(self):
        self.calculator = CVSSCalculator()

    def generate_summary_statistics(self, results: List[Dict]) -> Dict:
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0,
            "Unknown": 0,
        }

        scores = []

        for r in results:
            sev = r.get("severity", "Unknown")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["Unknown"] += 1

            try:
                scores.append(float(r["scores"]["base_score"]))
            except Exception:
                pass

        avg_score = (sum(scores) / len(scores)) if scores else 0.0

        highest = None
        lowest = None

        if scores:
            sorted_by_score = sorted(results, key=lambda x: x["scores"]["base_score"], reverse=True)

            highest = {
                "id": sorted_by_score[0]["id"],
                "score": sorted_by_score[0]["scores"]["base_score"],
                "severity": sorted_by_score[0]["severity"],
            }

            lowest = {
                "id": sorted_by_score[-1]["id"],
                "score": sorted_by_score[-1]["scores"]["base_score"],
                "severity": sorted_by_score[-1]["severity"],
            }

        return {
            "total_vulnerabilities": len(results),
            "severity_counts": severity_counts,
            "average_score": round(avg_score, 2),
            "highest": highest,
            "lowest": lowest,
        }

    def generate_recommendations(self, severity_counts: Dict) -> List[str]:
        recs = []

        if severity_counts.get("Critical", 0) > 0:
            recs.append("Immediate action required: Remediate Critical vulnerabilities within 24-72 hours.")

        if severity_counts.get("High", 0) > 0:
            recs.append("High priority: Fix High vulnerabilities within 7 days.")

        if severity_counts.get("Medium", 0) > 0:
            recs.append("Plan remediation for Medium vulnerabilities within 30 days.")

        if severity_counts.get("Low", 0) > 0:
            recs.append("Address Low vulnerabilities during maintenance cycles.")

        recs.append("Ensure re-testing after remediation.")
        recs.append("Implement continuous vulnerability scanning.")
        recs.append("Maintain secure coding practices and regular code reviews.")
        recs.append("Keep dependencies updated and maintain asset inventory.")

        return recs

    def export_json_report(self, results: List[Dict], output_file: str):
        results_sorted = sorted(results, key=lambda x: x["scores"]["base_score"], reverse=True)

        summary = self.generate_summary_statistics(results_sorted)
        recommendations = self.generate_recommendations(summary["severity_counts"])

        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "cvss_version": "3.1",
                "tool": "CVSSReporter",
            },
            "summary": summary,
            "recommendations": recommendations,
            "vulnerabilities": results_sorted,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    def export_html_report(self, results: List[Dict], output_file: str):
        results_sorted = sorted(results, key=lambda x: x["scores"]["base_score"], reverse=True)
        summary = self.generate_summary_statistics(results_sorted)
        recommendations = self.generate_recommendations(summary["severity_counts"])

        css = """
        body { font-family: Arial; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; }
        th { background: #f2f2f2; }
        .Critical { color: red; font-weight: bold; }
        .High { color: darkorange; font-weight: bold; }
        .Medium { color: blue; }
        .Low { color: green; }
        """

        html = []
        html.append("<html><head>")
        html.append("<meta charset='utf-8'>")
        html.append("<title>CVSS Report</title>")
        html.append(f"<style>{css}</style>")
        html.append("</head><body>")

        html.append("<h1>CVSS Vulnerability Report (v3.1)</h1>")
        html.append(f"<p>Generated: {datetime.now().isoformat()}</p>")

        html.append("<h2>Summary</h2>")
        html.append(f"<p>Total Vulnerabilities: {summary['total_vulnerabilities']}</p>")
        html.append("<ul>")
        for sev, cnt in summary["severity_counts"].items():
            html.append(f"<li>{sev}: {cnt}</li>")
        html.append("</ul>")
        html.append(f"<p>Average Score: {summary['average_score']}</p>")

        if summary["highest"]:
            html.append(f"<p>Highest: {summary['highest']['id']} ({summary['highest']['score']})</p>")
        if summary["lowest"]:
            html.append(f"<p>Lowest: {summary['lowest']['id']} ({summary['lowest']['score']})</p>")

        html.append("<h2>Recommendations</h2>")
        html.append("<ul>")
        for r in recommendations:
            html.append(f"<li>{r}</li>")
        html.append("</ul>")

        html.append("<h2>Vulnerabilities</h2>")
        html.append("<table>")
        html.append("<tr><th>ID</th><th>Name</th><th>CVE</th><th>Score</th><th>Severity</th><th>Vector</th></tr>")

        for v in results_sorted:
            html.append(
                f"<tr class='{v['severity']}'>"
                f"<td>{v['id']}</td>"
                f"<td>{v['name']}</td>"
                f"<td>{v['cve']}</td>"
                f"<td>{v['scores']['base_score']}</td>"
                f"<td>{v['severity']}</td>"
                f"<td><code>{v['vector']}</code></td>"
                f"</tr>"
            )

        html.append("</table>")
        html.append("</body></html>")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(html))

    def export_csv_report(self, results: List[Dict], output_file: str):
        columns = [
            "id",
            "name",
            "cve",
            "base_score",
            "severity",
            "vector",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "scope",
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
        ]

        results_sorted = sorted(results, key=lambda x: x["scores"]["base_score"], reverse=True)

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()

            for r in results_sorted:
                metrics = r["metrics"]

                row = {
                    "id": r["id"],
                    "name": r["name"],
                    "cve": r["cve"],
                    "base_score": r["scores"]["base_score"],
                    "severity": r["severity"],
                    "vector": r["vector"],
                    "attack_vector": metrics["attack_vector"],
                    "attack_complexity": metrics["attack_complexity"],
                    "privileges_required": metrics["privileges_required"],
                    "user_interaction": metrics["user_interaction"],
                    "scope": metrics["scope"],
                    "confidentiality_impact": metrics["confidentiality_impact"],
                    "integrity_impact": metrics["integrity_impact"],
                    "availability_impact": metrics["availability_impact"],
                }

                writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Generate CVSS reports.")
    parser.add_argument("input_file", nargs="?", default="../vulnerabilities/sample_vulnerabilities.json")
    parser.add_argument("-o", "--output", default="../reports/report.json")
    parser.add_argument("-f", "--format", choices=["json", "html", "csv"], default="json")

    args = parser.parse_args()

    reporter = CVSSReporter()

    results = reporter.calculator.process_vulnerabilities_file(args.input_file)

    if args.format == "json":
        reporter.export_json_report(results, args.output)
    elif args.format == "html":
        reporter.export_html_report(results, args.output)
    elif args.format == "csv":
        reporter.export_csv_report(results, args.output)

    summary = reporter.generate_summary_statistics(results)

    print("CVSS Report Generated")
    print("=" * 50)
    print(f"Output file: {args.output}")
    print(f"Format: {args.format}")
    print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
    print("Severity counts:")
    for sev, cnt in summary["severity_counts"].items():
        print(f"  {sev}: {cnt}")
    print(f"Average score: {summary['average_score']}")


if __name__ == "__main__":
    main()
