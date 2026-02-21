#!/usr/bin/env python3
"""
Vulnerability Prioritization Tool
Processes CVSS report JSON and prioritizes vulnerabilities.
"""

import json
import sys
from typing import List, Dict
from pathlib import Path


def prioritize_vulnerabilities(results: List[Dict]) -> Dict:
    """
    Prioritize vulnerabilities based on CVSS score and severity.
    """

    # Sort by base score (descending)
    results_sorted = sorted(
        results,
        key=lambda x: x.get("scores", {}).get("base_score", 0.0),
        reverse=True
    )

    # Group by severity
    grouped = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "None": [],
        "Unknown": [],
    }

    for r in results_sorted:
        sev = r.get("severity", "Unknown")
        if sev in grouped:
            grouped[sev].append(r)
        else:
            grouped["Unknown"].append(r)

    # Remediation timeline mapping
    timeline = {
        "Critical": "Immediate (24-72 hours)",
        "High": "Short-term (within 7 days)",
        "Medium": "Planned (within 30 days)",
        "Low": "Maintenance cycle (60-90 days)",
        "None": "No action required (monitor)",
        "Unknown": "Review required",
    }

    return {
        "prioritized_list": results_sorted,
        "grouped_by_severity": grouped,
        "remediation_timeline": timeline,
    }


def calculate_risk_score(results: List[Dict]) -> float:
    """
    Calculate overall system risk (0–100 scale).
    """

    weights = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "None": 0,
        "Unknown": 1,
    }

    if not results:
        return 0.0

    weighted_sum = 0.0
    max_possible = 0.0

    for r in results:
        score = float(r.get("scores", {}).get("base_score", 0.0))
        sev = r.get("severity", "Unknown")
        weight = weights.get(sev, 1)

        weighted_sum += score * weight
        max_possible += 10.0 * weight

    if max_possible <= 0:
        return 0.0

    risk_percent = (weighted_sum / max_possible) * 100.0

    # Clamp between 0–100
    risk_percent = max(0.0, min(100.0, risk_percent))

    return round(risk_percent, 2)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 prioritize_vulns.py <report.json>")
        print("Example: python3 prioritize_vulns.py ../reports/report.json")
        sys.exit(1)

    report_file = sys.argv[1]
    path = Path(report_file)

    if not path.exists():
        print(f"Error: file not found: {report_file}")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Support two structures:
    # 1. Reporter output dict
    # 2. Raw list of vulnerability results
    if isinstance(data, dict) and "vulnerabilities" in data:
        results = data["vulnerabilities"]
    elif isinstance(data, list):
        results = data
    else:
        print("Unsupported JSON format.")
        sys.exit(1)

    prioritized = prioritize_vulnerabilities(results)
    overall_risk = calculate_risk_score(results)

    print("\nVulnerability Prioritization")
    print("=" * 60)
    print(f"Overall Risk Score (0-100): {overall_risk}")
    print()

    timeline = prioritized["remediation_timeline"]

    for severity in ["Critical", "High", "Medium", "Low", "None", "Unknown"]:
        vulns = prioritized["grouped_by_severity"].get(severity, [])
        if not vulns:
            continue

        print("-" * 60)
        print(f"{severity} ({len(vulns)}) - Remediation Timeline: {timeline.get(severity)}")
        print("-" * 60)

        for v in vulns:
            vid = v.get("id")
            name = v.get("name", "")
            score = v.get("scores", {}).get("base_score", 0.0)
            vector = v.get("vector", "")

            print(f"{vid} | Score: {score} | {name}")
            print(f"Vector: {vector}")
            print()

    print("=" * 60)


if __name__ == "__main__":
    main()
