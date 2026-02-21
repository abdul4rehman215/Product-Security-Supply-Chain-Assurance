#!/usr/bin/env python3
import pandas as pd
from datetime import datetime

def generate_text_summary(events_file, vulns_file):
    """
    Generate text-based security summary.

    Args:
    events_file: Path to events CSV
    vulns_file: Path to vulnerabilities CSV
    """
    events = pd.read_csv(events_file)
    vulns = pd.read_csv(vulns_file)

    events["timestamp"] = pd.to_datetime(events["timestamp"])

    total_events = len(events)
    critical_events = (events["severity"] == "critical").sum()
    high_events = (events["severity"] == "high").sum()
    blocked_events = (events["action"] == "blocked").sum()
    quarantined_events = (events["action"] == "quarantined").sum()
    allowed_events = (events["action"] == "allowed").sum()

    top_event_types = events["event_type"].value_counts().head(5)
    top_countries = events["country"].value_counts().head(5)
    top_ports = events["port"].value_counts().head(5)

    total_vulns = len(vulns)
    open_vulns = (vulns["status"] == "open").sum()
    patched_vulns = (vulns["status"] == "patched").sum()
    mitigated_vulns = (vulns["status"] == "mitigated").sum()

    avg_cvss = vulns["cvss_score"].mean()
    max_cvss = vulns["cvss_score"].max()

    summary = []
    summary.append("SECURITY SUMMARY REPORT")
    summary.append("=" * 60)
    summary.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary.append("")

    summary.append("SECURITY EVENTS OVERVIEW")
    summary.append("-" * 60)
    summary.append(f"Total Events: {total_events}")
    summary.append(f"Critical Events: {critical_events}")
    summary.append(f"High Severity Events: {high_events}")
    summary.append(f"Blocked Events: {blocked_events}")
    summary.append(f"Quarantined Events: {quarantined_events}")
    summary.append(f"Allowed Events: {allowed_events}")
    summary.append("")

    summary.append("Top Event Types:")
    for k, v in top_event_types.items():
        summary.append(f"  - {k}: {v}")
    summary.append("")

    summary.append("Top Threat Countries:")
    for k, v in top_countries.items():
        summary.append(f"  - {k}: {v}")
    summary.append("")

    summary.append("Top Targeted Ports:")
    for k, v in top_ports.items():
        summary.append(f"  - {k}: {v}")
    summary.append("")

    summary.append("VULNERABILITY OVERVIEW")
    summary.append("-" * 60)
    summary.append(f"Total Vulnerabilities: {total_vulns}")
    summary.append(f"Open Vulnerabilities: {open_vulns}")
    summary.append(f"Patched Vulnerabilities: {patched_vulns}")
    summary.append(f"Mitigated Vulnerabilities: {mitigated_vulns}")
    summary.append(f"Average CVSS Score: {avg_cvss:.2f}")
    summary.append(f"Max CVSS Score: {max_cvss:.2f}")
    summary.append("")

    report_text = "\n".join(summary)

    print(report_text)

    output_file = "../outputs/security_summary.txt"
    with open(output_file, "w") as f:
        f.write(report_text)

    print("\nSaved summary to:", output_file)

def main():
    """Main execution function"""
    generate_text_summary("../data/security_events.csv", "../data/vulnerabilities.csv")

if __name__ == "__main__":
    main()
