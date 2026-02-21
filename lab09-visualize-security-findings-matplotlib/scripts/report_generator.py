#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.backends.backend_pdf import PdfPages
from datetime import datetime


class SecurityReportGenerator:
    """Generate comprehensive security reports with visualizations"""

    def __init__(self, events_file, vulns_file):
        """
        Initialize report generator.

        Args:
        events_file: Path to security events CSV
        vulns_file: Path to vulnerabilities CSV
        """
        self.events_file = events_file
        self.vulns_file = vulns_file
        self.events_df = None
        self.vulns_df = None

    def load_data(self):
        """Load all required data files"""
        try:
            self.events_df = pd.read_csv(self.events_file)
            self.vulns_df = pd.read_csv(self.vulns_file)

            self.events_df["timestamp"] = pd.to_datetime(self.events_df["timestamp"])

            return True
        except Exception as e:
            print("Error loading data:", str(e))
            return False

    def generate_summary_stats(self):
        """
        Calculate summary statistics.

        Returns:
        Dictionary with key metrics
        """
        events = self.events_df
        vulns = self.vulns_df

        total_events = int(len(events))
        critical_events = int((events["severity"] == "critical").sum())
        blocked_events = int((events["action"] == "blocked").sum())

        total_vulns = int(len(vulns))
        open_vulns = int((vulns["status"] == "open").sum())
        avg_cvss = float(vulns["cvss_score"].mean())

        stats = {
            "total_events": total_events,
            "critical_events": critical_events,
            "blocked_events": blocked_events,
            "total_vulnerabilities": total_vulns,
            "open_vulnerabilities": open_vulns,
            "average_cvss": round(avg_cvss, 2),
        }
        return stats

    def create_executive_summary_page(self, pdf):
        """
        Create executive summary page with 4 key charts.

        Args:
        pdf: PdfPages object
        """
        events = self.events_df
        vulns = self.vulns_df

        fig, axes = plt.subplots(2, 2, figsize=(11, 8.5))
        fig.suptitle("Executive Summary", fontsize=16)

        # 1) Event distribution pie chart
        event_counts = events["event_type"].value_counts()
        axes[0, 0].pie(event_counts.values, labels=event_counts.index, autopct="%1.1f%%", startangle=90)
        axes[0, 0].set_title("Event Distribution")

        # 2) Severity bar chart
        severity_counts = events["severity"].value_counts()
        colors_map = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}
        bar_colors = [colors_map.get(s, "blue") for s in severity_counts.index]
        bars = axes[0, 1].bar(severity_counts.index, severity_counts.values, color=bar_colors)
        axes[0, 1].set_title("Events by Severity")
        axes[0, 1].set_xlabel("Severity")
        axes[0, 1].set_ylabel("Count")
        for bar in bars:
            height = bar.get_height()
            axes[0, 1].text(bar.get_x() + bar.get_width()/2.0, height, str(int(height)),
                            ha="center", va="bottom")

        # 3) Top countries chart
        country_counts = events["country"].value_counts().head(10)
        axes[1, 0].barh(country_counts.index, country_counts.values)
        axes[1, 0].invert_yaxis()
        axes[1, 0].set_title("Top Threat Countries")
        axes[1, 0].set_xlabel("Count")

        # 4) Vulnerability status chart
        status_counts = vulns["status"].value_counts()
        axes[1, 1].bar(status_counts.index, status_counts.values)
        axes[1, 1].set_title("Vulnerabilities by Status")
        axes[1, 1].set_xlabel("Status")
        axes[1, 1].set_ylabel("Count")
        for i, v in enumerate(status_counts.values):
            axes[1, 1].text(i, v, str(int(v)), ha="center", va="bottom")

        plt.tight_layout()
        pdf.savefig(fig)
        plt.close(fig)

    def create_threat_analysis_page(self, pdf):
        """
        Create threat intelligence analysis page.

        Args:
        pdf: PdfPages object
        """
        events = self.events_df.copy()

        fig, axes = plt.subplots(2, 2, figsize=(11, 8.5))
        fig.suptitle("Threat Intelligence Analysis", fontsize=16)

        # 1) Timeline chart (events per minute in dataset timeframe)
        events = events.sort_values("timestamp")
        timeline_counts = events.set_index("timestamp").resample("1min").size()
        axes[0, 0].plot(timeline_counts.index, timeline_counts.values, marker="o")
        axes[0, 0].set_title("Event Timeline (Per Minute)")
        axes[0, 0].set_xlabel("Time")
        axes[0, 0].set_ylabel("Events")
        axes[0, 0].grid(True)

        # 2) Protocol analysis
        proto_counts = events["protocol"].value_counts()
        bars = axes[0, 1].bar(proto_counts.index, proto_counts.values)
        axes[0, 1].set_title("Events by Protocol")
        axes[0, 1].set_xlabel("Protocol")
        axes[0, 1].set_ylabel("Count")
        for bar in bars:
            height = bar.get_height()
            axes[0, 1].text(bar.get_x() + bar.get_width()/2.0, height, str(int(height)),
                            ha="center", va="bottom")

        # 3) Port analysis (top 10 ports)
        port_counts = events["port"].value_counts().head(10)
        axes[1, 0].bar(port_counts.index.astype(str), port_counts.values)
        axes[1, 0].set_title("Top Targeted Ports")
        axes[1, 0].set_xlabel("Port")
        axes[1, 0].set_ylabel("Count")
        axes[1, 0].grid(True)

        # 4) Action taken chart
        action_counts = events["action"].value_counts()
        axes[1, 1].bar(action_counts.index, action_counts.values)
        axes[1, 1].set_title("Actions Taken")
        axes[1, 1].set_xlabel("Action")
        axes[1, 1].set_ylabel("Count")
        for i, v in enumerate(action_counts.values):
            axes[1, 1].text(i, v, str(int(v)), ha="center", va="bottom")

        plt.tight_layout()
        pdf.savefig(fig)
        plt.close(fig)

    def create_vulnerability_page(self, pdf):
        """
        Create vulnerability assessment page.

        Args:
        pdf: PdfPages object
        """
        vulns = self.vulns_df.copy()

        fig, axes = plt.subplots(2, 2, figsize=(11, 8.5))
        fig.suptitle("Vulnerability Assessment", fontsize=16)

        # 1) CVSS distribution
        axes[0, 0].hist(vulns["cvss_score"], bins=10)
        mean_cvss = vulns["cvss_score"].mean()
        axes[0, 0].axvline(mean_cvss, linestyle="--")
        axes[0, 0].set_title("CVSS Score Distribution")
        axes[0, 0].set_xlabel("CVSS")
        axes[0, 0].set_ylabel("Count")
        axes[0, 0].grid(True)

        # 2) Vulnerability types
        type_counts = vulns["vulnerability_type"].value_counts()
        axes[0, 1].pie(type_counts.values, labels=type_counts.index, autopct="%1.1f%%", startangle=90)
        axes[0, 1].set_title("Vulnerability Types")

        # 3) Remediation status by severity
        table = pd.crosstab(vulns["severity"], vulns["status"])
        table.plot(kind="bar", stacked=True, ax=axes[1, 0])
        axes[1, 0].set_title("Remediation Status by Severity")
        axes[1, 0].set_xlabel("Severity")
        axes[1, 0].set_ylabel("Count")
        axes[1, 0].legend(title="Status")

        # 4) Risk scores
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        open_df = vulns[vulns["status"] == "open"]
        open_counts = open_df["severity"].value_counts()

        ordered = ["critical", "high", "medium", "low"]
        risk_scores = []
        for sev in ordered:
            risk_scores.append(severity_weights[sev] * int(open_counts.get(sev, 0)))

        colors = ["red", "orange", "yellow", "green"]
        axes[1, 1].bar(ordered, risk_scores, color=colors)
        axes[1, 1].set_title("Risk Score by Severity (Open Only)")
        axes[1, 1].set_xlabel("Severity")
        axes[1, 1].set_ylabel("Risk Score")
        axes[1, 1].grid(True)

        plt.tight_layout()
        pdf.savefig(fig)
        plt.close(fig)

    def generate_report(self, output_path):
        """
        Generate complete multi-page PDF report.

        Args:
        output_path: Where to save PDF report
        """
        if not self.load_data():
            print("Failed to load data. Report generation stopped.")
            return False

        stats = self.generate_summary_stats()

        with PdfPages(output_path) as pdf:
            # Cover page (simple)
            cover_fig = plt.figure(figsize=(11, 8.5))
            cover_fig.suptitle("Security Report", fontsize=22)
            text = (
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"Summary Metrics:\n"
                f"- Total Events: {stats['total_events']}\n"
                f"- Critical Events: {stats['critical_events']}\n"
                f"- Blocked Events: {stats['blocked_events']}\n"
                f"- Total Vulnerabilities: {stats['total_vulnerabilities']}\n"
                f"- Open Vulnerabilities: {stats['open_vulnerabilities']}\n"
                f"- Average CVSS: {stats['average_cvss']}\n"
            )
            plt.axis("off")
            cover_fig.text(0.1, 0.6, text, fontsize=14)
            pdf.savefig(cover_fig)
            plt.close(cover_fig)

            # Report pages
            self.create_executive_summary_page(pdf)
            self.create_threat_analysis_page(pdf)
            self.create_vulnerability_page(pdf)

        print("Report generated successfully:", output_path)
        return True


def main():
    """Main execution function"""
    generator = SecurityReportGenerator(
        "../data/security_events.csv",
        "../data/vulnerabilities.csv"
    )

    output_pdf = "../outputs/security_report.pdf"
    generator.generate_report(output_pdf)
    print("Security PDF report generation completed!")


if __name__ == "__main__":
    main()
