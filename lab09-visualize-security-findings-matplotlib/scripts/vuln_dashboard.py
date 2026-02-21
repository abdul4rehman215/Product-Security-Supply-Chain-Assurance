#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

def load_vulnerability_data(filepath):
    """
    Load vulnerability scan results.
    """
    df = pd.read_csv(filepath)
    return df

def create_cvss_distribution(df, ax):
    """
    Create CVSS score distribution histogram.
    """
    ax.hist(df["cvss_score"], bins=10)
    mean_score = df["cvss_score"].mean()
    ax.axvline(mean_score, linestyle="--")
    ax.set_title("CVSS Score Distribution")
    ax.set_xlabel("CVSS Score")
    ax.set_ylabel("Count")
    ax.grid(True)

def create_vulnerability_types_chart(df, ax):
    """
    Create pie chart of vulnerability types.
    """
    counts = df["vulnerability_type"].value_counts()
    ax.pie(counts.values, labels=counts.index, autopct="%1.1f%%", startangle=90)
    ax.set_title("Vulnerability Types")

def create_status_by_severity(df, ax):
    """
    Create stacked bar chart of status by severity.
    """
    table = pd.crosstab(df["severity"], df["status"])
    table.plot(kind="bar", stacked=True, ax=ax)
    ax.set_title("Remediation Status by Severity")
    ax.set_xlabel("Severity")
    ax.set_ylabel("Count")
    ax.legend(title="Status")
    ax.grid(True)

def create_risk_score_chart(df, ax):
    """
    Calculate and visualize risk scores.
    """
    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}

    open_df = df[df["status"] == "open"]
    counts = open_df["severity"].value_counts()

    risk_scores = {}
    for sev, cnt in counts.items():
        risk_scores[sev] = severity_weights.get(sev, 1) * int(cnt)

    ordered = ["critical", "high", "medium", "low"]
    for sev in ordered:
        if sev not in risk_scores:
            risk_scores[sev] = 0

    sev_list = ordered
    score_list = [risk_scores[s] for s in sev_list]

    colors = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "green"
    }

    ax.bar(sev_list, score_list, color=[colors[s] for s in sev_list])
    ax.set_title("Risk Score by Severity")
    ax.set_xlabel("Severity")
    ax.set_ylabel("Risk Score")
    ax.grid(True)

def create_dashboard(df, output_path):
    """
    Create comprehensive 4-panel vulnerability dashboard.
    """
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    create_cvss_distribution(df, axes[0, 0])
    create_vulnerability_types_chart(df, axes[0, 1])
    create_status_by_severity(df, axes[1, 0])
    create_risk_score_chart(df, axes[1, 1])

    fig.suptitle("Vulnerability Assessment Dashboard", fontsize=16)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def main():
    """Main execution function"""
    df = load_vulnerability_data("../data/vulnerabilities.csv")
    create_dashboard(df, "../outputs/vuln_dashboard.png")
    print("Generated: outputs/vuln_dashboard.png")
    print("Vulnerability dashboard created successfully!")

if __name__ == "__main__":
    main()
