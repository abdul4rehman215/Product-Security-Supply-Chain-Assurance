#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

def load_security_data(filepath):
    """
    Load security events from CSV file.

    Args:
    filepath: Path to CSV file

    Returns:
    DataFrame with security events
    """
    df = pd.read_csv(filepath)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def create_event_pie_chart(df, output_path):
    """
    Create pie chart showing event type distribution.

    Args:
    df: Security events dataframe
    output_path: Where to save the chart
    """
    counts = df["event_type"].value_counts()

    plt.figure(figsize=(10, 8))
    plt.pie(counts.values, labels=counts.index, autopct="%1.1f%%", startangle=90)
    plt.title("Security Event Distribution")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def create_severity_bar_chart(df, output_path):
    """
    Create bar chart showing severity levels.

    Args:
    df: Security events dataframe
    output_path: Where to save the chart
    """
    severity_counts = df["severity"].value_counts()

    color_map = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "green"
    }

    colors = [color_map.get(s, "blue") for s in severity_counts.index]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(severity_counts.index, severity_counts.values, color=colors)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, height, str(int(height)),
                 ha="center", va="bottom")

    plt.title("Security Event Severity Levels")
    plt.xlabel("Severity")
    plt.ylabel("Number of Events")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def main():
    """Main execution function"""
    events_file = "../data/security_events.csv"

    df = load_security_data(events_file)

    create_event_pie_chart(df, "../outputs/event_pie_chart.png")
    print("Generated: outputs/event_pie_chart.png")

    create_severity_bar_chart(df, "../outputs/severity_bar_chart.png")
    print("Generated: outputs/severity_bar_chart.png")

    print("Basic visualizations created successfully!")

if __name__ == "__main__":
    main()
