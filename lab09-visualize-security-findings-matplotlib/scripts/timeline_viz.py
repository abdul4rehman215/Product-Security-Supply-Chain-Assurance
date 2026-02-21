#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from datetime import datetime

def prepare_timeline_data(df):
    """
    Prepare data for timeline analysis.

    Args:
    df: Security events dataframe

    Returns:
    Processed dataframe with time features
    """
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    hourly_counts = df.groupby("hour").size().reset_index(name="event_count")
    return hourly_counts

def create_hourly_timeline(df, output_path):
    """
    Create timeline showing events per hour.
    """
    hourly_counts = prepare_timeline_data(df)

    plt.figure(figsize=(12, 6))
    plt.plot(hourly_counts["hour"], hourly_counts["event_count"], marker="o")
    plt.fill_between(hourly_counts["hour"], hourly_counts["event_count"], alpha=0.2)

    plt.title("Security Events Timeline (24-Hour)")
    plt.xlabel("Hour of Day")
    plt.ylabel("Number of Events")
    plt.xticks(range(0, 24))
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def create_severity_timeline(df, output_path):
    """
    Create stacked area chart showing severity over time.
    """
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour

    pivot = df.pivot_table(index="hour", columns="severity", aggfunc="size", fill_value=0)

    hours = pivot.index.values

    severities = ["low", "medium", "high", "critical"]
    for s in severities:
        if s not in pivot.columns:
            pivot[s] = 0

    pivot = pivot[severities]

    colors = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "green"
    }

    plt.figure(figsize=(12, 6))
    plt.stackplot(
        hours,
        [pivot[s].values for s in severities],
        labels=severities,
        colors=[colors[s] for s in severities],
        alpha=0.7
    )

    plt.title("Severity Timeline (Stacked by Hour)")
    plt.xlabel("Hour of Day")
    plt.ylabel("Number of Events")
    plt.xticks(range(0, 24))
    plt.legend(loc="upper left")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def main():
    """Main execution function"""
    df = pd.read_csv("../data/security_events.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    create_hourly_timeline(df, "../outputs/timeline_analysis.png")
    print("Generated: outputs/timeline_analysis.png")

    create_severity_timeline(df, "../outputs/severity_timeline.png")
    print("Generated: outputs/severity_timeline.png")

    print("Timeline analysis visualizations completed!")

if __name__ == "__main__":
    main()
