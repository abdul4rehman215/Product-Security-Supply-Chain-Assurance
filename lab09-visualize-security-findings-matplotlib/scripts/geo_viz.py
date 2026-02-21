#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd

def create_country_threat_chart(df, output_path):
    """
    Create horizontal bar chart of threats by country.
    """
    country_counts = df["country"].value_counts().sort_values(ascending=False)

    plt.figure(figsize=(10, 6))
    bars = plt.barh(country_counts.index, country_counts.values)
    plt.gca().invert_yaxis()

    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.05, bar.get_y() + bar.get_height()/2.0, str(int(width)),
                 va="center")

    plt.title("Threat Sources by Country")
    plt.xlabel("Number of Events")
    plt.ylabel("Country")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def create_protocol_analysis(df, output_path):
    """
    Analyze and visualize attacks by protocol.
    """
    proto_counts = df["protocol"].value_counts()

    plt.figure(figsize=(10, 6))
    bars = plt.bar(proto_counts.index, proto_counts.values)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, height, str(int(height)),
                 ha="center", va="bottom")

    plt.title("Events by Protocol")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Events")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

def main():
    """Main execution function"""
    df = pd.read_csv("../data/security_events.csv")

    create_country_threat_chart(df, "../outputs/geo_threats.png")
    print("Generated: outputs/geo_threats.png")

    create_protocol_analysis(df, "../outputs/protocol_analysis.png")
    print("Generated: outputs/protocol_analysis.png")

    print("Geographic threat and protocol analysis completed!")

if __name__ == "__main__":
    main()
