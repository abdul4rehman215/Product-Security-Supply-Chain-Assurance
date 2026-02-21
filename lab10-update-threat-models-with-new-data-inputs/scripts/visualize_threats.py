#!/usr/bin/env python3
import json
import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path

def load_threat_model(filepath):
    """Load threat model from file."""
    with open(filepath, "r") as f:
        return json.load(f)

def plot_technique_frequency(threat_model):
    """Create bar chart of technique frequencies."""
    patterns = threat_model.get("attack_patterns", [])
    techs = [(p.get("technique_id"), p.get("frequency", 0)) for p in patterns]
    techs = sorted(techs, key=lambda x: x[1], reverse=True)[:10]

    labels = [t[0] for t in techs]
    values = [t[1] for t in techs]

    plt.figure(figsize=(12, 6))
    bars = plt.bar(labels, values)
    plt.title("Top 10 MITRE ATT&CK Techniques by Frequency")
    plt.xlabel("Technique ID")
    plt.ylabel("Frequency")

    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, h, str(int(h)),
                 ha="center", va="bottom")

    plt.tight_layout()
    plt.savefig("../output/technique_frequency.png", dpi=300)
    plt.close()

def plot_severity_distribution(threat_model):
    """Create pie chart of severity distribution."""
    patterns = threat_model.get("attack_patterns", [])
    severities = [p.get("severity", "unknown") for p in patterns]
    counts = Counter(severities)

    plt.figure(figsize=(10, 8))
    plt.pie(counts.values(), labels=counts.keys(), autopct="%1.1f%%", startangle=90)
    plt.title("Threat Model Severity Distribution")
    plt.tight_layout()
    plt.savefig("../output/severity_distribution.png", dpi=300)
    plt.close()

def plot_tactic_coverage(threat_model):
    """Create horizontal bar chart of MITRE ATT&CK tactics."""
    patterns = threat_model.get("attack_patterns", [])
    tactics = [p.get("tactic", "unknown") for p in patterns]
    counts = Counter(tactics)
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)

    labels = [x[0] for x in sorted_items]
    values = [x[1] for x in sorted_items]

    plt.figure(figsize=(12, 6))
    bars = plt.barh(labels, values)
    plt.gca().invert_yaxis()
    plt.title("MITRE ATT&CK Tactic Coverage")
    plt.xlabel("Number of Techniques Observed")

    for bar in bars:
        w = bar.get_width()
        plt.text(w + 0.1, bar.get_y() + bar.get_height()/2.0, str(int(w)),
                 va="center")

    plt.tight_layout()
    plt.savefig("../output/tactic_coverage.png", dpi=300)
    plt.close()

def generate_all_visualizations():
    """Generate all threat model visualizations."""
    Path("../output").mkdir(parents=True, exist_ok=True)

    model = load_threat_model("../data/threat-models/updated_threat_model.json")

    plot_technique_frequency(model)
    plot_severity_distribution(model)
    plot_tactic_coverage(model)

    print("Threat visualizations generated successfully!")

if __name__ == "__main__":
    generate_all_visualizations()
