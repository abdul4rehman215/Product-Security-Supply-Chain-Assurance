#!/usr/bin/env python3
"""
Automated Threat Model Generator
Creates threat models based on system components and MITRE data
"""

import pandas as pd
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import networkx as nx
from datetime import datetime


class ThreatModelGenerator:
    def __init__(self, mitre_csv='mitre_techniques.csv'):
        self.mitre_df = None
        self.threat_model = {
            "metadata": {
                "created": datetime.now().isoformat(),
                "version": "1.0"
            },
            "assets": [],
            "threats": []
        }

        self.mitre_df = pd.read_csv(mitre_csv)

        if "name" in self.mitre_df.columns:
            self.mitre_df["name"] = self.mitre_df["name"].fillna("")
        if "description" in self.mitre_df.columns:
            self.mitre_df["description"] = self.mitre_df["description"].fillna("")
        if "tactics" in self.mitre_df.columns:
            self.mitre_df["tactics"] = self.mitre_df["tactics"].fillna("")
        if "platforms" in self.mitre_df.columns:
            self.mitre_df["platforms"] = self.mitre_df["platforms"].fillna("")
        if "technique_id" in self.mitre_df.columns:
            self.mitre_df["technique_id"] = self.mitre_df["technique_id"].fillna("")

    def add_asset(self, name, asset_type, trust_zone, criticality='Medium'):
        asset = {
            "id": f"ASSET_{len(self.threat_model['assets']) + 1:03d}",
            "name": name,
            "type": asset_type,
            "trust_zone": trust_zone,
            "criticality": criticality
        }
        self.threat_model["assets"].append(asset)
        return asset["id"]

    def find_relevant_techniques(self, asset_type):
        at = asset_type.lower().strip()

        if "web" in at or "server" in at:
            keywords = ["web", "http", "https", "injection", "xss", "csrf", "exploit", "shell"]
        elif "database" in at or "db" in at:
            keywords = ["data", "sql", "query", "database", "credential", "dump", "exfiltration"]
        elif "api" in at or "gateway" in at or "payment" in at:
            keywords = ["api", "service", "endpoint", "token", "key", "credential", "oauth", "intercept"]
        elif "browser" in at or "user" in at:
            keywords = ["phishing", "browser", "credential", "session", "cookie", "javascript"]
        else:
            keywords = [at]

        df = self.mitre_df.copy()
        combined = (
            df["name"].astype(str) + " " +
            df["description"].astype(str) + " " +
            df.get("tactics", "").astype(str) + " " +
            df.get("platforms", "").astype(str)
        ).str.lower()

        score = pd.Series([0] * len(df))
        for kw in keywords:
            score += combined.str.count(kw)

        df["relevance_score"] = score
        df = df[df["relevance_score"] > 0].sort_values("relevance_score", ascending=False)

        top = df.head(10)

        techniques = []
        for _, row in top.iterrows():
            techniques.append({
                "technique_id": str(row.get("technique_id", "")).strip(),
                "name": str(row.get("name", "")).strip(),
                "tactics": str(row.get("tactics", "")).strip(),
                "platforms": str(row.get("platforms", "")).strip(),
                "description": str(row.get("description", "")).strip()
            })
        return techniques

    def calculate_risk_score(self, likelihood, impact):
        mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        l = mapping.get(likelihood.upper(), 1)
        i = mapping.get(impact.upper(), 1)
        return l * i

    def _crit_to_levels(self, criticality):
        c = str(criticality).strip().lower()
        if c == "high":
            return "HIGH", "HIGH"
        if c == "low":
            return "LOW", "LOW"
        return "MEDIUM", "MEDIUM"

    def generate_threats_for_asset(self, asset_id):
        asset = None
        for a in self.threat_model["assets"]:
            if a["id"] == asset_id:
                asset = a
                break
        if asset is None:
            return

        relevant = self.find_relevant_techniques(asset["type"])
        likelihood_base, impact_base = self._crit_to_levels(asset.get("criticality", "Medium"))

        for t in relevant:
            threat_id = f"THREAT_{len(self.threat_model['threats']) + 1:04d}"

            tz = asset.get("trust_zone", "").lower()
            likelihood = likelihood_base
            impact = impact_base

            if tz in ("external", "internet", "public"):
                likelihood = "HIGH" if likelihood != "LOW" else "MEDIUM"

            if "database" in asset["type"].lower() or tz == "internal":
                impact = "HIGH" if impact != "LOW" else "MEDIUM"

            risk_score = self.calculate_risk_score(likelihood, impact)

            threat = {
                "threat_id": threat_id,
                "asset_id": asset_id,
                "asset_name": asset.get("name", ""),
                "mitre_id": t.get("technique_id", ""),
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "tactics": t.get("tactics", ""),
                "platforms": t.get("platforms", ""),
                "likelihood": likelihood,
                "impact": impact,
                "risk_score": risk_score
            }

            self.threat_model["threats"].append(threat)

    def generate_visualization(self, output_file='threat_model.png'):
        G = nx.DiGraph()

        for asset in self.threat_model["assets"]:
            G.add_node(asset["id"], label=asset["name"], node_type="asset", criticality=asset.get("criticality", "Medium"))

        for threat in self.threat_model["threats"]:
            tid = threat["threat_id"]
            G.add_node(tid, label=threat["name"], node_type="threat", risk=threat["risk_score"])
            G.add_edge(threat["asset_id"], tid)

        pos = nx.spring_layout(G, k=0.8, seed=42)

        asset_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset"]
        threat_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "threat"]

        high = [n for n in threat_nodes if G.nodes[n].get("risk", 1) >= 7]
        med = [n for n in threat_nodes if 4 <= G.nodes[n].get("risk", 1) <= 6]
        low = [n for n in threat_nodes if G.nodes[n].get("risk", 1) <= 3]

        plt.figure(figsize=(14, 9))

        nx.draw_networkx_edges(G, pos, alpha=0.4, arrows=True, arrowsize=10)
        nx.draw_networkx_nodes(G, pos, nodelist=asset_nodes, node_size=1800)
        nx.draw_networkx_nodes(G, pos, nodelist=high, node_size=900)
        nx.draw_networkx_nodes(G, pos, nodelist=med, node_size=700)
        nx.draw_networkx_nodes(G, pos, nodelist=low, node_size=500)

        labels = {}
        for n, d in G.nodes(data=True):
            lbl = d.get("label", n)
            if d.get("node_type") == "threat":
                labels[n] = (lbl[:28] + "...") if len(lbl) > 31 else lbl
            else:
                labels[n] = lbl

        nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)

        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_file, dpi=200)
        plt.close()

    def export_json(self, filename='threat_model.json'):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.threat_model, f, indent=2)

    def generate_report(self, filename='threat_report.txt'):
        threats = self.threat_model["threats"]
        assets = self.threat_model["assets"]

        high_risk = [t for t in threats if t["risk_score"] >= 7]
        sorted_threats = sorted(threats, key=lambda x: x["risk_score"], reverse=True)

        lines = []
        lines.append("Automated Threat Model Report")
        lines.append("============================")
        lines.append(f"Created: {self.threat_model['metadata']['created']}")
        lines.append(f"Version: {self.threat_model['metadata']['version']}")
        lines.append("")
        lines.append("Assets")
        lines.append("------")
        for a in assets:
            lines.append(f"- {a['id']}: {a['name']} | type={a['type']} | trust_zone={a['trust_zone']} | criticality={a['criticality']}")
        lines.append("")
        lines.append("Threat Summary")
        lines.append("--------------")
        lines.append(f"Total threats: {len(threats)}")
        lines.append(f"High risk threats (score >= 7): {len(high_risk)}")
        lines.append("")
        lines.append("Top 10 Threats by Risk Score")
        lines.append("----------------------------")
        for t in sorted_threats[:10]:
            lines.append(
                f"- {t['threat_id']} | asset={t['asset_name']} | mitre={t['mitre_id']} | "
                f"{t['name']} | likelihood={t['likelihood']} impact={t['impact']} score={t['risk_score']}"
            )
        lines.append("")
        lines.append("Notes")
        lines.append("-----")
        lines.append("Risk scoring uses Low=1, Medium=2, High=3 with score = likelihood * impact (1-9).")
        lines.append("Relevance mapping is keyword-based against MITRE technique name/description/tactics/platforms.")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


def main():
    tmg = ThreatModelGenerator()

    user_id = tmg.add_asset("User Browser", "browser", "external", "Medium")
    web_id = tmg.add_asset("Web Server", "web server", "dmz", "High")
    db_id = tmg.add_asset("Customer DB", "database", "internal", "High")
    pay_id = tmg.add_asset("Payment Gateway", "api", "third-party", "High")

    for aid in [user_id, web_id, db_id, pay_id]:
        tmg.generate_threats_for_asset(aid)

    tmg.export_json("threat_model.json")
    tmg.generate_report("threat_report.txt")
    tmg.generate_visualization("threat_model.png")

    total_assets = len(tmg.threat_model["assets"])
    total_threats = len(tmg.threat_model["threats"])
    high_risk = len([t for t in tmg.threat_model["threats"] if t["risk_score"] >= 7])

    print("[+] Threat model generation complete")
    print(f"[+] Assets: {total_assets}")
    print(f"[+] Threats: {total_threats}")
    print(f"[+] High-risk threats: {high_risk}")
    print("[+] Generated: threat_model.json, threat_report.txt, threat_model.png")


if __name__ == "__main__":
    main()
