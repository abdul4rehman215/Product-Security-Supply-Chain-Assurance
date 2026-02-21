#!/usr/bin/env python3
"""
Map and analyze attack paths that chain multiple vulnerabilities.
Builds a directed graph and scores multi-stage attack scenarios.
"""

import json
from pathlib import Path
from typing import List, Dict

import networkx as nx


class AttackPathMapper:
    """Map attack paths across multiple vulnerabilities."""

    def __init__(self, vulnerability_file: str):
        """
        Initialize mapper with vulnerability data.

        Args:
            vulnerability_file: Path to JSON file
        """
        self.vulnerability_file = vulnerability_file
        self.vuln_data = self._load_vulnerability_data(vulnerability_file)

        self.graph = nx.DiGraph()
        self.vulnerability_chains: List[List[str]] = []

        # Flattened lookup
        self.vuln_index = self._build_vulnerability_index()

    def _load_vulnerability_data(self, vulnerability_file: str) -> dict:
        vuln_path = Path(vulnerability_file)
        if not vuln_path.exists():
            raise FileNotFoundError(f"Vulnerability file not found: {vulnerability_file}")
        with open(vuln_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _flatten_vulnerabilities(self) -> List[Dict]:
        vulns = []
        for category, cdata in self.vuln_data.items():
            for v in cdata.get("vulnerabilities", []):
                vv = dict(v)
                vv["_category"] = category
                vulns.append(vv)
        return vulns

    def _build_vulnerability_index(self) -> Dict[str, Dict]:
        idx = {}
        for v in self._flatten_vulnerabilities():
            vid = v.get("id")
            if vid:
                idx[vid] = v
        return idx

    def build_attack_graph(self) -> nx.DiGraph:
        """
        Build directed graph of vulnerability relationships.

        Steps:
        1. Add nodes for each vulnerability with attributes
        2. Define edges representing attack chains
        """
        # Nodes
        for vid, v in self.vuln_index.items():
            self.graph.add_node(
                vid,
                type=v.get("type"),
                severity=v.get("severity"),
                location=v.get("location"),
                cvss_score=float(v.get("cvss_score", 0.0)),
                category=v.get("_category"),
            )

        # Edges (relationships)
        self.define_attack_relationships()
        return self.graph

    def define_attack_relationships(self) -> None:
        """
        Define how vulnerabilities can be chained.
        These are realistic examples used for lab demonstration.
        """
        relationships = [
            ("VULN-003", "VULN-001", "enables", "Weak authentication can enable access to SQLi entry points"),
            ("VULN-001", "VULN-004", "leverages", "SQLi can expose traffic/credentials that benefit from unencrypted channels"),
            ("VULN-002", "VULN-003", "bypasses", "XSS may steal session tokens or assist in bypassing authentication"),
        ]

        for src, dst, rel_type, desc in relationships:
            if src in self.graph.nodes and dst in self.graph.nodes:
                self.graph.add_edge(src, dst, relationship=rel_type, description=desc)

    def find_attack_paths(self, start_vuln: str = None, end_vuln: str = None) -> List[List[str]]:
        """
        Find all attack paths between vulnerabilities.

        Args:
            start_vuln: Starting vulnerability ID (optional)
            end_vuln: Target vulnerability ID (optional)

        Returns:
            List of paths (each path is list of vulnerability IDs)
        """
        paths: List[List[str]] = []

        if start_vuln and end_vuln:
            if start_vuln in self.graph.nodes and end_vuln in self.graph.nodes:
                for p in nx.all_simple_paths(self.graph, start_vuln, end_vuln):
                    paths.append(p)
            self.vulnerability_chains = paths
            return paths

        # All simple paths between all pairs
        nodes = list(self.graph.nodes)
        for i in range(len(nodes)):
            for j in range(len(nodes)):
                if i == j:
                    continue
                s, t = nodes[i], nodes[j]
                try:
                    for p in nx.all_simple_paths(self.graph, s, t):
                        paths.append(p)
                except nx.NetworkXNoPath:
                    continue

        # Deduplicate paths
        unique = []
        seen = set()
        for p in paths:
            tp = tuple(p)
            if tp not in seen:
                seen.add(tp)
                unique.append(p)

        self.vulnerability_chains = unique
        return unique

    def calculate_path_risk(self, path: List[str]) -> float:
        """
        Calculate overall risk score for an attack path.

        Formula (lab-friendly):
        - Sum CVSS scores weighted by position (earlier steps slightly higher)
        - Apply length penalty (longer chains are less likely end-to-end)
        """
        total_risk = 0.0

        for idx, vid in enumerate(path):
            node = self.graph.nodes.get(vid, {})
            cvss = float(node.get("cvss_score", 0.0))

            # Decrease weight by 10% each step, minimum 0.5
            weight = 1.0 - (0.1 * idx)
            if weight < 0.5:
                weight = 0.5

            total_risk += cvss * weight

        # Length penalty: reduces risk for longer chains
        length_penalty = 1.0 / (1.0 + (0.15 * (len(path) - 1)))
        final_risk = total_risk * length_penalty

        return float(final_risk)

    def generate_attack_scenarios(self) -> Dict[str, List[Dict]]:
        """
        Generate categorized attack scenarios.

        Categories:
        - high_impact_scenarios: risk >= 15
        - multi_stage_scenarios: path length >= 2
        - privilege_escalation_scenarios: includes auth weakness (VULN-003)
        """
        paths = self.find_attack_paths()

        scored = []
        for p in paths:
            scored.append({"path": p, "risk_score": self.calculate_path_risk(p)})

        high_impact = []
        multi_stage = []
        privilege_escalation = []

        for item in scored:
            path = item["path"]
            risk = item["risk_score"]

            if risk >= 15.0:
                high_impact.append(item)

            if len(path) >= 2:
                multi_stage.append(item)

            if "VULN-003" in path:
                privilege_escalation.append(item)

        # Sort by risk desc
        high_impact.sort(key=lambda x: x["risk_score"], reverse=True)
        multi_stage.sort(key=lambda x: x["risk_score"], reverse=True)
        privilege_escalation.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "high_impact_scenarios": high_impact,
            "multi_stage_scenarios": multi_stage,
            "privilege_escalation_scenarios": privilege_escalation,
        }

    def print_attack_scenarios(self) -> None:
        """Print formatted attack scenarios."""
        scenarios = self.generate_attack_scenarios()

        print("\n" + "=" * 70)
        print("Attack Scenarios (Categorized)")
        print("=" * 70)

        for category, items in scenarios.items():
            print("\n" + "-" * 70)
            print(f"{category}")
            print("-" * 70)

            if not items:
                print("No scenarios found.")
                continue

            for i, s in enumerate(items[:5], start=1):
                path = s["path"]
                risk = s["risk_score"]

                print(f"{i}. Risk Score: {risk:.2f}")
                print(f"   Path: {' -> '.join(path)}")

                descriptions = []
                for a, b in zip(path, path[1:]):
                    edata = self.graph.get_edge_data(a, b, default={})
                    rel = edata.get("relationship", "unknown")
                    desc = edata.get("description", "")
                    descriptions.append(f"{a} -> {b} ({rel}) {desc}".strip())

                if descriptions:
                    print("   Chain details:")
                    for d in descriptions:
                        print(f"     - {d}")
                print()

        print("=" * 70)


if __name__ == "__main__":
    mapper = AttackPathMapper("../data/vulnerabilities.json")
    mapper.build_attack_graph()
    mapper.print_attack_scenarios()
