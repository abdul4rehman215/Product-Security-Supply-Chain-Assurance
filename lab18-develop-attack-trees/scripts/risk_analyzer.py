#!/usr/bin/env python3
"""
Analyze attack trees and prioritize remediation efforts.
Combines CVSS, attack path frequency, and position in chains
to produce a prioritized remediation report.
"""

from typing import List, Dict, Tuple
import json
from pathlib import Path
from datetime import datetime

from vuln_attack_trees import VulnerabilityAttackTreeGenerator
from attack_path_mapper import AttackPathMapper


class RiskAnalyzer:
    """Analyze attack trees and prioritize remediation."""

    def __init__(self, attack_trees: dict, attack_scenarios: dict, vulnerability_data: dict):
        self.attack_trees = attack_trees
        self.attack_scenarios = attack_scenarios
        self.vulnerability_data = vulnerability_data
        self.remediation_priorities: List[Dict] = []
        self.vuln_index = self._build_vulnerability_index()

    def _flatten_vulnerabilities(self) -> List[Dict]:
        vulns = []
        for category, cdata in self.vulnerability_data.items():
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

    def _count_paths_involving_vuln(self, vuln_id: str) -> Tuple[int, float]:
        paths = []
        for category, items in self.attack_scenarios.items():
            for obj in items:
                p = obj.get("path", [])
                if p:
                    paths.append(p)

        count = 0
        position_weight_sum = 0.0

        for p in paths:
            if vuln_id in p:
                count += 1
                pos = p.index(vuln_id)
                weight = 1.0 - (0.15 * pos)
                if weight < 0.4:
                    weight = 0.4
                position_weight_sum += weight

        avg_weight = (position_weight_sum / count) if count > 0 else 0.0
        return count, avg_weight

    def calculate_vulnerability_criticality(self, vuln_id: str) -> float:
        v = self.vuln_index.get(vuln_id, {})
        cvss = float(v.get("cvss_score", 0.0))

        path_count, avg_position_weight = self._count_paths_involving_vuln(vuln_id)

        path_factor = min(1.5, 1.0 + (path_count * 0.15))

        if avg_position_weight == 0.0:
            avg_position_weight = 0.8

        raw_score = cvss * path_factor * avg_position_weight

        if raw_score > 10.0:
            raw_score = 10.0
        if raw_score < 0.0:
            raw_score = 0.0

        return float(raw_score)

    def _priority_level(self, score: float) -> str:
        if score > 8.0:
            return "Critical"
        if score > 6.0:
            return "High"
        if score > 4.0:
            return "Medium"
        return "Low"

    def _recommended_actions(self, vuln_type: str) -> List[str]:
        vtype = (vuln_type or "").lower()

        if "sql injection" in vtype:
            return [
                "Implement parameterized queries / prepared statements",
                "Apply strict server-side input validation",
                "Deploy Web Application Firewall (WAF) rules",
                "Use least privilege for database accounts"
            ]

        if "cross-site scripting" in vtype or "xss" in vtype:
            return [
                "Implement context-aware output encoding",
                "Deploy Content Security Policy (CSP)",
                "Sanitize and validate user inputs",
                "Use HttpOnly and Secure cookie flags"
            ]

        if "weak authentication" in vtype or "authentication" in vtype:
            return [
                "Enforce strong password policy",
                "Implement Multi-Factor Authentication (MFA)",
                "Enable rate limiting and account lockout policies",
                "Monitor login anomaly detection"
            ]

        if "unencrypted" in vtype:
            return [
                "Enforce TLS encryption for all communications",
                "Disable insecure protocols and cipher suites",
                "Implement certificate validation and pinning"
            ]

        return [
            "Review system configuration",
            "Apply security patches",
            "Implement logging and monitoring"
        ]

    def _affected_attack_paths(self, vuln_id: str) -> List[Dict]:
        affected = []

        for category, items in self.attack_scenarios.items():
            for obj in items:
                path = obj.get("path", [])
                if vuln_id in path:
                    affected.append({
                        "category": category,
                        "risk_score": obj.get("risk_score"),
                        "path": path
                    })

        affected.sort(key=lambda x: x["risk_score"], reverse=True)
        return affected

    def prioritize_remediation(self) -> List[Dict]:
        priorities = []

        for vid, v in self.vuln_index.items():
            score = self.calculate_vulnerability_criticality(vid)
            level = self._priority_level(score)

            priorities.append({
                "id": vid,
                "type": v.get("type"),
                "severity": v.get("severity"),
                "location": v.get("location"),
                "cvss_score": float(v.get("cvss_score", 0.0)),
                "criticality_score": score,
                "priority_level": level
            })

        priorities.sort(key=lambda x: x["criticality_score"], reverse=True)
        self.remediation_priorities = priorities
        return priorities

    def generate_remediation_report(self, output_file: str) -> None:
        if not self.remediation_priorities:
            self.prioritize_remediation()

        report = {
            "generated_at": datetime.now().isoformat(),
            "priorities": []
        }

        for item in self.remediation_priorities:
            vid = item["id"]
            vtype = item.get("type", "")

            entry = dict(item)
            entry["recommended_actions"] = self._recommended_actions(vtype)
            entry["affected_attack_paths"] = self._affected_attack_paths(vid)

            report["priorities"].append(entry)

        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"Remediation report generated: {out_path}")


if __name__ == "__main__":

    vuln_file = "../data/vulnerabilities.json"

    # Generate attack trees
    generator = VulnerabilityAttackTreeGenerator(vuln_file)
    attack_trees = generator.generate_all_trees()

    # Generate attack scenarios
    mapper = AttackPathMapper(vuln_file)
    mapper.build_attack_graph()
    attack_scenarios = mapper.generate_attack_scenarios()

    # Load vulnerability data
    with open(vuln_file, "r", encoding="utf-8") as f:
        vulnerability_data = json.load(f)

    analyzer = RiskAnalyzer(attack_trees, attack_scenarios, vulnerability_data)

    priorities = analyzer.prioritize_remediation()

    print("\n=== Remediation Priorities ===")
    for p in priorities:
        print(
            f"{p['id']}: {p['type']} | CVSS={p['cvss_score']} | "
            f"Criticality={p['criticality_score']:.2f} | Priority={p['priority_level']}"
        )

    analyzer.generate_remediation_report("../output/remediation_report.json")
