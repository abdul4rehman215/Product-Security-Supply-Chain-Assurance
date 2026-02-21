#!/usr/bin/env python3
"""
CVSS v3.1 Calculator
Implements full CVSS v3.1 Base Score calculation.
"""

import json
import math
from typing import Dict, List


class CVSSCalculator:
    """CVSS v3.1 Base Score Calculator"""

    # CVSS v3.1 metric values
    ATTACK_VECTOR = {
        "Network": 0.85,
        "Adjacent": 0.62,
        "Local": 0.55,
        "Physical": 0.2,
    }

    ATTACK_COMPLEXITY = {
        "Low": 0.77,
        "High": 0.44,
    }

    PRIVILEGES_REQUIRED = {
        "None": 0.85,
        "Low": 0.62,
        "High": 0.27,
    }

    PRIVILEGES_REQUIRED_CHANGED = {
        "None": 0.85,
        "Low": 0.68,
        "High": 0.5,
    }

    USER_INTERACTION = {
        "None": 0.85,
        "Required": 0.62,
    }

    IMPACT_METRICS = {
        "None": 0.0,
        "Low": 0.22,
        "High": 0.56,
    }

    def calculate_exploitability_score(self, av: float, ac: float, pr: float, ui: float) -> float:
        """Exploitability = 8.22 × AV × AC × PR × UI"""
        return 8.22 * av * ac * pr * ui

    def calculate_impact_score(self, c: float, i: float, a: float, scope: str) -> float:
        """
        Impact Score:
        ISS = 1 - [(1-C) × (1-I) × (1-A)]
        """
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        scope = scope.strip()
        if scope not in ("Unchanged", "Changed"):
            scope = "Unchanged"

        if scope == "Unchanged":
            return 6.42 * iss

        return 7.52 * (iss - 0.029) - 3.25 * pow((iss - 0.02), 15)

    def calculate_base_score(self, exploitability: float, impact: float, scope: str) -> float:
        """
        Base Score calculation per CVSS v3.1 specification.
        """
        scope = scope.strip()
        if scope not in ("Unchanged", "Changed"):
            scope = "Unchanged"

        if impact <= 0:
            return 0.0

        if scope == "Unchanged":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

        return math.ceil(score * 10) / 10.0

    def get_severity_rating(self, score: float) -> str:
        """Return severity based on CVSS score."""
        if score == 0.0:
            return "None"
        if 0.1 <= score <= 3.9:
            return "Low"
        if 4.0 <= score <= 6.9:
            return "Medium"
        if 7.0 <= score <= 8.9:
            return "High"
        if 9.0 <= score <= 10.0:
            return "Critical"
        return "Unknown"

    def create_vector_string(self, vulnerability: Dict) -> str:
        """Create CVSS vector string."""
        av_map = {"Network": "N", "Adjacent": "A", "Local": "L", "Physical": "P"}
        ac_map = {"Low": "L", "High": "H"}
        pr_map = {"None": "N", "Low": "L", "High": "H"}
        ui_map = {"None": "N", "Required": "R"}
        s_map = {"Unchanged": "U", "Changed": "C"}
        cia_map = {"None": "N", "Low": "L", "High": "H"}

        av = av_map.get(vulnerability.get("attack_vector"), "N")
        ac = ac_map.get(vulnerability.get("attack_complexity"), "L")
        pr = pr_map.get(vulnerability.get("privileges_required"), "N")
        ui = ui_map.get(vulnerability.get("user_interaction"), "N")
        s = s_map.get(vulnerability.get("scope"), "U")
        c = cia_map.get(vulnerability.get("confidentiality_impact"), "N")
        i = cia_map.get(vulnerability.get("integrity_impact"), "N")
        a = cia_map.get(vulnerability.get("availability_impact"), "N")

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    def calculate_cvss(self, vulnerability: Dict) -> Dict:
        """Calculate full CVSS scoring result."""

        av_name = vulnerability.get("attack_vector", "Network")
        ac_name = vulnerability.get("attack_complexity", "Low")
        pr_name = vulnerability.get("privileges_required", "None")
        ui_name = vulnerability.get("user_interaction", "None")
        scope = vulnerability.get("scope", "Unchanged")

        c_name = vulnerability.get("confidentiality_impact", "None")
        i_name = vulnerability.get("integrity_impact", "None")
        a_name = vulnerability.get("availability_impact", "None")

        av = self.ATTACK_VECTOR.get(av_name, 0.85)
        ac = self.ATTACK_COMPLEXITY.get(ac_name, 0.77)
        ui = self.USER_INTERACTION.get(ui_name, 0.85)
        c = self.IMPACT_METRICS.get(c_name, 0.0)
        i = self.IMPACT_METRICS.get(i_name, 0.0)
        a = self.IMPACT_METRICS.get(a_name, 0.0)

        if scope == "Changed":
            pr = self.PRIVILEGES_REQUIRED_CHANGED.get(pr_name, 0.85)
        else:
            pr = self.PRIVILEGES_REQUIRED.get(pr_name, 0.85)

        exploitability = self.calculate_exploitability_score(av, ac, pr, ui)
        impact = self.calculate_impact_score(c, i, a, scope)
        base_score = self.calculate_base_score(exploitability, impact, scope)
        severity = self.get_severity_rating(base_score)
        vector = self.create_vector_string(vulnerability)

        return {
            "id": vulnerability.get("id"),
            "name": vulnerability.get("name"),
            "description": vulnerability.get("description"),
            "cve": vulnerability.get("cve"),
            "metrics": {
                "attack_vector": av_name,
                "attack_complexity": ac_name,
                "privileges_required": pr_name,
                "user_interaction": ui_name,
                "scope": scope,
                "confidentiality_impact": c_name,
                "integrity_impact": i_name,
                "availability_impact": a_name,
            },
            "scores": {
                "exploitability": round(exploitability, 2),
                "impact": round(impact, 2),
                "base_score": base_score,
            },
            "severity": severity,
            "vector": vector,
        }

    def process_vulnerabilities_file(self, filename: str) -> List[Dict]:
        """Process vulnerability JSON file."""
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulns = data.get("vulnerabilities", [])
        results = []

        for v in vulns:
            results.append(self.calculate_cvss(v))

        return results


def main():
    calculator = CVSSCalculator()

    print("CVSS v3.1 Calculator")
    print("=" * 50)

    sample_file = "../vulnerabilities/sample_vulnerabilities.json"
    results = calculator.process_vulnerabilities_file(sample_file)

    results_sorted = sorted(results, key=lambda x: x["scores"]["base_score"], reverse=True)

    for r in results_sorted:
        print(f"Processed {r['id']}: {r['scores']['base_score']} ({r['severity']})")

    if results_sorted:
        avg = sum(r["scores"]["base_score"] for r in results_sorted) / len(results_sorted)
        print("-" * 50)
        print(f"Total vulnerabilities processed: {len(results_sorted)}")
        print(f"Average CVSS score: {avg:.2f}")
        print(f"Highest score: {results_sorted[0]['id']} = {results_sorted[0]['scores']['base_score']}")
        print(f"Lowest score: {results_sorted[-1]['id']} = {results_sorted[-1]['scores']['base_score']}")


if __name__ == "__main__":
    main()
