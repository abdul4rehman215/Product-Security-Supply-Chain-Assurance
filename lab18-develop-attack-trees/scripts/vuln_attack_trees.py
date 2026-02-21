#!/usr/bin/env python3
"""
Generate attack trees for specific vulnerability types.
Creates structured attack trees (SQLi, XSS, Weak Auth) from JSON dataset.
"""

import json
from pathlib import Path

from attack_tree import AttackTree


class VulnerabilityAttackTreeGenerator:
    """Generate attack trees for identified vulnerabilities."""

    def __init__(self, vulnerability_file: str):
        """
        Initialize generator with vulnerability data.

        Args:
            vulnerability_file: Path to JSON vulnerability file
        """
        self.vulnerability_file = vulnerability_file
        self.vuln_data = self._load_vulnerability_data(vulnerability_file)
        self.attack_trees = {}

    def _load_vulnerability_data(self, vulnerability_file: str) -> dict:
        vuln_path = Path(vulnerability_file)
        if not vuln_path.exists():
            raise FileNotFoundError(f"Vulnerability file not found: {vulnerability_file}")

        with open(vuln_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _flatten_vulnerabilities(self) -> list:
        """
        Flatten vulnerability structure into a list of vulnerability dicts.
        Adds `_category` to each vuln entry.
        """
        vulns = []
        for category_name, category_data in self.vuln_data.items():
            for v in category_data.get("vulnerabilities", []):
                v_copy = dict(v)
                v_copy["_category"] = category_name
                vulns.append(v_copy)
        return vulns

    def create_sql_injection_tree(self, vuln_data: dict) -> AttackTree:
        """
        Create attack tree for SQL injection vulnerability.

        Tree Structure:
        Root: Exploit SQL Injection
        ├── Bypass Authentication (AND)
        │   ├── Identify Injection Point (LEAF)
        │   ├── Craft Payload (LEAF)
        │   └── Execute Injection (LEAF)
        └── Extract Data (AND)
            ├── Enumerate Schema (LEAF)
            └── Extract Credentials (LEAF)
        """
        root_goal = f"Exploit SQL Injection ({vuln_data.get('id', 'UNKNOWN')})"
        tree = AttackTree(root_goal)

        bypass = tree.add_node(root_goal, "Bypass Authentication", "AND", probability=0.60, impact=8.0, cost=30)
        extract = tree.add_node(root_goal, "Extract Data", "AND", probability=0.70, impact=9.0, cost=40)

        if bypass:
            tree.add_node("Bypass Authentication", "Identify Injection Point", "LEAF", probability=0.85, impact=6.0, cost=10)
            tree.add_node("Bypass Authentication", "Craft Payload", "LEAF", probability=0.80, impact=7.0, cost=15)
            tree.add_node("Bypass Authentication", "Execute Injection", "LEAF", probability=0.75, impact=8.0, cost=5)

        if extract:
            tree.add_node("Extract Data", "Enumerate Schema", "LEAF", probability=0.70, impact=7.0, cost=20)
            tree.add_node("Extract Data", "Extract Credentials", "LEAF", probability=0.65, impact=9.0, cost=20)

        return tree

    def create_xss_tree(self, vuln_data: dict) -> AttackTree:
        """
        Create attack tree for XSS vulnerability.

        Tree Structure:
        Root: Exploit XSS
        ├── Steal Session Cookies (AND)
        │   ├── Inject Script (LEAF)
        │   ├── Victim Visits Page (LEAF)
        │   └── Extract Cookies (LEAF)
        └── Phishing Attack (AND)
            ├── Create Phishing Page (LEAF)
            └── Inject Redirect (LEAF)
        """
        root_goal = f"Exploit XSS ({vuln_data.get('id', 'UNKNOWN')})"
        tree = AttackTree(root_goal)

        steal = tree.add_node(root_goal, "Steal Session Cookies", "AND", probability=0.55, impact=7.5, cost=25)
        phishing = tree.add_node(root_goal, "Phishing Attack", "AND", probability=0.50, impact=8.0, cost=35)

        if steal:
            tree.add_node("Steal Session Cookies", "Inject Script", "LEAF", probability=0.80, impact=6.5, cost=10)
            tree.add_node("Steal Session Cookies", "Victim Visits Page", "LEAF", probability=0.60, impact=6.0, cost=5)
            tree.add_node("Steal Session Cookies", "Extract Cookies", "LEAF", probability=0.70, impact=7.5, cost=10)

        if phishing:
            tree.add_node("Phishing Attack", "Create Phishing Page", "LEAF", probability=0.75, impact=7.0, cost=15)
            tree.add_node("Phishing Attack", "Inject Redirect", "LEAF", probability=0.65, impact=8.0, cost=20)

        return tree

    def create_weak_auth_tree(self, vuln_data: dict) -> AttackTree:
        """
        Create attack tree for weak authentication.

        Tree Structure:
        Root: Exploit Weak Authentication
        ├── Brute Force (AND)
        │   ├── Identify Usernames (LEAF)
        │   └── Automated Attempts (LEAF)
        └── Dictionary Attack (AND)
            ├── Obtain Password List (LEAF)
            └── Test Passwords (LEAF)
        """
        root_goal = f"Exploit Weak Authentication ({vuln_data.get('id', 'UNKNOWN')})"
        tree = AttackTree(root_goal)

        brute = tree.add_node(root_goal, "Brute Force", "AND", probability=0.55, impact=8.0, cost=40)
        dictionary = tree.add_node(root_goal, "Dictionary Attack", "AND", probability=0.60, impact=8.5, cost=30)

        if brute:
            tree.add_node("Brute Force", "Identify Usernames", "LEAF", probability=0.70, impact=5.5, cost=10)
            tree.add_node("Brute Force", "Automated Attempts", "LEAF", probability=0.65, impact=8.0, cost=30)

        if dictionary:
            tree.add_node("Dictionary Attack", "Obtain Password List", "LEAF", probability=0.75, impact=6.0, cost=10)
            tree.add_node("Dictionary Attack", "Test Passwords", "LEAF", probability=0.70, impact=8.5, cost=20)

        return tree

    def generate_all_trees(self) -> dict:
        """
        Generate attack trees for all vulnerabilities.

        Returns:
            Dict mapping vulnerability ID -> AttackTree
        """
        vulnerabilities = self._flatten_vulnerabilities()

        for v in vulnerabilities:
            vid = v.get("id", "UNKNOWN")
            vtype = (v.get("type", "") or "").strip().lower()

            if "sql injection" in vtype:
                self.attack_trees[vid] = self.create_sql_injection_tree(v)

            elif "cross-site scripting" in vtype or "xss" in vtype:
                self.attack_trees[vid] = self.create_xss_tree(v)

            elif "weak authentication" in vtype or "authentication" in vtype:
                self.attack_trees[vid] = self.create_weak_auth_tree(v)

            else:
                root_goal = f"Exploit {v.get('type', 'Unknown Vulnerability')} ({vid})"
                tree = AttackTree(root_goal)
                tree.add_node(root_goal, "Identify Exploit Technique", "LEAF", probability=0.50, impact=5.0, cost=20)
                tree.add_node(root_goal, "Execute Exploit", "LEAF", probability=0.40, impact=6.0, cost=30)
                self.attack_trees[vid] = tree

        return self.attack_trees

    def print_all_trees(self) -> None:
        """Print all generated attack trees."""
        for vuln_id, tree in self.attack_trees.items():
            print("\n" + "=" * 60)
            print(f"Attack Tree for Vulnerability: {vuln_id}")
            print("=" * 60)
            tree.print_tree()


if __name__ == "__main__":
    generator = VulnerabilityAttackTreeGenerator("../data/vulnerabilities.json")
    generator.generate_all_trees()
    generator.print_all_trees()
