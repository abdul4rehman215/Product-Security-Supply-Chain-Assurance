#!/usr/bin/env python3
"""
Attack Tree Framework for Vulnerability Analysis
Implements AND/OR/LEAF logic with quantitative risk calculation.
"""

import json
from typing import List, Optional, Tuple


class AttackTreeNode:
    """
    Represents a node in an attack tree.

    Attributes:
        name: Node description
        node_type: "AND", "OR", or "LEAF"
        probability: Success probability (0.0-1.0)
        impact: Impact score (0.0-10.0)
        cost: Attack cost estimate
    """

    def __init__(
        self,
        name: str,
        node_type: str = "AND",
        probability: float = 0.0,
        impact: float = 0.0,
        cost: float = 0.0,
    ):
        self.name = name
        self.node_type = node_type.upper().strip()
        self.probability = float(probability)
        self.impact = float(impact)
        self.cost = float(cost)
        self.children: List["AttackTreeNode"] = []
        self.parent: Optional["AttackTreeNode"] = None

    def add_child(self, child: "AttackTreeNode") -> None:
        """
        Add a child node to this node.
        """
        child.parent = self
        self.children.append(child)

    def _aggregate_probability_and_impact(self) -> Tuple[float, float]:
        """
        Recursively aggregate probability and impact.
        """
        if self.node_type == "LEAF":
            p = max(0.0, min(1.0, self.probability))
            impact = max(0.0, min(10.0, self.impact))
            return p, impact

        if not self.children:
            p = max(0.0, min(1.0, self.probability))
            impact = max(0.0, min(10.0, self.impact))
            return p, impact

        child_probs = []
        child_impacts = []

        for c in self.children:
            cp, ci = c._aggregate_probability_and_impact()
            child_probs.append(max(0.0, min(1.0, cp)))
            child_impacts.append(max(0.0, min(10.0, ci)))

        agg_impact = max(child_impacts) if child_impacts else self.impact

        if self.node_type == "AND":
            agg_prob = 1.0
            for p in child_probs:
                agg_prob *= p
            return max(0.0, min(1.0, agg_prob)), agg_impact

        if self.node_type == "OR":
            prod_fail = 1.0
            for p in child_probs:
                prod_fail *= (1.0 - p)
            agg_prob = 1.0 - prod_fail
            return max(0.0, min(1.0, agg_prob)), agg_impact

        return self.probability, self.impact

    def calculate_risk(self) -> float:
        """
        Risk = Probability × Impact
        """
        prob, impact = self._aggregate_probability_and_impact()
        return float(prob * impact)


class AttackTree:
    """
    Main attack tree structure.
    """

    def __init__(self, goal: str):
        self.root = AttackTreeNode(goal, "OR")
        self.nodes = [self.root]

    def add_node(
        self,
        parent_name: str,
        node_name: str,
        node_type: str = "AND",
        probability: float = 0.0,
        impact: float = 0.0,
        cost: float = 0.0,
    ) -> Optional[AttackTreeNode]:

        parent = self.find_node(parent_name)
        if parent is None:
            return None

        new_node = AttackTreeNode(
            node_name,
            node_type=node_type,
            probability=probability,
            impact=impact,
            cost=cost,
        )

        parent.add_child(new_node)
        self.nodes.append(new_node)
        return new_node

    def find_node(self, name: str) -> Optional[AttackTreeNode]:
        for n in self.nodes:
            if n.name == name:
                return n
        return None

    def print_tree(self, node: Optional[AttackTreeNode] = None, level: int = 0) -> None:
        if node is None:
            node = self.root

        indent = "  " * level
        risk = node.calculate_risk()

        print(
            f"{indent}- [{node.node_type}] {node.name} "
            f"(p={node.probability:.2f}, impact={node.impact:.2f}, "
            f"cost={node.cost:.2f}, risk={risk:.2f})"
        )

        for child in node.children:
            self.print_tree(child, level + 1)


# -----------------------------
# Standalone Test
# -----------------------------
if __name__ == "__main__":
    tree = AttackTree("Compromise Web Application")
    tree.add_node("Compromise Web Application", "SQL Injection", "LEAF", 0.8, 9.0, 50)
    tree.print_tree()
