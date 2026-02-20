#!/usr/bin/env python3
"""
Draw.io Integration Script
Converts threat model JSON to Draw.io XML format
"""

import json
import xml.etree.ElementTree as ET
from xml.dom import minidom


class DrawioExporter:
    def __init__(self, threat_model_file='threat_model.json'):
        with open(threat_model_file, "r", encoding="utf-8") as f:
            self.model = json.load(f)

        self.assets = self.model.get("assets", [])
        self.threats = self.model.get("threats", [])

        self.threats_by_asset = {}
        for t in self.threats:
            self.threats_by_asset.setdefault(t["asset_id"], []).append(t)

        self._id_counter = 2  # 0 and 1 reserved

    def _next_id(self):
        self._id_counter += 1
        return str(self._id_counter)

    def create_xml_structure(self):
        mxfile = ET.Element("mxfile", {
            "host": "app.diagrams.net",
            "modified": "",
            "agent": "ThreatModelAutomation",
            "version": "20.8.3",
            "type": "device"
        })

        diagram = ET.SubElement(mxfile, "diagram", {
            "id": "diagram1",
            "name": "Threat Model"
        })

        mxGraphModel = ET.SubElement(diagram, "mxGraphModel", {
            "dx": "1000",
            "dy": "1000",
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "1",
            "pageScale": "1",
            "pageWidth": "1100",
            "pageHeight": "850",
            "math": "0",
            "shadow": "0"
        })

        root = ET.SubElement(mxGraphModel, "root")

        ET.SubElement(root, "mxCell", {"id": "0"})
        ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

        return mxfile, root

    def add_asset_node(self, asset, x, y, root):
        cell_id = self._next_id()

        crit = str(asset.get("criticality", "Medium")).lower()
        if crit == "high":
            fill = "#ffe0e0"
        elif crit == "low":
            fill = "#e6ffed"
        else:
            fill = "#e8f0ff"

        style = (
            f"rounded=1;whiteSpace=wrap;html=1;"
            f"strokeColor=#1f2937;fillColor={fill};"
            f"fontStyle=1;"
        )

        cell = ET.SubElement(root, "mxCell", {
            "id": cell_id,
            "value": f"{asset.get('name','')}&#10;({asset.get('type','')})&#10;zone={asset.get('trust_zone','')}",
            "style": style,
            "vertex": "1",
            "parent": "1"
        })

        ET.SubElement(cell, "mxGeometry", {
            "x": str(x),
            "y": str(y),
            "width": "220",
            "height": "90",
            "as": "geometry"
        })

        return cell_id

    def add_threat_node(self, threat, asset_cell_id, x, y, root):
        threat_cell_id = self._next_id()

        risk = int(threat.get("risk_score", 1))
        if risk >= 7:
            fill = "#ffcccc"
            stroke = "#b91c1c"
        elif risk >= 4:
            fill = "#ffe8cc"
            stroke = "#f59e0b"
        else:
            fill = "#fff9c4"
            stroke = "#ca8a04"

        label = (
            f"{threat.get('name','')}&#10;"
            f"MITRE: {threat.get('mitre_id','')}&#10;"
            f"Score: {risk} ({threat.get('likelihood','')}/{threat.get('impact','')})"
        )

        style = (
            f"shape=note;whiteSpace=wrap;html=1;"
            f"fillColor={fill};strokeColor={stroke};"
            f"rounded=1;"
        )

        tcell = ET.SubElement(root, "mxCell", {
            "id": threat_cell_id,
            "value": label,
            "style": style,
            "vertex": "1",
            "parent": "1"
        })

        ET.SubElement(tcell, "mxGeometry", {
            "x": str(x),
            "y": str(y),
            "width": "260",
            "height": "90",
            "as": "geometry"
        })

        edge_id = self._next_id()
        edge = ET.SubElement(root, "mxCell", {
            "id": edge_id,
            "value": "",
            "style": "endArrow=block;html=1;rounded=0;strokeColor=#6b7280;",
            "edge": "1",
            "parent": "1",
            "source": asset_cell_id,
            "target": threat_cell_id
        })

        ET.SubElement(edge, "mxGeometry", {
            "relative": "1",
            "as": "geometry"
        })

        return threat_cell_id

    def generate_drawio_file(self, output_file='automated_threat_model.drawio'):
        mxfile, root = self.create_xml_structure()

        asset_positions = {}
        start_x = 60
        start_y = 60
        x_gap = 300
        y_gap = 220

        for idx, asset in enumerate(self.assets):
            x = start_x + (idx % 2) * x_gap
            y = start_y + (idx // 2) * y_gap
            asset_cell_id = self.add_asset_node(asset, x, y, root)
            asset_positions[asset["id"]] = (asset_cell_id, x, y)

        for asset in self.assets:
            aid = asset["id"]
            if aid not in asset_positions:
                continue
            asset_cell_id, ax, ay = asset_positions[aid]
            threats = self.threats_by_asset.get(aid, [])

            threats_sorted = sorted(threats, key=lambda t: t.get("risk_score", 1), reverse=True)[:6]

            tx = ax + 240
            ty = ay
            for i, t in enumerate(threats_sorted):
                self.add_threat_node(t, asset_cell_id, tx, ty + i * 110, root)

        xml_str = ET.tostring(mxfile, encoding="utf-8")
        parsed = minidom.parseString(xml_str)
        pretty_xml = parsed.toprettyxml(indent="  ", encoding="utf-8")

        with open(output_file, "wb") as f:
            f.write(pretty_xml)

        print(f"[+] Draw.io file generated: {output_file}")
        print("[+] Import instructions:")
        print("    1) Open https://app.diagrams.net/")
        print("    2) File -> Import From -> Device")
        print(f"    3) Select {output_file}")


def main():
    exporter = DrawioExporter()
    exporter.generate_drawio_file("automated_threat_model.drawio")


if __name__ == "__main__":
    main()
