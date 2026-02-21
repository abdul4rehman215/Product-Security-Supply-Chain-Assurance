#!/usr/bin/env python3
import json
from datetime import datetime
from collections import defaultdict
import os


class ThreatModelManager:
    """Manages threat model creation and updates."""

    def __init__(self):
        self.threat_model = {
            "metadata": {
                "version": "1.0",
                "created_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "description": "Dynamic MITRE ATT&CK-based threat model updated from telemetry and network data"
            },
            "attack_patterns": [],
            "indicators": {
                "malicious_ips": [],
                "malicious_domains": []
            },
            "mitigations": [],
        }

        self.attack_techniques = {
            "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
            "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
            "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
            "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
            "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
            "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
            "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
        }

    def load_telemetry_data(self, file_path):
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Telemetry data JSON must be a list of events")
            return data
        except Exception as e:
            print(f"Error loading telemetry data from {file_path}: {e}")
            return []

    def load_network_data(self, file_path):
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Network data JSON must be a list of flows")
            return data
        except Exception as e:
            print(f"Error loading network data from {file_path}: {e}")
            return []

    def analyze_telemetry_patterns(self, telemetry_data):
        technique_freq = defaultdict(int)
        severity_counts = defaultdict(int)
        host_activity = defaultdict(int)

        for ev in telemetry_data:
            tid = ev.get("technique_id", "UNKNOWN")
            sev = ev.get("severity", "unknown")
            host = ev.get("host", "unknown")

            technique_freq[tid] += 1
            severity_counts[sev] += 1
            host_activity[host] += 1

        return {
            "technique_frequency": dict(technique_freq),
            "severity_distribution": dict(severity_counts),
            "host_activity": dict(host_activity),
            "total_events": len(telemetry_data)
        }

    def analyze_network_patterns(self, network_data):
        malicious_ips = defaultdict(int)
        malicious_domains = defaultdict(int)
        protocol_counts = defaultdict(int)
        indicator_counts = defaultdict(int)

        for flow in network_data:
            proto = flow.get("protocol", "UNKNOWN")
            indicator = flow.get("threat_indicator", "NONE")
            dst_ip = flow.get("dst_ip", "")
            dst_domain = flow.get("dst_domain", "")

            protocol_counts[proto] += 1
            indicator_counts[indicator] += 1

            if indicator in ["C2", "EXFIL"]:
                if dst_ip:
                    malicious_ips[dst_ip] += 1
                if dst_domain:
                    malicious_domains[dst_domain] += 1

        return {
            "malicious_ips": dict(malicious_ips),
            "malicious_domains": dict(malicious_domains),
            "protocol_distribution": dict(protocol_counts),
            "threat_indicator_counts": dict(indicator_counts),
            "total_flows": len(network_data)
        }

    def update_threat_model(self, telemetry_analysis, network_analysis):
        self.threat_model["metadata"]["last_updated"] = datetime.now().isoformat()

        attack_patterns = []
        technique_frequency = telemetry_analysis.get("technique_frequency", {})

        for tid, freq in technique_frequency.items():
            mapping = self.attack_techniques.get(tid, {"name": "Unknown Technique", "tactic": "Unknown"})

            confidence = round(
                min(0.99, 0.50 + (freq / max(1, telemetry_analysis.get("total_events", 1))) * 1.5),
                2
            )

            if freq >= 150:
                severity = "critical"
            elif freq >= 80:
                severity = "high"
            elif freq >= 30:
                severity = "medium"
            else:
                severity = "low"

            attack_patterns.append({
                "technique_id": tid,
                "technique_name": mapping["name"],
                "tactic": mapping["tactic"],
                "frequency": freq,
                "severity": severity,
                "confidence": confidence
            })

        attack_patterns.sort(key=lambda x: x["frequency"], reverse=True)
        self.threat_model["attack_patterns"] = attack_patterns

        ips = network_analysis.get("malicious_ips", {})
        domains = network_analysis.get("malicious_domains", {})

        self.threat_model["indicators"]["malicious_ips"] = [
            {"ip": ip, "count": cnt}
            for ip, cnt in sorted(ips.items(), key=lambda x: x[1], reverse=True)
        ]

        self.threat_model["indicators"]["malicious_domains"] = [
            {"domain": d, "count": cnt}
            for d, cnt in sorted(domains.items(), key=lambda x: x[1], reverse=True)
        ]

    def generate_recommendations(self):
        recs = []
        patterns = self.threat_model.get("attack_patterns", [])

        for p in patterns[:10]:
            tid = p["technique_id"]
            sev = p["severity"]
            freq = p["frequency"]
            tactic = p["tactic"]

            recommendation = {
                "technique_id": tid,
                "tactic": tactic,
                "severity": sev,
                "priority": "high" if sev in ["critical", "high"] else "medium",
                "recommendation": ""
            }

            if tid == "T1110":
                recommendation["recommendation"] = "Implement account lockout policies, MFA, and monitor failed login attempts."
            elif tid == "T1059":
                recommendation["recommendation"] = "Restrict scripting interpreters and enable command-line auditing."
            elif tid == "T1055":
                recommendation["recommendation"] = "Monitor process injection behavior and enable EDR detection."
            elif tid == "T1071":
                recommendation["recommendation"] = "Inspect outbound traffic and apply egress filtering."
            elif tid == "T1041":
                recommendation["recommendation"] = "Monitor data transfer anomalies and apply DLP controls."
            else:
                recommendation["recommendation"] = f"Increase monitoring and detection coverage for {tid} under {tactic}."

            recs.append(recommendation)

        if self.threat_model["indicators"]["malicious_ips"] or \
           self.threat_model["indicators"]["malicious_domains"]:
            recs.append({
                "technique_id": "INDICATORS",
                "tactic": "Command and Control",
                "severity": "high",
                "priority": "high",
                "recommendation": "Block or monitor malicious IPs/domains and update firewall/DNS filtering."
            })

        return recs

    def generate_threat_report(self):
        patterns = self.threat_model.get("attack_patterns", [])
        indicators = self.threat_model.get("indicators", {})

        return {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_attack_patterns": len(patterns),
                "high_severity_techniques": sum(1 for p in patterns if p["severity"] in ["critical", "high"]),
                "top_threats": patterns[:5],
                "indicator_counts": {
                    "malicious_ips": len(indicators.get("malicious_ips", [])),
                    "malicious_domains": len(indicators.get("malicious_domains", []))
                }
            },
            "attack_patterns": patterns,
            "indicators": indicators,
            "recommendations": self.generate_recommendations()
        }

    def save_threat_model(self, file_path):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f:
                json.dump(self.threat_model, f, indent=2)
            print(f"Saved threat model to {file_path}")
            return True
        except Exception as e:
            print(f"Error saving threat model: {e}")
            return False

    def save_threat_report(self, report, file_path):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Saved threat report to {file_path}")
            return True
        except Exception as e:
            print(f"Error saving threat report: {e}")
            return False


def main():
    tm = ThreatModelManager()

    telemetry_file = "../data/telemetry/security_telemetry.json"
    network_file = "../data/network/network_analysis.json"

    telemetry_data = tm.load_telemetry_data(telemetry_file)
    network_data = tm.load_network_data(network_file)

    telemetry_analysis = tm.analyze_telemetry_patterns(telemetry_data)
    network_analysis = tm.analyze_network_patterns(network_data)

    tm.update_threat_model(telemetry_analysis, network_analysis)

    tm.save_threat_model("../data/threat-models/updated_threat_model.json")

    report = tm.generate_threat_report()
    tm.save_threat_report(report, "../output/threat_report.json")

    print("\nThreat Model Summary:")
    print(" Total Telemetry Events:", telemetry_analysis.get("total_events"))
    print(" Total Network Flows:", network_analysis.get("total_flows"))
    print(" Attack Patterns:", len(tm.threat_model.get("attack_patterns", [])))
    print(" Malicious IPs:", len(tm.threat_model["indicators"]["malicious_ips"]))
    print(" Malicious Domains:", len(tm.threat_model["indicators"]["malicious_domains"]))


if __name__ == "__main__":
    main()
