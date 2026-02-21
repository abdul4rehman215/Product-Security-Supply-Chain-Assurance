#!/usr/bin/env python3
import json
import logging
from datetime import datetime
from pathlib import Path
import time
import shutil

from threat_model_manager import ThreatModelManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("../logs/threat_updater.log"),
        logging.StreamHandler()
    ]
)

class AutomatedThreatUpdater:
    """Automates threat model updates and alerting."""

    def __init__(self):
        self.tm_manager = ThreatModelManager()

        self.paths = {
            "telemetry": Path("../data/telemetry/security_telemetry.json"),
            "network": Path("../data/network/network_analysis.json"),
            "model": Path("../data/threat-models/updated_threat_model.json"),
            "report": Path("../output/threat_report.json"),
            "backups": Path("../data/threat-models/backups"),
            "alerts_file": Path("../logs/alerts.json"),
        }

        self.alert_thresholds = {
            "new_techniques": 3,
            "frequency_increase_ratio": 0.50,
            "new_indicators": 2,
            "high_frequency": 20
        }

        self.paths["backups"].mkdir(parents=True, exist_ok=True)
        Path("../logs").mkdir(parents=True, exist_ok=True)
        Path("../output").mkdir(parents=True, exist_ok=True)

    def backup_current_model(self):
        """Create timestamped backup of current threat model."""
        if not self.paths["model"].exists():
            logging.info("No existing threat model to backup.")
            return None

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.paths["backups"] / f"threat_model_{ts}.json"
        shutil.copy2(self.paths["model"], backup_file)
        logging.info(f"Created backup: {backup_file}")
        return backup_file

    def detect_changes(self, old_model, new_model):
        """Detect significant changes between threat models."""
        changes = {
            "new_techniques": [],
            "frequency_increases": [],
            "new_malicious_ips": [],
            "new_malicious_domains": [],
            "severity_changes": []
        }

        old_patterns = {p["technique_id"]: p for p in old_model.get("attack_patterns", [])}
        new_patterns = {p["technique_id"]: p for p in new_model.get("attack_patterns", [])}

        # New techniques
        for tid in new_patterns:
            if tid not in old_patterns:
                changes["new_techniques"].append(tid)

        # Frequency increases + severity changes
        for tid, npat in new_patterns.items():
            if tid in old_patterns:
                old_freq = old_patterns[tid].get("frequency", 0)
                new_freq = npat.get("frequency", 0)

                if old_freq > 0:
                    ratio = (new_freq - old_freq) / old_freq
                    if ratio > self.alert_thresholds["frequency_increase_ratio"]:
                        changes["frequency_increases"].append({
                            "technique_id": tid,
                            "old_frequency": old_freq,
                            "new_frequency": new_freq,
                            "increase_ratio": round(ratio, 2)
                        })

                old_sev = old_patterns[tid].get("severity")
                new_sev = npat.get("severity")
                if old_sev != new_sev:
                    changes["severity_changes"].append({
                        "technique_id": tid,
                        "old_severity": old_sev,
                        "new_severity": new_sev
                    })

        # New indicators
        old_ips = {x["ip"] for x in old_model.get("indicators", {}).get("malicious_ips", [])}
        new_ips = {x["ip"] for x in new_model.get("indicators", {}).get("malicious_ips", [])}

        old_domains = {x["domain"] for x in old_model.get("indicators", {}).get("malicious_domains", [])}
        new_domains = {x["domain"] for x in new_model.get("indicators", {}).get("malicious_domains", [])}

        changes["new_malicious_ips"] = sorted(list(new_ips - old_ips))
        changes["new_malicious_domains"] = sorted(list(new_domains - old_domains))

        return changes

    def generate_alerts(self, changes):
        """Generate alerts based on detected changes."""
        alerts = []

        if len(changes["new_techniques"]) >= self.alert_thresholds["new_techniques"]:
            alerts.append({
                "type": "NEW_TECHNIQUES",
                "severity": "high",
                "message": f"Detected {len(changes['new_techniques'])} new techniques: {changes['new_techniques']}",
                "timestamp": datetime.now().isoformat()
            })

        for inc in changes["frequency_increases"]:
            alerts.append({
                "type": "FREQUENCY_INCREASE",
                "severity": "medium",
                "message": (
                    f"Technique {inc['technique_id']} frequency increased "
                    f"from {inc['old_frequency']} to {inc['new_frequency']} "
                    f"(ratio {inc['increase_ratio']})"
                ),
                "timestamp": datetime.now().isoformat()
            })

        if len(changes["new_malicious_ips"]) >= self.alert_thresholds["new_indicators"]:
            alerts.append({
                "type": "NEW_MALICIOUS_IPS",
                "severity": "high",
                "message": f"New malicious IP indicators detected: {changes['new_malicious_ips']}",
                "timestamp": datetime.now().isoformat()
            })

        if len(changes["new_malicious_domains"]) >= self.alert_thresholds["new_indicators"]:
            alerts.append({
                "type": "NEW_MALICIOUS_DOMAINS",
                "severity": "high",
                "message": f"New malicious domain indicators detected: {changes['new_malicious_domains']}",
                "timestamp": datetime.now().isoformat()
            })

        return alerts

    def send_alerts(self, alerts):
        """Process and log alerts."""
        if not alerts:
            logging.info("No alerts generated.")
            return

        for a in alerts:
            level = a.get("severity", "info").lower()
            if level == "high":
                logging.warning(a["message"])
            elif level == "medium":
                logging.info(a["message"])
            else:
                logging.info(a["message"])

        existing = []
        if self.paths["alerts_file"].exists():
            try:
                with open(self.paths["alerts_file"], "r") as f:
                    existing = json.load(f)
                if not isinstance(existing, list):
                    existing = []
            except Exception:
                existing = []

        existing.extend(alerts)

        with open(self.paths["alerts_file"], "w") as f:
            json.dump(existing, f, indent=2)

        logging.info(f"Saved alerts to {self.paths['alerts_file']}")

    def update_threat_model(self):
        """Main update function."""
        logging.info("Starting threat model update cycle...")

        self.backup_current_model()

        old_model = {}
        if self.paths["model"].exists():
            try:
                with open(self.paths["model"], "r") as f:
                    old_model = json.load(f)
            except Exception:
                old_model = {}

        telemetry_data = self.tm_manager.load_telemetry_data(str(self.paths["telemetry"]))
        network_data = self.tm_manager.load_network_data(str(self.paths["network"]))

        telemetry_analysis = self.tm_manager.analyze_telemetry_patterns(telemetry_data)
        network_analysis = self.tm_manager.analyze_network_patterns(network_data)

        self.tm_manager.update_threat_model(telemetry_analysis, network_analysis)
        new_model = self.tm_manager.threat_model

        changes = self.detect_changes(old_model, new_model)
        alerts = self.generate_alerts(changes)
        self.send_alerts(alerts)

        self.tm_manager.save_threat_model(str(self.paths["model"]))
        report = self.tm_manager.generate_threat_report()
        self.tm_manager.save_threat_report(report, str(self.paths["report"]))

        logging.info("Update completed.")
        logging.info(
            f"Techniques: {len(new_model.get('attack_patterns', []))}, "
            f"IPs: {len(new_model.get('indicators', {}).get('malicious_ips', []))}, "
            f"Domains: {len(new_model.get('indicators', {}).get('malicious_domains', []))}"
        )

    def generate_metrics_dashboard(self):
        """Generate metrics for monitoring dashboard."""
        metrics = {
            "generated_at": datetime.now().isoformat(),
            "techniques": 0,
            "severity_counts": {},
            "indicator_counts": {"ips": 0, "domains": 0}
        }

        if not self.paths["model"].exists():
            return metrics

        with open(self.paths["model"], "r") as f:
            model = json.load(f)

        patterns = model.get("attack_patterns", [])
        metrics["techniques"] = len(patterns)

        sev_counts = {}
        for p in patterns:
            sev = p.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        metrics["severity_counts"] = sev_counts

        metrics["indicator_counts"]["ips"] = len(model.get("indicators", {}).get("malicious_ips", []))
        metrics["indicator_counts"]["domains"] = len(model.get("indicators", {}).get("malicious_domains", []))

        metrics_file = Path("../output/metrics.json")
        with open(metrics_file, "w") as f:
            json.dump(metrics, f, indent=2)

        logging.info(f"Saved metrics dashboard to {metrics_file}")
        return metrics

    def run_continuous_monitoring(self, interval_seconds=300):
        """Run continuous threat model updates."""
        logging.info(
            f"Starting continuous monitoring loop (interval={interval_seconds}s)... "
            "Press Ctrl+C to stop."
        )
        while True:
            try:
                self.update_threat_model()
                self.generate_metrics_dashboard()
            except Exception as e:
                logging.error(f"Monitoring error: {e}")
            time.sleep(interval_seconds)


def main():
    updater = AutomatedThreatUpdater()
    updater.update_threat_model()
    updater.generate_metrics_dashboard()


if __name__ == "__main__":
    main()
