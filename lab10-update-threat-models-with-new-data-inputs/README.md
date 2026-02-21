# 🧪 Lab 10: Update Threat Models with New Data Inputs  

**Environment:** Ubuntu 24.04.x (Cloud Lab)  
**User:** `toor`  
**Working Directory:** `~/threat-model-lab`

---

## 📌 Objective
This lab focuses on **dynamic threat modeling** using **new data inputs** (telemetry + network flows). Instead of a static threat model, we build a workflow that continuously:
- generates/ingests telemetry and network data
- maps activity to **MITRE ATT&CK techniques**
- updates the threat model automatically
- detects changes and triggers alerts
- produces reports + visualizations for stakeholders

---

## 🎯 Learning Outcomes
By the end of this lab, I was able to:

- Integrate telemetry + network indicators into threat models
- Identify attack patterns and threat indicators from event streams
- Automate threat model updates using Python
- Generate actionable threat intelligence reports (JSON + recommendations)
- Implement basic continuous monitoring (backups, logs, metrics, config-driven workflow)

---

## ✅ Prerequisites
- Basic cybersecurity & threat modeling concepts  
- Familiarity with MITRE ATT&CK  
- Python fundamentals  
- Linux CLI experience  
- Comfortable working with JSON/YAML

---

## 🧱 Repo / Folder Structure

```text
lab10-update-threat-models-with-new-data-inputs/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── data/
│   ├── telemetry/
│   │   └── security_telemetry.json
│   ├── network/
│   │   └── network_analysis.json
│   └── threat-models/
│       ├── updated_threat_model.json
│       └── backups/
│           ├── threat_model_20260221_165418.json
│           └── threat_model_20260221_170344.json
├── scripts/
│   ├── telemetry_generator.py
│   ├── network_data_generator.py
│   ├── threat_model_manager.py
│   ├── automated_threat_updater.py
│   ├── visualize_threats.py
│   ├── threat_intel_config.yaml
│   └── config_loader.py
├── logs/
│   ├── threat_updater.log
│   └── alerts.json
└── output/
    ├── threat_report.json
    ├── metrics.json
    ├── technique_frequency.png
    ├── severity_distribution.png
    └── tactic_coverage.png
````

---

## 🧩 Task Overview

### ✅ Task 1 — Setup + Sample Data Generation

* Create lab structure
* Create + activate Python virtual environment
* Generate:

  * `security_telemetry.json` (1000 events, MITRE technique IDs)
  * `network_analysis.json` (500 flows, suspicious indicators)

### ✅ Task 2 — Threat Model Manager (MITRE ATT&CK mapped)

* Parse telemetry and network JSON
* Compute:

  * technique frequency
  * severity distribution
  * indicator extraction (IPs / domains)
* Build an updated threat model:

  * `data/threat-models/updated_threat_model.json`
* Generate threat report with recommendations:

  * `output/threat_report.json`

### ✅ Task 3 — Automated Threat Model Updates

* Create automation pipeline that:

  * backs up the previous threat model
  * detects changes (new techniques, deltas, indicator changes)
  * generates alerts (log + JSON)
  * writes monitoring metrics (`metrics.json`)
  * updates model + report

### ✅ Task 4 — Visualization + Config-driven workflow

* Visualize:

  * top technique frequency
  * severity distribution
  * MITRE tactic coverage
* Add YAML config file for CI-style workflow
* Validate config structure via loader script

---

## 📊 Result (What You Built)

You produced a **repeatable threat modeling pipeline** that:

* takes raw telemetry + network data
* extracts MITRE ATT&CK patterns + indicators
* updates a threat model dynamically
* logs changes and generates actionable output artifacts
* exports reporting and charts for security teams

---

## 🔐 Why This Matters (Security Relevance)

Static threat models become obsolete quickly. This lab demonstrates a practical path toward:

* **continuous threat modeling**
* **data-driven MITRE ATT&CK coverage**
* **operational detection engineering alignment**
* **threat intel reporting + stakeholder communication**
* **alerting and monitoring** when threat model changes

---

## 🌍 Real-World Applications

* SOC pipelines: update detection priorities as techniques trend up/down
* Blue team ops: map telemetry detections to MITRE for coverage gaps
* Product security: track attack techniques across fleets of devices
* Threat intel: maintain an evolving model of active threats and indicators
* Governance: generate consistent threat intelligence reports for review

---

## 🏁 Conclusion

This lab demonstrates how threat models can evolve automatically when new telemetry and network evidence appears. By combining MITRE ATT&CK mappings, analysis pipelines, reporting, alerting, and visuals, you gain a workflow that supports **continuous monitoring** and **dynamic threat intelligence**—a critical requirement for modern security programs.
