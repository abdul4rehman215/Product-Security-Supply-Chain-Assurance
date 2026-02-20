# 🧪 Lab 7: Trace Product Network Activity Using ProcDOT & Wireshark

**Environment:** Ubuntu 24.04.1 LTS (Cloud Lab Environment)  
**User:** `toor`  

---

## 🎯 Objectives

By the end of this lab, you will be able to:

- Capture and analyze network traffic using **Wireshark / tshark**
- Visualize network communication patterns and flows
- Develop Python scripts to automate traffic capture and analysis
- Identify suspicious network activities in product communications
- Correlate process activities with network traffic for security analysis

---

## 🧰 Tools & Tech Used

- **Wireshark / TShark** (PCAP capture + CLI statistics)
- **PyShark** (PCAP parsing in Python)
- **Pandas** (data processing)
- **Matplotlib + NetworkX** (flow visualization)
- **Linux networking tools** (`ip`, `tshark`, `xdg-open`)

---

## 📁 Repo Structure

```text
lab07-network-analysis/
├── README.md
├── commands.sh
├── output.txt   
├── interview_qna.md
├── troubleshooting.md
│  
├── scripts/
│   ├── traffic_generator.py
│   ├── pcap_converter.py
│   ├── create_procmon_log.py
│   ├── network_visualizer.py
│   ├── automated_analysis.py
│   └── config.py
│   
├── analysis_output/
│   ├── capture_20260221_143522.pcap
│   ├── capture_20260221_143522.csv
│   └── report_20260221_143603.txt
│
├── visual_reports/  
│   ├── product_traffic.pcap
│   ├── network_data.csv
│   ├── procmon_log.csv
│   └── network_flows.png
```

> ✅ **Note:** `analysis_output/` contains timestamped pipeline outputs from the automation script.

---

## 🧩 Lab Tasks Overview

### ✅ Task 1: Environment Setup & Traffic Capture

* Verified **wireshark**, **tshark**, **python3**
* Added user to **wireshark group** for capture permissions
* Identified capture interfaces (`ip link show`, `tshark -D`)
* Generated realistic “product-like” traffic:

  * HTTP GET/POST calls (simulated API telemetry)
  * DNS lookups (simulated product domains)
* Captured traffic into `product_traffic.pcap`

### ✅ Task 2: Convert & Process Captured Data

* Converted PCAP → CSV using **PyShark**
* Generated a simulated process-monitor log (`procmon_log.csv`)

  * Mimics ProcDOT-style correlation inputs

### ✅ Task 3: Network Traffic Visualization

* Built directed network graph from CSV
* Exported visualization as `network_flows.png`
* Generated traffic statistics + basic anomaly detection

### ✅ Task 4: Automated Analysis Pipeline

* Built one-command pipeline:

  * Start traffic generator
  * Start capture
  * Convert PCAP → CSV
  * Create procmon log
  * Generate visualization
  * Generate report into `analysis_output/`

---

## ✅ Expected Outputs

After completing this lab I had:

* `product_traffic.pcap` (manual capture)
* `network_data.csv` (converted packets)
* `procmon_log.csv` (process/network simulation)
* `network_flows.png` (visualized flows)
* `analysis_output/` folder containing:

  * timestamped `capture_*.pcap`
  * timestamped `capture_*.csv`
  * `report_*.txt`

---

## 🌍 Why This Matters (Real-World Relevance)

Tracing product network activity is a core skill in:

* **Product Security**: spotting suspicious beaconing or unexpected endpoints
* **Incident Response**: validating if processes are exfiltrating data
* **Forensics**: reconstructing communications from PCAP captures
* **Threat Hunting**: identifying anomalous flows and unknown infrastructure

This workflow resembles how defenders validate:

* “What did the product talk to?”
* “Was it expected?”
* “Which process initiated it?”
* “Does behavior match compromise indicators?”

---

## 🏁 Conclusion

This lab demonstrated an end-to-end, forensic-style workflow:

* Captured real network traffic using **tshark**
* Converted packet captures into structured datasets
* Visualized network relationships using **NetworkX**
* Automated the entire pipeline into repeatable scripts
* Built foundational correlation capability (process ↔ traffic)

---
