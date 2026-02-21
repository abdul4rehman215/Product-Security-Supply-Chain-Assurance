# 📊 Lab 09: Visualize Security Findings with Matplotlib

> **Category:** Product Security & Supply Chain Assurance  
> **Environment:** Ubuntu 24.04.x (Cloud Lab VM)  
> **User:** `toor`  
> **Working Directory:** `~/security_viz_lab`

This lab focuses on transforming raw security events and vulnerability scan results into **clear, actionable visual insights** using **Python + Matplotlib**. The output includes multiple PNG charts, a vulnerability dashboard image, a multi-page **PDF security report**, and a text-based summary report.

---

## 🧠 Objectives

By the end of this lab, I was able to:

- Create security data visualizations using **Matplotlib**
- Analyze security event patterns using time-series & categorical charts
- Generate an **automated PDF security report** with embedded plots
- Interpret threat intelligence patterns (country, protocol, port)
- Apply visualization best practices for cybersecurity reporting

---

## ✅ Prerequisites

- Python basics (scripts, functions, file I/O)
- Understanding of core cybersecurity concepts (events, severity, CVSS)
- Familiarity with Linux CLI operations
- Comfort with CSV datasets

---

## 🗂️ Repository Structure (Lab 09)

```text
lab09-visualize-security-findings-matplotlib/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── data/
│   ├── security_events.csv
│   └── vulnerabilities.csv
├── scripts/
│   ├── basic_viz.py
│   ├── timeline_viz.py
│   ├── geo_viz.py
│   ├── vuln_dashboard.py
│   ├── report_generator.py
│   └── stats_summary.py
└── outputs/
    ├── event_pie_chart.png
    ├── severity_bar_chart.png
    ├── timeline_analysis.png
    ├── severity_timeline.png
    ├── geo_threats.png
    ├── protocol_analysis.png
    ├── vuln_dashboard.png
    ├── security_report.pdf
    └── security_summary.txt
````

---

## 🧪 Lab Workflow Overview

### ✅ Task 1 — Environment Setup + Data Preparation

* Created a structured lab directory
* Verified Python version and required dependencies
* Created two CSV datasets:

  * `security_events.csv` (event telemetry)
  * `vulnerabilities.csv` (scan findings with CVSS)

### ✅ Task 2 — Basic Security Visualizations

Generated:

* **Event type distribution** (pie chart)
* **Severity level breakdown** (bar chart)

### ✅ Task 3 — Time-Series + Threat Source Analytics

Generated:

* **Hourly event timeline** (line chart)
* **Severity over time** (stacked area chart)
* **Threat sources by country** (horizontal bar chart)
* **Protocol distribution** (bar chart)

> Note: The sample dataset timestamps occur between **08:30–08:39**, so the hourly timeline is concentrated around **hour 8**, which is expected.

### ✅ Task 4 — Vulnerability Assessment Dashboard

Built a 4-panel dashboard image covering:

* CVSS distribution
* Vulnerability types
* Remediation status by severity (stacked bars)
* Risk scoring for open findings

### ✅ Task 5 — Automated Security Report Generator

Generated:

* `security_report.pdf` → multi-page PDF with charts and analysis
* `security_summary.txt` → text-based report with key metrics and top lists

---

## 📌 Results (What Was Produced)

### 🖼️ Charts Created (PNG)

* `event_pie_chart.png`
* `severity_bar_chart.png`
* `timeline_analysis.png`
* `severity_timeline.png`
* `geo_threats.png`
* `protocol_analysis.png`
* `vuln_dashboard.png`

### 📄 Reports Created

* `security_report.pdf` (multi-page, chart-embedded)
* `security_summary.txt` (executive-friendly text output)

---

## 🔐 Why This Matters (Security Relevance)

Security teams don’t just detect threats — they must **communicate** them clearly.

This lab demonstrates skills needed for:

* SOC dashboards
* Blue-team reporting
* Vulnerability prioritization
* Threat hunting summaries
* Executive security communication

Visualization improves speed and clarity when identifying:

* attack concentration (ports, protocols)
* high-severity activity trends
* geographic threat patterns
* vulnerability exposure & remediation progress

---

## 🧾 Key Takeaways

* Matplotlib can create professional, repeatable security visuals
* Visualization reveals trends hidden in raw logs
* Automated reporting saves time and improves consistency
* CVSS + severity + status can be combined into actionable risk scoring

---

## 🏁 Conclusion

This lab strengthened my ability to convert security data into **visual intelligence** and produce **automated security reports**. These skills are foundational for SOC analysis, vulnerability management workflows, and communicating security posture effectively.

---
