# 🧪 Lab 06: Windows Attack Surface Analysis with Open-Source Tools

> **Environment:** Ubuntu 24.04.1 LTS (Cloud Lab)  
> **User:** `toor`  
> **Focus:** Practical attack surface enumeration + automated reporting using Python

---

## 📌 Overview

This lab simulates **Windows-style attack surface analysis concepts** (processes, services, network exposure, and misconfigurations) using **Ubuntu tooling and open-source Python libraries**.  
The goal is to learn **how defenders enumerate and score exposure**, then generate **repeatable reports** that can support audits, hardening, and incident response triage.

---

## 🎯 Objectives

By the end of this lab, you will be able to:

- Understand **attack surface analysis** concepts in system security  
- Enumerate **processes and services** using CLI + scripts  
- Analyze **network exposure** and identify security risks  
- Build **automated security assessment scripts**  
- Generate **JSON + HTML security reports** suitable for sharing

---

## ✅ Prerequisites

- Linux command-line basics
- Understanding of processes/services/network listeners
- Basic Python scripting familiarity
- Basic cybersecurity concepts (exposure, privilege, misconfigurations)

---

## 🧰 Tools Used

- `psutil` (process + network analysis)
- `tabulate` (table formatting)
- `colorama` (terminal readability)
- `htop`, `lsof`, `net-tools` (manual verification + investigation)
- `ss`, `netstat`, `systemctl`, `find`, `stat`

---

## 🗂️ Repo / Lab Folder Structure

```text
lab06-windows-attack-surface-analysis/
│
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
│
├── scripts/
│   ├── process_enum.py
│   ├── service_enum.py
│   ├── attack_surface_analyzer.py
│   ├── vulnerability_scanner.py
│   └── generate_report.py
│
├── artifacts/
│   ├── attack_surface_report.json
│   ├── enumeration_results.txt
│   ├── findings.md
│   ├── security_report.html
│   └── vulnerability_report.json
```

---

## 🧩 Tasks Performed

### ✅ Task 1: Process & Service Enumeration

* Installed required packages and Python libraries
* Built a **process enumerator** (`process_enum.py`) to list top CPU processes and flag suspicious indicators
* Built a **service enumerator** (`service_enum.py`) to list active `systemd` services + detect listening network ports
* Stored outputs in a consolidated file (`enumeration_results.txt`)

### 🛡️ Task 2: Attack Surface Analysis

* Created `attack_surface_analyzer.py` to:

  * detect listening ports via `psutil.net_connections()`
  * map ports → process name/user
  * flag heuristic risks (high-risk ports, root+network)
  * generate a **risk score (0–100)** and export JSON report

### 🧾 Task 3: Reporting

* Created `vulnerability_scanner.py` to check:

  * SSH configuration hardening signals
  * network service exposure patterns
  * file permission issues (world-writable config, SUID/SGID review)
* Created `generate_report.py` to produce:

  * **Executive Summary**
  * **Detailed Findings**
  * **Recommendations**
  * Export to `security_report.html`

### 🔎 Manual Validation

* Cross-checked automation results with:

  * `sudo netstat -tlnp`
  * `ps aux | grep ...`
  * `find /usr/bin -perm -4000`
  * `sudo cat /etc/ssh/sshd_config | grep ...`

---

## 📌 Key Outputs

* `enumeration_results.txt` — combined process + service enumeration output
* `attack_surface_report.json` — structured analyzer report + calculated risk score
* `vulnerability_report.json` — scanner findings + recommendations
* `security_report.html` — human-friendly report for sharing
* `findings.md` — analyst notes + manual verification results

---

## 🧠 What I Learned

* How to **map system exposure** using:

  * listening ports + bound processes
  * privilege context (root vs user)
  * heuristic indicators for suspicious processes
* Why **root + network** is not always malicious, but is **high-value for defenders** to review
* How to create **repeatable audit tooling** with Python for:

  * compliance snapshots
  * triage support
  * change tracking over time
* How reporting formats matter:

  * **JSON** for machines/automation
  * **HTML** for stakeholders

---

## 🌍 Real-World Relevance

Attack surface analysis is a core workflow for:

* **SOC / Blue Team**: baseline exposure + detect drift
* **Hardening & Compliance**: ensure services/ports match policy
* **Incident Response**: identify attacker entry points quickly
* **Cloud Security**: validate instance-level posture and reduce exposed services

---

## ✅ Conclusion

This lab provided a hands-on approach to attack surface analysis using open-source tools and custom automation.
By combining **enumeration**, **heuristic detection**, **risk scoring**, and **report generation**, it demonstrates how defenders build visibility and prioritize remediation.

---
