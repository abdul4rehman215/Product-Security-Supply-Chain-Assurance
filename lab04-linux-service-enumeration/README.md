# 🧪 Lab 4: Perform Linux Service Enumeration with nmap & netstat

## 🎯 Objectives
By the end of this lab, I was able to:
- Understand the fundamentals of Linux service enumeration
- Use **nmap** to discover open ports and identify service versions
- Use **netstat** to inspect listening services and active network connections
- Automate enumeration workflows using **Bash** and **Python**
- Interpret results for basic security assessment and reporting

---

## ✅ Prerequisites
- Basic Linux command-line knowledge
- Understanding of IPs, ports, TCP/UDP, and common services (SSH/HTTP/etc.)
- Python basics (running scripts, installing modules)
- Authorization to scan the target (ethical requirement)

---

## 🧪 Lab Environment
- Platform: Ubuntu 24.04 cloud lab machine
- Tools:
  - `nmap`
  - `netstat` (from `net-tools`)
  - Python 3.x
  - Python module: `python-nmap`

---

## 📁 Repository Structure

```
lab04-linux-service-enumeration/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── scripts/
│   ├── nmap_scan.sh
│   ├── netstat_monitor.sh
│   ├── master_enumeration.sh
│   ├── service_enumeration.py
│   ├── advanced_nmap_scripts.py
│   └── analyze_services.py 
```    
---

## 🧩 Lab Tasks Overview 
### Task 1: Service Enumeration with nmap
- Verified installation and version
- Performed scans:
  - Basic scan and port range scan
  - Full port scan
  - Service/version detection (`-sV`)
  - Aggressive scan (`-A`)
  - Default NSE scripts (`-sC`)

### Task 2: Network Visibility with netstat
- Identified:
  - Listening ports and bound interfaces
  - Active connections (established sessions)
  - Process mapping (where allowed)
  - Network statistics and routing table

### Task 3: Automation
- Created automation scripts to:
  - Run repeated scans consistently
  - Save results into organized report files
  - Generate summaries (JSON/TXT) for quick review

---

## 📌 Results Summary
- Detected **SSH service on TCP port 22**
- **Service Version:** `OpenSSH 9.6p1 Ubuntu 3ubuntu13`
- Verified the system is actively listening on SSH (IPv4 + IPv6)
- Observed at least **one established SSH connection** (current session)

---

## 🧠 What I Learned
- How to quickly discover exposed services on a Linux host
- How to validate scan findings by comparing `nmap` results with `netstat`
- How automation improves repeatability, consistency, and reporting

---

## 🔐 Why This Matters
Service enumeration is often the **first step** in:
- Security assessments and penetration tests
- Incident response triage (checking unexpected listeners)
- System hardening and attack-surface reduction
- Continuous monitoring and compliance checks

---

## 🌍 Real-World Applications
- Detect unauthorized services running on production servers
- Baseline system exposure (what ports SHOULD be open vs. what IS open)
- Support vulnerability management by identifying service versions
- Assist defenders in spotting suspicious connections or abnormal listeners

---

## 📁 Generated Output Folders
- `scan_results/` (from `nmap_scan.sh`)
- `netstat_results/` (from `netstat_monitor.sh`)
- `enumeration_results/` (from `service_enumeration.py`)
- `master_enumeration_YYYYMMDD_HHMMSS/` (from `master_enumeration.sh`)

---

## 🧠 Notes
- Some `netstat -lnp` output is limited without root.
- UDP scanning requires sudo (`sudo nmap -sU ...`).
- Python script indentation in the lab text was corrected so the script runs (logic unchanged).

---

## ✅ Conclusion
This lab demonstrated how to enumerate Linux services using both **active scanning (nmap)**
and **local inspection (netstat)**, then automate the workflow using scripts.
The result is a repeatable process that helps identify exposed services and supports
basic security posture assessment.
