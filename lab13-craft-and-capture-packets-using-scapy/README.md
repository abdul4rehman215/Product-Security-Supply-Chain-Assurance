# 🧪 Lab 13: Craft and Capture Packets Using Scapy

This lab covers **packet crafting, packet capture, filtering, and automation** using **Scapy** on Ubuntu Linux.  
The goal is to understand how packets are structured, how traffic can be captured in real time, and how these workflows can be automated for security testing and analysis.

---

## 🎯 Objectives
By the end of this lab, I was able to:
- Install and verify Scapy in Ubuntu 24.04
- Craft packets for common protocols (ICMP, TCP, UDP)
- Save crafted traffic into PCAP files for analysis
- Capture live traffic using Scapy sniffing methods
- Apply filters for focused capture (TCP-only, HTTP, DNS)
- Automate send + capture + response-correlation workflows

---

## ✅ Prerequisites
- Basic Python programming
- TCP/IP fundamentals
- Linux command-line basics
- Familiarity with TCP/UDP/ICMP concepts

---

## 🧰 Lab Environment
- Ubuntu 24.04 LTS (Cloud Lab)
- Python 3.x
- Scapy (installed via Ubuntu packages)
- Supporting tools: tcpdump, curl, dnsutils, libpcap 
- **User:** `toor`  
- **Scapy Version:** 2.5.0  
- **Interfaces Observed:** `lo`, `ens5` 

---

## 📁 Folder Structure
```text
lab13-craft-and-capture-packets-using-scapy/
├── README.md
├── commands.sh
├── output.txt
├── scripts/
│   ├── packet_crafter.py
│   ├── advanced_crafter.py
│   ├── packet_capture.py
│   ├── filtered_capture.py
│   ├── packet_automation.py
│   └── send_receive.py 
├── pcaps/
│   ├── crafted_packets.pcap
│   ├── advanced_packets.pcap
│   ├── captured.pcap
│   ├── tcp_only.pcap
│   ├── http_traffic.pcap
│   ├── dns_traffic.pcap
│   ├── automation_sent_*.pcap
│   └── automation_captured_*.pcap
├── reports/
│   └── automation_report_*.json
├── interview_qna.md
└── troubleshooting.md
```

---

## 🧩 Tasks Overview

### Task 1: Install + Verify Scapy

* Installed Scapy and required dependencies
* Verified import/version and identified active interfaces

### Task 2: Craft Packets (ICMP/TCP/UDP)

* Built scripts to craft:

  * ICMP echo request
  * TCP SYN packets
  * UDP payload packets
* Exported crafted packets into PCAP for offline inspection

### Task 3: Capture + Filter Live Traffic

* Created scripts to sniff traffic on a chosen interface
* Generated statistics (protocol counts, top IPs, top ports)
* Implemented filtered captures for:

  * TCP-only
  * HTTP (port 80)
  * DNS (port 53)

### Task 4: Automate Packet Operations

* Automated:

  * background packet capture
  * sending sequences (ping + SYN scans)
  * correlating responses (ICMP replies, TCP RST/SYN-ACK)
* Generated PCAP + JSON report artifacts

---

## ✅ Results (Summary)

* Successfully generated **multiple PCAP artifacts** (crafted + captured + filtered captures)
* Captured and verified real traffic patterns (ICMP, TCP handshake, HTTP payload preview, DNS queries/answers)
* Produced automation output reports to support repeatable testing

---

## 📘 What I Learned

* How packet layers are built and stacked (IP/TCP/UDP/ICMP)
* How sniffing works and why interface selection matters
* How filters reduce noise and improve investigations
* How to build repeatable network test workflows using automation

---

## 🧠 Why This Matters

Packet crafting and capture are foundational for:

* network troubleshooting,
* intrusion detection validation,
* protocol testing,
* blue-team investigations,
* and offensive security assessments.

---

## 🌍 Real-World Relevance / Applications

* Verifying IDS/IPS detection rules with controlled packet patterns
* Investigating suspicious traffic using filtered packet capture
* Testing protocol behavior (timeouts, responses, firewall behavior)
* Building lightweight network monitoring and analysis tools

---

## 📌 Notes

* Raw socket crafting/sniffing typically requires **sudo/root**.
* If a default interface isn’t available, scripts should fall back to an available interface.

---
