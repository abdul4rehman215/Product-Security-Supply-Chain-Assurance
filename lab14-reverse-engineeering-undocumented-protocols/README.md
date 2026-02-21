# 🧪 Lab 14: Reverse-Engineer Undocumented Protocols

## 📌 Lab Overview
This lab focuses on reverse-engineering an undocumented/custom TCP protocol by capturing real traffic, identifying repeating byte patterns, reconstructing the message format, and documenting a protocol specification. Then we automate analysis and vulnerability detection using Python + Scapy, and create safe localhost-only proof-of-concepts to validate findings.

---

## 🎯 Objectives
By the end of this lab, I was able to:
- Capture and analyze traffic from a custom protocol over TCP
- Reverse-engineer protocol structure (header fields, payload, checksum)
- Build Python tools to parse and dissect messages from PCAP files
- Identify protocol security weaknesses (plaintext leaks, weak integrity, missing auth, replay risk)
- Produce protocol documentation/spec + analysis reports (JSON)

---

## ✅ Prerequisites
- Basic TCP/IP + packet capture concepts
- Python basics (files, structs, classes)
- Linux command line skills
- Familiarity with tcpdump and PCAP format is helpful

---

## 🧰 Lab Environment
- OS: Ubuntu 24.04.1 LTS (Cloud Lab)
- User: `toor`
- Tools/Utilities used:
  - `tcpdump` for packet capture + hex inspection
  - Python 3 for server/client + analysis tooling
  - Scapy for PCAP parsing and automated analysis

---

## 🧩 Tasks Summary (High-Level)
### **Task 1: Capture Traffic from a Custom Protocol**
- Built a custom TCP server and client.
- Captured traffic on localhost using `tcpdump`.
- Confirmed traffic includes consistent magic bytes and readable payloads.

### **Task 2: Reverse-Engineer Protocol Structure**
- Extracted TCP payloads from PCAP.
- Detected common protocol signature (magic bytes).
- Reconstructed message format:
  `[MAGIC(4)][VERSION(1)][TYPE(1)][LENGTH(2)][DATA][CHECKSUM(1)]`
- Implemented analyzer + dissector and saved structured results.

### **Task 3: Identify Security Vulnerabilities**
- Implemented automated scanning:
  - plaintext disclosure detection (keywords like `flag`)
  - weak integrity detection (1-byte checksum)
  - missing authentication / replay risk indicators
  - length mismatch / parsing risk checks
- Created safe localhost-only PoC to demonstrate ease of crafting malformed packets.

### **Task 4: Automate Analysis**
- Built automated analyzer:
  - pattern mining (top magic/prefixes)
  - entropy-based plaintext detection
  - protocol fingerprinting (SHA-256)
- Built a localhost-only fuzzer to generate malformed cases and log anomalies.

---

## 🧾 Key Artifacts Produced
- PCAP capture of the custom protocol session
- Protocol analyzer + dissector outputs (JSON)
- Protocol specification document (JSON)
- Vulnerability report (JSON)
- Exploit PoC results (JSON)
- Automated analysis report (JSON)
- Fuzzing report (JSON)

---

## ✅ Results (What we proved)
- The protocol is **easy to fingerprint** (fixed magic `CPRO`)
- Messages are **plaintext** (low entropy + readable strings)
- Integrity is **weak** (`sum(data) % 256` checksum)
- No authentication/anti-replay fields exist → **injection/replay risk**
- Length-based parsing risks can exist if server-side validation is weak

---

## 🌍 Why This Matters (Real-World Relevance)
Undocumented/proprietary protocols are common in:
- IoT devices (sensors, routers, cameras)
- Industrial control systems (SCADA/OT)
- Internal enterprise tooling
- Legacy client/server applications

Reverse engineering lets security analysts:
- understand how data flows
- detect hidden vulnerabilities
- build detection signatures
- harden systems by enforcing encryption/authentication and safe parsing

---

## ✅ What I Learned
- How to move from raw PCAP bytes → a structured protocol format
- How to confirm field boundaries using hex inspection + `struct.unpack`
- How to automate protocol inspection using Scapy
- How protocol design mistakes create security vulnerabilities quickly
- How to document a protocol clearly for defenders and developers

---

## ⚠️ Safety Note
All exploit/fuzz steps in this lab are **localhost-only** and intended strictly for authorized lab testing.
Never run these techniques against systems you do not own or have permission to test.

---
