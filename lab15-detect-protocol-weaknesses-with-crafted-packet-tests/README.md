# 🧪 Lab 15: Detect Protocol Weaknesses with Crafted Packet Tests

## 📌 Lab Summary
This lab focuses on **protocol security testing** by crafting custom packets and sending them to a **deliberately vulnerable protocol server**. Using **Python + Scapy**, we performed structured tests (valid/invalid fields, hidden commands, overflow conditions, injection-like payloads), then automated scanning and traffic pattern analysis to identify protocol weaknesses and document results.

---

## 🎯 Objectives
By the end of this lab, I was able to:
- Craft custom packets using **Scapy** to test protocol implementations
- Identify common protocol vulnerabilities through systematic testing
- Automate protocol security testing using Python scripts
- Analyze protocol responses and observed traffic patterns
- Generate and export a vulnerability scan report (JSON)

---

## ✅ Prerequisites
- Basic understanding of TCP/IP networking and OSI model
- Familiarity with Python (loops, functions, exceptions)
- Basic Linux command line skills
- Understanding of packet structure (headers/payload)

---

## 🧪 Lab Environment

| Component | Details |
|---|---|
| OS | Ubuntu 24.04 LTS (Cloud Lab) |
| User | `toor` |
| Python | 3.12.3 |
| Libraries | scapy, tabulate, colorama |
| Utilities | tcpdump, netcat |

---

## 📁 Project Structure (Repository Format)

```text
lab15-detect-protocol-weaknesses-with-crafted-packet-tests/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
│   
├── scripts/
│   ├── protocol_server.py
│   ├── packet_crafter.py
│   ├── automated_scanner.py
│   ├── test_config.json
│   └── traffic_analyzer.py
│
├── reports/   
│   └── scan_report.json
```

> Notes:
>
> * `protocol_server.py` was kept running in Terminal 1.
> * All testing and scanning was performed from Terminal 2.

---

## 🧠 Protocol Under Test (Vulnerable Design)

### Protocol Header Format

```
[Magic:2][Version:2][Command:2][Length:2][Payload:N]
```

### Security-Relevant Behavior Implemented in Server

* **Magic validation**

  * If magic is not `0xDEAD`, server responds with a fixed error header
* **Overflow simulation**

  * If length > 1000 → server returns `BUFFER_OVERFLOW_DETECTED`
* **Hidden admin command**

  * If command == `999` → server returns plaintext credentials
    `ADMIN:root PASSWORD:supersecret`

---

## 🧭 Execution Flow 

1. Verify environment (Python + Scapy)
2. Create and launch the vulnerable protocol server
3. Run packet crafting tests for:

   * Valid commands
   * Invalid magic values
   * Authentication bypass discovery
   * Overflow boundary handling
   * Injection-like payload reflection
4. Run automated scanner and export JSON report
5. Observe traffic patterns using Scapy sniffing analyzer

---

## ✅ Tasks Performed (Overview)

### ✅ Task 1: Setup + Build Target Server

* Confirmed Python and Scapy readiness
* Created `protocol_server.py` (vulnerable server)
* Started server: `127.0.0.1:8888`

### ✅ Task 2: Packet Crafting + Systematic Weakness Testing

Created `packet_crafter.py` which tested:

* Command handling (Echo/Status/Unknown)
* Invalid magic responses
* Hidden command sweep for sensitive data leak
* Overflow behavior using fake length field
* Injection-like payload reflection

### ✅ Task 3: Automated Scanner + Report Output

Created:

* `automated_scanner.py` (config-driven fuzzing + reporting)
* `test_config.json` (toggles and payload lists)
* Output report written to `scan_report.json`

### ✅ Task 4: Traffic Pattern Analysis

Created `traffic_analyzer.py` to:

* Sniff TCP/8888 traffic on `lo`
* Extract header fields (magic, command, length)
* Summarize command frequency and payload sizes

---

## 🔍 Key Findings (Confirmed)

### 1) Hidden Administrative Command (Credential Leak) — **CRITICAL**

* Command `999` returns credentials in plaintext:

  * `ADMIN:root PASSWORD:supersecret`

### 2) Overflow Condition Trigger — **HIGH**

* `Length > 1000` triggers special server response:

  * `BUFFER_OVERFLOW_DETECTED`

### 3) Weak Input Handling / Reflection — **MEDIUM**

* Echo endpoint reflects raw bytes back to client
* “Injection-like” payloads were not executed, but accepted and echoed:

  * `; ls -la`
  * `| whoami`
  * `&& cat /etc/passwd`

### 4) Fuzzing Observations — **LOW**

* Server responds to random commands without lockout
* Demonstrates weak hardening controls (no throttling / abuse prevention)

---

## 📊 Evidence Snapshot (What Was Verified)

* Python version confirmed: **3.12.3**
* Scapy availability confirmed: **Scapy ready**
* Credential leak verified in response for command `999`
* Overflow behavior verified with length field set to 2000
* Traffic analyzer verified:

  * multiple commands observed including fuzzed commands
  * non-standard magic numbers present during fuzzing
  * max observed payload length reached overflow test size

---

## 🧾 Result

✅ Protocol weakness testing framework successfully implemented.
✅ Vulnerabilities detected and documented with exported JSON report.
✅ Traffic patterns validated using live capture analysis (Scapy sniffing).

---

## 🔥 Why This Matters

Crafted packet testing is a real-world method used in:

* Reverse engineering proprietary protocols
* Testing IoT/embedded device communications
* Validating protocol hardening and implementation safety
* Identifying hidden commands, unsafe parsing, and insecure defaults

---

## 🌍 Real-World Applications

* Security testing of proprietary services and appliances
* QA validation for protocol error handling
* Protocol fuzzing and resilience testing
* Blue-team simulation of malicious protocol behavior
* SOC investigations into abnormal protocol fields and traffic patterns

---

## ✅ Conclusion

This lab demonstrated practical protocol security testing using packet crafting techniques.

I successfully:

* Built and ran a vulnerable protocol server for assessment
* Crafted protocol packets and tested core weaknesses
* Identified sensitive data leakage via hidden admin command
* Triggered and detected overflow conditions through length manipulation
* Automated fuzz testing and generated a structured JSON security report
* Analyzed protocol traffic behavior using a Scapy-based sniffer

### Note:
⚠️ Only test protocols and systems you have explicit permission to assess.

---
