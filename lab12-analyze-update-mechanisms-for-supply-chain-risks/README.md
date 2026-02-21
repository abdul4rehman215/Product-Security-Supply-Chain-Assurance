# 🧪 Lab 12: Analyze Update Mechanisms for Supply Chain Risks  
**Environment:** Ubuntu 24.04 LTS (Cloud Lab)  
**User:** toor  

---

## 🎯 Objectives
By the end of this lab, I was able to:

- Identify vulnerabilities in software update mechanisms  
- Analyze package manager configurations for security risks  
- Evaluate TLS/SSL security of update servers  
- Monitor network traffic during update processes  
- Build automated tools to assess supply chain security  

---

## ✅ Prerequisites
- Basic Linux command line proficiency  
- Understanding of networking concepts (HTTP/HTTPS, DNS, TLS)  
- Python programming fundamentals  
- Familiarity with package managers (APT, pip)  

---

## 🧰 Lab Environment
This lab is performed in a cloud-based Ubuntu 24.04 lab environment with:

- Ubuntu 24.04 LTS  
- Python 3.12+  
- Network tools: `net-tools` (netstat), `ss` (default), `tcpdump` (optional)  
- Text editors: nano, vim  

---

## 📁 Repository Structure

```

lab12-analyze-update-mechanisms-for-supply-chain-risks/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── scripts/
│   ├── package_analyzer.py
│   ├── update_monitor.py
│   ├── tls_analyzer.py
│   └── supply_chain_auditor.py
└── reports/
├── package_security_report.json
├── update_traffic_report.json
├── tls_security_report.json
├── supply_chain_audit_report.json
└── supply_chain_audit_report.txt

````

---

## 🧠 Lab Overview (What I Did)
Software update pipelines are a major supply-chain attack surface. In this lab, you performed a 4-part assessment:

### ✅ Task 1: Audit Package Manager Security (APT + pip)
- Reviewed APT sources (`/etc/apt/sources.list`, `/etc/apt/sources.list.d/`)
- Audited repository key trust (`apt-key list`, audit only)
- Built and ran a Python analyzer that flags risky patterns like **HTTP repositories**

### ✅ Task 2: Monitor Update Network Traffic
- Installed `net-tools` to use `netstat` (Ubuntu 24.04 note)
- Built a Python monitor to capture live established connections during an update check
- Flagged suspicious indicators like:
  - **HTTP traffic (port 80)**
  - destination as **raw IP** (informational/medium)
  - unusual ports (1337/4444/etc.)

### ✅ Task 3: Evaluate TLS Security of Update Servers
- Built a TLS scanner that:
  - connects to servers using verified TLS
  - extracts certificate fields (notBefore/notAfter, SAN)
  - evaluates TLS version and cipher properties
- Generated a TLS risk summary report

### ✅ Task 4: Create a Comprehensive Supply Chain Auditor
- Built an integrated auditor that combines:
  - package manager findings
  - network monitoring findings
  - TLS checks
- Generated a final consolidated report including:
  - overall score
  - risk level
  - recommendations

---

## 📌 Key Findings (From My Run)
### Package Manager Audit
- **Total Issues Found:** 3  
- **Security Score:** 40/100  
- **Main issue:** APT sources using **HTTP** instead of HTTPS

### Network Monitoring
- Captured established connections during update activity  
- Flagged **HTTP connections** (port 80) including:
  - `169.254.169.254:80` (amazon-ssm-agent)
  - Ubuntu archive destinations on port 80

### TLS Analysis
- **Servers analyzed:** 4  
- **HIGH severity:** 0  
- **MEDIUM severity:** 1  
- **LOW severity:** 3  
> Note from your lab: the TLSv1.3 forward secrecy “MEDIUM” flag is due to a **simplistic heuristic** (TLS 1.3 cipher names don’t include ECDHE even though forward secrecy is provided by the protocol).

### Integrated Audit Summary
From `supply_chain_audit_report.txt`:

- **Overall Score:** 63.0  
- **Risk Level:** HIGH  
- **Category Scores:**
  - Package Security: 40  
  - Network Security: 70  
  - TLS Security: 90  

---

## ▶️ How to Run (Lab Replay)
> Run these scripts from the lab directory.

```bash
# from: ~/supply-chain-lab

python3 scripts/package_analyzer.py
python3 scripts/update_monitor.py
python3 scripts/tls_analyzer.py
python3 scripts/supply_chain_auditor.py
````

---

## ✅ Deliverables Produced

* `reports/package_security_report.json`
* `reports/update_traffic_report.json`
* `reports/tls_security_report.json`
* `reports/supply_chain_audit_report.json`
* `reports/supply_chain_audit_report.txt`

---

## 🌍 Real-World Relevance

Supply-chain incidents often start with update abuse (compromised mirrors, poisoned packages, or update traffic interception).
This lab strengthens your ability to:

* validate repo trust posture
* observe update network behavior
* verify TLS posture of update infrastructure
* generate audit evidence in a repeatable way

---

## 🧾 Conclusion

This lab demonstrated how software updates can introduce supply chain risk through:

* insecure repository transport (HTTP)
* suspicious network destinations during update operations
* misinterpreted / weak TLS configurations
* lack of unified auditing visibility

You built practical automation that produces evidence-driven reports and an overall risk classification—useful for real-world supply chain assessments and update hardening reviews.

---
