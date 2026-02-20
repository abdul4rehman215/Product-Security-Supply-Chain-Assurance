# 🧩 Lab 05: Create Threat Models in Draw.io + MITRE ATT&CK Navigator

---

## 📌 Lab Summary

This lab focuses on building **practical threat models** for a web-based e-commerce application using:

- **Draw.io (diagrams.net)** for visual system architecture modeling + trust boundaries
- **MITRE ATT&CK Navigator** to map real-world attacker techniques across a compromise scenario
- **Python automation** to:
  - Fetch MITRE ATT&CK Enterprise dataset
  - Extract technique data into CSV
  - Generate structured threat model JSON
  - Produce a risk-prioritized threat report
  - Create a network graph visualization
  - Export an **importable Draw.io diagram** automatically

The result is a repeatable workflow that combines **manual architecture threat modeling** with **automated MITRE-driven threat generation**.

---

## 🎯 Objectives

By the end of this lab, I was able to:

- Create visual threat models in **Draw.io** for system architecture documentation
- Navigate and utilize the **MITRE ATT&CK Navigator** to identify attack techniques
- Map realistic attack paths and threat scenarios for web applications
- Automate threat model generation using Python scripts
- Integrate MITRE ATT&CK framework data into threat modeling workflows

---

## ✅ Prerequisites

- Basic understanding of cybersecurity concepts and common attack vectors
- Familiarity with Linux command-line operations
- Basic Python programming knowledge
- Understanding of web application architecture

---

## 🧪 Lab Environment

This lab was completed in a cloud lab environment with:

- **OS:** Ubuntu 24.04 LTS
- **Python:** Python 3.x + pip
- **Browser:** Firefox
- **Editors:** nano, vim
- **Python libs (installed as needed):**
  - `requests`
  - `pandas`
  - `matplotlib`
  - `networkx`

---

## 🗂️ Repository Structure (Portfolio Format)

```text
lab05-threat-models-drawio-mitre-navigator/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
└── scripts/
    ├── requirements.txt
    ├── mitre_fetcher.py
    ├── threat_model_generator.py
    └── drawio_exporter.py
```

> Note: Manual GUI artifacts (Draw.io + Navigator exports) were created during execution and verified in `output.txt`:

* `~/Downloads/ecommerce_threat_model.drawio`
* `~/Downloads/ecommerce_attack_layer.json`
* Automation outputs in the working directory:

  * `mitre_techniques.csv`
  * `threat_model.json`
  * `threat_report.txt`
  * `threat_model.png`
  * `automated_threat_model.drawio`

---

## 🧭 Lab Tasks Overview

### ✅ Task 1 — Visual Threat Modeling in Draw.io

Created an e-commerce architecture diagram including:

* **Components**

  * User Browser
  * Web Server
  * Customer DB
  * Payment Gateway
* **Connections**

  * User → Web (HTTP/HTTPS)
  * Web → DB (SQL)
  * Web → Payment (API calls)
* **Trust Boundaries**

  * External Zone, DMZ, Internal Zone, Third-party
* **Threat Annotations**

  * User → Web: SQLi, XSS, CSRF, Session Hijacking
  * Web → DB: Privilege Escalation, Unauthorized Access, Data Breach
  * Web → Payment: MITM, API Key Exposure, Data Interception
* **Threat Summary Table**

  * T001 SQL Injection
  * T002 Data Breach
  * T003 API Key Exposure
  * T004 Session Hijacking

Manual export verified:

* `ecommerce_threat_model.drawio` downloaded successfully

---

### ✅ Task 2 — MITRE ATT&CK Navigator Attack Path Mapping

Created a compromise layer for a web-app attack scenario:

* **Initial Access:** `T1190` Exploit Public-Facing Application
* **Execution:** `T1059.007` JavaScript
* **Persistence:** `T1505.003` Web Shell
* **Privilege Escalation:** `T1068` Exploitation for Privilege Escalation
* **Credential Access:** `T1555` Credentials from Password Stores
* **Collection:** `T1005` Data from Local System
* **Exfiltration:** `T1041` Exfiltration Over C2 Channel

Layer exported and verified:

* `ecommerce_attack_layer.json` downloaded successfully

---

### ✅ Task 3 — Automated Threat Modeling with Python

Built an end-to-end automation pipeline:

1. Install dependencies from `requirements.txt`
2. Fetch MITRE Enterprise ATT&CK dataset from GitHub CTI repository
3. Extract techniques and export as CSV
4. Auto-generate threats for assets (keyword relevance matching)
5. Calculate risk score using:

   * Low=1, Medium=2, High=3
   * **risk_score = likelihood * impact**
6. Generate outputs:

   * `threat_model.json`
   * `threat_report.txt`
   * `threat_model.png` (graph visualization)
7. Export a Draw.io importable diagram:

   * `automated_threat_model.drawio`

---

## 🔍 Verification & Validation

Validation actions performed:

* Verified GUI downloads exist:

  * `~/Downloads/ecommerce_threat_model.drawio`
  * `~/Downloads/ecommerce_attack_layer.json`
* Verified python scripts syntax:

  * `python3 -m py_compile <script>.py`
* Verified pipeline execution:

  * MITRE techniques extracted successfully
  * Threat model generated successfully
  * Draw.io exporter produced importable `.drawio` XML
* Verified generated outputs exist in working directory:

  * `.csv`, `.json`, `.png`, `.txt`, `.drawio`

---

## ✅ Result

At the end of the lab, I produced:

* ✅ Manual Draw.io threat model with trust boundaries + annotated threats
* ✅ MITRE ATT&CK Navigator layer JSON for a full web-app compromise path
* ✅ Automated MITRE technique dataset export (`mitre_techniques.csv`)
* ✅ Automated threat model JSON (`threat_model.json`)
* ✅ Risk-ranked reporting output (`threat_report.txt`)
* ✅ Visualization graph (`threat_model.png`)
* ✅ Auto-generated Draw.io diagram (`automated_threat_model.drawio`)

---

## 🧠 What I Learned

* How to represent a system architecture visually and add **trust boundaries**
* How to map an attacker narrative using **MITRE ATT&CK tactics + techniques**
* How to integrate MITRE CTI data into Python-based automation
* How to generate multi-stakeholder outputs (diagram, JSON, report, PNG)
* How automation improves **repeatability** and **coverage** in threat modeling

---

## 💡 Why This Matters

Threat modeling is essential for security programs because it enables:

* Early identification of attack paths **before** development mistakes ship to production
* Consistent security documentation for engineering and governance teams
* MITRE-aligned communication using a common security language
* Automation and scaling across multiple systems or application services

This workflow aligns well with product security, architecture review, and secure design practices.

---

## 🌍 Real-World Applications

These skills directly support:

* Secure design reviews for new services (web apps, APIs, microservices)
* Product security threat modeling for SDLC and release readiness
* Detection engineering alignment (mapping controls to ATT&CK techniques)
* Security architecture documentation for audit and compliance needs
* Building reusable automation pipelines for recurring assessments

---

## 🏁 Conclusion

This lab demonstrated a full threat modeling workflow combining:

* **Manual visual modeling** (Draw.io) for architecture + boundaries + threats
* **Attack-path mapping** (MITRE ATT&CK Navigator) for realistic adversary behavior
* **Automation** (Python) to scale technique extraction and threat generation

By integrating MITRE data into structured and visual outputs, threat modeling becomes more consistent, repeatable, and actionable across teams.

✅ Lab completed successfully with manual + automated outputs verified.
