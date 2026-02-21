# 🧪 Lab 19: Apply CVSS Scoring to Discovered Threats  

---

# 🎯 Objective

The objective of this lab was to:

- Understand the **CVSS v3.1 framework**
- Perform **manual CVSS base score calculations**
- Develop a **Python-based CVSS calculator**
- Generate structured reports in **JSON, HTML, and CSV**
- Prioritize vulnerabilities using severity and risk scoring
- Produce an executive-level vulnerability assessment summary

This lab focused on transforming vulnerability data into structured, measurable, and actionable risk intelligence.

---

# 📌 Prerequisites

- Basic understanding of cybersecurity and vulnerability concepts
- Familiarity with Linux command line operations
- Basic Python programming knowledge (functions, dictionaries, file I/O)
- Understanding of common vulnerability types (SQL injection, XSS, etc.)

---

# 🖥 Lab Environment

- Ubuntu 24.04 (Cloud Lab Environment)
- Python 3.8+
- Text editors (nano, vim)
- JSON processing capabilities

---

# 📚 CVSS v3.1 Framework Overview

### 🔹 Exploitability Metrics
- Attack Vector (AV)
- Attack Complexity (AC)
- Privileges Required (PR)
- User Interaction (UI)

### 🔹 Scope
- Unchanged (U)
- Changed (C)

### 🔹 Impact Metrics
- Confidentiality (C)
- Integrity (I)
- Availability (A)

### 🔹 Severity Ratings

| Score | Severity |
|--------|----------|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

---

## 📁 Repository Structure

```

lab19-apply-cvss-scoring/
│
├── commands_lab19.md
│
├── vulnerabilities/
│   ├── sample_vulnerabilities.json
│   ├── web_vulnerabilities.json
│   └── manual_calculation.txt
│
├── scripts/
│   ├── cvss_calculator.py
│   ├── cvss_reporter.py
│   └── prioritize_vulns.py
│
├── reports/
│   ├── report.json
│   ├── report.html
│   ├── report.csv
│   └── executive_summary.txt
│
└── output/
└── output.txt

```

---

# 🛠 Tasks Performed

## ✅ Task 1: Manual CVSS Calculation

- Created structured vulnerability dataset
- Calculated exploitability and impact manually
- Verified rounding rules (ceiling method)
- Confirmed final severity rating

Manual verification example:

- Exploitability: **3.89**
- Impact: **5.88**
- Base Score: **9.8**
- Severity: **Critical**

This ensured conceptual understanding before automation.

---

## ✅ Task 2: Implement CVSS Calculator (Python)

Developed:

### 📌 `cvss_calculator.py`

Features:
- Full CVSS v3.1 base score calculation
- Proper scope handling
- Correct PR handling for Changed scope
- Ceiling rounding logic
- Automatic severity classification
- CVSS vector string generation

Validated output:

```

Processed VULN-001: 9.8 (Critical)
Processed VULN-003: 8.8 (High)
Processed VULN-002: 6.4 (Medium)

```

---

## ✅ Task 3: Multi-Format Reporting

Developed:

### 📌 `cvss_reporter.py`

Generated:

- JSON Report (automation-friendly)
- HTML Report (management-ready)
- CSV Report (analysis-ready)

Included:
- Summary statistics
- Severity distribution
- Highest & lowest scoring vulnerabilities
- Recommendations
- Structured vulnerability listing

---

## ✅ Task 4: Vulnerability Prioritization

Developed:

### 📌 `prioritize_vulns.py`

Capabilities:

- Sort vulnerabilities by severity
- Group by Critical / High / Medium / Low
- Assign remediation timelines
- Calculate overall risk score (0–100 normalized scale)

Example output:

```

Overall Risk Score: 82.47%
Critical: Immediate (24–72 hours)
High: Within 7 days
Medium: Within 30 days

```

---

## 📊 Results

| Vulnerability | Score | Severity |
|---------------|--------|----------|
| VULN-001 | 9.8 | Critical |
| VULN-003 | 8.8 | High |
| VULN-002 | 6.4 | Medium |

Overall System Risk: **82.47% (High Risk Level)**

---

# 🧠 Key Learning Outcomes

After completing this lab, I gained:

- Deep understanding of CVSS v3.1 metrics
- Practical experience with manual risk calculation
- Implementation skills for vulnerability scoring automation
- Knowledge of severity classification logic
- Experience generating executive-level security reports
- Understanding of risk normalization and prioritization models
- Real-world vulnerability management workflow experience

---

# 🔐 Why This Lab Matters (Real-World Relevance)

CVSS scoring is critical in:

- SOC operations
- Vulnerability management programs
- Risk assessments
- Compliance reporting
- Penetration testing reports
- Executive security briefings

Organizations rely on CVSS to:

- Standardize vulnerability severity
- Prioritize remediation
- Allocate security resources
- Communicate risk to stakeholders

This lab mirrors real enterprise vulnerability management processes.

---

# 📈 Practical Applications

This implementation can be extended to:

- Integrate NVD API for real CVE feeds
- Automate CI/CD vulnerability gating
- Add Temporal and Environmental metrics
- Connect with SIEM platforms
- Build vulnerability dashboards

---

# 🧩 Executive Summary Snapshot

- Total Vulnerabilities Assessed: 3  
- Critical: 1  
- High: 1  
- Medium: 1  
- Average CVSS Score: 8.33  
- Overall Risk Level: High (82.47%)

Immediate remediation recommended for Critical vulnerabilities.

---

# 🏁 Conclusion

This lab provided hands-on experience with:

- CVSS v3.1 scoring methodology
- Risk quantification
- Security automation
- Vulnerability prioritization
- Professional reporting for technical and executive audiences

The key takeaway:

> CVSS transforms raw vulnerability findings into structured, measurable, and actionable security intelligence.

This lab strengthened both technical implementation skills and strategic risk assessment capabilities.

---
