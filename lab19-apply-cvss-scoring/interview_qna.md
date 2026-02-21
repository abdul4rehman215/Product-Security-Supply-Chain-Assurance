# 🎤 Interview Q&A - Lab 19 – Apply CVSS Scoring to Discovered Threats  

---

## 1️⃣ What is CVSS?

**CVSS (Common Vulnerability Scoring System)** is an industry-standard framework used to measure the severity of software vulnerabilities.

It provides:
- A numerical score (0.0 – 10.0)
- A severity rating (Low, Medium, High, Critical)
- A standardized way to prioritize remediation

---

## 2️⃣ What are the three metric groups in CVSS v3.1?

CVSS v3.1 consists of:

1. **Base Metrics** – Intrinsic characteristics of the vulnerability  
2. **Temporal Metrics** – Characteristics that change over time  
3. **Environmental Metrics** – Organization-specific impact  

In this lab, we implemented **Base Metrics only**.

---

## 3️⃣ What are the Exploitability Metrics in CVSS v3.1?  

Exploitability metrics include:

- **Attack Vector (AV)**
- **Attack Complexity (AC)**
- **Privileges Required (PR)**
- **User Interaction (UI)**

Exploitability Formula:

```

8.22 × AV × AC × PR × UI

```

---

## 4️⃣ What is the Impact Score formula?

Impact Sub-Score (ISS):

```

ISS = 1 - [(1-C) × (1-I) × (1-A)]

```

If Scope = Unchanged:

```

Impact = 6.42 × ISS

```

If Scope = Changed:

```

Impact = 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15

```

---

## 5️⃣ Why is rounding important in CVSS calculations?

CVSS v3.1 requires:
- Rounding **up** to one decimal place
- Using `math.ceil(score * 10) / 10`

Incorrect rounding can lead to:
- Wrong severity rating
- Inconsistent risk assessment

---

## 6️⃣ What severity ranges are defined in CVSS v3.1?

| Score Range | Severity |
|-------------|----------|
| 0.0         | None     |
| 0.1–3.9     | Low      |
| 4.0–6.9     | Medium   |
| 7.0–8.9     | High     |
| 9.0–10.0    | Critical |

---

## 7️⃣ Why did VULN-001 receive a Critical rating?

VULN-001 (SQL Injection):

- Attack Vector: Network
- No Privileges Required
- No User Interaction
- High Impact on Confidentiality, Integrity, Availability

Final Score = **9.8 → Critical**

This represents a remotely exploitable full system compromise.

---

## 8️⃣ What is the purpose of the CVSS Vector String?

Example:

```

CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

```

The vector string:
- Encodes all metric values
- Allows reproduction of the score
- Standardizes vulnerability documentation

---

## 9️⃣ Why is automation important in CVSS scoring?

Automation ensures:

- Consistency
- Reduced human error
- Faster large-scale analysis
- Integration into DevSecOps pipelines

Manual scoring is useful for understanding — automation is required for scale.

---

## 🔟 How does vulnerability prioritization improve remediation?

Prioritization ensures:

- Critical vulnerabilities fixed first
- Resources allocated efficiently
- Business risk reduced faster

In this lab:
- Overall risk normalized to **82.47%**
- Immediate remediation recommended for Critical vulnerabilities

---

## 1️⃣1️⃣ What is the benefit of multi-format reporting?

Different audiences require different formats:

| Format | Audience |
|--------|----------|
| JSON   | Automation / SIEM tools |
| HTML   | Management dashboards |
| CSV    | Analysts / Data processing |
| TXT    | Executive summaries |

Security reporting must be audience-aware.

---

## 1️⃣2️⃣ How does CVSS support vulnerability management programs?

CVSS helps organizations:

- Standardize severity evaluation
- Prioritize remediation timelines
- Track risk over time
- Align with compliance standards

It is widely used in:
- SOC operations
- Risk assessments
- Penetration testing reports
- Compliance audits

---

## 1️⃣3️⃣ What are common mistakes when calculating CVSS?

Common issues:

- Using wrong PR values for Changed scope
- Incorrect rounding method
- Confusing v2.0 with v3.1 metrics
- Wrong severity mapping

This lab ensured correct implementation.

---

## 1️⃣4️⃣ How can this lab be extended further?

Possible improvements:

- Integrate NVD API for real CVE scoring
- Add Temporal and Environmental metrics
- Build web dashboard interface
- Integrate into CI/CD pipeline

---

## 1️⃣5️⃣ What was the key takeaway from this lab?

The key learning:

> CVSS transforms raw vulnerability data into structured, actionable risk intelligence.

Security is not just finding flaws —
It is quantifying risk and enabling strategic remediation.

---
