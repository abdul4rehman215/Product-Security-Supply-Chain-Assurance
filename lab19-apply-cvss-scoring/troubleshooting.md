# 🛠 Troubleshooting Guide - Lab 19 – Apply CVSS Scoring to Discovered Threats  

---

## 🔎 Overview

This lab involved:

- Manual CVSS calculation
- Python-based CVSS automation
- JSON data processing
- Multi-format report generation
- Vulnerability prioritization
- Risk normalization (0–100 scale)

Below are common issues encountered during implementation and their resolutions.

---

# 🧩 1️⃣ Issue: CVSS Score Does Not Match Online Calculator

### ❌ Symptom
Calculated score differs from official CVSS calculator.

### 🎯 Possible Causes

- Using CVSS v2 instead of v3.1
- Incorrect Privileges Required value when Scope = Changed
- Incorrect rounding (must round up)
- Using standard rounding instead of ceiling
- Wrong metric numeric mapping

### ✅ Solution

Verify:

```bash
python3 -m json.tool vulnerabilities/sample_vulnerabilities.json
````

Check:

* PR uses correct table for Changed scope
* Rounding implemented as:

```python
math.ceil(score * 10) / 10.0
```

Ensure CVSS v3.1 formulas are strictly followed.

---

# 🧩 2️⃣ Issue: JSON Parsing Error

### ❌ Error Example

`
json.decoder.JSONDecodeError
`

### 🎯 Cause

* Missing comma
* Incorrect quotes
* Invalid JSON structure

### ✅ Solution

Validate JSON:

```bash
python3 -m json.tool file.json
```

Fix any syntax issues shown in error line.

---

# 🧩 3️⃣ Issue: ImportError – cvss_calculator Not Found

### ❌ Error Example

`
ModuleNotFoundError: No module named 'cvss_calculator'
`

### 🎯 Cause

Script executed from wrong directory.

### ✅ Solution

Run from `scripts` directory:

```bash
cd scripts
python3 cvss_reporter.py
```

OR ensure correct relative import structure.

---

# 🧩 4️⃣ Issue: Severity Rating Incorrect

### ❌ Symptom

Score 9.8 but severity not "Critical".

### 🎯 Cause

Incorrect conditional logic.

Correct mapping:

| Score    | Severity |
| -------- | -------- |
| 0.0      | None     |
| 0.1–3.9  | Low      |
| 4.0–6.9  | Medium   |
| 7.0–8.9  | High     |
| 9.0–10.0 | Critical |

### ✅ Solution

Verify:

```python
if 9.0 <= score <= 10.0:
    return "Critical"
```

---

# 🧩 5️⃣ Issue: Incorrect Rounding

### ❌ Symptom

9.77 becomes 9.7 instead of 9.8

### 🎯 Cause

Using round() instead of ceiling.

### ✅ Correct Implementation

```python
math.ceil(score * 10) / 10.0
```

CVSS requires rounding **up**, not normal rounding.

---

# 🧩 6️⃣ Issue: HTML Report Not Opening Properly

### ❌ Symptom

Broken formatting or blank page.

### 🎯 Cause

* Invalid HTML structure
* Missing CSS block
* File not saved properly

### ✅ Solution

Verify:

```bash
cat reports/report.html
```

Open in browser:

```bash
xdg-open reports/report.html
```

Ensure `<html>`, `<head>`, `<body>` tags exist.

---

# 🧩 7️⃣ Issue: CSV File Empty

### ❌ Symptom

CSV file created but no data rows.

### 🎯 Cause

* Incorrect column mapping
* Results list empty
* Wrong input file path

### ✅ Solution

Check:

```bash
ls reports
cat reports/report.csv
```

Verify JSON input path:

```bash
python3 cvss_reporter.py ../vulnerabilities/sample_vulnerabilities.json -o ../reports/report.csv -f csv
```

---

# 🧩 8️⃣ Issue: Overall Risk Score Incorrect

### ❌ Symptom

Risk score too low or above 100.

### 🎯 Cause

Improper normalization.

Correct formula:

```
(weighted_sum / max_possible) × 100
```

Then clamp between 0–100.

### ✅ Verify Code

```python
risk_percent = (weighted_sum / max_possible) * 100.0
risk_percent = max(0.0, min(100.0, risk_percent))
```

---

# 🧩 9️⃣ Issue: Permission Denied When Running Script

### ❌ Error

`
Permission denied
`

### 🎯 Cause

Script not executable.

### ✅ Solution

```bash
chmod +x scripts/cvss_calculator.py
chmod +x scripts/cvss_reporter.py
chmod +x scripts/prioritize_vulns.py
```

---

# 🧩 🔟 Incorrect Privileges Required Value

### ❌ Symptom

Score slightly off when Scope = Changed.

### 🎯 Cause

PR values differ depending on scope.

For Scope = Changed:

```
Low = 0.68
High = 0.5
```

For Scope = Unchanged:

```
Low = 0.62
High = 0.27
```

Ensure correct table is used.

---

# 🧠 Debugging Checklist Used in This Lab

✔ Validate JSON
✔ Verify metric mappings
✔ Confirm rounding method
✔ Test manual vs automated score
✔ Compare with official calculator
✔ Verify severity thresholds
✔ Validate report file creation
✔ Confirm prioritization logic

---

# 🔐 Security Lessons from Troubleshooting

* Small calculation errors can alter severity classification
* Incorrect scoring leads to wrong remediation priorities
* Automation must strictly follow standards
* Validation and testing are critical in risk analysis tools

---

# ✅ Final Verification Steps

Run complete workflow:

```bash
python3 cvss_calculator.py
python3 cvss_reporter.py ../vulnerabilities/sample_vulnerabilities.json -o ../reports/report.json
python3 prioritize_vulns.py ../reports/report.json
```

Confirm:

✔ Scores match expected values
✔ Reports generated in all formats
✔ Risk score normalized (0–100)
✔ Executive summary created

---

# 🎯 Final Status

Lab 19 completed successfully:

* Manual CVSS scoring validated
* Automated CVSS calculator implemented
* Multi-format reporting operational
* Risk-based prioritization working
* Executive-level reporting generated

This lab demonstrated practical vulnerability scoring and enterprise-grade reporting capabilities.

---
