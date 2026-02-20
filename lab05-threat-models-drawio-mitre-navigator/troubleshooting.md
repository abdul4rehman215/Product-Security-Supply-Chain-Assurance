# 🛠 Troubleshooting Guide — Lab 05: Threat Modeling with Draw.io + MITRE ATT&CK + Python Automation

---

# 1️⃣ Issue: MITRE Data Fetch Fails

## ❌ Problem
Running:

```bash
python3 mitre_fetcher.py
````

Returns an error such as:

```
Failed to fetch MITRE ATT&CK data
```

## 🔍 Possible Causes

* No internet connectivity
* GitHub URL inaccessible
* DNS resolution issue
* Firewall blocking outbound HTTPS
* Timeout too low

## ✅ Resolution Steps

### Step 1: Check Internet Connectivity

```bash
ping github.com
```

### Step 2: Test Direct Access

```bash
curl -I https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### Step 3: Increase Timeout (if needed)

Ensure the script contains:

```python
requests.get(self.enterprise_url, timeout=60)
```

### Step 4: Retry

```bash
python3 mitre_fetcher.py
```

## 🔐 Security Note

If working in a restricted enterprise environment, outbound GitHub access may require proxy configuration.

---

# 2️⃣ Issue: Python Module Not Found

## ❌ Problem

Error like:

`
ModuleNotFoundError: No module named 'networkx'
`

## 🔍 Cause

Dependencies were not installed properly.

## ✅ Resolution

```bash
pip3 install --upgrade -r requirements.txt
```

Verify:

```bash
pip3 list | grep networkx
```

---

# 3️⃣ Issue: Matplotlib Backend Error

## ❌ Problem

Error related to display or Tkinter:

`
cannot connect to X server
`

## 🔍 Cause

Headless environment without GUI display.

## ✅ Solution

Ensure this line appears **before importing pyplot**:

```python
matplotlib.use('Agg')
```

Then re-run:

```bash
python3 threat_model_generator.py
```

---

# 4️⃣ Issue: Empty Threat List Generated

## ❌ Problem

Script runs but:

`
Threats: 0
`

## 🔍 Possible Causes

* `mitre_techniques.csv` not generated
* CSV file corrupted
* Asset type keywords do not match technique data
* Pandas failed to load data

## ✅ Resolution Steps

### Step 1: Verify CSV Exists

```bash
ls -lh mitre_techniques.csv
```

### Step 2: Inspect CSV Content

```bash
head mitre_techniques.csv
```

### Step 3: Verify DataFrame Loads Correctly

Add debug print in script:

```python
print(self.mitre_df.head())
```

---

# 5️⃣ Issue: Draw.io File Won't Import

## ❌ Problem

Draw.io shows XML parsing error.

## 🔍 Possible Causes

* Corrupted XML
* Incorrect encoding
* Special characters not escaped
* Incomplete file write

## ✅ Resolution

### Step 1: Validate File Encoding

Ensure file is UTF-8:

```bash
file automated_threat_model.drawio
```

### Step 2: Open File in Text Editor

```bash
nano automated_threat_model.drawio
```

Verify it begins with:

```xml
<?xml version="1.0" encoding="utf-8"?>
```

### Step 3: Re-generate File

```bash
python3 drawio_exporter.py
```

---

# 6️⃣ Issue: Permission Denied When Running Script

## ❌ Problem

`
Permission denied
`

## 🔍 Cause

Script not executable.

## ✅ Fix

```bash
chmod +x mitre_fetcher.py threat_model_generator.py drawio_exporter.py
```

Then run again.

---

# 7️⃣ Issue: Pandas CSV Parsing Error

## ❌ Problem

Error while loading CSV in ThreatModelGenerator.

## 🔍 Cause

MITRE data incomplete or corrupted download.

## ✅ Fix

Delete and regenerate:

```bash
rm mitre_techniques.csv
python3 mitre_fetcher.py
```

---

# 8️⃣ Issue: Graph PNG Not Generated

## ❌ Problem

`threat_model.png` missing after script run.

## 🔍 Cause

Matplotlib error or script execution interrupted.

## ✅ Fix

Check for errors in console.

Re-run:

```bash
python3 threat_model_generator.py
```

Verify:

```bash
ls -lh threat_model.png
```

---

# 9️⃣ Issue: Very Large CSV File (Performance Lag)

## 🔍 Explanation

MITRE Enterprise dataset is large (~700+ techniques).

## ✅ Optimization Suggestion

* Filter by specific tactics
* Limit relevance keyword matching
* Cache parsed JSON locally

---

# 🔟 Issue: Risk Scores Seem Too High

## 🔍 Explanation

Risk formula:

```
Risk = Likelihood × Impact
```

High trust-zone exposure increases likelihood automatically.

## ✅ Recommendation

Adjust `_crit_to_levels()` mapping or risk formula if required for enterprise alignment.

---

# 🔐 Security Best Practices Learned During Troubleshooting

* Always validate external data sources.
* Avoid running `pip` as root in production systems.
* Sanitize XML content when generating programmatically.
* Use headless-safe backends in server environments.
* Validate outputs before importing into third-party tools.

---

# ✅ Final Verification Checklist

After troubleshooting, ensure:

```bash
ls -lh *.csv *.json *.png *.drawio *.txt
```

You should see:

* mitre_techniques.csv
* threat_model.json
* threat_model.png
* threat_report.txt
* automated_threat_model.drawio

---

✔ Troubleshooting documentation completed.
