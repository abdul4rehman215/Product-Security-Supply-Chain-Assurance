# 🛠️ Troubleshooting Guide - Lab 09: Visualize Security Findings with Matplotlib  

> This document lists common issues encountered during the lab along with clear diagnostic steps and solutions.

---

# 1️⃣ ModuleNotFoundError (matplotlib / pandas / seaborn)

## ❌ Error Example
`
ModuleNotFoundError: No module named 'matplotlib'
`

## 🔎 Cause
Required Python libraries are not installed in the current environment.

## ✅ Fix
```bash
pip3 install --user matplotlib pandas seaborn numpy
````

Verify installation:

```bash
python3 -c "import matplotlib, pandas, seaborn; print('Libraries OK')"
```

---

# 2️⃣ Permission Denied When Saving Output Files

## ❌ Error Example

`
PermissionError: [Errno 13] Permission denied: '../outputs/event_pie_chart.png'
`

## 🔎 Cause

The `outputs/` directory does not have write permissions.

## ✅ Fix

```bash
chmod 755 ~/security_viz_lab/outputs
```

Verify:

```bash
ls -ld ~/security_viz_lab/outputs
```

---

# 3️⃣ CSV File Not Found

## ❌ Error Example

`
FileNotFoundError: ../data/security_events.csv
`

## 🔎 Cause

* Script executed from wrong directory
* Incorrect relative path
* CSV file missing

## ✅ Fix Option 1 — Verify Path

```bash
ls -la ~/security_viz_lab/data/
```

## ✅ Fix Option 2 — Use Absolute Path

Instead of:

```python
pd.read_csv("../data/security_events.csv")
```

Use:

```python
pd.read_csv("/home/toor/security_viz_lab/data/security_events.csv")
```

---

# 4️⃣ Plots Not Displaying (Headless Environment)

## 🔎 Cause

Cloud VM does not have GUI display.

## ✅ Solution

Use:

```python
plt.savefig("output.png")
```

Instead of:

```python
plt.show()
```

For local debugging:

```python
plt.show()
```

---

# 5️⃣ Empty or Incorrect Charts

## 🔎 Possible Causes

* CSV loaded incorrectly
* Column names mismatch
* Null values in dataset

## ✅ Diagnostic Steps

```python
print(df.head())
print(df.columns)
print(df.isnull().sum())
```

Ensure CSV header matches:

```
timestamp,event_type,severity,source_ip,port,protocol,action,country
```

---

# 6️⃣ Timeline Chart Shows Single Hour Only

## 🔎 Explanation

The dataset timestamps are between 08:30–08:39, so hourly aggregation results in events grouped under hour 8.

## ✅ This is expected behavior

No fix required.

---

# 7️⃣ PDF Report Not Generated

## ❌ Error Example

`
Report generation stopped.
`

## 🔎 Cause

Data loading failure.

## ✅ Fix

Test loading manually:

```python
import pandas as pd
pd.read_csv("../data/security_events.csv")
pd.read_csv("../data/vulnerabilities.csv")
```

Verify PDF output:

```bash
ls -lh ~/security_viz_lab/outputs/security_report.pdf
```

---

# 8️⃣ Stats Summary Not Saving File

## 🔎 Cause

Wrong working directory.

## ✅ Fix

Always run from:

```bash
cd ~/security_viz_lab/scripts
python3 stats_summary.py
```

---

# 9️⃣ Warning: Running pip as root

## ⚠️ Warning Example

```
WARNING: Running pip as the 'root' user can result in broken permissions...
```

## 🔎 Explanation

Common in cloud lab VMs. Not critical for temporary lab environments.

## ✅ Optional Best Practice

Use virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install matplotlib pandas seaborn numpy
```

---

# 🔎 Final Health Check Commands

Run these to verify everything is correct:

```bash
cd ~/security_viz_lab

ls -lh data/
ls -lh scripts/
ls -lh outputs/

python3 scripts/basic_viz.py
python3 scripts/timeline_viz.py
python3 scripts/geo_viz.py
python3 scripts/vuln_dashboard.py
python3 scripts/report_generator.py
python3 scripts/stats_summary.py
```

If all scripts execute without errors and all files appear in `outputs/`, the lab is successfully completed.

---
