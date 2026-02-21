# 🛠️ Troubleshooting Guide - Lab 10: Update Threat Models with New Data Inputs

> This document outlines common issues encountered during the lab and how to resolve them.

---

# 1️⃣ Virtual Environment Issues

## ❌ Issue: `ModuleNotFoundError` (e.g., yaml, pandas, matplotlib)

### Cause
Dependencies were not installed or virtual environment not activated.

### ✅ Solution

Activate virtual environment:

```bash
cd ~/threat-model-lab
source threat-env/bin/activate
````

Reinstall dependencies:

```bash
pip install pandas numpy matplotlib requests pyyaml
```

Verify:

```bash
pip list
```

---

## ❌ Issue: `which python` shows system Python

### Cause

Virtual environment not activated.

### ✅ Solution

```bash
source threat-env/bin/activate
which python
```

Expected:

```
/home/toor/threat-model-lab/threat-env/bin/python
```

---

# 2️⃣ File & Directory Errors

## ❌ Issue: `FileNotFoundError` for telemetry or network JSON

### Cause

Scripts executed from wrong directory OR data generators not run.

### ✅ Solution

Ensure generators ran successfully:

```bash
cd ~/threat-model-lab/scripts
python3 telemetry_generator.py
python3 network_data_generator.py
```

Verify files:

```bash
ls -lh ../data/telemetry/
ls -lh ../data/network/
```

---

## ❌ Issue: Relative path errors (`../data/...` not found)

### Cause

Running script from wrong folder.

### ✅ Solution

Always execute from `scripts/`:

```bash
cd ~/threat-model-lab/scripts
python3 threat_model_manager.py
```

---

# 3️⃣ JSON Parsing Errors

## ❌ Issue: `json.decoder.JSONDecodeError`

### Cause

Corrupted or incomplete JSON file.

### ✅ Solution

Validate JSON:

```bash
python3 -m json.tool data/telemetry/security_telemetry.json > /dev/null
python3 -m json.tool data/network/network_analysis.json > /dev/null
```

If invalid:

* Regenerate data
* Ensure file not truncated

---

# 4️⃣ Threat Model Not Updating

## ❌ Issue: No changes in updated model

### Cause

Telemetry distribution similar to previous run.

### Explanation

The system uses delta-based change detection. If:

* No new techniques
* No major frequency increase
* No new malicious indicators

→ No alerts triggered.

### ✅ To Force Changes (Testing)

Modify:

* Increase suspicious IP probability in `network_data_generator.py`
* Add new technique ID to telemetry generator
* Lower alert thresholds in updater

---

# 5️⃣ Alerts Not Generating

## ❌ Issue: "No alerts generated." in logs

### Cause

Alert thresholds not exceeded.

Thresholds defined in:

```python
self.alert_thresholds = {
    "new_techniques": 3,
    "frequency_increase_ratio": 0.50,
    "new_indicators": 2,
}
```

### ✅ Fix (Testing)

Temporarily lower thresholds:

```python
"new_techniques": 1,
"new_indicators": 1,
```

Re-run:

```bash
python3 automated_threat_updater.py
```

---

# 6️⃣ Permission Errors

## ❌ Issue: `Permission denied` writing logs or outputs

### Cause

Incorrect file permissions.

### ✅ Solution

```bash
chmod -R 755 logs output data/threat-models
```

Ensure directories exist:

```bash
mkdir -p logs output data/threat-models/backups
```

---

# 7️⃣ Visualization Problems

## ❌ Issue: PNG files not created

### Cause

* matplotlib missing
* Output directory missing

### ✅ Solution

Ensure installed:

```bash
pip install matplotlib
```

Create output directory:

```bash
mkdir -p output
```

Re-run:

```bash
python3 scripts/visualize_threats.py
```

Verify:

```bash
ls -lh output/*.png
```

---

# 8️⃣ Config Loader Errors

## ❌ Issue: `Config validation failed`

### Cause

Missing required YAML sections:

* data_sources
* threat_model
* alerting
* reporting
* monitoring

### ✅ Solution

Validate YAML:

```bash
python3 config_loader.py
```

Ensure:

* All required sections exist
* Threshold values are non-negative integers
* Paths are correct

---

# 9️⃣ Backup Folder Not Created

## ❌ Issue: No backups in `/backups/`

### Cause

Threat model did not exist before first run.

### Explanation

Backup only occurs if previous model exists.

### ✅ Verify

After second run:

```bash
ls -lh data/threat-models/backups/
```

---

# 🔟 Metrics File Not Generated

## ❌ Issue: `metrics.json` missing

### Cause

Updater not executed OR script error occurred.

### ✅ Solution

Run:

```bash
python3 automated_threat_updater.py
```

Check:

```bash
ls -lh output/metrics.json
```

---

# 1️⃣1️⃣ Continuous Monitoring Loop Freezes Terminal

## ❌ Issue: Script appears stuck

### Cause

`run_continuous_monitoring()` runs infinite loop.

### ✅ Solution

Stop safely:

```
CTRL + C
```

To avoid loop, use default single execution mode.

---

# 1️⃣2️⃣ Technique Mapping Missing

## ❌ Issue: Technique appears as "Unknown Technique"

### Cause

Technique ID not present in mapping dictionary.

### ✅ Solution

Add mapping inside `ThreatModelManager`:

```python
self.attack_techniques["TXXXX"] = {
    "name": "Technique Name",
    "tactic": "Tactic Name"
}
```

---

# 1️⃣3️⃣ Unexpected Severity Classification

### Explanation

Severity inferred from frequency:

* > =150 → critical
* > =80 → high
* > =30 → medium
* else → low

To change logic:
Modify thresholds inside `update_threat_model()`.

---

# 🔐 Security Notes

* This lab uses **simulated telemetry**
* In production:

  * Validate data authenticity
  * Sanitize inputs
  * Enforce strict schema validation
  * Integrate with SIEM securely
  * Protect threat model files from tampering

---

# ✅ Final Validation Checklist

Before submission ensure:

✔ telemetry JSON exists
✔ network JSON exists
✔ updated_threat_model.json created
✔ threat_report.json generated
✔ metrics.json created
✔ PNG visualizations exist
✔ logs/threat_updater.log populated
✔ backups folder contains at least one backup
✔ config_loader.py runs without error

---

**End of Troubleshooting Document**
