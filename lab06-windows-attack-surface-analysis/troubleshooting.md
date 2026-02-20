# 🛠️ Troubleshooting Guide — Lab 06: Windows Attack Surface Analysis with Open-Source Tools

---

## 📌 Overview

This document outlines common issues encountered during the attack surface assessment lab and their respective resolutions. It ensures reproducibility and smooth execution across similar Ubuntu-based environments.

---

## 🔧 1. pip Installation Permission Errors

### ❌ Issue
`
WARNING: Running pip as the 'root' user can result in broken permissions...
`

### 🎯 Cause

Using `pip` as root may conflict with system-managed Python packages.

### ✅ Solution

Use:

```bash
pip3 install --user <package>
```

Or create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🌐 2. `ss` or `netstat` Command Not Found

### ❌ Issue

`
ss: command not found
`

### 🎯 Cause

Required networking tools not installed.

### ✅ Solution

Install:

```bash
sudo apt install iproute2 net-tools
```

---

## 🔐 3. Permission Denied Reading `/etc/ssh/sshd_config`

### ❌ Issue

`
PermissionError: [Errno 13] Permission denied
`

### 🎯 Cause

SSH config requires elevated privileges.

### ✅ Solution

Run scanner with sudo:

```bash
sudo python3 vulnerability_scanner.py
```

Or temporarily adjust read permissions (not recommended for production).

---

## 📊 4. JSON Validation Error

### ❌ Issue

`
ValueError: Expecting value...
`

### 🎯 Cause

Malformed JSON output due to incomplete write or script interruption.

### ✅ Solution

Validate:

```bash
cat attack_surface_report.json | python3 -m json.tool
```

If invalid:

* Re-run analyzer script
* Ensure no manual edits corrupted JSON

---

## 🖥️ 5. HTML Report Not Opening Properly

### ❌ Issue

Blank page or improperly formatted report.

### 🎯 Cause

Corrupted file or browser caching.

### ✅ Solution

* Regenerate:

```bash
python3 generate_report.py
```

* Clear browser cache
* Open in private/incognito mode
* Validate file exists:

```bash
ls -lh security_report.html
```

---

## 🧠 6. False Positives in SUID Detection

### ❌ Issue

Standard binaries flagged as risk.

### 🎯 Cause

SUID detection is heuristic-based.

### ✅ Solution

Manually verify necessity:

```bash
ls -l /usr/bin/sudo
dpkg -S /usr/bin/sudo
```

Accept expected binaries as baseline system behavior.

---

## 🔎 7. High Risk Score on Clean System

### ❌ Issue

Risk score appears high (e.g., 82/100) even though system seems normal.

### 🎯 Cause

Heuristic scoring weights:

* Privileged processes
* Open ports
* Vulnerabilities

### ✅ Solution

Understand that:

* This is a simulation scoring model
* Enterprise scoring would consider:

  * Network segmentation
  * Firewall rules
  * MFA enforcement
  * Monitoring controls

Adjust scoring weights if customizing tool.

---

## 🧪 8. `psutil` Import Error

### ❌ Issue

```bash
ModuleNotFoundError: No module named 'psutil'
```

### 🎯 Cause

Dependency not installed.

### ✅ Solution

```bash
pip3 install psutil
```

Or reinstall requirements:

```bash
pip3 install --upgrade -r requirements.txt
```

---

## 📁 9. Script Not Executable

### ❌ Issue

```bash
Permission denied
```

### 🎯 Cause

Missing executable permission.

### ✅ Solution

```bash
chmod +x *.py
```

Or run directly:

```bash
python3 script_name.py
```

---

## 🔄 10. Inconsistent Results Between Runs

### ❌ Issue

Different process counts or port counts.

### 🎯 Cause

System processes are dynamic:

* Cron jobs
* Temporary services
* Package updates

### ✅ Solution

This is expected behavior. Document timestamp and environment snapshot for accuracy.

---

# 🧾 Final Notes

This lab environment behaved as a minimal secure Ubuntu server with:

* SSH externally exposed
* Standard root-owned services
* Default SUID binaries
* No legacy insecure services

The troubleshooting steps above ensure the lab can be replicated reliably in similar environments.

---

# ✅ End of Troubleshooting Guide
