# 🛠 Troubleshooting Guide - Lab 12: Analyze Update Mechanisms for Supply Chain Risks

---

## 1️⃣ Permission Denied Reading System Files

### 🔍 Symptoms
- Script fails when reading `/etc/apt/sources.list`
- PermissionError exceptions
- Incomplete vulnerability results

### 🎯 Cause
System configuration files require elevated privileges.

### ✅ Resolution
Run the script with elevated privileges:

```bash
sudo python3 package_analyzer.py
sudo python3 supply_chain_auditor.py
````

Alternatively, adjust file permissions carefully (not recommended in production).

### 🔐 Best Practice

Use read-only sudo execution for auditing system-level configuration files.

---

## 2️⃣ `netstat` Command Not Found (Ubuntu 24.04)

### 🔍 Symptoms

* `FileNotFoundError: netstat`
* Network monitor fails to start

### 🎯 Cause

`netstat` is not installed by default in modern Ubuntu versions.

### ✅ Resolution

Install `net-tools`:

```bash
sudo apt update
sudo apt install -y net-tools
```

Alternatively, use `ss -tunp` (modern replacement).

---

## 3️⃣ Network Monitor Captures No Connections

### 🔍 Symptoms

* `Total connections captured: 0`
* No suspicious activity detected

### 🎯 Cause

No network activity during monitoring window.

### ✅ Resolution

Generate traffic manually during monitoring:

```bash
sudo apt update
```

Run this in another terminal while `update_monitor.py` is running.

### 🔐 Tip

Extend capture duration in script if needed:

```python
time.sleep(20)
```

---

## 4️⃣ TLS Connection Timeout

### 🔍 Symptoms

* `Connection timed out`
* `SSL_ERROR`
* No TLS data collected

### 🎯 Possible Causes

* Firewall blocking outbound connections
* No internet connectivity
* Remote server blocking automated requests

### ✅ Resolution

Verify internet access:

```bash
ping github.com
curl -I https://github.com
```

Check firewall rules:

```bash
sudo ufw status
```

---

## 5️⃣ False Positive – TLS Forward Secrecy Warning

### 🔍 Symptoms

* TLSv1.3 server flagged for missing forward secrecy
* MEDIUM severity issue on modern server

### 🎯 Cause

The heuristic checks for `ECDHE` in cipher name.
TLS 1.3 does not include ECDHE in cipher names but still provides forward secrecy.

### ✅ Resolution

Improve cipher evaluation logic to recognize TLS 1.3 behavior:

```python
if tls_version == "TLSv1.3":
    return {"severity": "LOW", "issue": None}
```

---

## 6️⃣ `apt-key` Deprecated Warning

### 🔍 Symptoms

```
Warning: apt-key is deprecated
```

### 🎯 Cause

Modern Ubuntu uses `/etc/apt/trusted.gpg.d/`.

### ✅ Resolution

Audit keyring files directly:

```bash
ls /etc/apt/trusted.gpg.d/
```

This lab uses `apt-key` only for visibility/audit demonstration.

---

## 7️⃣ JSON Report Not Generated

### 🔍 Symptoms

* No `package_security_report.json`
* No `tls_security_report.json`

### 🎯 Cause

Script execution interrupted or permissions issue.

### ✅ Resolution

Check execution logs and re-run:

```bash
python3 package_analyzer.py
python3 tls_analyzer.py
```

Ensure working directory is correct:

```bash
pwd
```

---

## 8️⃣ Incorrect Risk Level Calculation

### 🔍 Symptoms

Unexpected HIGH or CRITICAL classification.

### 🎯 Cause

Weighted scoring formula:

* Package → 40%
* Network → 30%
* TLS → 30%

Multiple HIGH findings reduce score significantly.

### ✅ Resolution

Review category scores inside:

```
supply_chain_audit_report.json
```

Adjust weighting model if needed.

---

## 9️⃣ Python Module Import Errors

### 🔍 Symptoms

```
ModuleNotFoundError
```

### 🎯 Cause

Missing Python modules.

### ✅ Resolution

Install missing packages:

```bash
pip3 install --user <module_name>
```

(Note: This lab uses only Python standard library.)

---

## 🔟 Scripts Hang During Execution

### 🔍 Symptoms

Script appears stuck during monitoring.

### 🎯 Cause

Network capture window still active.

### ✅ Resolution

Wait for monitoring period to finish (default 10 seconds).
You may safely terminate with:

```bash
CTRL + C
```

---

# 🔐 Security Notes

* Always test supply chain analysis tools in lab environments.
* Avoid modifying production APT sources without proper validation.
* Treat update infrastructure as a high-value security boundary.
* Combine transport security (TLS) with integrity validation (signing).

---

# ✅ End of Troubleshooting Guide
