# 🛠️ Troubleshooting Guide — Lab 01: OSINT-Based Product Reconnaissance with SpiderFoot & recon-ng

---

# 🔴 Issue 1: SpiderFoot Web Interface Does Not Start

## Symptoms
- Browser cannot access `http://127.0.0.1:5001`
- `curl` test fails
- No process appears running

## Possible Causes
- Port 5001 already in use
- Previous SpiderFoot instance still running
- Missing Python dependencies
- Firewall blocking local port

## Diagnosis

```bash
netstat -tuln | grep 5001
ps aux | grep sf.py
````

## Resolution

### Kill existing process

```bash
pkill -f sf.py
```

### Restart SpiderFoot

```bash
python3 sf.py -l 127.0.0.1:5001 &
```

### Reinstall dependencies

```bash
pip3 install -r requirements.txt
```

---

# 🔴 Issue 2: recon-ng Modules Fail to Install

## Symptoms

* Marketplace installation fails
* Module not found errors
* Timeout during module download

## Possible Causes

* No internet connectivity
* GitHub rate limits
* Outdated recon-ng repository
* DNS resolution issues

## Diagnosis

```bash
ping -c 3 github.com
dig github.com
```

## Resolution

### Update recon-ng

```bash
cd ~/osint-lab/recon-ng
git pull
```

### Install module individually

```bash
marketplace install recon/domains-hosts/hackertarget
```

### Verify connectivity

```bash
ping -c 3 8.8.8.8
```

---

# 🔴 Issue 3: DNS Queries Return No Results

## Symptoms

* `dig example.com A +short` returns nothing
* Subdomain enumeration empty
* MX/NS records missing unexpectedly

## Possible Causes

* Domain does not exist
* DNS misconfiguration
* Local resolver issue
* Firewall or network filtering

## Diagnosis

```bash
ping -c 3 8.8.8.8
dig @8.8.8.8 example.com
```

## Resolution

### Use public DNS resolver

```bash
dig @8.8.8.8 example.com A +short
```

### Check `/etc/resolv.conf`

```bash
cat /etc/resolv.conf
```

---

# 🔴 Issue 4: Python Script Permission Denied

## Symptoms

* `Permission denied`
* Script does not execute directly

## Possible Causes

* Script not executable
* Incorrect file ownership
* Missing shebang line

## Diagnosis

```bash
ls -l spiderfoot_scanner.py
```

## Resolution

### Make executable

```bash
chmod +x spiderfoot_scanner.py
```

### Run explicitly with Python

```bash
python3 spiderfoot_scanner.py example.com
```

---

# 🔴 Issue 5: pip Warning About Running as Root

## Symptoms

* Warning: Running pip as root

## Cause

Installing Python packages system-wide without a virtual environment.

## Recommended Fix (Best Practice)

### Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

This prevents system package conflicts.

---

# 🔴 Issue 6: osint_master.py Fails to Generate Report

## Symptoms

* No files in `results/`
* JSON file missing
* Script exits silently

## Possible Causes

* SpiderFoot not running
* recon-ng script missing
* Timeout during execution
* Permission issue in results directory

## Diagnosis

```bash
ls -l results/
ps aux | grep sf.py
```

## Resolution

### Ensure SpiderFoot is running

```bash
curl http://127.0.0.1:5001
```

### Check script existence

```bash
ls spiderfoot_scanner.py
ls reconng_scanner.py
```

---

# 🔴 Issue 7: recon-ng Database Errors

## Symptoms

* Workspace errors
* Database locked
* SQLite error messages

## Cause

Improper shutdown of recon-ng or corrupted workspace.

## Resolution

### Remove workspace

```bash
rm -rf ~/.recon-ng/workspaces/product_recon
```

Then re-run scan.

---

# 🔴 Issue 8: Slow OSINT Scan Performance

## Symptoms

* Long delays
* SpiderFoot scan stuck in RUNNING
* recon-ng slow responses

## Causes

* External API rate limits
* Network latency
* Limited system resources

## Mitigation

* Reduce modules used
* Increase script timeout
* Use API keys for OSINT providers
* Run during off-peak hours

---

# 🔴 Issue 9: JSON Parsing Error in analyze_results.py

## Symptoms

* JSONDecodeError
* File not valid JSON

## Cause

Attempting to analyze incomplete or corrupted report.

## Resolution

### Validate JSON

```bash
cat report.json | python3 -m json.tool
```

If invalid, regenerate report.

---

# 🔴 Issue 10: Port Already in Use Error

## Symptoms

* Error binding to 127.0.0.1:5001

## Resolution

Find process:

```bash
lsof -i :5001
```

Kill process:

```bash
kill -9 <PID>
```

Or run SpiderFoot on different port:

```bash
python3 sf.py -l 127.0.0.1:6001
```

---

# ✅ Best Practices Summary

* Use virtual environments for Python projects
* Periodically update OSINT tools
* Verify internet connectivity before scans
* Validate JSON outputs before analysis
* Restrict OSINT automation usage to authorized targets only
* Document findings systematically

---

# 🏁 End of Troubleshooting Guide — Lab 01
