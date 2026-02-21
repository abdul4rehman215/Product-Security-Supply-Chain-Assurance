# 🛠 Troubleshooting Guide - Lab 17: Fuzz Network Protocols with Boofuzz

---

# 1️⃣ Connection Refused Error

## ❌ Problem
`
Connection refused
`

## ✅ Solution
Ensure test server is running:

```bash
python3 test_server.py
````

Check port usage:

```bash
ss -tlnp | grep 8080
```

---

# 2️⃣ Boofuzz Import Error

## ❌ Problem

`
ModuleNotFoundError: No module named 'boofuzz'
`

## ✅ Solution

Activate virtual environment:

```bash
source boofuzz-env/bin/activate
```

Reinstall:

```bash
pip install --upgrade boofuzz
```

---

# 3️⃣ Fuzzer Runs Indefinitely

## Cause

Large mutation space.

## Fix

* Reduce fuzzable fields
* Limit test cases
* Lower sleep_time
* Adjust restart_interval

---

# 4️⃣ No Crashes Detected

This is normal for simple test server.

To increase detection chances:

* Introduce unsafe parsing
* Add buffer limits
* Test older vulnerable software

---

# 5️⃣ Port Already in Use

## Error

`
OSError: [Errno 98] Address already in use
`

## Fix

Find process:

```bash
lsof -i :8080
```

Kill process:

```bash
kill <PID>
```

---

# 6️⃣ Automated Framework Fails to Start Server

Check:

* File path correct
* Python available
* No permission issues

Run manually:

```bash
python3 test_server.py
```

---

# 7️⃣ Web Interface Not Accessible

Ensure:

* Port 26000 not blocked
* Running locally

If remote cloud:
Use SSH port forwarding:

```bash
ssh -L 26000:127.0.0.1:26000 user@server
```

---

# 8️⃣ Log File Not Created

Check write permissions in directory.

Verify logging configuration.

---

# 🔐 Security Best Practices

* Always fuzz in controlled lab environments
* Never fuzz unauthorized systems
* Log all activity
* Monitor system resources
* Use crash isolation when testing real targets

---

# ✅ Final Checklist

✔ Virtual environment activated
✔ Boofuzz installed
✔ Test server running
✔ Protocol definitions created
✔ Fuzzing executed
✔ Logs generated
✔ Reports saved
✔ Results analyzed

---

# 🎯 Final Conclusion

Common fuzzing issues are:

* Environment misconfiguration
* Port conflicts
* Incorrect protocol definitions
* Excessive mutation space
* Improper logging setup

Systematic debugging resolves most issues quickly.
