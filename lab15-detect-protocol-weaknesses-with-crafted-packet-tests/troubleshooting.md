# 🛠 Troubleshooting Guide - Lab 15: Detect Protocol Weaknesses with Crafted Packet Tests

---

# 📌 Overview

This document provides structured troubleshooting steps for common issues encountered while:

- Running the vulnerable protocol server
- Crafting packets using Scapy
- Capturing traffic
- Running the automated scanner
- Performing fuzz testing

Each issue includes:

- 🔍 Symptoms  
- 🧠 Root Cause  
- ✅ Solution  
- 🛡 Prevention Tip  

---

# 1️⃣ Scapy Permission Errors

## 🔍 Problem

`
PermissionError: [Errno 1] Operation not permitted
`

or

`
Socket permission denied
`

## 🧠 Root Cause

Scapy requires raw socket access for packet sniffing and crafting.  
Raw sockets require elevated privileges.

## ✅ Solution

Run scripts with sudo:

```bash
sudo python3 traffic_analyzer.py
sudo python3 packet_crafter.py
````

Alternative permanent solution:

```bash
sudo setcap cap_net_raw+ep $(which python3)
```

## 🛡 Prevention

Use a virtual lab environment with proper privileges configured.

---

# 2️⃣ Server Not Responding

## 🔍 Problem

Packet crafter shows:

`
Echo Response: None
`

or scanner shows no responses.

## 🧠 Root Cause

The server may not be running or listening on the expected port.

## ✅ Solution

Check if server is running:

```bash
ss -tlnp | grep 8888
```

Expected:

```
LISTEN 0 5 127.0.0.1:8888
```

Test connectivity:

```bash
nc -zv 127.0.0.1 8888
```

If not running, restart:

```bash
python3 protocol_server.py
```

## 🛡 Prevention

Always start server in Terminal 1 before running tests in Terminal 2.

---

# 3️⃣ Struct Unpacking Errors

## 🔍 Problem

```
struct.error: unpack requires a buffer of 8 bytes
```

## 🧠 Root Cause

Packet payload is shorter than expected header length.

## ✅ Solution

Ensure validation exists:

```python
if len(data) >= 8:
```

Already included in traffic analyzer and server logic.

## 🛡 Prevention

Always validate packet length before unpacking.

---

# 4️⃣ Fuzzing Causes Script Crash

## 🔍 Problem

Scanner crashes during fuzz testing.

## 🧠 Root Cause

Uncaught exceptions when random packets trigger unexpected behavior.

## ✅ Solution

Ensure try/except in send_packet():

```python
try:
    ...
except:
    return None
```

Already implemented in scanner.

## 🛡 Prevention

Always wrap network operations in exception handling.

---

# 5️⃣ tcpdump Captures No Packets

## 🔍 Problem

Analyzer reports zero packets captured.

## 🧠 Root Cause

Incorrect interface or wrong port filter.

## ✅ Solution

Check interfaces:

```bash
ip addr show
```

For localhost testing use:

```
lo
```

Correct capture command:

```bash
sudo tcpdump -i lo -w capture.pcap port 8888
```

## 🛡 Prevention

Match capture interface with target IP (localhost = lo).

---

# 6️⃣ Magic Number Mismatch Confusion

## 🔍 Problem

Analyzer shows unexpected magic values:

```
Magic Numbers Seen: Counter({57005: 11, ...})
```

## 🧠 Explanation

57005 = 0xDEAD (valid magic)

Other values are from:

* Invalid magic tests
* Fuzzing
* Malformed packets

This is expected behavior.

## ✅ No Fix Required

This confirms testing coverage.

---

# 7️⃣ scan_report.json Empty

## 🔍 Problem

Generated report file is empty.

## 🧠 Root Cause

automated_scanner.py does not automatically populate vulnerabilities list in this simplified implementation.

The example output was manually structured.

## ✅ Solution

Manually append vulnerabilities before generating report, or expand scanner logic to detect findings dynamically.

---

# 8️⃣ Port Already in Use

## 🔍 Problem

```
OSError: [Errno 98] Address already in use
```

## 🧠 Root Cause

Previous server instance still running.

## ✅ Solution

Find process:

```bash
ps aux | grep protocol_server
```

Kill process:

```bash
kill <PID>
```

Or:

```bash
pkill -f protocol_server.py
```

---

# 9️⃣ Packet Crafter Not Detecting Credential Leak

## 🔍 Problem

No sensitive data printed during authentication bypass test.

## 🧠 Root Cause

Server not running correct version of protocol_server.py
OR command 999 block removed.

## ✅ Solution

Ensure this code exists:

```python
elif command == 999:
    response_payload = b"ADMIN:root PASSWORD:supersecret"
```

Restart server.

---

# 🔟 Injection Payload Not Executing

## 🔍 Problem

Payload:

```
; ls -la
```

Is echoed but not executed.

## 🧠 Explanation

The server only reflects payload; it does not execute system commands.

This is safe behavior for this lab.

## ✅ No Fix Needed

This confirms echo reflection but not command execution.

---

# 🔐 Security Best Practice Notes

Even though this lab is controlled:

* Never test protocols without authorization
* Never fuzz production systems
* Always isolate test environments
* Log all testing activities
* Document vulnerabilities responsibly

---

# 📊 Diagnostic Command Reference

| Command  | Purpose                 |
| -------- | ----------------------- |
| ss -tlnp | Check listening ports   |
| nc -zv   | Verify TCP connectivity |
| ip addr  | Show interfaces         |
| ps aux   | List running processes  |
| tcpdump  | Capture packets         |
| pkill    | Stop background process |

---

# ✅ Final Troubleshooting Checklist

Before concluding lab:

✔ Server running
✔ Port 8888 open
✔ Packet crafter sends packets
✔ Analyzer captures traffic
✔ scan_report.json generated
✔ No unhandled exceptions
✔ Credential leak observed
✔ Buffer overflow simulation confirmed

---

# 🎯 Conclusion

Most protocol testing failures are caused by:

* Incorrect interface
* Missing privileges
* Server not running
* Incorrect port configuration
* Improper packet structure

By systematically verifying:

* Network state
* Process state
* Packet format
* Script integrity

You can resolve 95% of protocol testing issues efficiently.
