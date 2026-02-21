# 🛠 Troubleshooting Guide - Lab 14: Reverse-Engineer Undocumented Protocols

---

## 1️⃣ No Packets Captured in PCAP

### 🔎 Symptoms
- `protocol_capture.pcap` exists but is empty
- Analyzer shows `0 TCP packets with Raw payload`
- Vulnerability scanner reports no payloads

### 🎯 Possible Causes
- Server or client was not running during capture
- Wrong network interface selected
- tcpdump not executed with sudo
- Capture stopped too early

### ✅ Solution
- Ensure server is running:
  ```bash
  python3 custom_server.py &
````

* Use correct interface for localhost traffic:

  ```bash
  sudo tcpdump -i lo -w protocol_capture.pcap port 8888
  ```
* Run client while capture is active
* Stop capture only after client completes

---

## 2️⃣ Scapy Import Errors

### 🔎 Symptoms

```
ModuleNotFoundError: No module named 'scapy'
```

### 🎯 Cause

Scapy not installed in the environment.

### ✅ Solution

Install Scapy:

```bash
sudo apt install python3-scapy
```

If using pip:

```bash
pip3 install scapy
```

---

## 3️⃣ Cannot Parse Protocol Fields Correctly

### 🔎 Symptoms

* Incorrect length values
* Invalid checksum validation
* Parsing errors

### 🎯 Possible Causes

* Incorrect struct format string
* Wrong byte order (endianness)
* Miscalculated offsets

### ✅ Solution

Verify format:

```python
struct.unpack("!4sBBH", payload[:8])
```

`!` ensures big-endian.

Use tcpdump `-X` to manually inspect byte positions:

```bash
tcpdump -r protocol_capture.pcap -X
```

---

## 4️⃣ Server Not Responding

### 🔎 Symptoms

* Client shows "Connection refused"
* Exploit script fails to connect

### 🎯 Cause

Server not running or wrong port.

### ✅ Solution

Restart server:

```bash
python3 custom_server.py
```

Confirm listening port:

```bash
ss -tlnp | grep 8888
```

---

## 5️⃣ Exploit PoC Shows No Response

### 🔎 Symptoms

* `response_preview` is empty
* No visible error

### 🎯 Explanation

The lab server does NOT parse client packets.
It only sends initial messages and closes.

This is expected behavior and itself demonstrates:

* Lack of validation logic
* Weak protocol enforcement

---

## 6️⃣ Fuzzer Shows No Crash Cases

### 🔎 Symptoms

```
Crash/anomaly cases recorded: 0
```

### 🎯 Explanation

The lab server:

* Does not parse client data
* Uses Python (memory-safe)
* Has minimal logic

Thus fuzzing does not cause crashes.

In real-world C/C++ servers, fuzzing may trigger:

* Segmentation faults
* Memory corruption
* DoS conditions

---

## 7️⃣ tcpdump Permission Denied

### 🔎 Symptoms

```
You don't have permission to capture on that device
```

### ✅ Solution

Use sudo:

```bash
sudo tcpdump -i lo port 8888
```

---

## 8️⃣ PCAP Analysis Shows No Raw Layer

### 🔎 Symptoms

Analyzer prints:

```
Loaded X packets; 0 TCP packets with Raw payload
```

### 🎯 Cause

* No application data transmitted
* Capture filter incorrect

### ✅ Solution

Ensure client sends data:

```bash
python3 custom_client.py
```

Verify capture filter:

```bash
sudo tcpdump -i lo port 8888
```

---

## 9️⃣ JSON Tool Command Fails

### 🔎 Symptoms

```
No module named json.tool
```

### ✅ Solution

Use correct syntax:

```bash
python3 -m json.tool file.json
```

---

## 🔟 Entropy Calculation Appears Wrong

### 🔎 Symptoms

Entropy seems lower than expected.

### 🎯 Explanation

Short payloads naturally produce lower entropy.
Entropy values are more reliable with larger datasets.

---

# 🔐 Security Reminder

All exploit and fuzzing steps in this lab:

* Target localhost only
* Are performed in an isolated lab
* Must never be used against unauthorized systems

Unauthorized testing is illegal and unethical.

---

# ✅ End of Troubleshooting Guide

