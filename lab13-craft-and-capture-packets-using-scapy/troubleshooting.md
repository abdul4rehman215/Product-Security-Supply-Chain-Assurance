# 🛠 Troubleshooting Guide - Lab 13: Craft and Capture Packets Using Scapy

---

## 1️⃣ Permission Denied / Raw Socket Error

### 🔎 Symptoms
- `PermissionError`
- `Operation not permitted`
- Packet capture fails

### 🎯 Cause
Scapy requires raw socket access for:
- Packet crafting
- Packet sniffing

### ✅ Solution
Always run scripts with sudo:

```bash
sudo python3 script_name.py
````

---

## 2️⃣ No Packets Captured

### 🔎 Symptoms

* Capture completes with 0 packets
* No live traffic displayed

### 🎯 Possible Causes

* Wrong interface selected
* No traffic generated during capture

### ✅ Solution

Check available interfaces:

```bash
ip addr show
```

Use correct interface (e.g., `ens5` or `lo`).

Generate traffic in another terminal:

```bash
ping -c 5 127.0.0.1
curl http://example.com
nslookup google.com
```

---

## 3️⃣ Interface eth0 Not Found

### 🔎 Symptoms

* `eth0` does not appear in interface list

### 🎯 Cause

Modern Ubuntu systems use predictable interface names like:

* `ens5`
* `enp0s3`

### ✅ Solution

Update script to use available interface:

```python
interface = "ens5"
```

Or allow script to auto-select first interface.

---

## 4️⃣ TCP SYN Scan Shows Only RST Responses

### 🔎 Symptoms

* All ports return RST
* No SYN-ACK observed

### 🎯 Cause

Ports are closed (no listening service).

### ✅ Solution

Start a service for testing:

```bash
sudo apt install nginx
sudo systemctl start nginx
```

Then test port 80 again.

---

## 5️⃣ DNS Capture Shows Nothing

### 🔎 Symptoms

* No DNS queries captured

### 🎯 Cause

* Wrong interface
* DNS cached locally
* Local stub resolver in use

### ✅ Solution

Force DNS query:

```bash
nslookup google.com
```

Capture on active interface (`ens5`).

---

## 6️⃣ Scapy Import Error

### 🔎 Symptoms

`ModuleNotFoundError: No module named 'scapy'`

### 🎯 Cause

Scapy not installed correctly.

### ✅ Solution (Preferred)

```bash
sudo apt install python3-scapy
```

### Fallback (Lab Only)

```bash
python3 -m pip install --break-system-packages scapy
```

---

## 7️⃣ tcpdump Cannot Read PCAP Properly

### 🔎 Symptoms

Warning about link-type RAW.

### 🎯 Cause

Scapy writes RAW IP PCAP files.

### ✅ Solution

Use:

```bash
tcpdump -nn -r file.pcap
```

Or open in Wireshark for full decoding.

---

## 8️⃣ Automation Script Captures Nothing

### 🔎 Symptoms

Captured count remains 0.

### 🎯 Possible Causes

* Interface mismatch
* Capture stopped too early

### ✅ Solution

* Increase sleep time before stopping capture.
* Ensure correct interface.
* Generate traffic during capture.

---

## 9️⃣ Timeout Issues in sr1()

### 🔎 Symptoms

No response received.

### 🎯 Cause

Target host unreachable or firewall blocking.

### ✅ Solution

* Use localhost for testing.
* Increase timeout value:

```python
sr1(pkt, timeout=5)
```

---

# 🔐 Security Note

Packet crafting and sniffing tools are powerful.
Use them:

* Only in lab environments
* On systems you own or are authorized to test
* In compliance with organizational policies

---

# ✅ End of Troubleshooting Guide
