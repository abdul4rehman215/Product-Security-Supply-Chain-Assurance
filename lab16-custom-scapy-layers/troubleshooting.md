# 🛠 Troubleshooting Guide - Lab 16: Build Custom Scapy Layers for Proprietary Protocols

---

# 1️⃣ Scapy Import Errors

## ❌ Problem
`
ModuleNotFoundError: No module named 'scapy'
`

## ✅ Solution
```bash
sudo pip3 install scapy
````

OR

```bash
sudo apt-get install python3-scapy
```

---

# 2️⃣ Permission Denied Errors

## ❌ Problem

`
PermissionError: [Errno 1] Operation not permitted
`

## 🧠 Cause

Raw socket access requires elevated privileges.

## ✅ Solution

```bash
sudo python3 script.py
```

Optional permanent solution:

```bash
sudo setcap cap_net_raw+ep $(which python3)
```

---

# 3️⃣ Custom Layer Not Recognized

## ❌ Problem

Scapy does not decode SecureComm layer.

## 🧠 Cause

`bind_layers()` not configured correctly.

## ✅ Fix

Ensure:

```python
bind_layers(UDP, SecureCommHeader, dport=9999)
```

Also:

* Import custom module before usage
* Confirm port numbers match

---

# 4️⃣ No Packets Captured

## ❌ Problem

`tcpdump` shows no packets.

## ✅ Checklist

✔ Correct interface:

```bash
ip addr show
```

✔ For localhost use:

```
lo
```

✔ Server running:

```bash
ps aux | grep protocol_server
```

✔ Firewall not blocking:

```bash
sudo iptables -L
```

---

# 5️⃣ Checksum Mismatch Errors

## ❌ Problem

Analyzer reports checksum mismatch.

## 🧠 Possible Causes

* post_build() not executed
* Manual packet modification
* Corrupted capture

## ✅ Fix

Ensure:

* payload_len updated correctly
* checksum field updated after payload append

---

# 6️⃣ Wireshark GUI Not Launching

## ❌ Problem

```
Cannot open display
```

## 🧠 Cause

Cloud environment has no GUI display.

## ✅ Solution

Download `.pcap` file locally and open in Wireshark
OR use:

```bash
tshark -r custom_protocols.pcap
```

---

# 7️⃣ Server Not Responding

## ❌ Problem

Protocol tester shows:

`
No response
`

## ✅ Verify

```bash
ss -tulnp | grep 9999
```

If not running:

```bash
sudo python3 protocol_server.py
```

---

# 8️⃣ Fuzz Test Behaves Unexpectedly

## Explanation

Some fuzz cases may:

* Be silently dropped
* Generate no response
* Still produce ACK

This depends on validation logic in server implementation.

---

# 🔐 Security Best Practices

* Never test external systems without authorization
* Use isolated lab environment
* Log testing activity
* Avoid sending malformed traffic to production systems
* Validate checksum logic carefully

---

# ✅ Final Troubleshooting Checklist

✔ Scapy installed
✔ Scripts run with sudo
✔ Custom layers bound correctly
✔ Server running
✔ tcpdump capturing
✔ PCAP file generated
✔ Analyzer detects packets
✔ Anomalies correctly reported

---

# 🎯 Conclusion

Most issues in custom protocol development arise from:

* Incorrect field offsets
* Binding misconfiguration
* Privilege limitations
* Interface mis-selection
* Checksum miscalculation

Systematic debugging and packet inspection resolve nearly all issues.

---
