# 🛠 Troubleshooting Guide - Lab 7: Trace Product Network Activity Using ProcDOT & Wireshark

---

## 1️⃣ Permission Denied During Packet Capture

### ❌ Problem
`
tshark: You do not have permission to capture on that device
`

### ✅ Solution
1. Add user to wireshark group:
```bash
   sudo usermod -a -G wireshark $USER
```

2. Refresh group session:
 ```bash
   newgrp wireshark
```

3. Verify:

```bash
   groups $USER
```

4. If still failing, re-login to the system.

---

## 2️⃣ No Packets Captured

### ❌ Problem

PCAP file exists but contains little or no traffic.

### ✅ Solution Checklist

* Verify interface is up:
```bash
  ip link show
```
* Try capturing on `any`:
```bash
  tshark -i any
```
* Ensure traffic generator is running.
* Remove capture filter to test:

```bash
  tshark -i any -w test.pcap
```
* Confirm network connectivity:

```bash
  ping 8.8.8.8
```

---

## 3️⃣ PyShark Import Error

### ❌ Problem

`
ModuleNotFoundError: No module named 'pyshark'
`

### ✅ Solution

Install pyshark:

```bash
pip3 install pyshark
```

Verify tshark exists:

```bash
which tshark
```

If missing:

```bash
sudo apt install tshark
```

---

## 4️⃣ tshark Not Found

### ❌ Problem

`
command not found: tshark
`

### ✅ Solution

Install Wireshark CLI tools:

```bash
sudo apt update
sudo apt install tshark
```

---

## 5️⃣ Visualization Not Displaying

### ❌ Problem

Image not opening or display errors.

### ✅ Solution

* Save visualization to file:

```python
  plt.savefig("network_flows.png")
```
* Open manually:

```bash
  xdg-open network_flows.png
```
* If using SSH, ensure X11 forwarding:

```bash
  ssh -X user@host
```

---

## 6️⃣ CSV Conversion Fails

### ❌ Problem

PCAP conversion to CSV throws errors.

### ✅ Possible Causes

* Corrupted PCAP file
* PyShark unable to parse certain packets
* Missing permissions

### ✅ Fix

* Re-run capture
* Ensure PCAP file is complete:

```bash
  file product_traffic.pcap
```
* Use Wireshark GUI to validate integrity

---

## 7️⃣ Automated Pipeline Stops Unexpectedly

### ❌ Problem

`automated_analysis.py` exits early.

### ✅ Solution

* Verify traffic_generator.py runs independently
* Confirm tshark works manually
* Check analysis_output directory exists:

```bash
  mkdir -p analysis_output
```
* Run each component separately to isolate failure

---

## 8️⃣ No Anomalies Detected

### ❌ Concern

Script reports:

`
No significant anomalies detected.
`

### ✅ Explanation

This is expected in controlled lab traffic.
To test detection:

* Increase traffic frequency
* Modify anomaly threshold
* Introduce high-volume artificial requests

---

## 9️⃣ Capture File Too Large

### ❌ Problem

PCAP file grows excessively.

### ✅ Solution

Limit capture size or duration:

```bash
tshark -i any -a duration:60 -w limited_capture.pcap
```

---

## 🔟 Network Interface Not Visible

### ❌ Problem

Expected interface not listed.

### ✅ Solution

* Check network driver:

  ```bash
  lspci | grep -i ethernet
  ```
* Restart networking:

  ```bash
  sudo systemctl restart NetworkManager
  ```

---

# 🧠 Security Considerations

* Always exclude SSH when capturing remotely.
* Avoid capturing sensitive production traffic.
* Store PCAP files securely (they may contain credentials).
* Restrict capture permissions to trusted users only.

---

# ✅ End of Troubleshooting Guide
