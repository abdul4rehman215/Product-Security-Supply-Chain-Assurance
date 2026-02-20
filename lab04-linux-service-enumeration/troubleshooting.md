# 🛠️ Troubleshooting Guide - Lab 4: Linux Service Enumeration with nmap & netstat

---

# 1️⃣ nmap Command Not Found

## ❌ Problem
Running:
```
nmap localhost
```

Returns:
```
Command 'nmap' not found

```

## ✅ Solution
Install nmap:

```

sudo apt update
sudo apt install nmap -y

```

Verify:
```

nmap --version

```

---

# 2️⃣ netstat Command Not Found

## ❌ Problem
`
netstat: command not found
`

## ✅ Cause
Modern Ubuntu systems may not include `net-tools` by default.

## ✅ Solution
```

sudo apt install net-tools -y

```

Verify:
```

netstat --version

```

---

# 3️⃣ Permission Denied for UDP Scan

## ❌ Problem
`
nmap -sU localhost
`
Fails or shows limited results.

## ✅ Cause
UDP scans require elevated privileges.

## ✅ Solution
```

sudo nmap -sU --top-ports 100 localhost

```

---

# 4️⃣ nmap -A or -sS Requires Root

## ❌ Problem
Aggressive or stealth scans return incomplete results.

## ✅ Cause
SYN scan (`-sS`) requires raw socket access.

## ✅ Solution
Run with sudo:
```
sudo nmap -sS localhost
sudo nmap -A localhost
```

---

# 5️⃣ Python Module “nmap” Not Found

## ❌ Problem
Running:
```
python3 service_enumeration.py
```
Returns:
```

ModuleNotFoundError: No module named 'nmap'

```

## ✅ Solution
Install python-nmap:
```

pip3 install python-nmap

```

If still failing:
```

sudo apt install python3-nmap

```

---

# 6️⃣ netstat -lnp Does Not Show All Processes

## ❌ Problem
Process names are missing or partially shown.

## ✅ Cause
You are not running as root.

## ✅ Solution
```

sudo netstat -lnp

```

---

# 7️⃣ Slow Scanning Performance

## ❌ Problem
Full port scan (`-p-`) takes too long.

## ✅ Solutions
Use timing templates:
```

nmap -T4 localhost
nmap -T5 localhost

```

Or limit ports:
```

nmap -p 1-1000 localhost

```

---

# 8️⃣ Firewall Blocking Scan Results

## ❌ Problem
nmap shows ports as filtered.

## ✅ Cause
Firewall (ufw/iptables/security group) blocking probes.

## ✅ Solution
Check firewall:
```

sudo ufw status

```

Or review cloud security group rules.

---

# 9️⃣ Script Execution Permission Denied

## ❌ Problem
`
./nmap_scan.sh: Permission denied
`

## ✅ Solution
Make script executable:
```

chmod +x nmap_scan.sh

```

---

# 🔟 JSON Report Not Generated

## ❌ Problem
No JSON file created by Python script.

## ✅ Causes
- Script failed silently
- Directory permissions issue

## ✅ Solutions
Check:
```

ls -la enumeration_results

```

Ensure write permissions:
```

chmod -R u+w enumeration_results

```

---

# 1️⃣1️⃣ Difference Between nmap and netstat Results

## ❓ Why do they look slightly different?

- nmap shows ports as `22/tcp`
- netstat shows `0.0.0.0:22`

This is normal:
- nmap shows protocol + port
- netstat shows interface binding + port

---

# 1️⃣2️⃣ Unexpected Open Ports

## ❌ Problem
Additional services appear open.

## ✅ Steps
1. Identify service:
```

nmap -sV localhost

```
2. Identify process:
```

sudo netstat -lnp

```
3. Stop unnecessary service:
```

sudo systemctl stop <service>

```
4. Disable if not required:
```

sudo systemctl disable <service>

```

---

# 🔐 Security Best Practices Reminder

- Only scan systems you own or have permission to test.
- Keep tools updated.
- Log all enumeration activities.
- Secure output reports.
- Disable unnecessary services.
- Use key-based authentication for SSH.
- Monitor for unexpected listening ports regularly.

---

# 🧠 Key Lessons from Troubleshooting

- Many enumeration issues are permission-related.
- Always verify tool installation first.
- Compare external scan (nmap) with local inspection (netstat).
- Automation helps detect configuration inconsistencies.
- Service enumeration should be part of routine security auditing.

---
