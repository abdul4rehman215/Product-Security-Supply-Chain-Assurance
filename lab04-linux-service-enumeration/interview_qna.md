# 🎤 Interview Q&A - Lab 4: Linux Service Enumeration with nmap & netstat

---

## 1️⃣ What is service enumeration?

**Answer:**  
Service enumeration is the process of identifying open ports, running services, and their versions on a target system. It helps determine the attack surface and is a critical first step in security assessment and penetration testing.

---

## 2️⃣ What is the difference between port scanning and service enumeration?

**Answer:**  
- **Port Scanning** identifies open ports.
- **Service Enumeration** goes deeper by identifying the service running on the port and often its version, configuration, and additional details.

---

## 3️⃣ What does `nmap -sV` do?

**Answer:**  
The `-sV` option enables service version detection. It probes open ports to determine the exact service and version running on that port.

Example:
```

nmap -sV localhost

```

---

## 4️⃣ What does `nmap -A` perform?

**Answer:**  
The `-A` flag performs:
- OS detection
- Service version detection
- Script scanning (default NSE scripts)
- Traceroute

It provides aggressive and comprehensive information about the target.

---

## 5️⃣ What is the difference between TCP and UDP scanning?

**Answer:**  
- **TCP scanning** checks TCP ports (e.g., SSH, HTTP).
- **UDP scanning** checks UDP services (e.g., DNS, SNMP).
- UDP scans are generally slower because UDP is connectionless and lacks acknowledgments.

---

## 6️⃣ What is the purpose of `netstat -ln`?

**Answer:**  
`netstat -ln` displays listening ports using numeric addresses.  
It helps identify services actively listening on the system without resolving hostnames.

---

## 7️⃣ Why compare nmap results with netstat results?

**Answer:**  
- `nmap` scans externally (network perspective).
- `netstat` shows local listening services.
Comparing both ensures accuracy and detects discrepancies such as firewall filtering or hidden services.

---

## 8️⃣ What is NSE in nmap?

**Answer:**  
NSE (Nmap Scripting Engine) allows running scripts for:
- Vulnerability detection
- Banner grabbing
- Authentication testing
- Service enumeration

Example:
```

nmap --script vuln localhost

```

---

## 9️⃣ Why is port 22 significant in this lab?

**Answer:**  
Port 22 was identified as open and running **SSH (OpenSSH 9.6p1)**.  
SSH is commonly used for remote administration and is often targeted in brute-force attacks if not secured properly.

---

## 🔟 What security risks are associated with exposed services?

**Answer:**  
- Outdated software versions may contain vulnerabilities.
- Misconfigured services may allow unauthorized access.
- Unnecessary open ports increase attack surface.
- Weak authentication mechanisms may lead to compromise.

---

## 1️⃣1️⃣ Why automate enumeration using Python?

**Answer:**  
Automation:
- Improves efficiency
- Reduces human error
- Ensures repeatability
- Enables structured reporting (JSON/TXT)
- Supports integration into CI/CD or monitoring pipelines

---

## 1️⃣2️⃣ What is a stealth scan (`-sS`)?

**Answer:**  
A stealth scan sends SYN packets without completing the TCP handshake.  
It is less likely to be logged compared to a full TCP connect scan.

---

## 1️⃣3️⃣ Why is legal authorization important before scanning?

**Answer:**  
Unauthorized scanning can:
- Violate laws
- Be interpreted as malicious activity
- Trigger intrusion detection systems
- Result in legal consequences

Always obtain explicit permission before scanning.

---

## 1️⃣4️⃣ What is the purpose of service version detection?

**Answer:**  
Version detection helps:
- Identify vulnerable software
- Match versions against CVE databases
- Plan patch management strategies
- Conduct vulnerability assessments

---

## 1️⃣5️⃣ How does service enumeration support Product Security & Supply Chain Assurance?

**Answer:**  
Service enumeration:
- Identifies exposed services in deployed systems
- Validates hardening standards
- Detects unauthorized services
- Ensures compliance with security baselines
- Supports continuous monitoring of infrastructure security posture

---
