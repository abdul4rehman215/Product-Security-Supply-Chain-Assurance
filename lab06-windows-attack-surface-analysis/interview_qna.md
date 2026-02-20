# 🎤 Interview Q&A — Lab 06: Windows Attack Surface Analysis with Open-Source Tools

---

## 1️⃣ What is an attack surface?

**Answer:**  
An attack surface refers to the total number of potential entry points where an unauthorized user (attacker) can try to enter or extract data from a system. It includes:

- Open ports
- Running services
- Exposed APIs
- User accounts
- Installed software
- Misconfigurations

In this lab, we analyzed the attack surface by enumerating processes, services, network exposure, and file permissions.

---

## 2️⃣ Why is service enumeration important in security assessments?

**Answer:**  
Service enumeration helps identify:

- Open ports
- Running services
- Services exposed to external networks
- Misconfigured daemons

Exposed services like SSH, FTP, or databases may introduce vulnerabilities. Early detection allows proactive hardening before exploitation occurs.

---

## 3️⃣ What risks are associated with SSH being exposed to 0.0.0.0?

**Answer:**  
Binding to `0.0.0.0` means SSH listens on all network interfaces. Risks include:

- Brute-force attacks
- Credential stuffing
- Automated scanning
- Remote exploitation attempts

Mitigation:
- Restrict SSH via firewall rules
- Disable password authentication
- Enforce key-based authentication
- Enable rate limiting (fail2ban)

---

## 4️⃣ Why are SUID binaries considered a security risk?

**Answer:**  
SUID (Set User ID) binaries run with the file owner's privileges (often root). If:

- The binary has a vulnerability
- The binary is misconfigured
- The binary is outdated

It may allow privilege escalation.

While many SUID binaries are necessary (e.g., `sudo`, `passwd`), they must be monitored and kept patched.

---

## 5️⃣ How does your attack surface analyzer calculate risk?

**Answer:**  
The analyzer calculates risk based on:

- Number of open ports
- Number of privileged processes
- Identified vulnerabilities

Each factor contributes to a weighted score (0–100). While heuristic-based, it provides quick visibility into system security posture.

---

## 6️⃣ What is the difference between exposure and vulnerability?

**Answer:**

| Exposure | Vulnerability |
|----------|--------------|
| A service or port accessible externally | A weakness that can be exploited |
| Example: Port 22 open | Example: SSH weak password authentication |
| May be acceptable if controlled | Always needs mitigation |

In this lab, SSH exposure was identified, but configuration weaknesses were more critical.

---

## 7️⃣ Why should SSH configuration explicitly define security directives?

**Answer:**  
Relying on default settings can cause:

- Inconsistent behavior across environments
- Audit failures
- Unexpected security posture after updates

Best practice:
Explicitly define security settings like:
```

PermitRootLogin no
PasswordAuthentication no

```

---

## 8️⃣ How would you harden this system further?

**Answer:**

1. Restrict SSH via firewall (UFW/security groups)
2. Enforce key-based authentication
3. Disable root login
4. Enable intrusion detection (Fail2ban)
5. Regularly audit SUID binaries
6. Implement file integrity monitoring
7. Patch system regularly

---

## 9️⃣ Why combine automated and manual analysis?

**Answer:**  
Automation provides:

- Speed
- Consistency
- Scalability

Manual verification provides:

- Context awareness
- Reduced false positives
- Human reasoning

Security assessments should always combine both.

---

## 🔟 What is the importance of generating an HTML security report?

**Answer:**  
An HTML report:

- Provides executive-friendly presentation
- Supports audit documentation
- Enables management visibility
- Helps compliance tracking

Technical findings must be translated into business-impact language.

---

## 1️⃣1️⃣ What tools were used in this lab?

**Answer:**

- Python (automation scripting)
- psutil (process and network inspection)
- ss / netstat (service enumeration)
- find (file permission auditing)
- stat (ownership validation)
- colorama (terminal formatting)
- JSON & HTML report generation

---

## 1️⃣2️⃣ What is privilege escalation?

**Answer:**  
Privilege escalation occurs when an attacker gains higher permissions than intended. For example:

- Exploiting a SUID binary
- Exploiting a vulnerable service
- Misconfigured sudo rules

Monitoring root processes and SUID binaries helps detect escalation paths.

---

## 1️⃣3️⃣ Why is risk scoring important?

**Answer:**  
Risk scoring:

- Prioritizes remediation
- Allocates resources effectively
- Translates technical issues into business risk

Without scoring, all issues appear equally important, which is misleading.

---

## 1️⃣4️⃣ How would this lab translate to a real enterprise environment?

**Answer:**  
In enterprise:

- Systems may have hundreds of services
- Exposure could include web servers, databases, APIs
- Attack surface changes dynamically
- Compliance requirements apply (ISO 27001, NIST, CIS)

This lab simulates the methodology used in:

- Red Team reconnaissance
- Blue Team hardening
- Security posture assessments
- Internal audits

---

## 1️⃣5️⃣ What did you personally learn from this lab?

**Answer:**  
This lab strengthened understanding of:

- Attack surface identification
- Linux service exposure analysis
- Security configuration auditing
- Risk prioritization
- Security reporting for stakeholders
- Automation for repeatable assessments

It reinforced the importance of systematic security review rather than ad-hoc inspection.

---
