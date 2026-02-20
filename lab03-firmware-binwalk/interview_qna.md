# 🎤 Interview Q&A - Lab 3: Firmware Extraction & Filesystem Analysis using binwalk

---

## 1️⃣ What is firmware and why is it important in security?

**Answer:**  
Firmware is low-level software embedded into hardware devices such as routers, IoT devices, and embedded systems. It controls device functionality and hardware interaction.  

From a security perspective, firmware:
- Often contains hardcoded credentials
- May include outdated or vulnerable components
- Is rarely monitored after deployment
- Represents a major supply chain attack vector

---

## 2️⃣ What is binwalk used for?

**Answer:**  
`binwalk` is a firmware analysis tool used to:

- Identify embedded file signatures inside binary blobs
- Extract compressed filesystems
- Perform entropy analysis
- Carve embedded files from firmware images

It is widely used in IoT security, reverse engineering, and embedded device analysis.

---

## 3️⃣ What is entropy analysis in firmware?

**Answer:**  
Entropy measures randomness in binary data.

- **Low entropy** → likely plain text or empty data
- **High entropy** → compressed or encrypted content

Entropy analysis helps identify:
- Encrypted payloads
- Compressed archives
- Hidden embedded data

---

## 4️⃣ What is a SquashFS filesystem?

**Answer:**  
SquashFS is a compressed read-only filesystem commonly used in embedded devices and router firmware.

Characteristics:
- High compression ratio
- Optimized for low storage environments
- Frequently used in OpenWrt and router firmware

binwalk can detect and extract SquashFS partitions.

---

## 5️⃣ Why do we search for passwd and shadow files in firmware?

**Answer:**  
`/etc/passwd` and `/etc/shadow` may contain:

- Default credentials
- Weak password hashes
- Hardcoded user accounts

If extracted from firmware, they can:
- Allow offline password cracking
- Enable unauthorized device access
- Reveal administrative credentials

---

## 6️⃣ What are common firmware vulnerabilities?

**Answer:**

- Hardcoded credentials
- Insecure file permissions
- Weak cryptography (MD5, SHA1, DES)
- Command injection in scripts
- Outdated third-party libraries
- Insecure web interfaces
- Backdoor accounts

---

## 7️⃣ What is command injection in firmware context?

**Answer:**  
Command injection occurs when firmware scripts use dangerous functions like:

```bash
system()
exec()
popen()
eval()
````

If user input is passed unsafely into these functions, attackers may execute arbitrary commands on the device.

---

## 8️⃣ Why is automation important in firmware analysis?

**Answer:**
Manual firmware analysis is time-consuming and inconsistent.

Automation provides:

* Repeatability
* Scalability across multiple firmware images
* Standardized reporting
* Faster supply chain validation
* CI/CD integration capability

---

## 9️⃣ Why is weak cryptography dangerous in firmware?

**Answer:**
Weak algorithms such as:

* MD5
* SHA1
* DES
* RC4

Are vulnerable to:

* Collision attacks
* Brute-force attacks
* Cryptographic compromise

Modern secure alternatives include:

* SHA-256+
* AES-GCM
* Proper key derivation functions

---

## 🔟 What is supply chain risk in firmware?

**Answer:**
Firmware may include:

* Third-party libraries
* External vendor components
* Pre-compiled binaries

If these components are compromised:

* Backdoors can be inserted
* Malware can propagate
* Organizations may deploy vulnerable products unknowingly

Firmware validation reduces supply chain exposure.

---

## 1️⃣1️⃣ What is the significance of file permissions in firmware?

**Answer:**
Overly permissive files (e.g., world-writable):

* Allow privilege escalation
* Enable unauthorized modification
* Facilitate persistence mechanisms

Firmware should enforce least privilege.

---

## 1️⃣2️⃣ What challenges exist in firmware analysis?

**Answer:**

* Proprietary formats
* Encrypted firmware
* Obfuscated binaries
* Custom filesystems
* Large firmware size
* Missing extraction tools

Security analysts must combine tools and manual techniques.

---

## 1️⃣3️⃣ What is the difference between static and dynamic firmware analysis?

**Static Analysis:**

* Examines firmware without execution
* Uses tools like binwalk, strings, grep
* Safer and faster

**Dynamic Analysis:**

* Emulates firmware in QEMU
* Observes runtime behavior
* Detects active vulnerabilities

Both approaches complement each other.

---

## 1️⃣4️⃣ Why was no vulnerability found in this lab run?

**Answer:**
The test firmware `sample_firmware.bin` was created using:

```bash
dd if=/dev/zero
```

It contains only zeroed data and no embedded filesystem.
The absence of findings confirms:

* The pipeline works correctly
* The analysis baseline is clean
* The scripts handle empty firmware safely

---

## 1️⃣5️⃣ How would you improve this analysis in a real-world scenario?

**Answer:**

* Analyze real firmware (e.g., OpenWrt image downloaded)
* Use `foremost` and `jefferson` for deeper carving
* Perform binary analysis using `Ghidra` or `radare2`
* Emulate firmware with QEMU
* Scan for known CVEs in extracted packages
* Integrate into CI/CD firmware validation pipeline

---

# ✅ Summary

This lab demonstrates:

* Practical firmware extraction
* Filesystem analysis techniques
* Vulnerability pattern detection
* Security automation scripting
* Supply chain risk assessment fundamentals

These skills are critical for:

* IoT Security Engineers
* Product Security Analysts
* Embedded Security Researchers
* Supply Chain Security Professionals
