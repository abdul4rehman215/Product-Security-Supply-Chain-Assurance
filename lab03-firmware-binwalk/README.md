# 🧪 Lab 3: Extract Firmware Using binwalk and Analyze Filesystem

## 🧠 Overview
This lab focuses on **firmware extraction and filesystem analysis** using `binwalk` on Ubuntu 24.04.  
The workflow covers:

- Installing `binwalk` + extraction dependencies  
- Downloading a real firmware image (OpenWrt) and generating a dummy firmware blob for controlled testing  
- Running signature + entropy analysis  
- Attempting automated and manual extraction  
- Performing filesystem and security checks for common firmware risks  
- Building **automation scripts** (Python + Bash) to standardize extraction + reporting

> ⚠️ Note: In this lab run, the analysis was demonstrated on `sample_firmware.bin` (a zero-filled dummy firmware), so binwalk correctly found **no signatures** and extraction produced **no artifacts**. This is still valuable as it demonstrates a clean “no findings” baseline and validates automation logic.

---

## 🎯 Objectives
By the end of this lab, I was able to:

- Install and configure **binwalk** for firmware analysis  
- Extract firmware images and identify embedded filesystems  
- Navigate and analyze extracted firmware components  
- Identify common security vulnerabilities in firmware filesystems  
- Create Python scripts to automate firmware extraction and analysis  
- Document findings and assess security implications  

---

## ✅ Prerequisites
You should be comfortable with:

- Linux command line basics  
- Filesystems and directory structures  
- Python basics (files, subprocess, JSON)  
- Common vulnerability categories (credentials, permissions, crypto, command injection)

---

## 🧪 Lab Environment
- Ubuntu 24.04 (cloud lab)
- `binwalk` + extraction utilities
- Python 3 + pip
- Internet connectivity

---

## 🗂️ Repo Structure

```text
lab03-firmware-binwalk/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
└── scripts/
    ├── firmware_analyzer.py
    ├── vulnerability_scanner.py
    └── comprehensive_analysis.sh
````

---

## 🧩 What I Did (High-Level Workflow)

### 1) Installed Tools & Dependencies

Installed `binwalk` plus common extractors (`mtd-utils`, `squashfs-tools`, `p7zip`, `cabextract`, etc.) and Python deps (`python-magic`, `pycrypto`).

### 2) Downloaded Firmware + Created Dummy Firmware

* Downloaded a public OpenWrt sysupgrade image (real firmware artifact)
* Created a controlled dummy firmware blob using `/dev/zero` for baseline testing

### 3) Firmware Recon with binwalk

* Ran `binwalk` signature scan
* Performed entropy checks with `-E` and saved entropy data via `--save`

### 4) Firmware Extraction (Automatic + Manual Attempts)

* Attempted auto extraction with `binwalk -e`
* Confirmed no signatures matched for the dummy firmware
* Attempted manual carving with `--dd=".*"` and `--dd="filesystem"`

### 5) Filesystem + Security Checks

Performed searches (in extracted directory) for:

* `.conf`, `.cfg`, `.ini`
* `passwd`, `shadow`
* hardcoded credential patterns
* private keys (`.key`, `.pem`)
* executables
* scripts (`.sh`)
* web artifacts (`.php`, `.cgi`, `.html`)
* risky keywords (`system`, `exec`, `eval`)

### 6) Built Automation

Created:

* `firmware_analyzer.py` → runs binwalk, extracts, inventories files, greps for secret patterns, writes JSON report
* `vulnerability_scanner.py` → looks for command injection patterns, hardcoded creds, weak crypto usage, insecure file perms
* `comprehensive_analysis.sh` → end-to-end pipeline that produces quick analysis artifacts and a summary report

---

## 📌 Key Results (From This Run)

Because the firmware test file was generated using `dd if=/dev/zero`, it contained:

* No embedded signatures
* No filesystem objects
* No extracted files
* No security findings

✅ This validates the pipeline and reporting flow for a **clean baseline**.

---

## 🔐 Why This Matters (Product Security & Supply Chain Assurance)

Firmware is one of the most critical supply chain artifacts in embedded/IoT environments:

* Attackers can hide backdoors inside firmware filesystems
* Credentials and private keys are often embedded accidentally
* Weak crypto or unsafe command execution patterns may exist in shipped binaries/scripts
* Automated extraction + scanning enables scalable validation across third-party firmware dependencies

---

## 🏁 Conclusion

This lab established a firmware analysis workflow using `binwalk` and supporting tools, then automated extraction and scanning with Python/Bash. Even though the dummy firmware produced no findings, the analysis pipeline is now ready to be applied to real firmware images (like the OpenWrt sample downloaded in the lab).

---
