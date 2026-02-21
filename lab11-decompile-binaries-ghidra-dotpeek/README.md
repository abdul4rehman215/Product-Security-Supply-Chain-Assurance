# 🧪 Lab 11: Decompile Binaries Using Ghidra & dotPeek

**Environment:** Ubuntu 24.04.1 LTS (Cloud Lab Environment)  
**User:** `toor`

---

## 🧾 Lab Summary

This lab focuses on **static reverse engineering and security analysis** of both:

- **Native Linux binaries (ELF)** using **Ghidra**
- **.NET assemblies (PE/.exe)** using **JetBrains dotPeek (via Wine)**

You also implemented **Ghidra headless automation** using Python + a custom Ghidra Java script to detect common vulnerability patterns, and generated **professional security assessment reports**.

---

## 🎯 Objectives

By the end of this lab, I was able to:

- Install and configure **Ghidra** for binary reverse engineering
- Decompile native Linux binaries and identify security vulnerabilities
- Use **dotPeek** to analyze **.NET assemblies**
- Automate binary analysis using **Ghidra headless mode**
- Generate security assessment reports from decompiled code

---

## ✅ Prerequisites

Before performing this lab, the following knowledge was required:

- Basic understanding of **C/C++** and **C#**
- Familiarity with the **Linux command line**
- Knowledge of common security vulnerabilities:
  - Buffer overflows
  - Format string vulnerabilities
  - Command injection
  - SQL injection
  - Path traversal
  - Hardcoded secrets
- Understanding of binary file formats (**ELF**, **PE**)

---

## 🧰 Lab Environment

This lab was performed in a cloud lab environment.

| Component | Details |
|----------|---------|
| OS | Ubuntu 24.04.1 LTS |
| User | toor |
| Tools | Ghidra, Wine, dotPeek, Mono, gcc |
| Targets | ELF binary + .NET PE assembly |

---

## 📁 Repository Structure (Lab Format)

```text
lab11-decompile-binaries-ghidra-dotpeek/
├── README.md
├── commands.sh
├── output.txt
├── vulnerable_app.c
├── VulnerableApp.cs
├── vulnerable_app
├── VulnerableApp.exe
├── analysis_report.md
├── dotnet_analysis.md
├── ghidra/                             # Ghidra installation (local folder)
├── ghidra_projects/                    # Ghidra GUI project folder (created via GUI)
├── dotpeek_output/                     # dotPeek export project folder (GUI export)
├── automated_analysis/
│   ├── ghidra_projects/
│   └── analysis_report.json
└── scripts/
    ├── automated_analysis.py
    └── FindVulnerabilities.java
````

> ✅ Notes:
>
> * `output.txt` contains all command outputs (as executed in the lab).
> * `scripts/` contains automation + headless analysis tooling.
> * Reports are kept as separate `.md` files for portfolio-ready documentation.

---

## 🧩 Tasks Performed (High-Level Overview)

### ✅ Task 1: Install Ghidra + Create Sample Binaries

* Installed **Java 17** (required by Ghidra)
* Downloaded and extracted **Ghidra 10.4**
* Created a vulnerable **C program** and compiled it with mitigations disabled
* Installed **Wine** and installed **dotPeek** inside Wine
* Created a vulnerable **C# .NET application** and compiled it using Mono (`mcs`)

### ✅ Task 2: Analyze Native Binary Using Ghidra (GUI)

* Created a **Non-Shared Ghidra Project**
* Imported ELF binary `vulnerable_app`
* Ran full analysis in CodeBrowser
* Located vulnerable code paths inside decompiled functions

### ✅ Task 3: Analyze .NET Assembly Using dotPeek (GUI via Wine)

* Launched dotPeek using Wine (`dotPeek64.exe`)
* Loaded `VulnerableApp.exe`
* Reviewed decompiled C# code for security issues
* Exported decompiled project to `dotpeek_output/`

### ✅ Task 4: Automate Analysis Using Ghidra Headless + Python

* Built a Python automation tool to:

  * import binaries
  * run headless analysis
  * execute a post-script (`FindVulnerabilities.java`)
  * generate JSON report
* Validated that ELF analysis succeeds while PE/.NET analysis is not supported in this mode

---

## 🔍 Vulnerabilities Identified

### 🧨 Native ELF (`vulnerable_app`)

Identified from decompiled output in Ghidra:

1. **Buffer Overflow**

   * Unsafe `strcpy()` into stack buffer `char buffer[64]`

2. **Format String Vulnerability**

   * `printf(input)` directly prints attacker-controlled input as a format string

3. **Command Injection**

   * `system("echo <user_input>")` executes shell command built with untrusted input

---

### 🧬 .NET Assembly (`VulnerableApp.exe`)

Identified from dotPeek decompilation:

1. **SQL Injection**

   * query built using string concatenation from user inputs

2. **Path Traversal**

   * file path built using `"/var/data/" + filename` with no validation

3. **Hardcoded Secret**

   * API key stored directly in compiled assembly as plaintext string

---

## 🤖 Automation Results (Ghidra Headless)

The automated analysis script produced a structured JSON report:

* **Targets analyzed:** 2
* **Success:** 1 (ELF binary)
* **Failure:** 1 (PE/.NET assembly timed out)

The headless script successfully detected:

* `system()` reference
* `strcpy()` reference
* multiple `printf()` callsites
* large stack buffers like `char[64]` and `char[256]`

---

## 📊 Expected Outcomes Achieved

✅ Ghidra Analysis: vulnerabilities identified in native binary
✅ dotPeek Analysis: .NET issues documented and exported
✅ Automation: Python + headless analysis pipeline built
✅ Reports: professional security findings stored in separate Markdown docs

---

## 🧾 Reports Generated

* `analysis_report.md` → native ELF security assessment
* `dotnet_analysis.md` → .NET assembly security assessment
* `automated_analysis/analysis_report.json` → headless automation results

---

## 🌍 Why This Matters

Binary decompilation and static analysis are essential for:

* **Security auditing** of closed-source applications
* **Vulnerability research**
* **Malware analysis**
* Verification of security controls (safe APIs, proper validation, secret management)

This lab demonstrates practical **reverse engineering workflows** used in real-world AppSec and product security investigations.

---

## 🏢 Real-World Applications

Skills developed here apply directly to:

* Application Security (AppSec)
* Product Security & Supply Chain Assurance
* Reverse Engineering / Malware triage
* Vulnerability assessment of third-party software
* Static detection engineering (signatures + scripts)

---

## ✅ Conclusion

In this lab, you successfully:

* Installed and configured **Ghidra** and performed ELF reverse engineering
* Installed and ran **dotPeek via Wine** for .NET decompilation
* Identified real-world vulnerability patterns in both targets
* Automated binary analysis using **Ghidra headless mode**
* Produced structured reporting suitable for security assessment workflows

---

## 📌 Next Steps

* Explore Ghidra scripting deeper (API, analyzers, decompiler customization)
* Add more detection logic to the Java post-script (taint sources/sinks)
* Analyze additional binaries (stripped, PIE-enabled, hardened builds)
* Practice on controlled malware samples in a safe environment

✅ Lab 11 Completed Successfully
