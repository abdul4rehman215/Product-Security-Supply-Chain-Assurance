# 📱 Lab 02: Enumerate Android Apps with apktool, jadx, and apkleaks

> **Topic:** Android APK Static Analysis (apktool + JADX + apkleaks) + Automation (Python + Bash)  
> **Environment:** Ubuntu 24.04 Cloud Lab (Java 11, Python 3.12+)  
> **Focus:** Static analysis + secret discovery + automated reporting for mobile app security

---

## 🎯 Objectives

By the end of this lab, I was able to:

* Decompile Android APK files using **apktool** to extract resources and `AndroidManifest.xml`
* Analyze decompiled Java code using **JADX** to identify common security weaknesses
* Extract hardcoded secrets and sensitive patterns using **apkleaks**
* Automate APK analysis using **Python scripts**
* Generate structured outputs and **HTML security reports** for documentation

---

## ✅ Prerequisites

* Basic Android application architecture understanding
* Linux command-line familiarity
* Basic Java and Python knowledge
* Awareness of mobile application security concepts

---

## 🧪 Lab Environment

* **OS:** Ubuntu 24.04 (Cloud Lab)
* **Java:** OpenJDK 11
* **Python:** 3.12+
* **Tools:** apktool, JADX, apkleaks, aapt, jq, wget, unzip/zip
* **Sample APK:** OWASP MSTG Android Java Debug APK (for practice)

---

## 🧩 Tasks Performed

### ✅ Task 1: Decompile APK with apktool

* Created working directories for tool outputs
* Installed required dependencies and verified tool versions
* Downloaded a sample APK and confirmed it’s a valid zip archive
* Decompiled APK using apktool and inspected output structure
* Checked manifest for high-risk flags:

  * `android:debuggable="true"`
  * `android:allowBackup="true"`
  * `android:exported="true"`
  * `android:usesCleartextTraffic="true"`

---

### ✅ Task 2: Decompile and Review Code with JADX

* Decompiled APK to Java source using JADX
* Searched for security-sensitive patterns:

  * hardcoded secrets (`password`, `token`, `apikey`)
  * insecure SQL usage (`rawQuery`, `execSQL` concatenation)
  * insecure endpoints (`http://`)
  * weak crypto usage (e.g., `AES/ECB`)
  * WebView risks (`setJavaScriptEnabled(true)`, `addJavascriptInterface()`)

---

### ✅ Task 3: Extract Secrets with apkleaks

* Installed/updated apkleaks
* Extracted secrets with default patterns (text + JSON output)
* Created custom patterns file for:

  * AWS keys
  * Google API keys
  * Firebase URLs
  * JWT tokens
  * Private key headers
* Validated output using `jq`

---

### ✅ Task 4: Build Full Automation Pipeline

Built automation scripts to turn static analysis into a repeatable workflow:

* **APK decompilation + manifest checks** (`apk_decompiler.py`)
* **Java security pattern detection** (`java_analyzer.py`)
* **End-to-end analysis + summary generation** (`comprehensive_analyzer.py`)
* **HTML report generator** (`generate_report.py`)
* **Batch analysis of many APKs** (`batch_analyze.sh`)

---

## 📌 Key Security Findings (from sample APK)

This lab intentionally uses a vulnerable training APK. Findings included:

* ✅ Debug mode enabled in manifest
* ✅ Cleartext traffic allowed (HTTP allowed)
* ✅ Hardcoded secrets found (API key, token, password, secret)
* ✅ SQL queries built using string concatenation (potential SQL injection)
* ✅ Weak crypto mode detected (`AES/ECB/PKCS5Padding`)
* ✅ WebView JavaScript enabled + JS bridge exposed

---

## 📄 Evidence & Outputs

All executed commands and outputs are recorded in:

* `commands.sh` → exact commands executed during lab
* `output.txt` → captured outputs (including tool outputs + scan results)
* `scripts/` → all Python + Bash scripts used for automation
* `final_analysis/` (generated during execution) contains:

  * `comprehensive_analysis.json`
  * `report.html`

> ⚠️ Generated analysis folders can be recreated anytime by rerunning scripts, so only the automation scripts and captured outputs are committed.

---


## 🧭 Repository Structure

```text
lab02-enumerate-android-apps/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
├── scripts/
│   ├── apk_decompiler.py
│   ├── java_analyzer.py
│   ├── comprehensive_analyzer.py
│   ├── generate_report.py
│   └── batch_analyze.sh
└── notes/
    └── scope-and-safety.md
```

> ✅ **Note:** This lab uses a publicly available sample APK for learning and security testing.

---

## 🌍 Why This Matters (Real-World Relevance)

Static APK analysis is used in:

* Mobile application penetration testing (Android)
* Secure SDLC validations for release builds
* Security reviews of third-party apps before internal deployment
* Supply chain security (detecting embedded secrets or unsafe SDK usage)
* Threat hunting for leaked keys/tokens inside application binaries

---

## ✅ Result

At the end of the lab:

* I produced automation scripts for Android static security analysis
* I extracted high-risk indicators from:

  * manifest misconfigurations
  * Java source patterns
  * secret leakage (apkleaks)
* I generated a machine-readable report (JSON) and a human-readable report (HTML)

---

## 🏁 Conclusion

This lab strengthened my Android product security workflow by combining:

* **apktool** (resources + manifest)
* **JADX** (code visibility)
* **apkleaks** (secret discovery)
* **automation** (repeatable assessments + reporting)

This workflow is practical for real security engagements and internal product security checks, especially when analyzing third-party APKs or pre-release builds.

---

## 📎 Notes (Scope & Safety)

See: `notes/scope-and-safety.md`
This repo is for **defensive learning and authorized testing only**.
