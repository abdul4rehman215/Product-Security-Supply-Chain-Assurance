# 🕵️ Lab 01: OSINT-Based Product Reconnaissance with SpiderFoot & recon-ng

## 📌 Lab Summary
This lab demonstrates **OSINT-driven product/domain reconnaissance** using two industry-recognized frameworks:

- **SpiderFoot** (automated OSINT aggregation + correlation)
- **recon-ng** (module-driven reconnaissance workflows)

In addition to manual DNS recon, I built **Python automation scripts** to:
- start scans programmatically,
- collect/structure results,
- generate machine-readable JSON reports,
- generate executive-readable text summaries,
- perform lightweight risk scoring and recommendations.

This lab reflects **Product Security + Supply Chain Assurance** fundamentals: understanding **public exposure** of assets and deriving security insights from open data.

---

## 🎯 Objectives
By the end of this lab, I was able to:

- Install and configure **SpiderFoot** and **recon-ng** on Ubuntu
- Perform automated reconnaissance against a target domain/product footprint
- Collect intelligence from multiple OSINT sources and DNS enumeration
- Create Python scripts to orchestrate and automate OSINT workflows
- Analyze reconnaissance results and generate structured security reports

---

## ✅ Prerequisites
- Basic Linux command-line proficiency
- Fundamental networking knowledge (DNS, domains, IP addresses)
- Python programming basics
- Understanding of cybersecurity principles

---

## 🧪 Lab Environment
- **OS:** Ubuntu 24.04 LTS (Cloud Lab)
- **Python:** 3.12+
- **Tools:** Git, curl, wget, build-essential, dnsutils, net-tools
- **Connectivity:** Internet access required for OSINT sources

---

## 🗂️ Repository Structure
```text
lab01-osint-product-recon-spiderfoot-reconng/
├── README.md
├── commands.sh
├── output.txt
├── interview_qna.md
├── troubleshooting.md
└── scripts/
    ├── spiderfoot_scanner.py
    ├── reconng_scanner.py
    ├── osint_master.py
    └── analyze_results.py
```

---

## 🧩 What I Built

### 1) Tool Installation + Verification

* Updated OS packages
* Installed dependencies required for OSINT + Python tooling
* Cloned and installed:

  * SpiderFoot (from GitHub)
  * recon-ng (from GitHub)
* Verified:

  * `python3 --version`
  * `pip3 --version`
  * `python3 sf.py --help`
  * `python3 recon-ng --help`

---

## 🧭 Tasks Completed

## ✅ Task 1: Install and Configure OSINT Tools

### Step 1.1: System update + dependencies

Installed build and Python dependencies plus:

* `dnsutils` (for `dig`)
* `net-tools` (for `netstat`)

### Step 1.2: SpiderFoot install

* Cloned SpiderFoot
* Installed requirements using pip
* Verified CLI help output
* Started SpiderFoot web service on `127.0.0.1:5001`

### Step 1.3: recon-ng install

* Cloned recon-ng
* Installed requirements using pip
* Verified CLI help output

### Step 1.4: Start SpiderFoot web interface

* Started in background
* Validated service availability using `curl`

---

## 🤖 Task 2: Create OSINT Automation Scripts

I created 4 scripts:

### `scripts/spiderfoot_scanner.py`

* Starts a SpiderFoot scan via local web interface
* Enables key modules:

  * DNS resolve
  * SSL cert
  * Web framework detection
  * Subdomain enumeration

### `scripts/reconng_scanner.py`

* Runs recon-ng in a non-interactive way using stdin resource commands
* Builds a workspace + installs modules + runs workflows automatically

### `scripts/osint_master.py`

A complete OSINT workflow orchestrator:

* DNS enumeration with `dig`
* Basic subdomain discovery using common prefixes
* Calls SpiderFoot scan script
* Calls recon-ng scan script
* Writes:

  * JSON report
  * text summary report
* Produces a basic risk scoring + recommendations

### `scripts/analyze_results.py`

* Parses the JSON report
* Builds an executive summary
* Highlights risk factors
* Outputs risk score + recommended actions

---

## 🧭 Task 3: Execute OSINT Reconnaissance

### Step 3.1: Manual DNS Recon

Performed reconnaissance using:

* `dig example.com A +short`
* `dig example.com MX +short`
* `dig example.com NS +short`
* `dig -x 93.184.216.34 +short`
* Subdomain checks using a shell loop

### Step 3.2: Automated scans

Executed:

* `python3 spiderfoot_scanner.py example.com`
* `python3 reconng_scanner.py example.com`
* `python3 osint_master.py example.com`

### Step 3.3: Review reports

* Rendered JSON using `python3 -m json.tool`
* Viewed generated text summary
* Verified subdomain references via `grep`

---

## 🧾 Task 4: Create Analysis and Reporting Tools

* Built `analyze_results.py`
* Executed analysis against the generated JSON report
* Produced an executive summary (risk score + recommendations)

---

## ✅ Results

Artifacts produced during execution:

* SpiderFoot confirmed running and accepted scan requests
* recon-ng workflow executed and resolved `www.example.com`
* OSINT Master produced structured reports:

  * `results/osint_report_example.com_<timestamp>.json`
  * `results/osint_report_example.com_<timestamp>.txt`
* Analyzer produced executive summary output with:

  * discovered subdomain count
  * risk score + level
  * recommendations

---

## 📚 What I Learned

* OSINT is a **repeatable process** when automated with scripts and structured outputs
* DNS + subdomain exposure is often the first visible indicator of attack surface
* Combining multiple tools increases confidence and coverage
* Generating both **JSON + executive text** makes results usable for engineering and leadership audiences

---

## 🔐 Why This Matters (Product Security & Supply Chain Assurance)

Publicly exposed assets create real risk:

* misconfigured admin/staging endpoints,
* forgotten DNS records,
* exposed mail infrastructure,
* passive recon data used for targeting.

Regular OSINT-based recon supports:

* attack surface management,
* third-party/vendor exposure review,
* product footprint awareness,
* security posture validation.

---

## 🌍 Real-World Applications

* External attack surface discovery for products/services
* Pre-assessment reconnaissance before penetration tests
* Vendor domain footprint checks (supply chain exposure)
* Threat intelligence enrichment for SOC/IR workflows
* Continuous monitoring for newly exposed subdomains or services

---

## 🏁 Conclusion

This lab implemented OSINT-based reconnaissance using SpiderFoot and recon-ng, supported by Python automation and reporting tooling. The workflow demonstrates practical skills in identifying externally visible assets, generating actionable findings, and producing repeatable security intelligence reports.

✅ Lab completed successfully on Ubuntu 24.04 cloud environment.
