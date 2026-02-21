# 🎤 Interview Q&A - Lab 10: Update Threat Models with New Data Inputs

## 1) What is the purpose of a threat model?
A threat model identifies **what can go wrong**, **how it can happen**, and **what controls reduce risk**. It helps prioritize defensive work using real risks instead of guesses.

---

## 2) Why should threat models be continuously updated?
Because attackers, tooling, and your environment change. New telemetry/network data can reveal:
- new techniques being used
- new indicators (IPs/domains)
- increased frequency of existing techniques  
Continuous updates keep the model **accurate and actionable**.

---

## 3) Why map telemetry events to MITRE ATT&CK?
MITRE ATT&CK provides a **standard language** to classify attacks. Mapping makes it easier to:
- communicate findings
- correlate detections across tools
- build consistent reports and dashboards
- drive mitigations aligned with real attacker behavior

---

## 4) What is the difference between a MITRE tactic and a technique?
- **Tactic** = attacker goal / “why” (e.g., *Credential Access*)
- **Technique** = method / “how” (e.g., *T1110 Brute Force*)

---

## 5) What data sources were used to update the threat model in this lab?
Two JSON inputs:
- **Telemetry data** (`security_telemetry.json`): host/user/process/command + technique IDs + severity
- **Network data** (`network_analysis.json`): flows, domains, ports, bytes, threat indicators (C2/EXFIL)

---

## 6) How does the lab identify attack patterns from telemetry?
It aggregates telemetry by:
- technique frequency (`technique_id`)
- severity distribution
- host activity (which systems are most active/noisy)

Then it builds `attack_patterns[]` with:
- technique ID/name/tactic
- frequency
- inferred severity
- confidence score

---

## 7) How does the lab identify indicators from network data?
It looks for flows where `threat_indicator` is:
- `C2`
- `EXFIL`

Then extracts:
- destination IPs → `malicious_ips`
- destination domains → `malicious_domains`
…and stores them with counts.

---

## 8) Why are backups created before updating the threat model?
To prevent loss of the previous model and support:
- rollback if a bad update occurs
- audit trail of changes
- comparison between versions (diff/deltas)

---

## 9) What are “deltas” and why do they matter?
Deltas are **differences between an old model and a new model**, such as:
- new techniques appearing
- frequency spikes
- severity changes
- new malicious IPs/domains

They matter because deltas drive **alerts and prioritization**.

---

## 10) Why did the updater sometimes produce “No alerts generated.”?
Because the regenerated model was **similar enough** to the existing one, and changes did not exceed alert thresholds such as:
- `new_techniques >= 3`
- `new_indicators >= 2`
- frequency increase ratio > `0.50`

---

## 11) What improvements would you make to confidence scoring?
Better confidence should include:
- technique correlation across multiple hosts/users
- indicator reputation/OSINT enrichment
- historical trend (increasing vs stable)
- event quality (confirmed vs low confidence)
- detection source reliability

---

## 12) What is the purpose of `metrics.json`?
It provides lightweight monitoring metrics for dashboards/CI/CD:
- total techniques
- severity counts
- indicator counts (IPs/domains)
- generated timestamp  
Useful for automation pipelines and continuous monitoring.

---

## 13) Why generate visualizations like technique frequency and tactic coverage?
Visualizations help:
- highlight top active techniques quickly
- explain coverage gaps (tactic coverage)
- communicate severity distribution to stakeholders
- support decision-making without reading raw JSON

---

## 14) How would you integrate this workflow into a SIEM?
Typical approach:
- ingest telemetry and network logs into SIEM
- run the updater as a scheduled job (cron / CI pipeline)
- send alerts to SIEM, email, Slack, webhook
- enrich indicators via TI feeds
- create dashboards from metrics + model outputs

---

## 15) What risks exist if technique mappings are incomplete?
If mappings are missing:
- techniques become “Unknown”
- reporting becomes less useful
- mitigations may not align with real ATT&CK controls  
Solution: dynamically pull official ATT&CK mappings or maintain a continuously updated mapping database.

---

## 16) How would you test alerting functionality reliably?
To force deltas:
- regenerate data with different seeds
- inject new technique IDs into telemetry
- add new suspicious IPs/domains to network flows
- lower thresholds temporarily for testing

---

## 17) What does “continuous monitoring” mean in this lab context?
Running update cycles repeatedly (example every 5 minutes) to:
- refresh threat model
- detect changes
- generate metrics/dashboard outputs
- produce alerts for significant new activity
