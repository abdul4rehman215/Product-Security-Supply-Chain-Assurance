# 🎤 Interview Q&A — Lab 05: Threat Modeling with Draw.io + MITRE ATT&CK

---

## 1️⃣ What is threat modeling and why is it important?

Threat modeling is a structured approach to identifying, analyzing, and mitigating security risks in a system architecture. It helps security teams proactively identify potential attack paths before deployment, reducing vulnerabilities early in the SDLC.

---

## 2️⃣ What are trust boundaries in threat modeling?

Trust boundaries define areas where different levels of trust exist between components (e.g., Internet vs DMZ vs Internal Network). Attacks often occur at these boundaries because data crosses from a less trusted zone to a more trusted one.

---

## 3️⃣ What is MITRE ATT&CK?

MITRE ATT&CK is a knowledge base of adversary tactics and techniques based on real-world attack observations. It provides a standardized framework for understanding attacker behavior.

---

## 4️⃣ What is the difference between tactics and techniques in MITRE ATT&CK?

- **Tactics** represent high-level attack objectives (e.g., Initial Access, Persistence).
- **Techniques** describe specific methods used to achieve those objectives (e.g., T1190 – Exploit Public-Facing Application).

---

## 5️⃣ Why was T1190 (Exploit Public-Facing Application) selected in this lab?

Because the modeled system includes a web server exposed to the Internet, making it a common initial access vector for attackers.

---

## 6️⃣ How was risk scoring calculated in the automation script?

Risk scoring used a simple formula:

```

Risk Score = Likelihood × Impact

```

Where:
- Low = 1
- Medium = 2
- High = 3

This produces a score between 1 and 9.

---

## 7️⃣ How does the automation script determine relevant MITRE techniques for an asset?

The script uses keyword-based relevance matching across:
- Technique name
- Description
- Tactics
- Platforms

It assigns a relevance score and selects the top matching techniques.

---

## 8️⃣ Why was matplotlib configured with `matplotlib.use('Agg')`?

Because the environment is headless (no GUI display server).  
The `Agg` backend allows generating PNG files without requiring a graphical display.

---

## 9️⃣ What is the purpose of exporting a Draw.io XML file programmatically?

It enables automated visualization of threat models, making the process scalable and repeatable for multiple systems.

---

## 🔟 What outputs were generated in this lab?

- `mitre_techniques.csv`
- `threat_model.json`
- `threat_report.txt`
- `threat_model.png`
- `automated_threat_model.drawio`

---

## 1️⃣1️⃣ How does MITRE ATT&CK help detection engineering?

It allows mapping security controls and monitoring rules to specific adversary techniques, ensuring better detection coverage.

---

## 1️⃣2️⃣ What are the advantages of automating threat modeling?

- Scalability
- Consistency
- Reduced manual effort
- Faster risk prioritization
- Integration into DevSecOps pipelines

---

## 1️⃣3️⃣ How could this automation be improved?

- Integrate CVSS scoring
- Add mitigation recommendations
- Connect to vulnerability scanners
- Include asset inventory ingestion
- Implement threat likelihood based on exposure metrics

---

## 1️⃣4️⃣ Why is threat modeling useful for product security teams?

It ensures security risks are identified early in the development lifecycle and communicated clearly to engineering and leadership stakeholders.

---

## 1️⃣5️⃣ What real-world roles use threat modeling?

- Product Security Engineers
- Security Architects
- Cloud Security Engineers
- DevSecOps Engineers
- Risk & Compliance Analysts

---

✅ Interview Q&A completed.
