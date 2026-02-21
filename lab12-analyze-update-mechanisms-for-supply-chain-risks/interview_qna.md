# 🎤 Interview Q&A - Lab 12: Analyze Update Mechanisms for Supply Chain Risks

---

## 1️⃣ Why are software update mechanisms considered high-risk in supply chain security?

Software update mechanisms have privileged access and can automatically deploy code to thousands or millions of systems. If compromised, attackers can distribute malicious updates at scale (e.g., SolarWinds incident).

---

## 2️⃣ Why is using HTTP instead of HTTPS in APT repositories risky?

HTTP allows man-in-the-middle (MITM) attacks. An attacker could manipulate metadata, redirect downloads, or attempt downgrade attacks. Even though APT uses signing, HTTPS adds defense-in-depth protection.

---

## 3️⃣ What role do GPG keys play in APT security?

APT verifies package integrity using cryptographic signatures. GPG keys stored in trusted keyrings validate repository metadata and ensure packages are not tampered with.

---

## 4️⃣ What is the risk of using pip `trusted-host`?

`trusted-host` disables SSL verification for that host. This weakens TLS protections and allows MITM interception if the connection is compromised.

---

## 5️⃣ Why is monitoring update network traffic important?

It reveals:
- Unencrypted HTTP connections
- Unexpected external destinations
- Suspicious ports
- Abnormal update behavior

Network visibility helps detect update abuse or compromise.

---

## 6️⃣ Why was port 80 flagged in the network monitor?

Port 80 indicates unencrypted HTTP traffic. Updates should ideally use HTTPS (port 443) to protect against interception.

---

## 7️⃣ Why is connecting directly to IP addresses sometimes flagged?

Using raw IPs instead of domain names bypasses DNS-based reputation checks and certificate validation patterns. It can indicate suspicious behavior.

---

## 8️⃣ Why was GitHub flagged with a MEDIUM TLS issue?

The script used a heuristic checking for `ECDHE` in cipher names to detect forward secrecy. TLS 1.3 provides forward secrecy by default even if the cipher name does not include ECDHE, making this a false positive.

---

## 9️⃣ What TLS versions are considered insecure today?

- TLSv1.0  
- TLSv1.1  

Modern systems should use TLSv1.2 or TLSv1.3.

---

## 🔟 Why is certificate expiration important?

Expired certificates break trust validation and may indicate operational mismanagement, increasing risk of service disruption or exploitation.

---

## 1️⃣1️⃣ Why combine package, network, and TLS analysis?

Security is layered. A repository may be signed but transported insecurely. TLS may be strong but network behavior suspicious. Combining signals gives better risk assessment.

---

## 1️⃣2️⃣ How was the overall risk score calculated?

Weighted scoring model:

- Package Security → 40%  
- Network Security → 30%  
- TLS Security → 30%  

Final score determines risk classification (LOW, MEDIUM, HIGH, CRITICAL).

---

## 1️⃣3️⃣ What real-world attacks exploit update mechanisms?

- SolarWinds Orion compromise  
- Code-signing certificate abuse  
- Dependency confusion attacks  
- Compromised mirrors  

---

## 1️⃣4️⃣ What are key mitigation strategies?

- Enforce HTTPS-only repositories  
- Use signed packages  
- Monitor update traffic  
- Audit third-party repositories  
- Enforce strong TLS configurations  

---

## 1️⃣5️⃣ Why automate supply chain audits?

Automation:
- Ensures repeatability  
- Reduces manual errors  
- Enables CI/CD integration  
- Provides structured reporting for compliance  

---

# ✅ End of Interview Q&A
