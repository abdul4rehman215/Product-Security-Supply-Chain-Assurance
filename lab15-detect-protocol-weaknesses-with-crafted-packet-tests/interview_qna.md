# 🎤 Lab 15 Interview Q&A  
## Detect Protocol Weaknesses with Crafted Packet Tests

---

## 1️⃣ What is protocol security testing?

Protocol security testing is the process of analyzing a network protocol implementation to identify weaknesses such as:
- Improper input validation
- Authentication bypass
- Buffer overflows
- Information disclosure
- Logic flaws

It involves crafting custom packets and observing how the server responds to valid, malformed, and malicious inputs.

---

## 2️⃣ Why is packet crafting important in security assessments?

Packet crafting allows security professionals to:

- Bypass client-side validation
- Send malformed or edge-case data
- Manipulate header fields directly
- Test undocumented protocol behaviors
- Simulate attacker-controlled traffic

Tools like **Scapy** enable low-level control over packet structure.

---

## 3️⃣ What vulnerability was discovered using command 999?

Command `999` exposed sensitive credentials:
