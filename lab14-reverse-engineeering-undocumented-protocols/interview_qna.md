# 🎤 Interview Q&A - Lab 14: Reverse-Engineer Undocumented Protocols

---

## 1️⃣ What is protocol reverse engineering?

Protocol reverse engineering is the process of analyzing captured network traffic to determine the structure, format, and behavior of an undocumented or proprietary communication protocol.  
It involves identifying:

- Message boundaries  
- Field offsets and sizes  
- Header format  
- Encoding type  
- Integrity mechanisms  
- Authentication or encryption presence  

---

## 2️⃣ How did you identify the protocol structure in this lab?

We:

1. Captured TCP traffic using tcpdump.
2. Extracted Raw payloads using Scapy.
3. Observed repeating first 4 bytes (`CPRO`) → likely magic header.
4. Noticed fixed header pattern:
   - 4 bytes magic
   - 1 byte version
   - 1 byte type
   - 2 bytes length
5. Verified structure using `struct.unpack("!4sBBH", ...)`.
6. Confirmed final byte was checksum via validation logic.

---

## 3️⃣ What is the purpose of magic bytes in a protocol?

Magic bytes:

- Identify protocol type
- Help parsers detect valid messages
- Prevent accidental misinterpretation of data

Security Risk:
Predictable magic bytes allow:
- Easy fingerprinting
- Protocol identification by attackers
- Replay and injection preparation

---

## 4️⃣ Why is a 1-byte checksum considered weak?

A 1-byte checksum:

- Has only 256 possible values
- Is not cryptographically secure
- Can be easily forged
- Has high collision probability

It does NOT provide:
- Authenticity
- Strong integrity protection
- Tamper resistance

Better alternative:
- HMAC-SHA256
- Digital signatures

---

## 5️⃣ How did you detect plaintext traffic automatically?

We used Shannon entropy calculation:

- Encrypted traffic typically has entropy > 6.5
- Plaintext usually < 4.5

In this lab:
Average entropy ≈ 3.62 → strongly indicates plaintext.

---

## 6️⃣ What vulnerabilities were identified in this protocol?

1. Missing encryption (plaintext data)
2. Information disclosure (`flag{...}` visible)
3. Weak integrity (sum(data) % 256)
4. No authentication mechanism
5. Replay attack possibility
6. Length field validation risks

---

## 7️⃣ How can replay attacks occur in this protocol?

Replay attacks are possible because:

- No timestamp
- No nonce
- No sequence number
- No session token
- No cryptographic authentication

An attacker can:
- Capture valid packet
- Replay it later
- Server will accept it as valid

---

## 8️⃣ What is entropy and why is it useful in protocol analysis?

Entropy measures randomness of data.

Low entropy → likely plaintext  
High entropy → likely encrypted or compressed  

Used to:
- Detect encryption
- Identify obfuscation
- Flag sensitive exposure

---

## 9️⃣ How does fuzzing help in protocol security testing?

Fuzzing:

- Sends malformed inputs
- Tests parser robustness
- Detects crashes
- Identifies input validation flaws

In this lab we fuzzed:
- Magic bytes
- Length fields
- Data fields
- Oversized payloads

---

## 🔟 Why is length field validation critical?

Improper length validation can lead to:

- Buffer overflows
- Memory corruption
- Denial-of-service
- Arbitrary code execution (in unsafe languages)

Secure design requires:

- Strict bounds checking
- Reject mismatched lengths
- Safe memory handling

---

## 1️⃣1️⃣ What is protocol fingerprinting?

Protocol fingerprinting is identifying a protocol by:

- Magic bytes
- Header patterns
- Payload structure
- Port usage
- Behavioral patterns

We generated a SHA-256 protocol fingerprint to:
- Enable detection rules
- Support IDS/IPS integration

---

## 1️⃣2️⃣ How would you secure this protocol?

Improvements:

1. Use TLS for transport encryption
2. Replace checksum with HMAC-SHA256
3. Add authentication token
4. Implement nonce/sequence numbers
5. Enforce strict length validation
6. Remove plaintext secrets

---

## 1️⃣3️⃣ Why are proprietary protocols often insecure?

Because they often lack:

- Peer review
- Cryptographic expertise
- Security testing
- Formal specification

Security by obscurity does NOT equal security.

---

## 1️⃣4️⃣ What tools are useful for protocol reverse engineering?

- tcpdump
- Wireshark
- Scapy
- hexdump
- binwalk
- IDA/Ghidra (if binary involved)
- Custom Python parsers

---

## 1️⃣5️⃣ What is the difference between reverse engineering and vulnerability analysis?

Reverse Engineering:
- Understand structure and behavior

Vulnerability Analysis:
- Identify weaknesses in that structure

In this lab, we performed both.

---

# ✅ End of Interview Q&A
