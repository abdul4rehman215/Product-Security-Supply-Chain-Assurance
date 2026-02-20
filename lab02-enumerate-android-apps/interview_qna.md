# 🎤 Interview Q&A - Lab 2: Android APK Static Analysis (apktool + JADX + apkleaks)

---

## 1️⃣ What is APK static analysis?

**Answer:**  
APK static analysis is the process of examining an Android application package (APK) without executing it. Tools like apktool and JADX are used to extract resources, manifest files, and Java source code to identify vulnerabilities such as hardcoded secrets, insecure configurations, or weak cryptographic implementations.

---

## 2️⃣ What is the difference between apktool and JADX?

**Answer:**  

| Tool      | Purpose |
|-----------|---------|
| **apktool** | Decompiles APK into resources, smali code, and AndroidManifest.xml |
| **JADX**    | Converts DEX bytecode into readable Java source code |

apktool focuses on resources and low-level code (smali), while JADX reconstructs higher-level Java source for easier vulnerability analysis.

---

## 3️⃣ Why is `android:debuggable="true"` a security risk?

**Answer:**  
When debug mode is enabled:
- Attackers can attach debuggers
- Application memory can be inspected
- Sensitive data may be exposed
- Reverse engineering becomes easier  

Production applications must always disable debug mode.

---

## 4️⃣ What are exported components in Android?

**Answer:**  
Exported components (activities, services, receivers, providers) can be accessed by other applications.  

If `android:exported="true"` is set without proper permissions:
- Unauthorized apps may trigger internal functionality
- Sensitive data leakage or privilege escalation may occur

---

## 5️⃣ Why is `android:allowBackup="true"` dangerous?

**Answer:**  
It allows application data to be backed up via ADB.  
An attacker with physical or logical device access could extract:
- Shared preferences
- Databases
- Tokens
- Sensitive cached files  

For secure apps, backups should be disabled or encrypted.

---

## 6️⃣ Why is HTTP usage considered insecure?

**Answer:**  
Using `http://` instead of `https://`:
- Transmits data in plaintext
- Allows Man-in-the-Middle (MITM) attacks
- Enables session hijacking  

Production apps must enforce HTTPS and certificate validation.

---

## 7️⃣ What are hardcoded secrets and why are they dangerous?

**Answer:**  
Hardcoded secrets include:
- API keys
- Tokens
- Passwords
- Encryption keys  

If embedded in the app:
- They can be extracted through reverse engineering
- Attackers can abuse APIs
- Backend services may be compromised  

Secrets should be stored securely (e.g., server-side, Android Keystore).

---

## 8️⃣ How does apkleaks work?

**Answer:**  
apkleaks:
- Extracts DEX and resources
- Applies regex pattern matching
- Detects known secret formats (Google keys, AWS keys, JWTs, etc.)
- Generates structured reports (TXT or JSON)

It automates secret discovery in APK files.

---

## 9️⃣ What is SQL Injection in Android apps?

**Answer:**  
Occurs when user input is concatenated into SQL queries:

```java
db.execSQL("SELECT * FROM users WHERE name = '" + user + "'");
````

This allows attackers to manipulate queries.
Proper mitigation: use parameterized queries or prepared statements.

---

## 🔟 Why is AES/ECB considered weak?

**Answer:**
AES in ECB mode:

* Does not randomize encryption
* Produces identical ciphertext blocks for identical plaintext
* Leaks data patterns

Secure alternative: AES/GCM or AES/CBC with IV.

---

## 1️⃣1️⃣ What risks exist with WebView JavaScript enabled?

**Answer:**
If `setJavaScriptEnabled(true)` is enabled:

* XSS vulnerabilities may occur
* Malicious content may execute
* Combined with `addJavascriptInterface`, remote code execution may happen on older Android versions

---

## 1️⃣2️⃣ Why automate APK analysis?

**Answer:**
Automation enables:

* Faster assessments
* Consistent vulnerability detection
* Scalable batch analysis
* CI/CD integration
* Standardized reporting

Manual review alone is not scalable for enterprise environments.

---

## 1️⃣3️⃣ What is the purpose of generating HTML reports?

**Answer:**
HTML reports:

* Provide executive-level summaries
* Present findings professionally
* Enable sharing with stakeholders
* Improve audit documentation
* Support compliance reporting

---

## 1️⃣4️⃣ What is defense-in-depth in mobile security?

**Answer:**
Defense-in-depth means using multiple security layers:

* Secure manifest configuration
* Encrypted communication (HTTPS)
* Secure storage
* Obfuscation
* Backend validation
* Runtime protections

No single control should be relied upon.

---

## 1️⃣5️⃣ How would you secure an Android app before production?

**Answer:**

* Disable debug mode
* Disable cleartext traffic
* Remove hardcoded secrets
* Use secure API authentication
* Implement certificate pinning
* Apply ProGuard/R8 obfuscation
* Use Android Keystore
* Conduct static + dynamic analysis

---

# ✅ Summary

This lab demonstrates practical Android security assessment techniques using:

* apktool
* JADX
* apkleaks
* Custom automation scripts

It reflects real-world mobile application penetration testing and secure development review practices.
