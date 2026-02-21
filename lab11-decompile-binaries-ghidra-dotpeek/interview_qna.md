# 🎤 Interview Q&A - Lab 11: Decompile Binaries Using Ghidra & dotPeek

---

## 1️⃣ What is reverse engineering in cybersecurity?

Reverse engineering is the process of analyzing compiled binaries to understand their functionality, logic, and potential vulnerabilities without access to the original source code. It is widely used in malware analysis, vulnerability research, and security auditing.

---

## 2️⃣ What is Ghidra and why is it used?

Ghidra is a free and open-source reverse engineering tool developed by the NSA. It supports disassembly, decompilation, scripting, and headless automation for multiple architectures and binary formats.

---

## 3️⃣ What is the purpose of disabling stack protection during compilation?

Stack protection (e.g., stack canaries) prevents exploitation of buffer overflows. Disabling it using:

```

-fno-stack-protector -z execstack -no-pie

```

makes vulnerabilities easier to observe during analysis and testing in a controlled lab environment.

---

## 4️⃣ What is a buffer overflow vulnerability?

A buffer overflow occurs when data exceeds the allocated memory buffer size and overwrites adjacent memory. This can lead to crashes, arbitrary code execution, or privilege escalation.

---

## 5️⃣ Why is `printf(input)` dangerous?

Passing user-controlled input directly as a format string allows attackers to use format specifiers like `%x` or `%n` to read or write memory, leading to information disclosure or memory corruption.

---

## 6️⃣ What is command injection?

Command injection occurs when user input is included in a system command without sanitization. Attackers can append shell metacharacters (`;`, `&&`, `|`) to execute arbitrary commands.

---

## 7️⃣ What is headless analysis in Ghidra?

Headless analysis allows Ghidra to run without a GUI, enabling automation and batch processing of binaries. It is useful for large-scale vulnerability scanning.

---

## 8️⃣ Why did Ghidra headless fail on the .NET executable?

Ghidra headless primarily targets native binaries (e.g., ELF). .NET assemblies are managed code and may require different handling or specialized analysis tools like dotPeek.

---

## 9️⃣ What is SQL Injection in .NET applications?

SQL Injection occurs when unvalidated user input is concatenated into SQL queries. Attackers can manipulate queries to bypass authentication or extract database data.

---

## 🔟 Why are hardcoded secrets dangerous?

Hardcoded API keys or credentials embedded in binaries can be easily extracted through decompilation. This leads to credential leakage and service compromise.

---

## 1️⃣1️⃣ How can path traversal vulnerabilities occur?

Path traversal happens when user input is appended to file paths without validation, allowing attackers to access unauthorized files using `../` sequences.

---

## 1️⃣2️⃣ What is the importance of static analysis?

Static analysis identifies vulnerabilities without executing code. It is essential for secure code reviews, compliance, and early vulnerability detection.

---

## 1️⃣3️⃣ What are compiler protections that help prevent exploitation?

- Stack canaries (`-fstack-protector`)
- PIE (Position Independent Executables)
- NX (Non-executable stack)
- ASLR (Address Space Layout Randomization)

---

## 1️⃣4️⃣ When would you use dotPeek instead of Ghidra?

dotPeek is specifically designed for .NET assemblies. It reconstructs high-level C# code more accurately than generic disassemblers.

---

## 1️⃣5️⃣ How does automation improve security analysis?

Automation enables:
- Batch processing of binaries
- Standardized reporting
- Faster detection of common vulnerabilities
- Integration into CI/CD pipelines

---

# ✅ End of Interview Q&A
