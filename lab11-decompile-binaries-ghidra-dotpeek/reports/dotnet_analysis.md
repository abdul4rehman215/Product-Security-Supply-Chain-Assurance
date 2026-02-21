# .NET Assembly Analysis Report
## Assembly: VulnerableApp.exe

---

### Vulnerability 1: SQL Injection

- **Method**: LoginUser()
- **Risk**: Critical

**Details:**
The method builds an SQL query using string concatenation with untrusted `username` and `password`. An attacker can inject SQL syntax (e.g., `' OR '1'='1`) to bypass authentication or extract/modify data if executed against a real database connection.

**Fix:**
Use parameterized queries with `SqlCommand` parameters (e.g., `@username`, `@password`). Validate inputs and apply least-privilege DB permissions. Never compare plaintext credentials in SQL.

---

### Vulnerability 2: Path Traversal

- **Method**: ReadFile()
- **Risk**: High

**Details:**
The method concatenates a base directory (`/var/data/`) with user-controlled `filename` without validation. Attackers can use sequences like `../` to read arbitrary files on the filesystem (e.g., `/etc/passwd`) if file permissions allow.

**Fix:**
Normalize and validate paths using safe APIs. Enforce allowlists and verify that resolved paths remain within the intended base directory.

---

### Vulnerability 3: Hardcoded Credentials

- **Field**: API_KEY
- **Risk**: High

**Details:**
The API key is stored directly in the binary as a plaintext string. Anyone who decompiles the assembly can recover it, leading to account compromise and unauthorized API access.

**Fix:**
Store secrets in secure configuration systems (environment variables, secret managers). Rotate exposed credentials immediately.
