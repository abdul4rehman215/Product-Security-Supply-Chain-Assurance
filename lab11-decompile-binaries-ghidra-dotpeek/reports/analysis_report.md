# Binary Analysis Report
## Binary: vulnerable_app

---

### Vulnerability 1: Buffer Overflow

- **Function**: buffer_overflow_vuln()
- **Location**: strcpy() call
- **Risk**: High

**Description:**
The function copies attacker-controlled input into a fixed-size stack buffer using `strcpy()` without validating length. If the input exceeds 63 characters (plus null terminator), it can overwrite adjacent stack memory, potentially causing crashes or enabling code execution in certain conditions.

**Recommendation:**
Replace `strcpy()` with a bounds-checked alternative such as `snprintf()`, `strncpy()` (with careful null termination), or safer wrapper logic. Enforce maximum input size and enable modern compiler protections like stack canaries (`-fstack-protector-strong`), PIE, and NX stack.

---

### Vulnerability 2: Format String

- **Function**: format_string_vuln()
- **Location**: printf() call
- **Risk**: Medium

**Description:**
The function passes attacker-controlled input directly as the format string to `printf()`. This can allow reading memory contents (information disclosure) and in some cases writing memory using `%n`, leading to crashes or exploitation depending on protections and runtime environment.

**Recommendation:**
Always use a fixed format string when printing user input, for example:

```c
printf("%s", input);
```
Enable compiler warnings (`-Wformat -Wformat-security`) to detect unsafe patterns.
Vulnerability 3: Command Injection

**Function:** main()
**Location:** system() call
**Risk:** High

**Description:**
The program constructs a shell command (`echo <user_input>`) using unsanitized user input and executes it with `system()`. An attacker can inject shell metacharacters (e.g., `;`, `&&`, `|`, backticks) to execute arbitrary commands with the program’s privileges.

**Recommendation:**
Avoid `system()` when executing commands that include user input. Use safer alternatives such as `execve()` with fixed arguments, or avoid shell invocation entirely. Strictly validate or whitelist allowed characters.


