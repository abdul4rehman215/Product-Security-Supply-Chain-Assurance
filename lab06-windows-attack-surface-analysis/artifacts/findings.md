# Security Assessment Findings
## Date: 2026-02-21

## Network Exposure
- Listening ports discovered: 22/tcp (sshd), 53/tcp (systemd-resolved DNS stub)
- No high-risk ports like Telnet/FTP/SMB observed
- SSH exposed on 0.0.0.0 and :: (public interface)

## Process Analysis
- Privileged processes with network access:
  - sshd (root) listening on port 22
  - systemd-resolved (systemd-resolve) listening on port 53 (local stub)
- No obvious reverse shells or netcat indicators seen

## Vulnerabilities Identified
1. SSH Password Authentication Enabled
   - Severity: Medium
   - Description: SSH allows password login; increases brute-force risk.
   - Recommendation: Disable PasswordAuthentication and use key-based auth.

2. Root SSH login not explicitly set (commented default)
   - Severity: Low
   - Description: PermitRootLogin not explicitly enforced; relies on defaults.
   - Recommendation: Explicitly set PermitRootLogin no.

3. SUID/SGID binaries present
   - Severity: Medium
   - Description: Standard SUID tools exist (sudo, su, passwd). Risk if unpatched/misconfigured.
   - Recommendation: Review necessity, patch system, monitor SUID changes.

## Risk Score: 76/100

## Recommendations
1. Disable SSH password authentication; enforce keys + rate-limits/fail2ban
2. Explicitly disable root SSH login (PermitRootLogin no)
3. Periodically audit SUID/SGID binaries and keep packages updated
