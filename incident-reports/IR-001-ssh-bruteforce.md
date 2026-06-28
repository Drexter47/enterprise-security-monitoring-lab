# Incident Report IR-001: SSH Brute-Force Attack Simulation

## Incident Summary

A controlled SSH brute-force attack was simulated against the Ubuntu Server to validate the effectiveness of the server's security controls.

Multiple failed SSH authentication attempts triggered fail2ban, which automatically blocked the source IP address before a successful login could occur.

No unauthorized access was obtained during the exercise.

---

# Incident Information

| Field | Value |
|-------|-------|
| Incident ID | IR-001 |
| Incident Type | SSH Brute-Force Attack |
| Severity | Medium |
| Status | Resolved |
| Environment | Ubuntu Server ARM64 |
| Detection Method | fail2ban |

---

# Objective

Validate the Linux server's ability to:

- Detect repeated SSH authentication failures.
- Automatically block malicious clients.
- Record evidence for investigation.
- Demonstrate host-based intrusion prevention.

---

# Attack Scenario

A simulated attacker attempted to authenticate to the Ubuntu server over SSH using an incorrect password multiple times.

The failed login threshold exceeded the configured fail2ban policy.

The attacking IP address was automatically banned.

---

# Timeline

| Time | Event |
|------|-------|
| T0 | SSH connection initiated |
| T1 | Multiple failed authentication attempts |
| T2 | fail2ban detected brute-force behavior |
| T3 | Firewall rule automatically created |
| T4 | Source IP address blocked |
| T5 | Administrator verified detection |
| T6 | Administrator removed IP ban after validation |

---

# Indicators of Compromise (IOCs)

- Multiple failed SSH login attempts
- Source IP temporarily banned
- Authentication failures recorded in SSH logs
- fail2ban jail triggered

---

# Investigation

## Evidence Collected

### SSH Logs

Authentication failures were confirmed using:

bash sudo journalctl -u ssh --since "30 minutes ago" 

---

### fail2ban Status

The SSH jail confirmed an active ban:

bash sudo fail2ban-client status sshd 

Observed information included:

- Number of failed login attempts
- Number of banned IP addresses
- Banned IP list

---

### Firewall Verification

Firewall rules were verified using:

bash sudo ufw status verbose 

The firewall remained active with SSH explicitly allowed.

---

### Audit Framework

Linux Audit Framework logs were reviewed to confirm no unauthorized changes were made to monitored configuration files during the exercise.

bash sudo ausearch -k ssh_changes 

---

# Root Cause Analysis

The incident was intentionally generated as part of a controlled security validation exercise.

The objective was to verify that fail2ban correctly detected repeated authentication failures and automatically protected the server.

The behavior matched the expected security policy.

---

# Impact Assessment

No successful authentication occurred.

No system files were modified.

No privilege escalation occurred.

No service interruption occurred.

The server remained available for legitimate administrative access.

---

# Response Actions

- Verified fail2ban detection.
- Confirmed firewall remained operational.
- Confirmed attacking IP address was banned.
- Reviewed authentication logs.
- Removed the temporary IP ban after validation.

---

# Lessons Learned

- Automated intrusion prevention significantly reduces brute-force attack risk.
- Host-based firewalls and fail2ban provide complementary security controls.
- Security controls should be validated through controlled attack simulations.
- Audit logs and authentication logs provide valuable forensic evidence.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1110 | Brute Force |
| T1078 (Attempted) | Valid Accounts (attempted but unsuccessful) |

---

# Security Controls Demonstrated

- SSH Hardening
- UFW Host Firewall
- fail2ban Intrusion Prevention
- Linux Audit Framework
- Authentication Log Monitoring

---

# Evidence

Add screenshots of:

- fail2ban-client status sshd
- SSH authentication logs
- UFW status
- Audit logs

Store screenshots under:

text screenshots/linux/ 

---

# Conclusion

The Ubuntu server successfully detected and mitigated a simulated SSH brute-force attack.

The combination of SSH hardening, UFW, fail2ban, and auditd provided multiple layers of defense and visibility into the incident.

The exercise validated the effectiveness of the implemented security controls and demonstrated a practical incident response workflow suitable for enterprise Linux environments.
