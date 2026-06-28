# Linux Audit Framework (auditd)

## Objective

Configure the Linux Audit Framework (auditd) to monitor security-sensitive files and record system activity for security investigations and incident response.

---

# Why auditd?

The Linux Audit Framework records security-relevant events occurring on a Linux system.

Unlike traditional system logs, auditd provides detailed information about:

- File modifications
- User activity
- Privilege escalation
- Security policy changes
- Authentication-related events

This makes auditd an essential component for incident response and forensic investigations.

---

# Environment

| Item | Value |
|------|-------|
| Operating System | Ubuntu Server ARM64 |
| Audit Service | auditd |
| Rule File | /etc/audit/rules.d/lab.rules |

---

# Audit Rules Configured

The following files were configured for monitoring.

| File | Purpose | Audit Key |
|------|----------|-----------|
| /etc/passwd | User accounts | identity_changes |
| /etc/shadow | Password database | identity_changes |
| /etc/group | Group memberships | identity_changes |
| /etc/sudoers | Privilege configuration | privilege_changes |
| /etc/ssh/sshd_config | SSH configuration | ssh_changes |

---

# Rule Deployment

Rules were loaded using:

bash sudo augenrules --load 

The audit service was restarted to activate the new configuration.

bash sudo systemctl restart auditd 

---

# Validation

A test modification was performed on the SSH configuration file.

bash echo "# audit test" | sudo tee -a /etc/ssh/sshd_config 

Audit events were retrieved using:

bash sudo ausearch -k ssh_changes 

---

# Investigation Results

The audit logs successfully recorded:

- Modified file path
- Command responsible for the modification (tee)
- Original authenticated user (auid)
- Effective user (uid)
- Timestamp
- Process information

This demonstrates that auditd can identify:

- Who performed the action
- What file changed
- Which process made the change
- Whether elevated privileges were used

---

# Enterprise Perspective

Monitoring configuration files is a common security practice.

Unauthorized changes to SSH configuration may indicate:

- Persistence mechanisms
- Privilege escalation attempts
- Administrative mistakes
- Insider threats

Security teams use audit logs to investigate configuration changes and establish accountability.

---

# Security Benefits

- File integrity monitoring
- User accountability
- Change tracking
- Forensic evidence collection
- Privileged activity monitoring

---

# Lessons Learned

- Audit rules should target high-value configuration files.
- Changes should be validated by generating test events.
- Audit logs provide valuable context for incident investigations.
- Monitoring critical system files improves visibility into security-relevant activity.

---

# Interview Talking Points

This exercise demonstrates experience with:

- Linux Audit Framework (auditd)
- File integrity monitoring
- Security event generation
- Log analysis
- Incident investigation
- Linux security monitoring
