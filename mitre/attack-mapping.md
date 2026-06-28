# MITRE ATT&CK Mapping

## Overview

This document maps the simulated attacks and security activities performed in the Enterprise Security Monitoring Lab to the MITRE ATT&CK Framework.

The MITRE ATT&CK Framework is an industry-standard knowledge base used by security teams to classify attacker behavior, improve detections, and standardize incident investigations.

---

# Attack Mapping

| Lab Activity | Platform | Evidence | Detection Method | MITRE ATT&CK Technique | Tactic |
|--------------|----------|----------|------------------|------------------------|--------|
| SSH Brute Force Simulation | Ubuntu | SSH authentication logs, fail2ban logs | fail2ban, journalctl | T1110 – Brute Force | Credential Access |
| SSH Configuration Modification | Ubuntu | auditd (ssh_changes) | auditd | T1562.001 – Impair Defenses (Configuration Change) (lab simulation) | Defense Evasion |
| Monitoring /etc/passwd, /etc/shadow, /etc/group | Ubuntu | auditd | auditd | T1078 – Valid Accounts (supports monitoring of identity-related activity) | Defense / Detection |
| Create Local Windows User | Windows | Event ID 4720 | Event Viewer | T1136.001 – Create Account: Local Account | Persistence |
| Add User to Administrators Group | Windows | Event ID 4732 | Event Viewer | T1098 – Account Manipulation | Persistence / Privilege Escalation |
| Interactive User Logon | Windows | Event ID 4624 | Event Viewer | T1078 – Valid Accounts | Defense / Detection |
| Failed User Logon | Windows | Event ID 4625 | Event Viewer | T1110 – Brute Force (when repeated) | Credential Access |

---

# Security Controls Implemented

| Security Control | Purpose |
|------------------|---------|
| SSH Hardening | Reduce attack surface and secure remote administration |
| UFW Firewall | Restrict inbound network access using a default-deny policy |
| auditd | Monitor critical system files and privileged activity |
| fail2ban | Detect and block SSH brute-force attacks |
| Windows Security Logs | Monitor authentication, account management, and privilege changes |

---

# Detection Matrix

| Attack | Detection Tool | Evidence |
|---------|----------------|----------|
| SSH Brute Force | fail2ban | Banned IP, SSH logs |
| SSH Configuration Changes | auditd | ausearch -k ssh_changes |
| User Account Creation | Event Viewer | Event ID 4720 |
| Administrator Group Modification | Event Viewer | Event ID 4732 |
| Successful Login | Event Viewer | Event ID 4624 |
| Failed Login | Event Viewer | Event ID 4625 |

---

# Incident Reports

| Incident | Description | MITRE ATT&CK |
|----------|-------------|--------------|
| IR-001 | SSH Brute Force Attack | T1110 |
| IR-002 | Local User Account Creation | T1136.001 |
| IR-003 | Local Administrator Group Modification | T1098 |

---

# Lessons Learned

- The MITRE ATT&CK Framework provides a common language for describing attacker behavior.
- Mapping detections to ATT&CK techniques helps prioritize monitoring and improve incident response.
- Combining Linux and Windows telemetry provides better visibility into simulated attacks.
- Security controls are more valuable when they are linked to specific attacker techniques rather than deployed in isolation.

---

# Future Improvements

The following ATT&CK techniques will be added as the project expands:

- PowerShell Logging and Analysis
- Scheduled Task Creation
- Service Creation
- File Integrity Monitoring
- Python-based Detection Automation
- Active Directory Attack Simulation
- Kerberos Authentication Monitoring
- Network Discovery
- Credential Dumping Detection
- Sigma Rule Development
