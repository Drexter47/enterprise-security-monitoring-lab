# 🛡️ Enterprise Security Monitoring & Incident Response Lab

> A hands-on cybersecurity project demonstrating Linux hardening, Windows security monitoring, incident response, MITRE ATT&CK mapping, and Python-based security automation in a simulated enterprise environment.

![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Windows-blue)
![Python](https://img.shields.io/badge/Python-3.x-yellow)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-In%20Progress-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

# 📖 Project Overview

This project simulates an enterprise security environment where Linux and Windows systems are secured, monitored, investigated, and documented using industry security best practices.

Instead of focusing on a single security tool, this lab demonstrates the complete security lifecycle:

```
Secure
    ↓
Monitor
    ↓
Detect
    ↓
Investigate
    ↓
Document
    ↓
Automate
```

The project is designed to strengthen practical skills required for:

- SOC Analyst
- Security Analyst
- Network Security Engineer
- Blue Team Operations

---

# 🎯 Objectives

- Build a secure Linux server baseline
- Investigate Windows Security Events
- Simulate real-world attack scenarios
- Perform incident response investigations
- Map activities to the MITRE ATT&CK Framework
- Automate security monitoring with Python
- Produce professional security documentation

---

# 🏗️ Lab Architecture

```
                    Enterprise Security Monitoring
                     & Incident Response Lab

                      MacBook Air M3
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
          │                                     │
   Ubuntu Server ARM64                  Windows 11 Pro ARM
          │                                     │
          │                                     │
 SSH Hardening                         Windows Security Logs
 UFW Firewall                          Event Viewer
 auditd                               Account Monitoring
 fail2ban                             Event Investigation
          │                                     │
          └───────────────┬─────────────────────┘
                          │
                 Python Security Analyzer
                          │
        Incident Reports • MITRE ATT&CK Mapping
                          │
                    GitHub Documentation
```

---

# 💻 Lab Environment

| Component | Details |
|------------|---------|
| Host Machine | MacBook Air M3 |
| Virtualization | UTM |
| Linux VM | Ubuntu Server ARM64 |
| Windows VM | Windows 11 Pro ARM |
| Programming | Python 3 |
| Version Control | Git & GitHub |

---

# 🛠️ Technologies Used

## Operating Systems

- Ubuntu Server ARM64
- Windows 11 Pro ARM

## Linux Security

- OpenSSH
- UFW
- auditd
- fail2ban
- journalctl

## Windows Security

- Event Viewer
- Windows Security Logs
- Local User Management

## Automation

- Python
- Markdown Reporting

## Security Framework

- MITRE ATT&CK

---

# 🔒 Security Controls Implemented

## Linux

- SSH Hardening
- Host Firewall (UFW)
- Linux Audit Framework (auditd)
- File Integrity Monitoring
- fail2ban Intrusion Prevention

## Windows

- Successful Logon Investigation (Event ID 4624)
- Failed Logon Investigation (Event ID 4625)
- Local User Creation Monitoring (Event ID 4720)
- Local Administrator Group Monitoring (Event ID 4732)

---

# ⚔️ Attack Simulations

| Simulation | Platform | Status |
|------------|----------|--------|
| SSH Brute Force | Ubuntu | ✅ |
| Local User Creation | Windows | ✅ |
| Privilege Escalation | Windows | ✅ |
| SSH Configuration Modification | Ubuntu | ✅ |

---

# 🚨 Incident Reports

This repository includes detailed security investigations for each simulated attack.

| Incident | Description |
|-----------|-------------|
| IR-001 | SSH Brute Force Investigation |
| IR-002 | Windows Local User Creation |
| IR-003 | Windows Privilege Escalation |

Each report contains:

- Executive Summary
- Timeline
- Evidence
- Investigation
- Root Cause Analysis
- MITRE ATT&CK Mapping
- Lessons Learned

---

# 🎯 MITRE ATT&CK Mapping

| Activity | Technique |
|------------|-----------|
| SSH Brute Force | T1110 – Brute Force |
| Windows Local User Creation | T1136.001 – Create Local Account |
| Add User to Administrators | T1098 – Account Manipulation |

A complete mapping is available in:

```
mitre/attack-mapping.md
```

---

# 🤖 Python Security Automation

A custom Python tool was developed to automate Linux authentication log analysis.

Current Features:

- Analyze SSH authentication logs
- Count failed login attempts
- Count successful logins
- Identify top offending IP addresses
- Generate Markdown security reports

Example Output

```
LINUX SECURITY SUMMARY

Failed SSH Logins : 6

Successful Logins : 3

Top Failed IP

192.168.64.1

Risk Level

MEDIUM
```

---

# 📂 Repository Structure

```
enterprise-security-monitoring-lab/

docs/
linux/
windows/
incident-reports/
mitre/
scripts/
screenshots/
architecture/
assets/
resume/
README.md
```

---

# 📸 Project Screenshots

The repository contains screenshots demonstrating:

- Linux SSH Hardening
- UFW Firewall
- auditd Monitoring
- fail2ban Detection
- Windows Event Viewer
- Windows Security Investigations
- Python Security Analyzer

```
screenshots/

├── linux/
├── windows/
├── scripts/
├── incidents/
└── architecture/
```

---

# 📚 Skills Demonstrated

### Linux Security

- SSH Hardening
- Firewall Management
- Audit Logging
- Intrusion Prevention

### Windows Security

- Event Log Analysis
- User Account Monitoring
- Privilege Escalation Detection

### Security Operations

- Incident Response
- Log Analysis
- MITRE ATT&CK Mapping

### Automation

- Python
- Security Reporting

### Documentation

- Technical Documentation
- Incident Reports
- Security Playbooks

---

# 🚀 Future Improvements

- Windows PowerShell Logging
- Active Directory Integration
- Kerberos Monitoring
- Sigma Detection Rules
- HTML Security Dashboard
- CSV/JSON Report Export
- Threat Hunting Scenarios
- Cloud Security Monitoring
- Detection Engineering

---

# 💼 Resume Highlights

This project demonstrates hands-on experience with:

- Linux Security Hardening
- Windows Security Monitoring
- Incident Response
- Detection Engineering
- MITRE ATT&CK Framework
- Python Security Automation
- Git & GitHub
- Technical Documentation

---

# ⭐ Connect

If you found this project interesting, consider giving the repository a ⭐.

Feedback, suggestions, and collaboration are always welcome.
