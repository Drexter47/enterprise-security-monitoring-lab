# Lab Setup

## Project Information

Project Name: Enterprise Security Monitoring Lab

Objective:
Build a professional cybersecurity home lab that demonstrates Linux hardening, Windows security monitoring, incident response, log analysis, and security automation using enterprise best practices.

---

# Host System

| Item | Value |
|------|-------|
| Host Machine | MacBook Air M3 |
| Memory | 16 GB RAM |
| Storage | 512 GB SSD |
| Operating System | macOS |
| Virtualization Platform | UTM |
| Virtualization Mode | Apple Virtualization |

---

# Ubuntu Security Server

| Item | Value |
|------|-------|
| Server Name | wazuh |
| Operating System | Ubuntu Server ARM64 |
| Architecture | ARM64 (aarch64) |
| Access Method | SSH from macOS Terminal |
| User Account | wazuh |
| IP Address | 192.168.64.7 |

---

# Windows Endpoint

| Item | Value |
|------|-------|
| Operating System | Windows 11 Pro ARM |
| Architecture | ARM64 |
| Virtualization | UTM |

---

# Installed Security Tools

- OpenSSH Server
- auditd
- audispd-plugins
- fail2ban
- UFW (Uncomplicated Firewall)
- curl
- git
- vim
- net-tools

---

# Current Project Status

- Ubuntu Server installed
- Windows 11 Pro installed
- SSH connectivity verified
- System updated
- Security tools installed
- GitHub repository created
- Project directory structure initialized

---

# GitHub Repository

https://github.com/Drexter47/enterprise-security-monitoring-lab

---

# Notes

The original plan was to deploy Wazuh as the SIEM platform. During installation it was determined that the Wazuh 4.11.x all-in-one installer requires an x86_64 (AMD64) environment and is not compatible with the ARM64 Ubuntu VM running on Apple Silicon using Apple Virtualization.

The project has been redesigned to focus on enterprise security monitoring concepts that are architecture-independent, with the flexibility to integrate a SIEM such as Wazuh, Splunk, Elastic, or Microsoft Sentinel in a future phase.
