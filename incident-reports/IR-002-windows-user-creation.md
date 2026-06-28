# Incident Report IR-002: Windows Local User Account Creation

## Incident Summary

A new local Windows user account was created as part of a controlled security simulation to validate Windows Security Event logging and incident investigation procedures.

The activity generated Event ID 4720, confirming successful detection of user account creation.

No malicious activity occurred during this exercise.

---

# Incident Information

| Field | Value |
|-------|-------|
| Incident ID | IR-002 |
| Incident Type | Local User Account Creation |
| Severity | Medium |
| Status | Resolved |
| Operating System | Windows 11 Pro ARM |
| Detection Source | Windows Security Event Log |

---

# Objective

Validate Windows Security logging by generating and investigating a user account creation event.

---

# Attack Simulation

A new local user account was created using the following command:

cmd net user attacker Password123! /add 

This simulates a common attacker persistence technique after obtaining administrative privileges.

---

# Detection

Windows generated:

Event ID: 4720

Event Description:

> A user account was created.

---

# Investigation

The following information was collected from Event Viewer.

| Evidence | Value |
|----------|-------|
| Event ID | 4720 |
| Created Account | attacker |
| Creator Account | (Your Administrator Account) |
| Time Created | (Your Event Time) |

---

# Security Analysis

Unexpected local user creation is considered a high-value security event.

Attackers frequently create local accounts to:

- Maintain persistence
- Establish alternate access
- Escalate privileges
- Evade account removal

For this exercise, the account creation was intentional and performed as part of a controlled security validation.

---

# Impact Assessment

- No unauthorized access occurred.
- No privilege escalation occurred.
- No persistence remained after testing.

---

# Response

The event was verified through Event Viewer.

The account can be removed after validation using:

cmd net user attacker /delete 

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1136.001 | Create Account: Local Account |

---

# Evidence

Include screenshots of:

- Event Viewer showing Event ID 4720
- Command Prompt with net user
- Local Users (optional)

Store screenshots under:

text screenshots/windows/ 

---

# Lessons Learned

- Windows Security logs provide detailed visibility into account management activities.
- Event ID 4720 is a valuable detection point for unauthorized persistence.
- User account creation events should always be reviewed in enterprise environments.
- Controlled attack simulations help validate logging and monitoring capabilities.

---

# Interview Talking Points

This exercise demonstrates experience with:

- Windows Event Viewer
- Windows Security Logs
- Event ID 4720 investigation
- Account management monitoring
- Incident documentation
- MITRE ATT&CK mapping
