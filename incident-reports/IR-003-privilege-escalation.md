# Incident Report IR-003: Local Administrator Group Modification

## Incident Summary

A newly created local user account was added to the local Administrators group as part of a controlled security simulation.

Windows generated a security event indicating modification of a privileged local security group.

The activity was successfully detected and investigated using Windows Event Viewer.

---

# Incident Information

| Field | Value |
|-------|-------|
| Incident ID | IR-003 |
| Incident Type | Privilege Escalation |
| Severity | High |
| Status | Resolved |
| Detection Source | Windows Security Event Log |

---

# Objective

Validate Windows Security logging for privileged group membership changes.

---

# Attack Simulation

A previously created user account was granted local administrator privileges using:

cmd net localgroup Administrators attacker /add 

---

# Detection

Windows generated an event indicating that a member was added to a security-enabled local group.

Observed Event ID:

- 4732 (Local Security Group)
  or
- Equivalent event depending on Windows configuration.

---

# Investigation

Evidence collected:

| Evidence | Value |
|----------|-------|
| User Added | attacker |
| Target Group | Administrators |
| Performed By | (Administrator Account) |
| Event ID | 4732 |
| Timestamp | (Event Time) |

---

# Security Analysis

Adding users to privileged groups is considered a high-risk administrative activity.

Threat actors frequently elevate privileges after gaining initial access in order to:

- Disable security controls
- Access protected files
- Install malware
- Maintain persistence
- Execute privileged commands

Although this activity was authorized for testing purposes, similar events in production should be investigated immediately.

---

# Impact Assessment

The simulated account successfully obtained administrative privileges.

No malicious activity occurred after privilege assignment.

The event validated Windows Security logging and detection capabilities.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|-----------|-------------|
| T1098 | Account Manipulation |
| T1078 | Valid Accounts |
| T1068 | Privilege Escalation (Conceptually Related) |

---

# Response

The event was reviewed using Event Viewer.

The account should be removed from the Administrators group after validation.

Example:

cmd net localgroup Administrators attacker /delete 

---

# Lessons Learned

- Group membership changes are high-value security events.
- Newly created administrator accounts require immediate investigation.
- Windows Security logs provide strong visibility into privilege changes.
- Monitoring privileged group modifications is a critical SOC responsibility.

---

# Interview Talking Points

This exercise demonstrates experience with:

- Windows Event Viewer
- Privilege escalation detection
- Windows Security Event investigation
- Windows account management
- MITRE ATT&CK mapping
- Incident response documentation
