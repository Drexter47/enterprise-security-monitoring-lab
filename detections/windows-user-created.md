# Detection Playbook – Windows Local User Creation

## Detection Name

Windows Local User Creation

---

## Severity

Medium

---

## MITRE ATT&CK

**Technique:** T1136.001 – Create Account: Local Account  
**Tactic:** Persistence

---

## Objective

Detect the creation of a new local Windows account, which may indicate persistence or unauthorized administrative activity.

---

## Detection Logic

Trigger when:

- Event ID 4720 appears in the Windows Security log
- A new local user account is created

---

## Data Sources

- Windows Security Event Log
- Event Viewer

---

## Investigation Steps

1. Open Event Viewer
2. Navigate to **Windows Logs → Security**
3. Filter for **Event ID 4720**
4. Identify:
   - Created account
   - Creator account
   - Timestamp
5. Determine whether the activity was authorized

---

## Indicators

- New user account created
- Unexpected administrative activity
- Creation during unusual hours
- Account name similar to a legitimate account

---

## Response

- Verify whether the account was approved
- Disable or delete the account if unauthorized
- Review nearby authentication and privilege events
- Document the incident

---

## False Positives

Possible legitimate causes include:

- IT provisioning a new user
- Lab testing
- Administrative maintenance

Always confirm the business justification.

---

## Evidence

- Event ID 4720
- Account name created
- Creator account
- Timestamp
- Incident Report IR-002

---

## Lessons Learned

User account creation is a high-value event because attackers often create local accounts to maintain access after compromise.
