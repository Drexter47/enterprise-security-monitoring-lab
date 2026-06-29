# Detection Playbook – Administrator Group Modification

## Detection Name

Administrator Group Modification

---

## Severity

High

---

## MITRE ATT&CK

**Technique:** T1098 – Account Manipulation  
**Tactic:** Persistence / Privilege Escalation

---

## Objective

Detect when a user account is added to the local **Administrators** group, as this significantly increases the user's privileges and may indicate privilege escalation or persistence.

---

## Detection Logic

Trigger when:

- Windows Security Event ID **4732** is generated
- A member is added to the local **Administrators** group

---

## Data Sources

- Windows Security Event Log
- Event Viewer

---

## Investigation Steps

1. Open **Event Viewer**
2. Navigate to:

```
Windows Logs
    └── Security
```

3. Filter for **Event ID 4732**
4. Identify:
   - User added to the group
   - Target group
   - Account that performed the action
   - Time of the event
5. Check if the user account was recently created (Event ID 4720)
6. Determine whether the activity was authorized

---

## Indicators

- User added to the Administrators group
- Newly created account immediately receiving administrative privileges
- Administrative changes outside normal maintenance windows

---

## Response

- Verify whether the privilege assignment was approved.
- Review related events (4624, 4625, 4720).
- Remove the account from the Administrators group if unauthorized.
- Escalate the incident if malicious activity is suspected.
- Document findings in an incident report.

---

## False Positives

Possible legitimate causes include:

- IT administrative tasks
- Software installation requiring temporary elevation
- Lab testing

Always verify the business justification before escalating.

---

## Evidence

- Event ID **4732**
- User account added
- Administrator account that performed the action
- Timestamp
- Incident Report **IR-003**

---

## Lessons Learned

Membership changes to privileged groups are high-value security events.

Attackers commonly add compromised or newly created accounts to privileged groups after gaining initial access to maintain persistence and execute privileged actions.

Monitoring Event ID 4732 provides valuable visibility into potential privilege escalation attempts.
