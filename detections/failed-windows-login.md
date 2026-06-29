# Detection Playbook – Failed Windows Login

## Detection Name

Failed Windows Authentication

---

## Severity

Medium

---

## MITRE ATT&CK

**Technique:** T1110 – Brute Force  
**Tactic:** Credential Access

---

## Objective

Detect failed Windows authentication attempts that may indicate password guessing, brute-force attacks, or unauthorized access attempts.

---

## Detection Logic

Trigger when:

- Windows Security Event ID **4625** is generated.
- Multiple failed authentication attempts originate from the same account or source.
- Failed logins occur repeatedly within a short period.

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

3. Filter for **Event ID 4625**
4. Review:
   - Account Name
   - Failure Reason
   - Logon Type
   - Source Workstation
   - Source Network Address
   - Timestamp
5. Determine whether multiple failures occurred.
6. Check if the account later successfully authenticated (Event ID 4624).

---

## Indicators

- Multiple failed login attempts
- Unknown or disabled account
- Same source repeatedly attempting authentication
- Login attempts outside business hours

---

## Response

- Verify whether the user forgot their password.
- Determine if the source device is trusted.
- Review related successful logins.
- Reset credentials if necessary.
- Escalate repeated failures to the security team.

---

## False Positives

Possible legitimate causes include:

- Incorrect password
- Expired password
- Cached credentials
- User typing mistakes

Repeated failures from the same source should always be investigated.

---

## Evidence

- Event ID **4625**
- Account Name
- Failure Reason
- Logon Type
- Source Address
- Timestamp

---

## Detection Priority

| Condition | Priority |
|------------|----------|
| Single failed login | Low |
| Multiple failed logins | Medium |
| Continuous failures from same source | High |
| Multiple accounts targeted | Critical |

---

## Lessons Learned

Failed authentication events are among the earliest indicators of unauthorized access attempts.

Reviewing Event ID 4625 alongside successful authentication events provides valuable context during investigations.
