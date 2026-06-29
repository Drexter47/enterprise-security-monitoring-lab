# Detection Playbook – SSH Brute Force

## Detection Name

SSH Brute Force Detection

---

## Severity

High

---

## MITRE ATT&CK

**Technique:** T1110 – Brute Force

**Tactic:** Credential Access

---

## Objective

Detect repeated failed SSH authentication attempts that may indicate a brute-force attack.

---

## Detection Logic

Trigger when:

- More than 3 failed SSH login attempts
- Within 10 minutes
- Same source IP address

fail2ban automatically bans the offending IP address.

---

## Data Sources

- journalctl
- SSH Logs
- fail2ban
- UFW

---

## Investigation Steps

1. Review SSH logs

```bash
sudo journalctl -u ssh --since "30 minutes ago"
```

2. Check fail2ban status

```bash
sudo fail2ban-client status sshd
```

3. Identify banned IP

4. Determine whether authentication was successful

5. Check for additional suspicious activity

---

## Indicators

- Multiple failed login attempts
- Single source IP
- Automatic IP ban
- No successful authentication

---

## Response

- Verify attacker IP
- Leave IP banned
- Review firewall rules
- Document incident
- Update incident report

---

## False Positives

Possible causes include:

- User entering incorrect password repeatedly
- Misconfigured SSH client
- Forgotten credentials

Always validate before escalating.

---

## Evidence

- SSH authentication logs
- fail2ban status
- UFW status
- Incident Report IR-001

---

## Lessons Learned

Brute-force attacks are among the most common attacks against Internet-facing Linux servers.

Combining SSH hardening, fail2ban, and UFW provides multiple layers of defense while maintaining legitimate administrative access.
