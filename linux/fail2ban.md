# fail2ban Configuration

## Objective

Configure fail2ban to detect repeated failed SSH authentication attempts and automatically block malicious IP addresses, reducing the risk of brute-force attacks against the Ubuntu server.

---

# Why fail2ban?

SSH is one of the most frequently targeted services on Linux servers.

Attackers commonly perform brute-force attacks by repeatedly attempting different username and password combinations until valid credentials are found.

fail2ban monitors authentication logs and automatically creates temporary firewall rules to block IP addresses that exceed a configurable number of failed login attempts.

This provides an automated intrusion prevention mechanism.

---

# Environment

| Item | Value |
|------|-------|
| Operating System | Ubuntu Server ARM64 |
| Service Protected | SSH |
| Firewall | UFW |
| Detection Tool | fail2ban |

---

# Configuration

A local configuration file was created instead of modifying the default configuration.

Configuration File:

text /etc/fail2ban/jail.local 

Configuration:

ini [DEFAULT]  bantime = 10m findtime = 10m maxretry = 3  [sshd] enabled = true port = ssh logpath = %(sshd_log)s backend = systemd 

---

# Configuration Explanation

| Parameter | Value | Purpose |
|-----------|-------|----------|
| bantime | 10 minutes | Duration an IP remains blocked |
| findtime | 10 minutes | Time window used to count failed logins |
| maxretry | 3 | Maximum failed login attempts before banning |
| backend | systemd | Reads authentication logs from the systemd journal |

---

# Validation

After creating the configuration:

bash sudo systemctl restart fail2ban 

The service status was verified using:

bash sudo systemctl status fail2ban 

The configured jail was verified:

bash sudo fail2ban-client status 

SSH-specific status was checked using:

bash sudo fail2ban-client status sshd 

---

# Attack Simulation

A controlled SSH brute-force simulation was performed.

Steps:

1. Open a new terminal.
2. Connect using SSH.
3. Enter an incorrect password multiple times.
4. Exceed the configured retry threshold.

After the third failed authentication attempt, fail2ban automatically banned the attacking IP address.

---

# Verification

The active ban was confirmed using:

bash sudo fail2ban-client status sshd 

Example output:

text Status for the jail: sshd  Currently banned: 1  Banned IP list: 192.168.x.x 

The IP address was later removed using:

bash sudo fail2ban-client set sshd unbanip <IP Address> 

---

# Security Benefits

- Detects SSH brute-force attacks.
- Automatically blocks malicious IP addresses.
- Reduces password guessing attempts.
- Integrates with the Linux firewall.
- Requires no manual administrator intervention during detection.

---

# Enterprise Perspective

fail2ban is commonly deployed on Linux servers that expose SSH services.

Although enterprise environments often use additional security controls such as centralized identity management, VPNs, or network firewalls, host-based intrusion prevention remains an important defense-in-depth control.

---

# Lessons Learned

- Never enable a firewall without first allowing SSH access.
- Use a local configuration file (jail.local) instead of modifying default files.
- Validate the configuration before simulating attacks.
- Generate test attacks to confirm detection rules operate correctly.
- Security controls should be continuously tested rather than assumed to work.

---

# Interview Talking Points

This exercise demonstrates experience with:

- Linux security hardening
- SSH protection
- Intrusion prevention
- Brute-force mitigation
- Firewall integration
- Security validation
- Incident response preparation

---

# Commands Used

bash sudo systemctl status fail2ban sudo fail2ban-client status sudo fail2ban-client status sshd sudo systemctl restart fail2ban sudo fail2ban-client set sshd unbanip <IP Address> 

---

# Future Improvements

- Configure email notifications for ban events.
- Monitor additional services such as Nginx or Apache.
- Integrate fail2ban events with a centralized SIEM platform.
- Develop Python scripts to summarize ban activity and generate security reports.
