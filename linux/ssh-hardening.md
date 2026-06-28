# SSH Hardening

## Objective

Secure the Ubuntu Server SSH service by reducing the attack surface while maintaining reliable remote administrative access.

---

# Why SSH Hardening Matters

Secure Shell (SSH) is the primary remote administration protocol for Linux servers.

If an attacker gains SSH access, they may be able to:

- Execute arbitrary commands
- Read or modify sensitive files
- Create unauthorized users
- Escalate privileges
- Move laterally within the network

Hardening SSH reduces the likelihood of successful brute-force attacks and limits unnecessary functionality.

---

# Environment

| Item | Value |
|------|-------|
| Operating System | Ubuntu Server ARM64 |
| Access Method | SSH |
| Configuration File | /etc/ssh/sshd_config |
| Service | ssh |

---

# Initial Configuration Review

The default SSH configuration was reviewed before making any changes.

Important parameters examined:

| Setting | Default Value | Purpose |
|----------|---------------|----------|
| PermitRootLogin | prohibit-password | Prevents password-based root logins |
| PasswordAuthentication | yes | Allows password authentication |
| PubkeyAuthentication | yes | Enables SSH key authentication |
| X11Forwarding | yes | Allows graphical application forwarding |
| MaxAuthTries | 6 | Maximum authentication attempts |

---

# Security Improvements

## Disable X11 Forwarding

### Configuration

text X11Forwarding no 

### Reason

Graphical forwarding was not required for this server.

Disabling unused features reduces the attack surface and follows the principle of least functionality.

---

## Reduce Maximum Authentication Attempts

### Configuration

text MaxAuthTries 3 

### Reason

Reducing authentication attempts limits brute-force password guessing opportunities before the SSH server disconnects the client.

---

# Configuration Validation

After modifying the configuration:

bash sudo sshd -t 

The command completed successfully without errors, confirming the configuration syntax was valid.

---

# Service Verification

The SSH service was restarted.

bash sudo systemctl restart ssh 

Service status was verified using:

bash sudo systemctl status ssh 

The service remained in the active (running) state after configuration changes.

---

# Security Benefits

- Reduced attack surface
- Limited brute-force login attempts
- Disabled unnecessary graphical forwarding
- Preserved secure remote administration

---

# Enterprise Perspective

SSH hardening is one of the first tasks performed when deploying Linux servers in enterprise environments.

These controls reduce risk while maintaining operational access for system administrators.

---

# Lessons Learned

- Review the default configuration before making changes.
- Validate configuration syntax before restarting services.
- Avoid disabling authentication methods until an alternative access method (such as SSH keys) has been configured.
- Security controls should improve protection without preventing legitimate administration.

---

# Interview Talking Points

This exercise demonstrates:

- Linux system administration
- SSH security hardening
- Service management with systemd
- Secure configuration management
- Configuration validation
- Risk reduction through attack surface minimization
