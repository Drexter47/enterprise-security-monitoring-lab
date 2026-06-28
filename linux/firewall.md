# Linux Firewall Configuration (UFW)

## Objective

Configure a host-based firewall to reduce the server's attack surface while preserving secure remote administration over SSH.

---

# Why a Host Firewall?

A host firewall provides an additional layer of protection beyond network firewalls.

It controls which services running on the server are accessible over the network.

This follows the principle of defense in depth, where multiple independent security controls protect the system.

---

# Firewall Software

Ubuntu uses UFW (Uncomplicated Firewall) as a simplified interface for managing Linux firewall rules.

---

# Configuration Steps

## Verify Initial Status

bash sudo ufw status verbose 

Result:

text Status: inactive 

The firewall was installed but not enforcing any rules.

---

## Allow SSH

bash sudo ufw allow OpenSSH 

This ensures remote administration remains available after enabling the firewall.

---

## Enable Firewall

bash sudo ufw enable 

---

## Verify Configuration

bash sudo ufw status verbose 

Result:

- Firewall Status: Active
- Default Incoming Policy: Deny
- Default Outgoing Policy: Allow
- SSH (Port 22): Allowed

---

# Security Benefits

- Blocks unsolicited inbound connections.
- Allows only required administrative access.
- Reduces the exposed attack surface.
- Implements the principle of least exposure.

---

# Enterprise Perspective

Host firewalls complement perimeter firewalls by protecting individual systems.

Even if an attacker gains access to an internal network, host firewall policies continue to restrict unnecessary communication.

---

# Lessons Learned

- Always allow SSH before enabling the firewall on a remote server.
- Verify firewall rules after configuration.
- Prefer a default-deny policy for inbound traffic.
- Review firewall rules periodically to remove unnecessary or duplicate entries.
