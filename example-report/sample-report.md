# Security Compliance Report — vm

| | |
|---|---|
| Run | `20261117-220800` (audit-only) |
| OS | Ubuntu 24.04.5 LTS (debian family, ufw), kernel 6.18.44-fc-v553 |
| Compliance score | **86%** — 21 pass, 3 warn, 2 fail |
| Lynis hardening index | 62 |

## Checks

| ID | Status | Check | Detail |
|---|---|---|---|
| PRM-01 | PASS | Critical system files have correct mode/owner |  |
| PRM-02 | FAIL | No world-writable files | 2 found |
| PRM-03 | PASS | World-writable dirs have sticky bit |  |
| PRM-04 | PASS | No unowned files/dirs |  |
| PRM-05 | PASS | No new SUID/SGID binaries since baseline | 19 total |
| PRM-06 | PASS | Home directories are 750 or stricter |  |
| SSH-01 | PASS | Root login over SSH disabled |  |
| SSH-02 | PASS | SSH password authentication disabled |  |
| SSH-03 | PASS | SSH public-key authentication enabled |  |
| SSH-04 | PASS | SSH MaxAuthTries ≤ 4 | 3 |
| SSH-05 | PASS | SSH X11 forwarding disabled |  |
| SSH-06 | PASS | SSH empty passwords refused |  |
| SSH-07 | PASS | A non-root sudo user can log in with a key | deploy rheluser  |
| FW-01 | PASS | Firewall (UFW) active |  |
| FW-02 | PASS | Default inbound policy is deny |  |
| FW-03 | PASS | SSH port allowed (rate-limited) |  |
| F2B-01 | PASS | Fail2ban jail configured | service state not checkable without systemd |
| UPD-01 | PASS | Automatic security updates enabled | unattended-upgrades |
| UPD-02 | WARN | No pending security updates | 23 pending |
| UPD-03 | PASS | No reboot pending |  |
| SVC-02 | PASS | No legacy insecure packages installed |  |
| MAC-01 | WARN | AppArmor enabled | not enabled or not available |
| KRN-01 | FAIL | Kernel hardening parameters active | 10/25 |
| ACC-01 | PASS | Only root has UID 0 |  |
| ACC-02 | PASS | No accounts with empty passwords |  |
| LYN-01 | WARN | Lynis hardening index ≥ 65 | 62/100, 2 warnings, 43 suggestions |

## Changes made in this run

_None — system already compliant with this tool's configuration (idempotent run)._

## Lynis warnings

- PKGS-7392: Found one or more vulnerable packages.
- LOGG-2138: klogd is not running, which could lead to missing kernel messages in log files

## Lynis suggestions (top 25)

- LYNIS: This release is more than 4 months old. Check the website or GitHub to see if there is an update available.
- DEB-0280: Install libpam-tmpdir to set $TMP and $TMPDIR for PAM sessions
- DEB-0810: Install apt-listbugs to display a list of critical bugs prior to each APT installation.
- DEB-0831: Install needrestart, alternatively to debian-goodies, so that you can run needrestart after upgrades to determine which daemons are using old versions of libraries and need restarting.
- DEB-0880: Copy /etc/fail2ban/jail.conf to jail.local to prevent it being changed by updates.
- BOOT-5180: Determine runlevel and services at startup
- BOOT-5264: Consider hardening system services (Run '/usr/bin/systemd-analyze security SERVICE' for each service)
- KRNL-5788: Determine why /vmlinuz or /boot/vmlinuz is missing on this Debian/Ubuntu system. (/vmlinuz or /boot/vmlinuz)
- KRNL-5820: If not required, consider explicit disabling of core dump in /etc/security/limits.conf file
- AUTH-9230: Configure password hashing rounds in /etc/login.defs
- AUTH-9262: Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc
- AUTH-9284: Look at the locked accounts and consider removing them
- AUTH-9286: Configure minimum password age in /etc/login.defs
- AUTH-9286: Configure maximum password age in /etc/login.defs
- AUTH-9328: Default umask in /etc/login.defs could be more strict like 027
- FILE-6310: To decrease the impact of a full /home file system, place /home on a separate partition
- FILE-6310: To decrease the impact of a full /tmp file system, place /tmp on a separate partition
- FILE-6310: To decrease the impact of a full /var file system, place /var on a separate partition
- USB-1000: Disable drivers like USB storage when not used, to prevent unauthorized storage or data theft
- STRG-1846: Disable drivers like firewire storage when not used, to prevent unauthorized storage or data theft
- NAME-4028: Check DNS configuration for the dns domain name
- PKGS-7370: Install debsums utility for the verification of packages with known good database.
- PKGS-7392: Update your system with apt-get update, apt-get upgrade, apt-get dist-upgrade and/or unattended-upgrades
- PKGS-7394: Install package apt-show-versions for patch management purposes
- NETW-3200: Determine if protocol 'dccp' is really needed on this system

## File findings

### World-writable files
- `/root/.cache/uv/.lock`
- `/root/.local/share/uv/tools/.lock`

---
Backups: `/var/backups/hardening/20261117-220800` · Roll back with `sudo harden.sh --rollback 20261117-220800`
