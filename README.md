# harden.sh: automated Linux server hardening 🔐

A single Bash script that secures a fresh server and then audits it. It works
on **both Ubuntu/Debian and Red Hat-family systems**. It detects the OS
automatically and uses the right tools for each, with the same flags on both.

You can run it as many times as you like: each step checks the current state
first, changes only what's different, and backs up every file before it
touches it.

```bash
sudo ./harden.sh --admin-user deploy --pubkey ~/.ssh/id_ed25519.pub \
                 --allow 80/tcp --allow 443/tcp --fix-perms
```

## Supported systems

| Family | Distributions | Package manager | Firewall | Auto-updates | Admin group | Access control |
|---|---|---|---|---|---|---|
| **Debian** | Ubuntu 20.04+, Debian 11+ | `apt` | UFW | `unattended-upgrades` | `sudo` | AppArmor (checked) |
| **Red Hat** | RHEL 8, 9, 10 · Rocky · AlmaLinux · CentOS Stream · Oracle Linux | `dnf` (+ EPEL) | firewalld | `dnf-automatic` | `wheel` | SELinux (configured + checked) |

The family is read from `/etc/os-release` (`ID` / `ID_LIKE`). Fedora isn't
supported because it has moved to DNF 5.

## What it does

| Module | Ubuntu / Debian | RHEL family |
|---|---|---|
| **packages** | Installs `ufw fail2ban lynis unattended-upgrades python3-systemd openssh-server` | Enables **EPEL**, then installs `firewalld fail2ban fail2ban-systemd lynis dnf-automatic policycoreutils-python-utils openssh-server` |
| **ssh** | Creates the admin user, installs the public key, and writes `/etc/ssh/sshd_config.d/00-hardening.conf`: no root login, key-only auth, `MaxAuthTries 3`, no forwarding, idle timeouts, a login banner and optional `AllowUsers`. The config is checked with `sshd -t` before the reload and the old one is restored if the check fails. Handles `ssh.socket` activation on Ubuntu 22.10+. | Same, plus: adds the `Include` line that **RHEL 8** lacks, and **labels a custom SSH port for SELinux** (`semanage port -a -t ssh_port_t`) so sshd can actually listen on it |
| **firewall** | UFW: deny inbound and routed traffic, allow outbound, `limit` the SSH port, extra ports from `--allow` | firewalld: makes sure the default zone isn't set to accept everything, opens SSH and your `--allow` ports, and **closes Cockpit's web console (port 9090)** unless you pass `--keep cockpit` |
| **fail2ban** | `sshd` jail with incremental bans plus a `recidive` jail. Bans through UFW. Watches `ssh.service` in the journal. | Same jails. Bans through firewalld rich rules. Watches `sshd.service`. |
| **services** | Disables avahi, cups, rpcbind, nfs, bluetooth, telnet, xinetd, vsftpd, snmpd, samba, squid, cockpit and others, if they're present | Same list (missing services are skipped) |
| **updates** | Security-only unattended upgrades, kernel cleanup, optional reboot time | `dnf-automatic` with `upgrade_type = security` and `apply_updates = yes`. With `--auto-reboot`, a cron job reboots only when `dnf needs-restarting -r` says it's needed. |
| **sysctl** | 25 kernel and network settings (rp_filter, no redirects or source routing, syncookies, kptr/dmesg restrict, ptrace scope, protected links). `ip_forward` is left alone so Docker and VPN hosts keep working. | Same |
| **perms** (audit) | Mode and owner of `passwd`, `shadow`, `group`, `sudoers`, `sshd_config`, cron dirs and GRUB config (`/boot/grub` or `/boot/grub2`). World-writable files, unowned files, loose home dirs, and **SUID/SGID drift** against a baseline saved on the first run. `--fix-perms` tightens anything that fails. | Same |
| **lynis** (audit) | Hardening index, warnings and suggestions | Same (Lynis comes from EPEL) |
| **report** | Markdown and HTML compliance report in `/var/log/hardening/`, with `latest.html` and `latest.md` symlinks | Same |

### Compliance checks in the report

| ID | Check |
|---|---|
| SSH-01…07 | Root login off, password auth off, pubkey on, MaxAuthTries ≤ 4, X11 off, no empty passwords, an admin user has a key |
| FW-01…03 | Firewall active, inbound denied by default, SSH port allowed (rate-limited on UFW) |
| F2B-01/02 | Fail2ban running, sshd jail active |
| UPD-01…03 | Automatic security updates on, no pending security updates, no reboot pending |
| SVC-01/02 | No unnecessary services enabled, no legacy insecure packages (telnet, rsh, NIS, tftp…) |
| MAC-01 | **SELinux enforcing** (RHEL) / **AppArmor enabled** (Ubuntu) |
| KRN-01 | Kernel hardening parameters active |
| ACC-01/02 | Only root has UID 0, no empty passwords |
| PRM-01…06 | File permissions, world-writable files and dirs, unowned files, SUID drift, home dirs |
| LYN-01 | Lynis hardening index ≥ 65 |

## Usage

```
sudo ./harden.sh [options]

Modes
  (default)                 Apply hardening, then audit and write reports
  --audit-only              Change nothing; only checks + Lynis + reports
  --dry-run                 Print every change that would be made
  --rollback <RUN_ID>       Restore files backed up by a previous run
  --list-runs               List runs available for rollback

SSH          --admin-user NAME  --pubkey FILE|"KEY"  --ssh-port N
             --ssh-allow-users "a b"  --force-key-only
Firewall     --allow PORT[/proto]           (repeatable; ranges as 6000:6010)
Services     --disable SVC  --keep SVC      (repeatable)
Updates      --auto-reboot HH:MM
Audit        --fix-perms  --skip-lynis  --report-dir DIR
Other        --skip MODULE (repeatable: packages ssh firewall fail2ban
             services updates sysctl perms lynis)   -h  -V
```

`--pubkey` accepts a `.pub` file, an `authorized_keys` file with several keys,
or a key pasted in quotes.

**Exit codes:** `0` means every check passed and `2` means at least one FAIL,
so you can use it in cron or CI (`harden.sh --audit-only || alert`).

Settings can also come from environment variables: `SSH_PORT`, `ADMIN_USER`,
`PUBKEY`, `SSH_ALLOW_USERS`, `REPORT_DIR`.

### Examples

```bash
# Ubuntu web server
sudo ./harden.sh --admin-user deploy --pubkey deploy.pub --allow 80/tcp --allow 443/tcp

# RHEL 9 with SSH moved to 2222 (firewalld and SELinux are both updated)
sudo ./harden.sh --admin-user ops --pubkey ops.pub --ssh-port 2222

# RHEL, but keep the Cockpit web console
sudo ./harden.sh --admin-user ops --pubkey ops.pub --keep cockpit

# See what would change, on either OS
sudo ./harden.sh --dry-run
```

## Safety: built not to lock you out

- **Lockout guard:** password authentication is turned off only if a non-root
  admin user (in `sudo` or `wheel`) already has a valid key. Otherwise the
  script leaves it on and warns you. Override this with `--force-key-only`.
- **Port changes:** the firewall opens the new SSH port *before* sshd moves to
  it, the old port stays open until you remove it yourself, and on RHEL the
  SELinux label is added first.
- **Validated configs:** `sshd -t` runs before every reload, and the previous
  config comes back automatically if it fails. `fail2ban-client -t` also runs.
- **Reload, not restart:** your current SSH session stays connected. Always
  test a new login in a second terminal before you close the first one.
- **Backups:** every modified file goes to
  `/var/backups/hardening/<RUN_ID>/`, and created files and changed directory
  modes are recorded. `--rollback <RUN_ID>` undoes all three. Not rolled back:
  firewall rules, SELinux port labels, created users and disabled services.
- `flock` stops two runs from overlapping.

### Removing the old SSH port after a move

```bash
# Ubuntu
sudo ufw delete limit 22/tcp
# RHEL
sudo firewall-cmd --permanent --remove-service=ssh && sudo firewall-cmd --reload
```

## How idempotency works

- `write_file` compares the new content with what's on disk and writes only
  when they differ. It also fixes mode and owner if those have drifted.
- `ensure_line` appends a line only if it isn't already there. SSH keys are
  compared by type and key body, so the same key with a different comment
  isn't added twice.
- Firewall rules are queried before they're added (`ufw` skips existing rules
  and the script runs `firewall-cmd --query-port` first). SELinux labels are
  checked with `semanage port -l`. Packages, services and timers are queried
  before anything is changed.
- Daemons are reloaded only when their config actually changed.
- Each run reports what it changed. A second run on an already hardened
  server reports **`Changes: 0`**.

## Tested

- **Ubuntu 24.04:** real runs. `shellcheck` clean. A full apply, a second run
  with 0 changes, rollback (files and directory modes), re-applying, dry-run,
  and audit-only with Lynis (`example-report/sample-report.html`).
- **RHEL family:** the Red Hat code path was run with a Rocky Linux 9
  `os-release` and stateful stand-ins for `rpm`, `dnf`, `firewalld`,
  `semanage` and `getenforce`. Covered: EPEL and package install, the
  `wheel` group, firewalld port and range rules, Cockpit removal, the SELinux
  port label, Fail2ban firewalld actions, dnf-automatic, adding and removing
  the reboot job, a second run with 0 changes, and dry-run.
  **It hasn't been run on a real RHEL machine yet.** Test it on a RHEL, Rocky
  or Alma VM before you use it in production.

In both cases the test machine was a container, so the systemd service steps
were skipped.

`OS_RELEASE_FILE=/path/to/os-release` overrides OS detection, which is useful
for testing.

## Recommended workflow

```bash
scp harden.sh you@server:
ssh you@server
sudo ./harden.sh --dry-run --admin-user you --pubkey ~/.ssh/authorized_keys
sudo ./harden.sh --admin-user you --pubkey ~/.ssh/authorized_keys
# in a NEW terminal: ssh you@server   ← confirm before logging out
# weekly audit by cron (works on both OS families):
echo '0 3 * * 1 root /usr/local/sbin/harden.sh --audit-only' | sudo tee /etc/cron.d/harden-audit
```
