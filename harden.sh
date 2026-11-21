#!/usr/bin/env bash
# =============================================================================
#  harden.sh — Automated, idempotent Linux server hardening
#
#  Targets : Ubuntu 20.04+ / Debian 11+            (apt, UFW, unattended-upgrades)
#            RHEL 8-10 / Rocky / Alma / CentOS Stream / Oracle Linux
#                                                   (dnf, firewalld, dnf-automatic, SELinux)
#            The OS family is detected automatically; same flags on both.
#  Covers  : SSH key auth, firewall, Fail2ban, automatic security updates,
#            unnecessary services, kernel sysctl hardening, file-permission
#            audit, Lynis audit, HTML/Markdown compliance report
#
#  Safe to re-run: every step checks current state first and only changes
#  what differs. Every file it touches is backed up and can be rolled back.
# =============================================================================
set -Eeuo pipefail
shopt -s nullglob

readonly TOOL_VERSION="1.1.0"
SCRIPT_NAME="$(basename "$0")"; readonly SCRIPT_NAME
RUN_ID="$(date +%Y%m%d-%H%M%S)"; readonly RUN_ID

# ----------------------------------------------------------------------------
# Defaults (override with flags or environment variables)
# ----------------------------------------------------------------------------
SSH_PORT="${SSH_PORT:-22}"
ADMIN_USER="${ADMIN_USER:-}"
PUBKEY="${PUBKEY:-}"
SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-}"
ALLOW_PORTS=()
DRY_RUN=0
AUDIT_ONLY=0
FIX_PERMS=0
FORCE_KEY_ONLY=0
SKIP_LYNIS=0
AUTO_REBOOT_TIME=""
REPORT_DIR="${REPORT_DIR:-/var/log/hardening}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/hardening}"
STATE_DIR="${STATE_DIR:-/var/lib/hardening}"
LOCK_FILE="/run/harden.lock"
SKIP_MODULES=()
ROLLBACK_ID=""

OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

# Services that a typical headless server does not need (names are the same
# on both families; missing ones are simply skipped).
DISABLE_SERVICES=(
  avahi-daemon cups cups-browsed rpcbind nfs-server bluetooth
  telnet.socket xinetd vsftpd snmpd isc-dhcp-server dhcpd slapd
  smb nmb smbd nmbd squid rsync rsyncd ModemManager cockpit.socket
)
KEEP_SERVICES=()

# Filled in by detect_os() for the detected family.
OS_FAMILY=""          # debian | rhel
OS_MAJOR=""
OS_PRETTY=""
ADMIN_GROUP=""        # sudo (Debian/Ubuntu) | wheel (RHEL)
SSH_SERVICE=""        # ssh  (Debian/Ubuntu) | sshd  (RHEL)
FIREWALL=""           # ufw  | firewalld
REQUIRED_PACKAGES=()
INSECURE_PACKAGES=()

# Files we manage
readonly SSHD_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
readonly F2B_JAIL="/etc/fail2ban/jail.d/00-hardening.local"
readonly F2B_MAIN="/etc/fail2ban/fail2ban.d/00-hardening.local"
readonly APT_AUTO="/etc/apt/apt.conf.d/20auto-upgrades"
readonly APT_UU="/etc/apt/apt.conf.d/52hardening-unattended-upgrades"
readonly DNF_AUTO="/etc/dnf/automatic.conf"
readonly DNF_REBOOT_CRON="/etc/cron.d/harden-auto-reboot"
readonly SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"

# ----------------------------------------------------------------------------
# Runtime state
# ----------------------------------------------------------------------------
BACKUP_DIR=""
LOG_FILE=""
LAST_CHANGED=0
CHANGES=()            # human-readable list of changes made in this run
CHECK_IDS=() CHECK_STATUS=() CHECK_DESC=() CHECK_DETAIL=()
LYNIS_INDEX="n/a"
LYNIS_WARNINGS=() LYNIS_SUGGESTIONS=()
WW_FILES=() WW_DIRS=() UNOWNED=() SUID_NEW=() SUID_ALL=()

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
if [[ -t 2 ]]; then
  C_RED=$'\e[31m' C_GRN=$'\e[32m' C_YEL=$'\e[33m' C_BLU=$'\e[34m' C_DIM=$'\e[2m' C_RST=$'\e[0m'
else
  C_RED="" C_GRN="" C_YEL="" C_BLU="" C_DIM="" C_RST=""
fi

_log() {
  local level="$1" color="$2"; shift 2
  local line; line="$(date '+%F %T') [$level] $*"
  printf '%s%s%s\n' "$color" "$line" "$C_RST" >&2
  [[ -n "$LOG_FILE" && -w "$(dirname "$LOG_FILE")" ]] && printf '%s\n' "$line" >>"$LOG_FILE" || true
}
info()    { _log INFO  "$C_BLU" "$@"; }
ok()      { _log OK    "$C_GRN" "$@"; }
warn()    { _log WARN  "$C_YEL" "$@"; }
err()     { _log ERROR "$C_RED" "$@"; }
die()     { err "$@"; exit 1; }
section() { printf '\n%s==> %s%s\n' "$C_BLU" "$*" "$C_RST" >&2; [[ -n "$LOG_FILE" ]] && printf '\n==> %s\n' "$*" >>"$LOG_FILE" || true; }

# Report unexpected failures in the main shell only (not in $(...) helpers).
trap 'rc=$?; (( BASH_SUBSHELL == 0 )) && err "Unexpected failure at line $LINENO (exit $rc): $BASH_COMMAND"' ERR

# Execute a command, or just print it in dry-run mode.
run() {
  if (( DRY_RUN )); then
    printf '%s[dry-run]%s %s\n' "$C_DIM" "$C_RST" "$*" >&2
    return 0
  fi
  "$@"
}

record_change() { CHANGES+=("$*"); ok "CHANGED: $*"; }

has_cmd()     { command -v "$1" >/dev/null 2>&1; }
has_systemd() { [[ -d /run/systemd/system ]]; }
skip_module() { local m; for m in "${SKIP_MODULES[@]}"; do [[ "$m" == "$1" ]] && return 0; done; return 1; }
# is_kept <svc> — true if the user passed --keep for it (with or without .service/.socket)
is_kept() { local k; for k in "${KEEP_SERVICES[@]}"; do [[ "$k" == "$1" || "$k" == "${1%.*}" ]] && return 0; done; return 1; }

# ----------------------------------------------------------------------------
# Idempotent file primitives (with backup + rollback manifest)
# ----------------------------------------------------------------------------
backup_file() {
  local f="$1"
  (( DRY_RUN )) && return 0
  mkdir -p "$BACKUP_DIR"
  if [[ -d "$f" ]]; then
    # Directories: we only ever change their mode/owner, so record metadata.
    grep -q "^$f " "$BACKUP_DIR/perms.list" 2>/dev/null && return 0
    printf '%s %s\n' "$f" "$(stat -c '%a %U %G' "$f")" >>"$BACKUP_DIR/perms.list"
  elif [[ -e "$f" ]]; then
    # Only back up the first time a file is touched in this run.
    [[ -e "$BACKUP_DIR/files$f" ]] && return 0
    mkdir -p "$BACKUP_DIR/files$(dirname "$f")"
    cp -a "$f" "$BACKUP_DIR/files$f"
    printf '%s\n' "$f" >>"$BACKUP_DIR/modified.list"
  else
    printf '%s\n' "$f" >>"$BACKUP_DIR/created.list"
  fi
}

# write_file <path> <mode> <owner:group> <content>
# Sets LAST_CHANGED=1 if the file was created/modified, else 0.
write_file() {
  local path="$1" mode="$2" owner="$3" content="$4"
  LAST_CHANGED=0
  if [[ -f "$path" ]] && [[ "$(cat "$path")" == "$content" ]]; then
    # Content identical — still enforce mode/owner.
    if [[ "$(stat -c '%a %U:%G' "$path")" != "$mode $owner" ]]; then
      run chmod "$mode" "$path"; run chown "$owner" "$path"
      record_change "fixed mode/owner of $path"
      LAST_CHANGED=1
    fi
    return 0
  fi
  backup_file "$path"
  if (( DRY_RUN )); then
    printf '%s[dry-run]%s would write %s\n' "$C_DIM" "$C_RST" "$path" >&2
  else
    mkdir -p "$(dirname "$path")"
    local tmp; tmp="$(mktemp "${path}.XXXXXX")"
    printf '%s\n' "$content" >"$tmp"
    chmod "$mode" "$tmp"; chown "$owner" "$tmp"
    mv -f "$tmp" "$path"
  fi
  record_change "wrote $path"
  LAST_CHANGED=1
}

# ensure_line <file> <exact line> — append if missing
ensure_line() {
  local file="$1" line="$2"
  LAST_CHANGED=0
  grep -qxF -- "$line" "$file" 2>/dev/null && return 0
  backup_file "$file"
  if (( DRY_RUN )); then
    printf '%s[dry-run]%s would append to %s: %s\n' "$C_DIM" "$C_RST" "$file" "$line" >&2
  else
    printf '%s\n' "$line" >>"$file"
  fi
  record_change "appended line to $file"
  LAST_CHANGED=1
}

# ----------------------------------------------------------------------------
# Compliance check registry
# ----------------------------------------------------------------------------
# check <ID> <PASS|WARN|FAIL|INFO> <description> [detail]
check() {
  CHECK_IDS+=("$1"); CHECK_STATUS+=("$2"); CHECK_DESC+=("$3"); CHECK_DETAIL+=("${4:-}")
  case "$2" in
    PASS) _log PASS "$C_GRN" "[$1] $3" ;;
    WARN) _log WARN "$C_YEL" "[$1] $3${4:+ — $4}" ;;
    FAIL) _log FAIL "$C_RED" "[$1] $3${4:+ — $4}" ;;
    *)    _log INFO "$C_DIM" "[$1] $3${4:+ — $4}" ;;
  esac
}

# ----------------------------------------------------------------------------
# Usage / argument parsing
# ----------------------------------------------------------------------------
usage() {
  cat <<EOF
$SCRIPT_NAME v$TOOL_VERSION — automated, idempotent Linux server hardening

Usage: sudo $SCRIPT_NAME [options]

Works on Ubuntu/Debian (apt + UFW) and RHEL/Rocky/Alma 8-10 (dnf + firewalld
+ SELinux). The OS is detected automatically.

Modes:
  (default)                 Apply hardening, then audit and write reports
  --audit-only              Change nothing; only run checks, Lynis and reports
  --dry-run                 Show every change that would be made, make none
  --rollback <RUN_ID>       Restore files backed up by a previous run
  --list-runs               List previous runs available for rollback

SSH:
  --admin-user <name>       Non-root admin user that will log in with a key
                            (created if missing, added to sudo/wheel).
                            Default: \$SUDO_USER
  --pubkey <file|"key">     Public key to install for the admin user
  --ssh-port <port>         SSH port (default: 22)
  --ssh-allow-users "a b"   Restrict SSH logins to these users
  --force-key-only          Disable password auth even if no key is detected
                            (DANGEROUS: can lock you out)

Firewall:
  --allow <port[/proto]>    Extra inbound port to open (repeatable),
                            e.g. --allow 80/tcp --allow 443/tcp

Services:
  --disable <svc>           Extra service to disable (repeatable)
  --keep <svc>              Do not disable this service (repeatable).
                            --keep cockpit also keeps it open in firewalld.

Updates:
  --auto-reboot <HH:MM>     Allow unattended reboots at this time when needed

Audit:
  --fix-perms               Tighten critical file permissions that fail audit
  --skip-lynis              Do not run Lynis (it takes 1–3 minutes)
  --report-dir <dir>        Where reports go (default: $REPORT_DIR)

Other:
  --skip <module>           Skip a module (repeatable). Modules:
                            packages ssh firewall fail2ban services updates
                            sysctl perms lynis
  -y, --yes                 Non-interactive; assume yes
  -h, --help                Show this help
  -V, --version             Show version

Examples:
  sudo $SCRIPT_NAME --admin-user deploy --pubkey ~/.ssh/id_ed25519.pub
  sudo $SCRIPT_NAME --ssh-port 2222 --allow 80/tcp --allow 443/tcp --fix-perms
  sudo $SCRIPT_NAME --audit-only
  sudo $SCRIPT_NAME --dry-run
EOF
}

LIST_RUNS=0
parse_args() {
  while (($#)); do
    case "$1" in
      --audit-only)      AUDIT_ONLY=1 ;;
      --dry-run)         DRY_RUN=1 ;;
      --rollback)        ROLLBACK_ID="${2:?--rollback needs a RUN_ID}"; shift ;;
      --list-runs)       LIST_RUNS=1 ;;
      --admin-user)      ADMIN_USER="${2:?}"; shift ;;
      --pubkey)          PUBKEY="${2:?}"; shift ;;
      --ssh-port)        SSH_PORT="${2:?}"; shift ;;
      --ssh-allow-users) SSH_ALLOW_USERS="${2:?}"; shift ;;
      --force-key-only)  FORCE_KEY_ONLY=1 ;;
      --allow)           ALLOW_PORTS+=("${2:?}"); shift ;;
      --disable)         DISABLE_SERVICES+=("${2:?}"); shift ;;
      --keep)            KEEP_SERVICES+=("${2:?}"); shift ;;
      --auto-reboot)     AUTO_REBOOT_TIME="${2:?}"; shift ;;
      --fix-perms)       FIX_PERMS=1 ;;
      --skip-lynis)      SKIP_LYNIS=1 ;;
      --report-dir)      REPORT_DIR="${2:?}"; shift ;;
      --skip)            SKIP_MODULES+=("${2:?}"); shift ;;
      -y|--yes)          ;; # all prompts are already safe-by-default
      -h|--help)         usage; exit 0 ;;
      -V|--version)      echo "$TOOL_VERSION"; exit 0 ;;
      *) usage >&2; die "Unknown option: $1" ;;
    esac
    shift
  done

  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) \
    || die "Invalid --ssh-port: $SSH_PORT"
  local p
  for p in "${ALLOW_PORTS[@]}"; do
    [[ "$p" =~ ^[0-9]+(:[0-9]+)?(/(tcp|udp))?$ ]] || die "Invalid --allow value: $p"
  done
  if [[ -n "$AUTO_REBOOT_TIME" && ! "$AUTO_REBOOT_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
    die "Invalid --auto-reboot time (use HH:MM): $AUTO_REBOOT_TIME"
  fi
  if [[ -n "$ADMIN_USER" && ! "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    die "Invalid --admin-user: $ADMIN_USER"
  fi
  if [[ -z "$ADMIN_USER" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    ADMIN_USER="$SUDO_USER"
  fi
  if (( AUDIT_ONLY )); then DRY_RUN=0; fi
  return 0
}

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------
# shellcheck disable=SC1090  # os-release path is configurable for testing
detect_os() {
  [[ -r "$OS_RELEASE_FILE" ]] || die "Cannot detect OS ($OS_RELEASE_FILE missing)"
  local id like ver
  # Read in a subshell so os-release variables (VERSION, ID...) don't leak in.
  id="$(  . "$OS_RELEASE_FILE"; echo "${ID:-}")"
  like="$(. "$OS_RELEASE_FILE"; echo "${ID_LIKE:-}")"
  ver="$( . "$OS_RELEASE_FILE"; echo "${VERSION_ID:-0}")"
  OS_PRETTY="$(. "$OS_RELEASE_FILE"; echo "${PRETTY_NAME:-$id $ver}")"
  OS_MAJOR="${ver%%.*}"

  case " $id $like " in
    *" debian "*|*" ubuntu "*) OS_FAMILY=debian ;;
    *" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) OS_FAMILY=rhel ;;
    *) die "Unsupported OS: $OS_PRETTY. Supported: Ubuntu/Debian and RHEL 8+ family." ;;
  esac

  if [[ "$OS_FAMILY" == debian ]]; then
    ADMIN_GROUP=sudo; SSH_SERVICE=ssh; FIREWALL=ufw
    REQUIRED_PACKAGES=(ufw fail2ban lynis unattended-upgrades apt-listchanges python3-systemd openssh-server)
    INSECURE_PACKAGES=(telnetd inetutils-telnetd rsh-server rsh-redone-server nis tftpd tftpd-hpa xinetd talkd)
  else
    [[ "$OS_MAJOR" =~ ^[0-9]+$ ]] && (( OS_MAJOR >= 8 )) || die "RHEL-family $OS_MAJOR is too old (8+ required)"
    ADMIN_GROUP=wheel; SSH_SERVICE=sshd; FIREWALL=firewalld
    # fail2ban + lynis come from EPEL (enabled automatically).
    # policycoreutils-python-utils provides semanage for SELinux port labels.
    REQUIRED_PACKAGES=(firewalld fail2ban fail2ban-systemd python3-systemd lynis dnf-automatic
                       policycoreutils-python-utils openssh-server)
    INSECURE_PACKAGES=(telnet-server rsh-server ypserv tftp-server xinetd talk-server)
  fi
}

preflight() {
  (( EUID == 0 )) || die "Run as root (sudo $SCRIPT_NAME ...)"
  detect_os
  has_systemd || warn "systemd is not running (container?) — service actions will be skipped"

  mkdir -p "$REPORT_DIR" "$STATE_DIR"
  chmod 750 "$REPORT_DIR" "$STATE_DIR"
  LOG_FILE="$REPORT_DIR/harden-$RUN_ID.log"
  BACKUP_DIR="$BACKUP_ROOT/$RUN_ID"

  # Prevent concurrent runs.
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "Another $SCRIPT_NAME run is in progress"

  info "$SCRIPT_NAME v$TOOL_VERSION on $(hostname) — $OS_PRETTY ($OS_FAMILY family: $FIREWALL, admin group '$ADMIN_GROUP') — run $RUN_ID"
  (( DRY_RUN ))    && warn "DRY-RUN: no changes will be made"
  (( AUDIT_ONLY )) && info "AUDIT-ONLY: no changes will be made"
  return 0
}

# ----------------------------------------------------------------------------
# Module: packages
# ----------------------------------------------------------------------------
pkg_installed() {
  if [[ "$OS_FAMILY" == debian ]]; then
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
  else
    # --whatprovides also matches virtual names (e.g. dnf-utils -> yum-utils)
    rpm -q --whatprovides "$1" >/dev/null 2>&1
  fi
}

mod_packages() {
  section "Packages"
  local missing=() p
  for p in "${REQUIRED_PACKAGES[@]}"; do pkg_installed "$p" || missing+=("$p"); done
  if ((${#missing[@]} == 0)); then ok "All required packages already installed"; return 0; fi
  info "Installing: ${missing[*]}"

  if [[ "$OS_FAMILY" == debian ]]; then
    export DEBIAN_FRONTEND=noninteractive
    run apt-get update -qq
    run apt-get install -y -qq --no-install-recommends "${missing[@]}"
  else
    # fail2ban and lynis live in EPEL. Rocky/Alma/CentOS ship epel-release in
    # their own repos; on real RHEL we install it from the Fedora project URL.
    if ! pkg_installed epel-release; then
      info "Enabling EPEL repository"
      run dnf install -y -q epel-release \
        || run dnf install -y -q "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_MAJOR}.noarch.rpm"
      record_change "enabled EPEL repository"
    fi
    run dnf install -y -q "${missing[@]}"
  fi
  record_change "installed packages: ${missing[*]}"
}

# ----------------------------------------------------------------------------
# Module: SSH
# ----------------------------------------------------------------------------
ssh_service_name() {
  # Ubuntu/Debian call it ssh.service, RHEL calls it sshd.service.
  if has_systemd && ! systemctl cat "$SSH_SERVICE.service" >/dev/null 2>&1; then
    [[ "$SSH_SERVICE" == ssh ]] && echo sshd || echo ssh
  else
    echo "$SSH_SERVICE"
  fi
}

# SELinux (RHEL) refuses to let sshd bind to a port that isn't labelled
# ssh_port_t. Label the new port before sshd is reloaded.
selinux_allow_ssh_port() {
  [[ "$SSH_PORT" == 22 ]] && return 0
  has_cmd getenforce || return 0
  [[ "$(getenforce 2>/dev/null)" == Disabled ]] && return 0
  if ! has_cmd semanage; then
    warn "SELinux is on but semanage is missing; sshd may fail to bind port $SSH_PORT"
    return 0
  fi
  if semanage port -l 2>/dev/null | awk '$1=="ssh_port_t"' | grep -qw "$SSH_PORT"; then
    ok "SELinux already allows sshd on port $SSH_PORT"
    return 0
  fi
  # -a adds a new label; -m changes a port already labelled for another type.
  local op="-a"
  semanage port -l 2>/dev/null | awk '$2=="tcp"' | grep -qw "$SSH_PORT" && op="-m"
  run semanage port "$op" -t ssh_port_t -p tcp "$SSH_PORT"
  record_change "SELinux: labelled tcp/$SSH_PORT as ssh_port_t"
}

# Users (non-root) who are in sudo/admin/wheel and have at least one valid key
key_capable_admins() {
  local u home ak
  local members
  members="$( { getent group sudo admin wheel 2>/dev/null || true; } | cut -d: -f4 | tr ',' '\n' | sort -u)"
  for u in $members; do
    [[ "$u" == root ]] && continue
    home="$(getent passwd "$u" | cut -d: -f6)"
    ak="$home/.ssh/authorized_keys"
    [[ -s "$ak" ]] && ssh-keygen -l -f "$ak" >/dev/null 2>&1 && echo "$u"
  done
  return 0
}

ensure_admin_user() {
  [[ -n "$ADMIN_USER" ]] || return 0
  if ! id "$ADMIN_USER" >/dev/null 2>&1; then
    run useradd -m -s /bin/bash "$ADMIN_USER"
    record_change "created user $ADMIN_USER"
    if [[ -t 0 && -t 1 ]] && (( ! DRY_RUN )); then
      info "Set a password for $ADMIN_USER (needed for sudo):"
      passwd "$ADMIN_USER" || warn "Password not set — sudo will not work until you set one"
    else
      warn "User $ADMIN_USER has no password; run 'passwd $ADMIN_USER' so sudo works"
    fi
  fi
  if ! id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$ADMIN_GROUP"; then
    run usermod -aG "$ADMIN_GROUP" "$ADMIN_USER"
    record_change "added $ADMIN_USER to $ADMIN_GROUP group"
  fi
}

install_pubkey() {
  [[ -n "$PUBKEY" ]] || return 0
  [[ -n "$ADMIN_USER" ]] || die "--pubkey requires --admin-user (root login will be disabled)"
  # Accept a .pub file, an authorized_keys file (several keys), or a literal key.
  local keys=()
  if [[ -f "$PUBKEY" ]]; then
    grep -q 'PRIVATE KEY' "$PUBKEY" && die "That looks like a PRIVATE key. Pass the .pub file."
    mapfile -t keys < <(grep -Ev '^[[:space:]]*(#|$)' "$PUBKEY")
  else
    keys=("$PUBKEY")
  fi
  ((${#keys[@]})) || die "No public keys found in $PUBKEY"

  local home; home="$(getent passwd "$ADMIN_USER" | cut -d: -f6 || true)"
  if (( DRY_RUN )) && [[ -z "$home" ]]; then home="/home/$ADMIN_USER"; fi
  local sshdir="$home/.ssh" ak="$home/.ssh/authorized_keys" key body
  if [[ ! -d "$sshdir" ]]; then run install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$sshdir"; fi
  for key in "${keys[@]}"; do
    ssh-keygen -l -f /dev/stdin <<<"$key" >/dev/null 2>&1 || die "Not a valid SSH public key: ${key:0:40}…"
    # Compare on type + base64 body so a different comment doesn't duplicate it.
    body="$(awk '{print $1" "$2}' <<<"$key")"
    if [[ -f "$ak" ]] && awk '{print $1" "$2}' "$ak" | grep -qxF -- "$body"; then
      ok "Key ${body:0:30}… already authorized for $ADMIN_USER"
    else
      ensure_line "$ak" "$key"
    fi
  done
  if [[ -f "$ak" ]] && (( ! DRY_RUN )); then
    chmod 600 "$ak"; chmod 700 "$sshdir"; chown -R "$ADMIN_USER:$ADMIN_USER" "$sshdir"
  fi
}

mod_ssh() {
  section "SSH"
  has_cmd sshd || [[ -x /usr/sbin/sshd ]] || { warn "openssh-server not installed; skipping"; return 0; }
  ensure_admin_user
  install_pubkey

  # Lockout guard: only disable passwords when a sudo user can log in with a key.
  local admins password_auth="no"
  admins="$(key_capable_admins | tr '\n' ' ')"
  # In dry-run the key isn't actually written, so count a pending --pubkey.
  if (( DRY_RUN )) && [[ -n "$PUBKEY" && -n "$ADMIN_USER" ]]; then admins+="$ADMIN_USER(pending)"; fi
  if [[ -z "${admins// }" ]]; then
    if (( FORCE_KEY_ONLY )); then
      warn "No sudo user has an SSH key, but --force-key-only was given. You may be locked out."
    else
      password_auth="yes"
      warn "No non-root sudo user with an authorized SSH key found."
      warn "Keeping PasswordAuthentication=yes to avoid lockout. Re-run with --admin-user/--pubkey."
    fi
  else
    info "Key-capable admin users: ${admins:-$ADMIN_USER (pending)}"
  fi

  # Make sure the drop-in directory is included (default on Ubuntu and RHEL 9+,
  # missing on RHEL 8) and placed first: sshd uses the FIRST value it sees, so
  # 00- beats 50-cloud-init.conf, 50-redhat.conf and 01-permitrootlogin.conf.
  run mkdir -p /etc/ssh/sshd_config.d
  if ! grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    backup_file /etc/ssh/sshd_config
    run sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    record_change "added Include for sshd_config.d"
  fi

  local allow_line=""
  [[ -n "$SSH_ALLOW_USERS" ]] && allow_line="AllowUsers $SSH_ALLOW_USERS"

  local conf
  conf="$(cat <<EOF
# Managed by $SCRIPT_NAME — local edits will be overwritten on the next run.
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication $password_auth
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
LogLevel VERBOSE
Banner /etc/issue.net
${allow_line}
EOF
)"
  # Drop directives unsupported by this OpenSSH build (e.g. Protocol on 9.x warns).
  conf="$(sed '/^Protocol 2$/d' <<<"$conf")"
  mkdir -p /run/sshd   # sshd -t needs it; must exist before probing or output differs
  if ! /usr/sbin/sshd -t -o KbdInteractiveAuthentication=no 2>/dev/null; then
    conf="$(sed '/^KbdInteractiveAuthentication/d' <<<"$conf")"
  fi
  conf="$(sed '/^$/d' <<<"$conf")"

  write_file /etc/issue.net 644 root:root \
"Authorized access only. All activity may be monitored and reported."
  local banner_changed=$LAST_CHANGED

  write_file "$SSHD_DROPIN" 600 root:root "$conf"
  local changed=$(( LAST_CHANGED || banner_changed ))

  selinux_allow_ssh_port

  (( DRY_RUN )) && return 0
  # Ensure privilege separation dir exists (needed for sshd -t on fresh systems).
  mkdir -p /run/sshd
  if ! /usr/sbin/sshd -t 2>>"$LOG_FILE"; then
    err "sshd config test FAILED — restoring previous configuration"
    rollback_files_from "$BACKUP_DIR" "$SSHD_DROPIN" /etc/ssh/sshd_config
    die "SSH hardening aborted; see $LOG_FILE"
  fi
  ok "sshd -t: configuration valid"

  if (( changed )) && has_systemd; then
    local svc; svc="$(ssh_service_name)"
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
      # Ubuntu 22.10+ socket activation: port comes from a generator.
      systemctl daemon-reload
      systemctl restart ssh.socket
    fi
    systemctl reload "$svc" 2>/dev/null || systemctl restart "$svc"
    ok "Reloaded $svc (existing sessions stay open)"
    warn "Test a NEW ssh login on port $SSH_PORT before closing this session."
  fi
}

# ----------------------------------------------------------------------------
# Module: firewall (UFW)
# ----------------------------------------------------------------------------
current_ssh_ports() {
  [[ -x /usr/sbin/sshd ]] || return 0
  mkdir -p /run/sshd
  { /usr/sbin/sshd -T 2>/dev/null || true; } | awk '$1=="port"{print $2}' | sort -u
}

mod_firewall() {
  section "Firewall ($FIREWALL)"
  if [[ "$FIREWALL" == ufw ]]; then firewall_ufw; else firewall_firewalld; fi
  local old; for old in $(current_ssh_ports); do
    [[ "$old" != "$SSH_PORT" ]] && warn "Port $old/tcp is still open for SSH; close it once port $SSH_PORT works."
  done
  ok "Firewall configured"
}

firewall_ufw() {
  has_cmd ufw || { warn "ufw not installed; skipping"; return 0; }
  local before after p
  before="$(ufw status verbose 2>/dev/null || true)"

  run ufw default deny incoming  >/dev/null
  run ufw default allow outgoing >/dev/null
  run ufw default deny routed    >/dev/null

  # Always keep every port sshd currently listens on open, plus the target
  # port, so changing --ssh-port can never cut off the running session.
  local ports; ports="$( { current_ssh_ports; echo "$SSH_PORT"; } | sort -u)"
  for p in $ports; do
    run ufw limit "$p/tcp" comment 'SSH (rate-limited)' >/dev/null
  done
  for p in "${ALLOW_PORTS[@]}"; do
    run ufw allow "$p" comment "hardening: user allowed" >/dev/null
  done
  run ufw logging low >/dev/null

  if ! ufw status 2>/dev/null | grep -q '^Status: active'; then
    run ufw --force enable >/dev/null
    record_change "enabled UFW"
  fi
  after="$(ufw status verbose 2>/dev/null || true)"
  if [[ "$before" != "$after" ]] && (( ! DRY_RUN )); then record_change "updated UFW rules"; fi
}

# firewalld wrappers: use the live daemon when it runs, otherwise edit the
# permanent config offline (firewall-offline-cmd) so it applies at next boot.
firewalld_running() { has_cmd firewall-cmd && firewall-cmd --state >/dev/null 2>&1; }
fwd() {
  if firewalld_running; then firewall-cmd --permanent "$@"; else firewall-offline-cmd "$@"; fi
}
fwd_zone() {
  if firewalld_running; then firewall-cmd --get-default-zone; else firewall-offline-cmd --get-default-zone; fi
}
fwd_state() { local z; z="$(fwd_zone)"; fwd --zone="$z" --list-all 2>/dev/null || true; }

firewall_firewalld() {
  has_cmd firewall-cmd || has_cmd firewall-offline-cmd || { warn "firewalld not installed; skipping"; return 0; }
  if has_systemd && (( ! DRY_RUN )); then
    if ! systemctl is-enabled --quiet firewalld; then
      systemctl enable --now firewalld >/dev/null 2>&1; record_change "enabled firewalld"
    elif ! systemctl is-active --quiet firewalld; then
      systemctl start firewalld; record_change "started firewalld"
    fi
  fi
  local zone before after p port proto
  zone="$(fwd_zone)"
  before="$(fwd_state)"

  # firewalld rejects everything not explicitly allowed in the zone, so we
  # only need to make sure the zone isn't set to ACCEPT everything.
  if [[ "$(fwd --zone="$zone" --get-target 2>/dev/null)" == ACCEPT ]]; then
    run fwd --zone="$zone" --set-target=default >/dev/null
    record_change "firewalld: zone $zone no longer accepts all traffic"
  fi

  # Keep current and target SSH ports open (see firewall_ufw for why).
  # Adding a rule that already exists just prints ALREADY_ENABLED: idempotent.
  local ports; ports="$( { current_ssh_ports; echo "$SSH_PORT"; } | sort -u)"
  for p in $ports; do
    if [[ "$p" == 22 ]]; then
      fwd --zone="$zone" --query-service=ssh >/dev/null 2>&1 || run fwd --zone="$zone" --add-service=ssh >/dev/null
    else
      fwd --zone="$zone" --query-port="$p/tcp" >/dev/null 2>&1 || run fwd --zone="$zone" --add-port="$p/tcp" >/dev/null
    fi
  done
  for p in "${ALLOW_PORTS[@]}"; do
    port="${p%%/*}"; proto="tcp"; [[ "$p" == */* ]] && proto="${p##*/}"
    port="${port/:/-}"                     # ufw uses 6000:6010, firewalld 6000-6010
    fwd --zone="$zone" --query-port="$port/$proto" >/dev/null 2>&1 \
      || run fwd --zone="$zone" --add-port="$port/$proto" >/dev/null
  done
  # RHEL opens Cockpit's web console (port 9090) by default.
  if ! is_kept cockpit && fwd --zone="$zone" --query-service=cockpit >/dev/null 2>&1; then
    run fwd --zone="$zone" --remove-service=cockpit >/dev/null
  fi

  (( DRY_RUN )) && return 0
  firewalld_running && firewall-cmd --reload >/dev/null
  after="$(fwd_state)"
  [[ "$before" != "$after" ]] && record_change "updated firewalld rules (zone $zone)"
  return 0
}

# ----------------------------------------------------------------------------
# Module: Fail2ban
# ----------------------------------------------------------------------------
mod_fail2ban() {
  section "Fail2ban"
  has_cmd fail2ban-client || { warn "fail2ban not installed; skipping"; return 0; }
  local backend="systemd" journal=""
  pkg_installed python3-systemd || backend="auto"
  # The stock sshd filter only matches sshd.service, but Ubuntu/Debian name
  # the unit ssh.service. Match the real unit so bans actually happen.
  [[ "$backend" == systemd ]] && journal="journalmatch = _SYSTEMD_UNIT=$(ssh_service_name).service"

  local banaction banaction_all
  if [[ "$FIREWALL" == ufw ]]; then
    banaction="ufw"; banaction_all="ufw"
  else
    banaction="firewallcmd-rich-rules"; banaction_all="firewallcmd-allports"
  fi

  # Pin fail2ban's own log file so the recidive jail always has a log to read.
  write_file "$F2B_MAIN" 644 root:root "$(cat <<EOF
# Managed by $SCRIPT_NAME
[Definition]
logtarget = /var/log/fail2ban.log
EOF
)"
  local main_changed=$LAST_CHANGED

  write_file "$F2B_JAIL" 644 root:root "$(cat <<EOF
# Managed by $SCRIPT_NAME
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
bantime.increment = true
bantime.maxtime   = 1w
banaction = $banaction
banaction_allports = $banaction_all
backend   = $backend
ignoreip  = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = $SSH_PORT
maxretry = 3
$journal

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
backend  = auto
bantime  = 1w
findtime = 1d
EOF
)"
  local changed=$(( LAST_CHANGED || main_changed ))
  (( DRY_RUN )) && return 0
  [[ -e /var/log/fail2ban.log ]] || install -m 640 /dev/null /var/log/fail2ban.log
  if fail2ban-client -t >/dev/null 2>&1; then ok "fail2ban config valid"
  else warn "fail2ban config test reported problems (fail2ban-client -t)"; fi

  if has_systemd; then
    if ! systemctl is-enabled --quiet fail2ban; then systemctl enable fail2ban >/dev/null 2>&1; record_change "enabled fail2ban"; fi
    if ! systemctl is-active --quiet fail2ban; then systemctl start fail2ban; record_change "started fail2ban"
    elif (( changed )); then systemctl restart fail2ban; fi
  fi
}

# ----------------------------------------------------------------------------
# Module: unnecessary services
# ----------------------------------------------------------------------------
mod_services() {
  section "Unnecessary services"
  has_systemd || { warn "systemd not running; skipping"; return 0; }
  local svc unit
  for svc in "${DISABLE_SERVICES[@]}"; do
    is_kept "$svc" && { info "Keeping $svc (--keep)"; continue; }
    unit="$svc"; [[ "$unit" == *.* ]] || unit="$svc.service"
    systemctl cat "$unit" >/dev/null 2>&1 || continue      # not installed
    if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
      run systemctl disable --now "$unit" >/dev/null 2>&1 || warn "Could not disable $unit"
      record_change "disabled service $unit"
    fi
  done
  ok "Service review complete"
}

# ----------------------------------------------------------------------------
# Module: automatic security updates
# ----------------------------------------------------------------------------
mod_updates() {
  section "Automatic security updates"
  if [[ "$OS_FAMILY" == debian ]]; then updates_apt; else updates_dnf; fi
}

updates_apt() {
  write_file "$APT_AUTO" 644 root:root "$(cat <<'EOF'
// Managed by harden.sh
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
)"
  local reboot="false" reboot_time=""
  if [[ -n "$AUTO_REBOOT_TIME" ]]; then
    reboot="true"; reboot_time="Unattended-Upgrade::Automatic-Reboot-Time \"$AUTO_REBOOT_TIME\";"
  fi
  # 50unattended-upgrades (shipped by the package) already limits origins to
  # the security pocket; we only add behavioural settings.
  write_file "$APT_UU" 644 root:root "$(cat <<EOF
// Managed by $SCRIPT_NAME
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$reboot";
$reboot_time
Unattended-Upgrade::SyslogEnable "true";
EOF
)"
  enable_units apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service
  ok "Unattended security upgrades configured"
}

updates_dnf() {
  # dnf-automatic (DNF 4, used by RHEL 8, 9 and 10) reads /etc/dnf/automatic.conf.
  # We write the whole file so the result is identical on every run.
  write_file "$DNF_AUTO" 644 root:root "$(cat <<EOF
# Managed by $SCRIPT_NAME — local edits will be overwritten on the next run.
[commands]
upgrade_type = security
random_sleep = 300
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[base]
debuglevel = 1
EOF
)"
  # dnf-automatic has no portable "reboot at HH:MM" setting, so use cron:
  # 'dnf needs-restarting -r' exits 1 when a reboot is required.
  if [[ -n "$AUTO_REBOOT_TIME" ]]; then
    local hh="${AUTO_REBOOT_TIME%%:*}" mm="${AUTO_REBOOT_TIME##*:}"
    write_file "$DNF_REBOOT_CRON" 644 root:root \
"# Managed by $SCRIPT_NAME — reboot only if updates require it
$((10#$mm)) $((10#$hh)) * * * root /usr/bin/dnf -q needs-restarting -r >/dev/null 2>&1 || /usr/sbin/shutdown -r +5 'Rebooting to finish security updates'"
  elif [[ -f "$DNF_REBOOT_CRON" ]]; then
    backup_file "$DNF_REBOOT_CRON"; run rm -f "$DNF_REBOOT_CRON"
    record_change "removed $DNF_REBOOT_CRON (no --auto-reboot)"
  fi
  enable_units dnf-automatic.timer
  ok "dnf-automatic security updates configured"
}

enable_units() {
  has_systemd && (( ! DRY_RUN )) || return 0
  local t
  for t in "$@"; do
    if systemctl cat "$t" >/dev/null 2>&1 && ! systemctl is-enabled --quiet "$t"; then
      systemctl enable --now "$t" >/dev/null 2>&1 && record_change "enabled $t"
    fi
  done
  return 0
}

# ----------------------------------------------------------------------------
# Module: kernel / network sysctl hardening
# ----------------------------------------------------------------------------
readonly SYSCTL_SETTINGS="# Managed by harden.sh
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0"

mod_sysctl() {
  section "Kernel parameters (sysctl)"
  # NOTE: ip_forward is intentionally untouched so Docker/VPN hosts keep working.
  write_file "$SYSCTL_FILE" 644 root:root "$SYSCTL_SETTINGS"
  if (( LAST_CHANGED )) && (( ! DRY_RUN )); then
    sysctl -q -e -p "$SYSCTL_FILE" >/dev/null 2>&1 || warn "Some sysctl keys could not be applied (normal in containers)"
  fi
  ok "sysctl hardening in place"
}

# ----------------------------------------------------------------------------
# Audit: file permissions
# ----------------------------------------------------------------------------
# path  max-mode  owner  group(s allowed, | separated)
readonly PERM_POLICY="
/etc/passwd            644 root root
/etc/passwd-           644 root root
/etc/group             644 root root
/etc/group-            644 root root
/etc/shadow            640 root root|shadow
/etc/shadow-           640 root root|shadow
/etc/gshadow           640 root root|shadow
/etc/gshadow-          640 root root|shadow
/etc/sudoers           440 root root
/etc/ssh/sshd_config   600 root root
/etc/crontab           600 root root
/etc/cron.hourly       700 root root
/etc/cron.daily        700 root root
/etc/cron.weekly       700 root root
/etc/cron.monthly      700 root root
/etc/cron.d            700 root root
/boot/grub/grub.cfg    600 root root
/boot/grub2/grub.cfg   600 root root
/boot/grub2/user.cfg   600 root root
"

audit_permissions() {
  section "File permission audit"
  local path max owner groups actual a_owner a_group excess bad=0
  while read -r path max owner groups; do
    [[ -z "$path" || ! -e "$path" ]] && continue
    read -r actual a_owner a_group < <(stat -c '%a %U %G' "$path")
    excess=$(( 8#$actual & ~8#$max & 8#7777 ))
    local problems=()
    (( excess )) && problems+=("mode $actual > $max")
    [[ "$a_owner" != "$owner" ]] && problems+=("owner $a_owner≠$owner")
    [[ "|$groups|" != *"|$a_group|"* ]] && problems+=("group $a_group∉{$groups}")
    if ((${#problems[@]})); then
      bad=1
      if (( FIX_PERMS && ! AUDIT_ONLY )); then
        backup_file "$path"
        run chmod "$(printf '%o' $(( 8#$actual & 8#$max )))" "$path"
        [[ "$a_owner" != "$owner" ]] && run chown "$owner" "$path"
        [[ "|$groups|" != *"|$a_group|"* ]] && run chgrp "${groups%%|*}" "$path"
        record_change "tightened permissions on $path (${problems[*]})"
        check "PRM-FILE" PASS "$path permissions" "fixed: ${problems[*]}"
      else
        check "PRM-FILE" FAIL "$path permissions" "${problems[*]} (use --fix-perms)"
      fi
    fi
  done <<<"$PERM_POLICY"
  (( bad )) || check "PRM-01" PASS "Critical system files have correct mode/owner"

  # Only scan real local filesystems.
  local fs_args=(-xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /var/lib/docker -o -path /var/lib/containers \) -prune -o)
  # Sticky temp dirs legitimately hold world-writable lock/socket files.
  mapfile -t WW_FILES < <(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /tmp -o -path /var/tmp -o -path /var/lib/docker -o -path /var/lib/containers \) -prune -o -type f -perm -0002 -print 2>/dev/null | head -n 200)
  mapfile -t WW_DIRS  < <(find / "${fs_args[@]}" -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -n 200)
  mapfile -t UNOWNED  < <(find / "${fs_args[@]}" \( -nouser -o -nogroup \) -print 2>/dev/null | head -n 200)
  mapfile -t SUID_ALL < <(find / "${fs_args[@]}" -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort)

  ((${#WW_FILES[@]})) && check PRM-02 FAIL "No world-writable files" "${#WW_FILES[@]} found" \
                      || check PRM-02 PASS "No world-writable files"
  ((${#WW_DIRS[@]}))  && check PRM-03 FAIL "World-writable dirs have sticky bit" "${#WW_DIRS[@]} without sticky bit" \
                      || check PRM-03 PASS "World-writable dirs have sticky bit"
  ((${#UNOWNED[@]}))  && check PRM-04 WARN "No unowned files/dirs" "${#UNOWNED[@]} found" \
                      || check PRM-04 PASS "No unowned files/dirs"

  # SUID/SGID drift against a baseline captured on the first run.
  local baseline="$STATE_DIR/suid.baseline"
  if [[ -f "$baseline" ]]; then
    mapfile -t SUID_NEW < <(comm -13 "$baseline" <(printf '%s\n' "${SUID_ALL[@]}"))
    ((${#SUID_NEW[@]})) && check PRM-05 FAIL "No new SUID/SGID binaries since baseline" "${#SUID_NEW[@]} new: ${SUID_NEW[*]:0:5}" \
                        || check PRM-05 PASS "No new SUID/SGID binaries since baseline" "${#SUID_ALL[@]} total"
  else
    (( DRY_RUN )) || printf '%s\n' "${SUID_ALL[@]}" >"$baseline"
    check PRM-05 INFO "SUID/SGID baseline recorded" "${#SUID_ALL[@]} binaries → $baseline"
  fi

  # Home directories should not be group/world-writable or world-readable.
  local loose=() u h
  while IFS=: read -r u _ uid _ _ h _; do
    (( uid >= 1000 && uid < 65534 )) || continue
    [[ -d "$h" ]] || continue
    (( 8#$(stat -c '%a' "$h") & 8#027 )) && loose+=("$h")
  done </etc/passwd
  ((${#loose[@]})) && check PRM-06 WARN "Home directories are 750 or stricter" "${loose[*]}" \
                   || check PRM-06 PASS "Home directories are 750 or stricter"
}

# ----------------------------------------------------------------------------
# Audit: compliance checks (read-only)
# ----------------------------------------------------------------------------
sshd_val() { { /usr/sbin/sshd -T 2>/dev/null || true; } | awk -v k="$1" '$1==k{ $1=""; sub(/^ /,""); print; exit }'; }

audit_compliance() {
  section "Compliance checks"

  # --- SSH
  if [[ -x /usr/sbin/sshd ]]; then
    mkdir -p /run/sshd 2>/dev/null || true
    local v
    v="$(sshd_val permitrootlogin)";        [[ "$v" == no ]] && check SSH-01 PASS "Root login over SSH disabled" || check SSH-01 FAIL "Root login over SSH disabled" "PermitRootLogin=$v"
    v="$(sshd_val passwordauthentication)"; [[ "$v" == no ]] && check SSH-02 PASS "SSH password authentication disabled" || check SSH-02 FAIL "SSH password authentication disabled" "PasswordAuthentication=$v"
    v="$(sshd_val pubkeyauthentication)";   [[ "$v" == yes ]] && check SSH-03 PASS "SSH public-key authentication enabled" || check SSH-03 FAIL "SSH public-key authentication enabled" "PubkeyAuthentication=$v"
    v="$(sshd_val maxauthtries)";           [[ -n "$v" && "$v" -le 4 ]] && check SSH-04 PASS "SSH MaxAuthTries ≤ 4" "$v" || check SSH-04 WARN "SSH MaxAuthTries ≤ 4" "MaxAuthTries=$v"
    v="$(sshd_val x11forwarding)";          [[ "$v" == no ]] && check SSH-05 PASS "SSH X11 forwarding disabled" || check SSH-05 WARN "SSH X11 forwarding disabled" "X11Forwarding=$v"
    v="$(sshd_val permitemptypasswords)";   [[ "$v" == no ]] && check SSH-06 PASS "SSH empty passwords refused" || check SSH-06 FAIL "SSH empty passwords refused"
    local admins; admins="$(key_capable_admins | tr '\n' ' ')"
    [[ -n "${admins// }" ]] && check SSH-07 PASS "A non-root sudo user can log in with a key" "$admins" \
                            || check SSH-07 FAIL "A non-root sudo user can log in with a key" "risk of lockout if passwords are disabled"
  else
    check SSH-00 INFO "OpenSSH server not installed"
  fi

  # --- Firewall
  if [[ "$FIREWALL" == ufw ]]; then
    if has_cmd ufw; then
      local st; st="$(ufw status verbose 2>/dev/null || true)"
      grep -q '^Status: active' <<<"$st" && check FW-01 PASS "Firewall (UFW) active" || check FW-01 FAIL "Firewall (UFW) active"
      grep -q 'deny (incoming)' <<<"$st" && check FW-02 PASS "Default inbound policy is deny" || check FW-02 FAIL "Default inbound policy is deny"
      grep -Eq "^${SSH_PORT}/tcp +LIMIT" <<<"$(ufw status 2>/dev/null)" && check FW-03 PASS "SSH port allowed (rate-limited)" || check FW-03 WARN "SSH port allowed (rate-limited)"
    else
      check FW-01 FAIL "Firewall (UFW) installed"
    fi
  else
    if has_cmd firewall-cmd || has_cmd firewall-offline-cmd; then
      if has_systemd; then
        systemctl is-active --quiet firewalld && check FW-01 PASS "Firewall (firewalld) active" || check FW-01 FAIL "Firewall (firewalld) active"
      else
        check FW-01 INFO "Firewall (firewalld) configured" "service state not checkable without systemd"
      fi
      local zone target; zone="$(fwd_zone 2>/dev/null || echo public)"
      target="$(fwd --zone="$zone" --get-target 2>/dev/null || true)"
      [[ "$target" != ACCEPT ]] && check FW-02 PASS "Default zone ($zone) rejects unlisted traffic" "target=$target" \
                                || check FW-02 FAIL "Default zone ($zone) rejects unlisted traffic" "target=ACCEPT"
      if { [[ "$SSH_PORT" == 22 ]] && fwd --zone="$zone" --query-service=ssh >/dev/null 2>&1; } \
         || fwd --zone="$zone" --query-port="$SSH_PORT/tcp" >/dev/null 2>&1; then
        check FW-03 PASS "SSH port allowed in firewall" "port $SSH_PORT"
      else
        check FW-03 FAIL "SSH port allowed in firewall" "port $SSH_PORT not open in zone $zone"
      fi
    else
      check FW-01 FAIL "Firewall (firewalld) installed"
    fi
  fi

  # --- Fail2ban
  if has_cmd fail2ban-client; then
    if has_systemd; then
      systemctl is-active --quiet fail2ban && check F2B-01 PASS "Fail2ban running" || check F2B-01 FAIL "Fail2ban running"
      fail2ban-client status sshd >/dev/null 2>&1 && check F2B-02 PASS "Fail2ban sshd jail active" || check F2B-02 FAIL "Fail2ban sshd jail active"
    else
      [[ -f "$F2B_JAIL" ]] && check F2B-01 PASS "Fail2ban jail configured" "service state not checkable without systemd" || check F2B-01 FAIL "Fail2ban jail configured"
    fi
  else
    check F2B-01 FAIL "Fail2ban installed"
  fi

  # --- Updates
  if [[ "$OS_FAMILY" == debian ]]; then
    if pkg_installed unattended-upgrades; then
      local uu; uu="$(apt-config dump 2>/dev/null | awk -F'"' '/^APT::Periodic::Unattended-Upgrade /{print $2}')"
      [[ "$uu" == 1 ]] && check UPD-01 PASS "Automatic security updates enabled" "unattended-upgrades" || check UPD-01 FAIL "Automatic security updates enabled" "APT::Periodic::Unattended-Upgrade=$uu"
    else
      check UPD-01 FAIL "unattended-upgrades installed"
    fi
    local pending; pending="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst .*securi' || true)"
    (( pending == 0 )) && check UPD-02 PASS "No pending security updates" || check UPD-02 WARN "No pending security updates" "$pending pending"
    [[ -f /var/run/reboot-required ]] && check UPD-03 WARN "No reboot pending" "reboot required to finish updates" || check UPD-03 PASS "No reboot pending"
  else
    if pkg_installed dnf-automatic; then
      local ut au timer_ok=1
      ut="$(awk -F' *= *' '$1=="upgrade_type"{print $2}' "$DNF_AUTO" 2>/dev/null)"
      au="$(awk -F' *= *' '$1=="apply_updates"{print $2}' "$DNF_AUTO" 2>/dev/null)"
      if has_systemd && ! systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null \
                     && ! systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; then timer_ok=0; fi
      if [[ "$au" == yes ]] && (( timer_ok )); then
        check UPD-01 PASS "Automatic security updates enabled" "dnf-automatic, upgrade_type=$ut"
      else
        check UPD-01 FAIL "Automatic security updates enabled" "apply_updates=$au, timer enabled=$timer_ok"
      fi
    else
      check UPD-01 FAIL "dnf-automatic installed"
    fi
    local adv
    if adv="$(timeout 90 dnf -q --cacheonly updateinfo list --security 2>/dev/null)"; then
      local pending; pending="$(grep -c . <<<"$adv" || true)"
      (( pending == 0 )) && check UPD-02 PASS "No pending security updates" || check UPD-02 WARN "No pending security updates" "$pending advisories pending"
    else
      check UPD-02 INFO "Pending security updates" "unknown (dnf cache empty; run 'dnf makecache')"
    fi
    if dnf -q needs-restarting -r >/dev/null 2>&1; then check UPD-03 PASS "No reboot pending"
    else check UPD-03 WARN "No reboot pending" "reboot required to finish updates"; fi
  fi

  # --- Services & packages
  if has_systemd; then
    local running=() s u
    for s in "${DISABLE_SERVICES[@]}"; do
      u="$s"; [[ "$u" == *.* ]] || u="$s.service"
      is_kept "$s" && continue
      systemctl is-enabled --quiet "$u" 2>/dev/null && running+=("$s")
    done
    ((${#running[@]})) && check SVC-01 FAIL "No unnecessary services enabled" "${running[*]}" || check SVC-01 PASS "No unnecessary services enabled"
  fi
  local bad=() p
  for p in "${INSECURE_PACKAGES[@]}"; do pkg_installed "$p" && bad+=("$p"); done
  ((${#bad[@]})) && check SVC-02 FAIL "No legacy insecure packages installed" "${bad[*]} (apt purge them)" || check SVC-02 PASS "No legacy insecure packages installed"

  # --- Mandatory access control: SELinux on RHEL, AppArmor on Ubuntu/Debian
  if [[ "$OS_FAMILY" == rhel ]]; then
    local se; se="$(getenforce 2>/dev/null || echo unknown)"
    case "$se" in
      Enforcing)  check MAC-01 PASS "SELinux enforcing" ;;
      Permissive) check MAC-01 WARN "SELinux enforcing" "Permissive: violations are logged, not blocked" ;;
      *)          check MAC-01 FAIL "SELinux enforcing" "$se (set SELINUX=enforcing in /etc/selinux/config)" ;;
    esac
  else
    if has_cmd aa-status && aa-status --enabled 2>/dev/null; then check MAC-01 PASS "AppArmor enabled"
    else check MAC-01 WARN "AppArmor enabled" "not enabled or not available"; fi
  fi

  # --- Kernel
  local total=0 good=0 key want have
  while IFS='=' read -r key want; do
    key="${key// /}"; want="${want// /}"
    [[ -z "$key" || "$key" == \#* ]] && continue
    total=$((total+1))
    have="$(sysctl -n "$key" 2>/dev/null || echo '?')"
    [[ "$have" == "$want" ]] && good=$((good+1))
  done <<<"$SYSCTL_SETTINGS"
  if (( good == total )); then check KRN-01 PASS "Kernel hardening parameters active" "$good/$total"
  elif (( good * 100 / total >= 80 )); then check KRN-01 WARN "Kernel hardening parameters active" "$good/$total"
  else check KRN-01 FAIL "Kernel hardening parameters active" "$good/$total"; fi

  # --- Accounts
  local uid0; uid0="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')"
  [[ -z "${uid0// }" ]] && check ACC-01 PASS "Only root has UID 0" || check ACC-01 FAIL "Only root has UID 0" "$uid0"
  local empty; empty="$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
  [[ -z "${empty// }" ]] && check ACC-02 PASS "No accounts with empty passwords" || check ACC-02 FAIL "No accounts with empty passwords" "$empty"
}

# ----------------------------------------------------------------------------
# Audit: Lynis
# ----------------------------------------------------------------------------
audit_lynis() {
  section "Lynis audit"
  if (( SKIP_LYNIS )) || skip_module lynis; then info "Lynis skipped"; return 0; fi
  has_cmd lynis || { warn "Lynis not installed; skipping"; return 0; }
  (( DRY_RUN )) && { info "Lynis skipped in dry-run"; return 0; }
  local dat="$REPORT_DIR/lynis-$RUN_ID.dat"
  info "Running Lynis (this takes a minute or two)…"
  lynis audit system --quick --no-colors --cronjob \
        --report-file "$dat" --logfile "$REPORT_DIR/lynis-$RUN_ID.log" >/dev/null 2>&1 || true
  if [[ -s "$dat" ]]; then
    LYNIS_INDEX="$(awk -F= '/^hardening_index=/{print $2}' "$dat")"
    mapfile -t LYNIS_WARNINGS    < <(awk -F= '/^warning\[\]=/{sub(/^warning\[\]=/,""); print}' "$dat")
    mapfile -t LYNIS_SUGGESTIONS < <(awk -F= '/^suggestion\[\]=/{sub(/^suggestion\[\]=/,""); print}' "$dat")
    local s=PASS; (( ${LYNIS_INDEX:-0} < 65 )) && s=WARN
    check LYN-01 "$s" "Lynis hardening index ≥ 65" "${LYNIS_INDEX}/100, ${#LYNIS_WARNINGS[@]} warnings, ${#LYNIS_SUGGESTIONS[@]} suggestions"
  else
    warn "Lynis produced no report"
  fi
}

# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }
# Lynis entries look like: TEST-ID|text|details|solution|
lynis_fmt() { awk -F'|' '{d=($3!="-"&&$3!="")?" ("$3")":""; print $1": "$2 d}' <<<"$1"; }

generate_reports() {
  section "Reports"
  local md="$REPORT_DIR/report-$RUN_ID.md" html="$REPORT_DIR/report-$RUN_ID.html"
  local n=${#CHECK_IDS[@]} pass=0 warn_n=0 fail=0 i
  for ((i=0; i<n; i++)); do
    case "${CHECK_STATUS[i]}" in PASS) pass=$((pass+1));; WARN) warn_n=$((warn_n+1));; FAIL) fail=$((fail+1));; esac
  done
  local scored=$((pass+warn_n+fail)) score=0
  (( scored )) && score=$(( (pass*100 + warn_n*50) / scored ))
  local mode="harden"; (( AUDIT_ONLY )) && mode="audit-only"; (( DRY_RUN )) && mode="dry-run"
  local host kernel; host="$(hostname -f 2>/dev/null || hostname)"; kernel="$(uname -r)"

  # ---------- Markdown ----------
  {
    echo "# Security Compliance Report — $host"
    echo
    echo "| | |"; echo "|---|---|"
    echo "| Run | \`$RUN_ID\` ($mode) |"
    echo "| OS | $OS_PRETTY ($OS_FAMILY family, $FIREWALL), kernel $kernel |"
    echo "| Compliance score | **$score%** — $pass pass, $warn_n warn, $fail fail |"
    echo "| Lynis hardening index | $LYNIS_INDEX |"
    echo
    echo "## Checks"; echo
    echo "| ID | Status | Check | Detail |"; echo "|---|---|---|---|"
    for ((i=0; i<n; i++)); do
      echo "| ${CHECK_IDS[i]} | ${CHECK_STATUS[i]} | ${CHECK_DESC[i]} | ${CHECK_DETAIL[i]//|/\\|} |"
    done
    echo; echo "## Changes made in this run"; echo
    if ((${#CHANGES[@]})); then printf -- '- %s\n' "${CHANGES[@]}"; else echo "_None — system already compliant with this tool's configuration (idempotent run)._"; fi
    if ((${#LYNIS_WARNINGS[@]})); then
      echo; echo "## Lynis warnings"; echo
      local w; for w in "${LYNIS_WARNINGS[@]}"; do echo "- $(lynis_fmt "$w")"; done
    fi
    if ((${#LYNIS_SUGGESTIONS[@]})); then
      echo; echo "## Lynis suggestions (top 25)"; echo
      local s; for s in "${LYNIS_SUGGESTIONS[@]:0:25}"; do echo "- $(lynis_fmt "$s")"; done
    fi
    if ((${#WW_FILES[@]} + ${#WW_DIRS[@]} + ${#UNOWNED[@]} + ${#SUID_NEW[@]})); then
      echo; echo "## File findings"
      ((${#WW_FILES[@]})) && { echo; echo "### World-writable files"; printf -- '- `%s`\n' "${WW_FILES[@]:0:50}"; }
      ((${#WW_DIRS[@]}))  && { echo; echo "### World-writable dirs without sticky bit"; printf -- '- `%s`\n' "${WW_DIRS[@]:0:50}"; }
      ((${#UNOWNED[@]}))  && { echo; echo "### Unowned files"; printf -- '- `%s`\n' "${UNOWNED[@]:0:50}"; }
      ((${#SUID_NEW[@]})) && { echo; echo "### New SUID/SGID binaries"; printf -- '- `%s`\n' "${SUID_NEW[@]}"; }
    fi
    echo; echo "---"
    echo "Backups: \`$BACKUP_DIR\` · Roll back with \`sudo $SCRIPT_NAME --rollback $RUN_ID\`"
  } >"$md"

  # ---------- HTML ----------
  local rows="" cls
  for ((i=0; i<n; i++)); do
    cls="$(tr '[:upper:]' '[:lower:]' <<<"${CHECK_STATUS[i]}")"
    rows+="<tr class=\"$cls\"><td><code>$(html_escape "${CHECK_IDS[i]}")</code></td><td><span class=\"badge $cls\">${CHECK_STATUS[i]}</span></td><td>$(html_escape "${CHECK_DESC[i]}")</td><td>$(html_escape "${CHECK_DETAIL[i]}")</td></tr>"$'\n'
  done
  local changes_html="" x
  if ((${#CHANGES[@]})); then
    for x in "${CHANGES[@]}"; do changes_html+="<li>$(html_escape "$x")</li>"; done
    changes_html="<ul>$changes_html</ul>"
  else
    changes_html="<p class=\"muted\">None — the system already matched this tool's configuration (idempotent run).</p>"
  fi
  local lynis_html="" items
  if ((${#LYNIS_WARNINGS[@]})); then
    items=""; for x in "${LYNIS_WARNINGS[@]}"; do items+="<li>$(html_escape "$(lynis_fmt "$x")")</li>"; done
    lynis_html+="<h3>Warnings</h3><ul class=\"warn-list\">$items</ul>"
  fi
  if ((${#LYNIS_SUGGESTIONS[@]})); then
    items=""; for x in "${LYNIS_SUGGESTIONS[@]:0:25}"; do items+="<li>$(html_escape "$(lynis_fmt "$x")")</li>"; done
    lynis_html+="<details><summary>Suggestions (${#LYNIS_SUGGESTIONS[@]}, top 25 shown)</summary><ul>$items</ul></details>"
  fi
  [[ -z "$lynis_html" ]] && lynis_html="<p class=\"muted\">Lynis not run.</p>"
  local files_html=""
  _list() { local title="$1"; shift; (($#)) || return 0; local o="" f; for f in "$@"; do o+="<li><code>$(html_escape "$f")</code></li>"; done; files_html+="<details><summary>$title ($#)</summary><ul>$o</ul></details>"; }
  _list "World-writable files" "${WW_FILES[@]:0:100}"
  _list "World-writable dirs without sticky bit" "${WW_DIRS[@]:0:100}"
  _list "Unowned files" "${UNOWNED[@]:0:100}"
  _list "New SUID/SGID binaries since baseline" "${SUID_NEW[@]}"
  _list "All SUID/SGID binaries" "${SUID_ALL[@]}"

  local ring_color="#1a7f37"; (( score < 85 )) && ring_color="#9a6700"; (( score < 60 )) && ring_color="#cf222e"

  cat >"$html" <<EOF
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security report — $(html_escape "$host") — $RUN_ID</title>
<style>
:root{--fg:#1f2328;--muted:#656d76;--line:#d0d7de;--bg:#fff;--card:#f6f8fa;--pass:#1a7f37;--warn:#9a6700;--fail:#cf222e;--info:#0969da}
@media(prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--bg:#0d1117;--card:#161b22;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--info:#58a6ff}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:1100px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 4px;font-size:24px}h2{margin:36px 0 12px;font-size:18px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .k{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}.card .v{font-size:26px;font-weight:650}
.score .v{color:$ring_color}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;color:var(--muted)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.badge.pass{background:var(--pass)}.badge.warn{background:var(--warn)}.badge.fail{background:var(--fail)}.badge.info{background:var(--info)}
.filters{margin:0 0 10px;display:flex;gap:6px}.filters button{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:4px 10px;cursor:pointer}
.filters button.on{border-color:var(--info);color:var(--info)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0}summary{cursor:pointer;font-weight:600}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}ul{margin:6px 0;padding-left:22px}.warn-list li{color:var(--fail)}
footer{margin-top:40px;font-size:13px;color:var(--muted)}
</style></head><body><main>
<h1>Security compliance report</h1>
<div class="muted">$(html_escape "$host") · $(html_escape "$OS_PRETTY") · kernel $(html_escape "$kernel") · run <code>$RUN_ID</code> ($mode)</div>
<div class="summary">
  <div class="card score"><div class="k">Compliance score</div><div class="v">$score%</div></div>
  <div class="card"><div class="k">Passed</div><div class="v" style="color:var(--pass)">$pass</div></div>
  <div class="card"><div class="k">Warnings</div><div class="v" style="color:var(--warn)">$warn_n</div></div>
  <div class="card"><div class="k">Failed</div><div class="v" style="color:var(--fail)">$fail</div></div>
  <div class="card"><div class="k">Lynis index</div><div class="v">$(html_escape "$LYNIS_INDEX")</div></div>
  <div class="card"><div class="k">Changes this run</div><div class="v">${#CHANGES[@]}</div></div>
</div>
<h2>Checks</h2>
<div class="filters"><button class="on" data-f="all">All</button><button data-f="fail">Fail</button><button data-f="warn">Warn</button><button data-f="pass">Pass</button></div>
<table id="checks"><thead><tr><th>ID</th><th>Status</th><th>Check</th><th>Detail</th></tr></thead><tbody>
$rows</tbody></table>
<h2>Changes made in this run</h2>
$changes_html
<h2>Lynis</h2>
$lynis_html
<h2>File findings</h2>
${files_html:-<p class="muted">No world-writable, unowned or new SUID files found.</p>}
<footer>Generated by $SCRIPT_NAME v$TOOL_VERSION · Backups in <code>$(html_escape "$BACKUP_DIR")</code> · Roll back with <code>sudo $SCRIPT_NAME --rollback $RUN_ID</code></footer>
</main>
<script>
document.querySelectorAll('.filters button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('.filters button').forEach(x=>x.classList.toggle('on',x===b));
  const f=b.dataset.f;document.querySelectorAll('#checks tbody tr').forEach(r=>r.style.display=(f==='all'||r.classList.contains(f))?'':'none');
});
</script></body></html>
EOF
  chmod 640 "$md" "$html"
  ln -sfn "$(basename "$html")" "$REPORT_DIR/latest.html"
  ln -sfn "$(basename "$md")"   "$REPORT_DIR/latest.md"

  ok "Markdown report: $md"
  ok "HTML report:     $html"
  local clabel="Changes"; (( DRY_RUN )) && clabel="Planned changes"
  printf '\n%sCompliance score: %s%%  (%d pass / %d warn / %d fail)  ·  Lynis: %s  ·  %s: %d%s\n' \
    "$C_BLU" "$score" "$pass" "$warn_n" "$fail" "$LYNIS_INDEX" "$clabel" "${#CHANGES[@]}" "$C_RST" >&2
  (( fail == 0 ))
}

# ----------------------------------------------------------------------------
# Rollback
# ----------------------------------------------------------------------------
# rollback_files_from <backup_dir> [only these paths...]
rollback_files_from() {
  local dir="$1"; shift
  local only=("$@") f
  _wanted() { ((${#only[@]} == 0)) && return 0; local o; for o in "${only[@]}"; do [[ "$o" == "$1" ]] && return 0; done; return 1; }
  if [[ -f "$dir/modified.list" ]]; then
    while read -r f; do _wanted "$f" || continue
      cp -a "$dir/files$f" "$f" && info "restored $f"
    done < <(sort -u "$dir/modified.list")
  fi
  if [[ -f "$dir/perms.list" ]]; then
    local mode own grp
    while read -r f mode own grp; do _wanted "$f" || continue
      chmod "$mode" "$f" && chown "$own:$grp" "$f" && info "restored mode $mode on $f"
    done <"$dir/perms.list"
  fi
  if [[ -f "$dir/created.list" ]]; then
    while read -r f; do _wanted "$f" || continue
      [[ -e "$f" ]] && rm -f "$f" && info "removed $f (created by run)"
    done < <(sort -u "$dir/created.list")
  fi
}

do_rollback() {
  (( EUID == 0 )) || die "Run as root"
  detect_os
  local dir="$BACKUP_ROOT/$ROLLBACK_ID"
  [[ -d "$dir" ]] || die "No backup for run '$ROLLBACK_ID' (see --list-runs)"
  section "Rolling back run $ROLLBACK_ID"
  rollback_files_from "$dir"
  mkdir -p /run/sshd
  if [[ -x /usr/sbin/sshd ]] && /usr/sbin/sshd -t; then
    has_systemd && { systemctl reload "$(ssh_service_name)" 2>/dev/null || true; }
  else
    warn "sshd config invalid after rollback — check before reloading!"
  fi
  sysctl -q -e --system >/dev/null 2>&1 || true
  has_systemd && systemctl restart fail2ban 2>/dev/null || true
  ok "Rollback complete. Not reverted automatically: firewall rules, SELinux port labels, created users, disabled services."
}

list_runs() {
  [[ -d "$BACKUP_ROOT" ]] || { echo "No runs recorded."; return 0; }
  local d
  for d in "$BACKUP_ROOT"/*/; do
    d="${d%/}"
    printf '%s  modified=%s created=%s perms=%s\n' "$(basename "$d")" \
      "$(sort -u "$d/modified.list" 2>/dev/null | wc -l)" "$(sort -u "$d/created.list" 2>/dev/null | wc -l)" \
      "$( { wc -l <"$d/perms.list"; } 2>/dev/null || echo 0)"
  done
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  parse_args "$@"
  if (( LIST_RUNS )); then list_runs; exit 0; fi
  if [[ -n "$ROLLBACK_ID" ]]; then do_rollback; exit 0; fi

  preflight

  if (( ! AUDIT_ONLY )); then
    local m
    # Order matters: firewall opens the (new) SSH port before sshd moves to it.
    for m in packages firewall ssh fail2ban services updates sysctl; do
      if skip_module "$m"; then info "Skipping module: $m"; continue; fi
      "mod_$m"
    done
  fi

  skip_module perms || audit_permissions
  audit_compliance
  audit_lynis

  local rc=0
  generate_reports || rc=2
  if (( ! AUDIT_ONLY && ! DRY_RUN )) && ((${#CHANGES[@]})); then
    info "Backups for this run: $BACKUP_DIR  (undo: $SCRIPT_NAME --rollback $RUN_ID)"
  fi
  # Exit codes: 0 = all checks pass, 2 = at least one FAIL (useful for CI/cron)
  exit "$rc"
}

main "$@"
