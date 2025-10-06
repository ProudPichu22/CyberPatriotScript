#!/usr/bin/env bash
# cyberpatriot_harden.sh
# Simple Linux hardening checklist script for CyberPatriots-style tasks.
# Dry-run by default. Use --apply to make changes.
#
# Tested conceptually on Debian/Ubuntu and RHEL/CentOS/Fedora systems.
# Always test in a VM before running on production.

set -o errexit
set -o nounset
set -o pipefail

APPLY=false

if [[ "${1:-}" == "--apply" ]]; then
  APPLY=true
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Exiting."
  exit 2
fi

timestamp() { date +"%Y-%m-%d %H:%M:%S"; }

log() { printf "%s %s\n" "$(timestamp)" "$*"; }

edit_file() {
    local file="$1"
    [[ -f "$file" ]] || touch "$file"
    ${EDITOR:-nano} "$file"
}

# Detect distro family
PKG_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MANAGER="yum"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MANAGER="pacman"
else
  PKG_MANAGER="unknown"
fi

log "Package manager detected: $PKG_MANAGER"
log "Mode: $( $APPLY && echo "APPLY (will attempt fixes)" || echo "DRY-RUN (no changes)")"

# Helpers
report() {
  echo
  echo "==== $1 ===="
  shift
  while (( "$#" )); do
    echo "- $1"
    shift
  done
  echo
}

safe_edit_replace() {
  # usage: safe_edit_replace <file> <pattern> <replacement>
  local file="$1" pattern="$2" replacement="$3"
  if grep -qE "$pattern" "$file" 2>/dev/null; then
    if $APPLY; then
      cp -a "$file" "$file.bak.$(date +%s)"
      sed -ri "s/$pattern/$replacement/" "$file"
      log "Patched $file ($pattern -> $replacement)"
    else
      log "Would patch $file: s/$pattern/$replacement/"
    fi
  else
    if $APPLY; then
      cp -a "$file" "$file.bak.$(date +%s)"
      printf "%s\n" "$replacement" >> "$file"
      log "Appended to $file: $replacement"
    else
      log "Would append to $file: $replacement"
    fi
  fi
}

# 1) Check for users with UID 0 other than root
check_uid0() {
  local extras
  extras=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd || true)
  if [[ -n "$extras" ]]; then
    report "Extra UID 0 accounts found" "Accounts with UID 0: $extras" \
      "These are high risk; remove or change UID if not required."
  else
    log "No extra UID 0 users found."
  fi
}

# 2) Ensure no empty password accounts (no shadow entries with empty password)
check_empty_passwords() {
  local empties
  empties=$(awk -F: '($2==""){print $1}' /etc/shadow || true)
  if [[ -n "$empties" ]]; then
    report "Accounts with empty password fields in /etc/shadow" "Accounts: $empties" \
      "Set passwords or lock accounts."
  else
    log "No empty password fields in /etc/shadow."
  fi
}

# 3) Permissions on /etc/passwd and /etc/shadow
check_passwd_shadow_perms() {
  local pperm sperm
  pperm=$(stat -c "%a %U:%G" /etc/passwd)
  sperm=$(stat -c "%a %U:%G" /etc/shadow)
  log "/etc/passwd: $pperm"
  log "/etc/shadow: $sperm"
  if [[ "$(stat -c %a /etc/passwd)" -gt 644 ]]; then
    report "/etc/passwd is too permissive" "/etc/passwd perms: $pperm"
  fi
  if [[ "$(stat -c %a /etc/shadow)" -ne 600 ]]; then
    report "/etc/shadow should be 600 owned by root:root" "/etc/shadow perms: $sperm"
    if $APPLY; then
      chmod 600 /etc/shadow
      chown root:root /etc/shadow
      log "Fixed /etc/shadow permissions to 600 root:root"
    else
      log "Would set /etc/shadow to 600 root:root"
    fi
  fi
}

# 4) Check SSH config: disable root login, disable empty passwords, protocol, PermitRootLogin no
check_ssh() {
  local sshcfg="/etc/ssh/sshd_config"
  if [[ ! -f "$sshcfg" ]]; then
    log "No SSH server config found at $sshcfg (maybe SSH not installed)."
    return
  fi
  local issues=()
  if grep -Ei "^\s*PermitRootLogin\s+yes" "$sshcfg" >/dev/null 2>&1; then
    issues+=("PermitRootLogin is set to yes")
    if $APPLY; then
      safe_edit_replace "$sshcfg" "^\s*PermitRootLogin\s+yes" "PermitRootLogin no"
    fi
  fi
  if ! grep -Ei "^\s*PermitRootLogin\s+no" "$sshcfg" >/dev/null 2>&1; then
    issues+=("PermitRootLogin not explicitly set to no")
    if $APPLY; then
      safe_edit_replace "$sshcfg" "^(#\s*)?PermitRootLogin.*" "PermitRootLogin no"
    fi
  fi
  if grep -Ei "^\s*PermitEmptyPasswords\s+yes" "$sshcfg" >/dev/null 2>&1; then
    issues+=("PermitEmptyPasswords is yes")
    if $APPLY; then
      safe_edit_replace "$sshcfg" "^\s*PermitEmptyPasswords\s+yes" "PermitEmptyPasswords no"
    fi
  fi
  if grep -Ei "^\s*Protocol\s+1" "$sshcfg" >/dev/null 2>&1; then
    issues+=("SSH protocol 1 explicitly enabled (deprecated)")
    if $APPLY; then
      safe_edit_replace "$sshcfg" "^\s*Protocol\s+1" "Protocol 2"
    fi
  fi

  # Restrict RootLogin, PasswordAuthentication (consider setting to no if key-based)
  if grep -Ei "^\s*PasswordAuthentication\s+yes" "$sshcfg" >/dev/null 2>&1; then
    issues+=("PasswordAuthentication is yes — consider disabling if using key auth")
    # only notify; don't disable automatically
  fi

  if [[ ${#issues[@]} -gt 0 ]]; then
    report "SSH hardening issues" "${issues[@]}"
    if $APPLY; then
      log "Restarting sshd"
      if command -v systemctl >/dev/null 2>&1; then
        systemctl reload sshd || systemctl restart sshd || true
      else
        service ssh restart || service sshd restart || true
      fi
    fi
  else
    log "SSH config looks reasonable (basic checks)."
  fi
}

# 5) Check for world-writable files (exclude /proc and mounts) — list top 50
check_world_writable() {
  log "Looking for world-writable files (this may take a moment)..."
  local ww
  ww=$(find / -xdev -path /proc -prune -o -perm -0002 -type f -print 2>/dev/null | head -n 200 || true)
  if [[ -n "$ww" ]]; then
    report "World-writable files found (top results)" "$ww"
  else
    log "No world-writable regular files found on root filesystem."
  fi
}

# 6) Check for SUID/SGID files
check_suid_sgid() {
  local suid sgid
  suid=$(find / -xdev -type f -perm -4000 -print 2>/dev/null | head -n 200 || true)
  sgid=$(find / -xdev -type f -perm -2000 -print 2>/dev/null | head -n 200 || true)
  if [[ -n "$suid" ]]; then
    report "SUID files (top results)" "$suid" "Review if unexpected."
  else
    log "No unusual SUID files found (top check)."
  fi
  if [[ -n "$sgid" ]]; then
    report "SGID files (top results)" "$sgid" "Review if unexpected."
  else
    log "No unusual SGID files found (top check)."
  fi
}

# 7) Check package updates (list available)
check_updates() {
  case "$PKG_MANAGER" in
    apt)
      if command -v apt-get >/dev/null 2>&1; then
        log "Updating package lists (apt-get update)..."
        apt-get update -qq
        local upgradable
        upgradable=$(apt-get --just-print upgrade | grep "^Inst " || true)
        if [[ -n "$upgradable" ]]; then
          report "APT Upgradable packages" "$upgradable"
          if $APPLY; then
            apt-get upgrade -y
            log "Upgraded packages with apt-get."
          fi
        else
          log "No apt upgrades available."
        fi
      fi
      ;;
    dnf|yum)
      if command -v "$PKG_MANAGER" >/dev/null 2>&1; then
        log "Checking for package updates ($PKG_MANAGER)..."
        if [[ "$PKG_MANAGER" == "dnf" ]]; then
          local updates
          updates=$(dnf check-update || true)
          if [[ -n "$updates" ]]; then
            report "DNF updates available" "See 'dnf check-update' output"
            if $APPLY; then
              dnf -y upgrade
            fi
          else
            log "No dnf updates available."
          fi
        else
          local updates
          updates=$(yum check-update || true)
          if [[ -n "$updates" ]]; then
            report "YUM updates available" "See 'yum check-update' output"
            if $APPLY; then
              yum -y update
            fi
          else
            log "No yum updates available."
          fi
        fi
      fi
      ;;
    pacman)
      log "Checking pacman updates..."
      if pacman -Qu | grep -q .; then
        report "pacman updates available" "$(pacman -Qu | head -n 20)"
        if $APPLY; then
          pacman -Syu --noconfirm
        fi
      else
        log "No pacman updates available."
      fi
      ;;
    *)
      log "Unknown package manager; skipping update check."
      ;;
  esac
}

# 8) Firewall: ufw (Debian) or firewalld (RHEL)
check_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    log "ufw detected: status follows"
    ufw status verbose || true
    if ufw status | grep -Ei "inactive|disabled" >/dev/null 2>&1; then
      report "ufw is inactive" "Consider enabling firewall and allowing necessary services (ssh/http...)."
      if $APPLY; then
        ufw --force enable
        ufw allow ssh
        log "Enabled ufw and allowed ssh."
      fi
    fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    log "firewalld detected"
    if ! systemctl is-active --quiet firewalld; then
      report "firewalld inactive" "Consider starting and enabling firewalld"
      if $APPLY; then
        systemctl enable --now firewalld
        log "Started and enabled firewalld."
      fi
    fi
  else
    report "No recognized firewall tool (ufw/firewalld) found" "Consider installing or configuring the system firewall."
  fi
}

# 9) Check that auditd is running
check_auditd() {
  if command -v auditctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd; then
      log "auditd is running."
    else
      report "auditd not running" "Install/enable auditd for auditing."
      if $APPLY; then
        if [[ "$PKG_MANAGER" == "apt" ]]; then
          apt-get install -y auditd || true
        elif [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
          $PKG_MANAGER install -y audit || true
        fi
        systemctl enable --now auditd || true
        log "Installed/enabled auditd (if available)."
      fi
    fi
  else
    log "auditctl not present; skipping auditd check."
  fi
}

# 10) SELinux status (RHEL/Fedora)
check_selinux() {
  if command -v getenforce >/dev/null 2>&1; then
    local se
    se=$(getenforce)
    log "SELinux mode: $se"
    if [[ "$se" == "Disabled" ]]; then
      report "SELinux is disabled" "On RHEL-family systems, SELinux should usually be enforcing for best security."
    fi
  fi
}

# 11) Check PAM / password hashing (SHA-512)
check_password_hashing() {
  local ld="/etc/login.defs"
  if [[ -f "$ld" ]]; then
    if grep -E "^\s*ENCRYPT_METHOD\s+SHA512" "$ld" >/dev/null 2>&1; then
      log "ENCRYPT_METHOD is SHA512 in /etc/login.defs"
    else
      report "ENCRYPT_METHOD not set to SHA512 in /etc/login.defs" "Consider setting ENCRYPT_METHOD SHA512"
      if $APPLY; then
        safe_edit_replace "$ld" "^\s*ENCRYPT_METHOD.*" "ENCRYPT_METHOD SHA512"
      fi
    fi
  fi

  # Check /etc/pam.d/common-password (Debian) or /etc/pam.d/system-auth (RHEL)
  local pamfile=""
  if [[ -f /etc/pam.d/common-password ]]; then pamfile="/etc/pam.d/common-password"; fi
  if [[ -f /etc/pam.d/system-auth && -z "$pamfile" ]]; then pamfile="/etc/pam.d/system-auth"; fi
  if [[ -n "$pamfile" ]]; then
    if grep -E "pam_unix\.so.*sha512" "$pamfile" >/dev/null 2>&1; then
      log "PAM configured to use sha512 in $pamfile"
    else
      report "PAM not configured to use sha512 in $pamfile" "Add 'sha512' to pam_unix.so options"
      if $APPLY; then
        cp -a "$pamfile" "$pamfile.bak.$(date +%s)"
        sed -ri 's/(pam_unix\.so.*)(\n|$)/\1 sha512\2/' "$pamfile" || true
        log "Attempted to add sha512 to pam_unix in $pamfile (check manually)."
      fi
    fi
  fi
}

# 12) Check for passwordless sudo entries
check_sudoers_passwordless() {
  local entries
  entries=$(grep -E "NOPASSWD:" /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true)
  if [[ -n "$entries" ]]; then
    report "Passwordless sudo entries found" "$entries" "Review whether these are allowed."
  else
    log "No passwordless sudo entries found."
  fi
}

# 13) Check crontab permissions and world-writable cron dirs
check_cron() {
  if [[ -d /etc/cron.* ]]; then
    local bad
    bad=$(find /etc/cron.* -maxdepth 2 -perm -0002 -print 2>/dev/null || true)
    if [[ -n "$bad" ]]; then
      report "World-writable cron directories/files" "$bad"
    else
      log "Cron directories look OK (no world-writable)."
    fi
  fi
}

# 14) Check for obvious unnecessary services (httpd, vsftpd, samba, telnet)
check_unnecessary_services() {
  local list=(telnetd telnet rsyncd vsftpd ftp apache2 httpd samba smb nfs-server rpcbind)
  local found=()
  for svc in "${list[@]}"; do
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl list-unit-files | grep -Ei "^${svc}" >/dev/null 2>&1 || systemctl status "$svc" >/dev/null 2>&1; then
        found+=("$svc")
      fi
    else
      if service "$svc" status >/dev/null 2>&1; then
        found+=("$svc")
      fi
    fi
  done
  if (( ${#found[@]} > 0 )); then
    report "Potentially unnecessary services detected" "${found[@]}" "Consider disabling/removing if not required."
    if $APPLY; then
      for s in "${found[@]}"; do
        systemctl disable --now "$s" >/dev/null 2>&1 || true
        log "Attempted to disable $s"
      done
    fi
  else
    log "No common unnecessary services found running/enabled."
  fi
}

# 15) Check for accounts with no shell (disabled) vs interactive shells
check_accounts_shells() {
  local interactive
  interactive=$(awk -F: '($7!~/(nologin|false|\/sbin\/nologin)/){print $1 ":" $7}' /etc/passwd)
  report "Interactive shell accounts (sample)" "$(echo "$interactive" | head -n 40)"
}

linux_user_audit() {
    if ! prompt_confirm "Would you like to perform a user audit?"; then
        log "User audit canceled."
        return
    fi

    AUTH_USERS_FILE="authorized_users.txt"
    AUTH_ADMINS_FILE="authorized_admins.txt"

    # Edit authorized users
    log "Editing list of authorized users..."
    edit_file "$AUTH_USERS_FILE"
    mapfile -t AUTH_USERS < <(awk 'NF' "$AUTH_USERS_FILE") # remove empty lines

    # Edit authorized admins
    log "Editing list of authorized admins..."
    edit_file "$AUTH_ADMINS_FILE"
    mapfile -t AUTH_ADMINS < <(awk 'NF' "$AUTH_ADMINS_FILE")

    # Get local users (UID >= 1000)
    PERMITTED_USERS=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody")
    LOCAL_USERS=()
    while IFS=: read -r user _ uid _ _ _ _; do
        (( uid >= 1000 )) && LOCAL_USERS+=("$user")
    done < /etc/passwd

    # Filter out permitted/system users
    LOCAL_USERS=($(comm -23 <(printf "%s\n" "${LOCAL_USERS[@]}" | sort) <(printf "%s\n" "${PERMITTED_USERS[@]}" | sort)))

    # Users to add/remove
    USERS_TO_ADD=($(comm -23 <(printf "%s\n" "${AUTH_USERS[@]}" | sort) <(printf "%s\n" "${LOCAL_USERS[@]}" | sort)))
    USERS_TO_REMOVE=($(comm -23 <(printf "%s\n" "${LOCAL_USERS[@]}" | sort) <(printf "%s\n" "${AUTH_USERS[@]}" | sort)))

    log "Proposed user changes:"
    echo "Users to add: ${USERS_TO_ADD[*]:-None}"
    echo "Users to remove: ${USERS_TO_REMOVE[*]:-None}"

    if prompt_confirm "Apply these user changes?"; then
        for u in "${USERS_TO_ADD[@]}"; do
            sudo useradd -m "$u"
            sudo passwd "$u"
            log "Added user: $u"
        done
        for u in "${USERS_TO_REMOVE[@]}"; do
            sudo userdel -r "$u"
            log "Removed user: $u"
        done
    fi

    # Admins (sudo group)
    CURRENT_ADMINS=($(getent group sudo | awk -F: '{print $4}' | tr ',' ' '))
    ADMINS_TO_ADD=($(comm -23 <(printf "%s\n" "${AUTH_ADMINS[@]}" | sort) <(printf "%s\n" "${CURRENT_ADMINS[@]}" | sort)))
    ADMINS_TO_REMOVE=($(comm -23 <(printf "%s\n" "${CURRENT_ADMINS[@]}" | sort) <(printf "%s\n" "${AUTH_ADMINS[@]}" | sort)))

    log "Proposed admin changes:"
    echo "Admins to add: ${ADMINS_TO_ADD[*]:-None}"
    echo "Admins to remove: ${ADMINS_TO_REMOVE[*]:-None}"

    if prompt_confirm "Apply these admin changes?"; then
        for a in "${ADMINS_TO_ADD[@]}"; do
            sudo usermod -aG sudo "$a"
            log "Added $a to sudo group"
        done
        for a in "${ADMINS_TO_REMOVE[@]}"; do
            sudo gpasswd -d "$a" sudo
            log "Removed $a from sudo group"
        done
    fi

    log "User audit complete."
}


# Run checks
log "Starting checks..."
check_uid0
check_empty_passwords
check_passwd_shadow_perms
check_ssh
check_world_writable
check_suid_sgid
check_updates
check_firewall
check_auditd
check_selinux
check_password_hashing
check_sudoers_passwordless
check_cron
check_unnecessary_services
check_accounts_shells

log "Checks complete."

if $APPLY; then
  echo
  echo "FINISHED applying fixes (where safe/possible)."
  echo "Review backups (*.bak.*) for changed config files."
else
  echo
  echo "Dry-run complete. To attempt fixes, run with --apply"
fi

exit 0
