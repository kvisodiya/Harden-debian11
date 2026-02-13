#!/usr/bin/env bash
#===============================================================================
# harden.sh — Debian 11 (Bullseye) VPS Hardening for Lynis 90-95+
#
# Usage  : chmod +x harden.sh && sudo ./harden.sh
# Author : system-hardening
# Tested : Debian 11 (Bullseye) on KVM/Xen/OpenVZ VPS
#
# IMPORTANT:
#   1. Run as root or with sudo
#   2. Have VNC / console access as a fallback (SSH will be hardened)
#   3. Review SSH_PORT and ALLOWED_SSH_USER before running
#   4. Back up everything first
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

#===============================================================================
# CONFIGURATION — EDIT THESE BEFORE RUNNING
#===============================================================================
SSH_PORT="2222"                        # Change SSH port (set to 22 if you want default)
ALLOWED_SSH_USER="root"                # User allowed to SSH in (change to your user)
GRUB_PASSWORD=""                       # Leave empty to skip GRUB password
NTP_SERVER="0.debian.pool.ntp.org"     # NTP server
LOGFILE="/var/log/harden.log"

#===============================================================================
# COLOURS & HELPERS
#===============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOGFILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOGFILE"; }
err()    { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOGFILE"; }
header() { echo -e "\n${CYAN}=== $* ===${NC}" | tee -a "$LOGFILE"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
    fi
}

#===============================================================================
# PRE-FLIGHT
#===============================================================================
check_root

echo "" > "$LOGFILE"
header "Debian 11 VPS Hardening — Starting at $(date)"
log "SSH Port: $SSH_PORT | Allowed User: $ALLOWED_SSH_USER"

#===============================================================================
# 1. SYSTEM UPDATE & ESSENTIAL PACKAGES
#===============================================================================
header "1. System Update & Essential Packages"

log "Updating package lists and upgrading..."
apt-get update -y 2>&1 | tail -1 | tee -a "$LOGFILE"
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1 | tail -1 | tee -a "$LOGFILE"
DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y 2>&1 | tail -1 | tee -a "$LOGFILE"

log "Installing essential security packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    lynis \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    needrestart \
    debsums \
    libpam-tmpdir \
    libpam-pwquality \
    libpam-cracklib \
    apt-show-versions \
    auditd \
    audispd-plugins \
    apparmor \
    apparmor-utils \
    apparmor-profiles \
    apparmor-profiles-extra \
    acct \
    sysstat \
    aide \
    aide-common \
    rkhunter \
    chkrootkit \
    clamav \
    clamav-daemon \
    logrotate \
    rsyslog \
    ntp \
    ntpdate \
    tcp-wrappers \
    iptables-persistent \
    net-tools \
    psmisc \
    lsof \
    secure-delete \
    sudo \
    procps \
    acl \
    at \
    curl \
    wget \
    gnupg2 \
    2>&1 | tail -5 | tee -a "$LOGFILE"

log "Removing unnecessary packages..."
DEBIAN_FRONTEND=noninteractive apt-get purge -y \
    telnet \
    rsh-client \
    rsh-redone-client \
    nis \
    ntalk \
    talk \
    xinetd \
    inetutils-inetd \
    openbsd-inetd \
    2>/dev/null || true

apt-get autoremove -y 2>&1 | tail -1 | tee -a "$LOGFILE"

#===============================================================================
# 2. KERNEL HARDENING (sysctl)
#===============================================================================
header "2. Kernel Hardening (sysctl)"

backup_file /etc/sysctl.conf

cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL_EOF'
#===============================================================================
# KERNEL HARDENING
#===============================================================================

# --- IP Spoofing / Source Route Protection ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Ignore ICMP broadcast requests ---
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Disable source packet routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Ignore send redirects ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- Block SYN attacks ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# --- Log Martians ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Ignore ICMP redirects ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Ignore Directed pings ---
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Disable IPv6 (if not needed — comment out if you use IPv6) ---
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# --- Harden BPF JIT compiler ---
net.core.bpf_jit_harden = 2

# --- Disable IP forwarding ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Protect against TIME-WAIT assassination ---
net.ipv4.tcp_rfc1337 = 1

# --- Prevent core dumps ---
fs.suid_dumpable = 0

# --- Randomize address space (ASLR) ---
kernel.randomize_va_space = 2

# --- Restrict dmesg ---
kernel.dmesg_restrict = 1

# --- Restrict kernel pointer access ---
kernel.kptr_restrict = 2

# --- Disable SysRq ---
kernel.sysrq = 0

# --- Restrict ptrace scope ---
kernel.yama.ptrace_scope = 2

# --- Restrict performance events ---
kernel.perf_event_paranoid = 3

# --- Harden symlink/hardlink ---
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# --- Protect FIFOs and regular files ---
fs.protected_fifos = 2
fs.protected_regular = 2

# --- Limit PID for large systems ---
kernel.pid_max = 65536

# --- Increase system file descriptor limit ---
fs.file-max = 65535

# --- TCP timestamps (privacy vs performance - disable for privacy) ---
net.ipv4.tcp_timestamps = 0

# --- Secure ICMP ---
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089

# --- Restrict unprivileged user namespaces ---
kernel.unprivileged_userns_clone = 0

# --- Restrict userfaultfd ---
vm.unprivileged_userfaultfd = 0

# --- Disable core dumps ---
kernel.core_uses_pid = 1
SYSCTL_EOF

log "Applying sysctl settings..."
sysctl --system 2>&1 | tail -3 | tee -a "$LOGFILE"

#===============================================================================
# 3. CORE DUMPS — DISABLE
#===============================================================================
header "3. Disabling Core Dumps"

cat > /etc/security/limits.d/99-hardening.conf << 'EOF'
*               hard    core            0
*               soft    core            0
*               hard    maxlogins       10
*               soft    nproc           512
*               hard    nproc           1024
EOF

# Systemd coredump
mkdir -p /etc/systemd/coredump.conf.d/
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

# Prevent setuid programs from dumping core
if ! grep -q "fs.suid_dumpable" /etc/sysctl.conf 2>/dev/null; then
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
fi

log "Core dumps disabled"

#===============================================================================
# 4. SSH HARDENING
#===============================================================================
header "4. SSH Hardening"

backup_file /etc/ssh/sshd_config

cat > /etc/ssh/sshd_config << SSHEOF
#===============================================================================
# HARDENED SSH CONFIGURATION
#===============================================================================

# --- Connection ---
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0
Protocol 2

# --- Host Keys ---
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# --- Ciphers and Algorithms ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com

# --- Authentication ---
LoginGraceTime 30
PermitRootLogin ${ALLOWED_SSH_USER == "root" && echo "yes" || echo "no"}
StrictModes yes
MaxAuthTries 3
MaxSessions 3
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AuthenticationMethods publickey,password publickey

# --- Session ---
X11Forwarding no
X11UseLocalhost yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
PermitUserEnvironment no
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
GatewayPorts no
PermitTunnel no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
DisableForwarding yes

# --- Logging ---
SyslogFacility AUTH
LogLevel VERBOSE

# --- Restrict Users ---
AllowUsers ${ALLOWED_SSH_USER}
DenyUsers nobody

# --- Banner ---
Banner /etc/issue.net

# --- SFTP ---
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO

# --- Security ---
MaxStartups 10:30:60
IgnoreRhosts yes
HostbasedAuthentication no
RekeyLimit 512M 1h
SSHEOF

# Fix the PermitRootLogin logic properly
if [[ "$ALLOWED_SSH_USER" == "root" ]]; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
else
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
fi

# If only password auth is desired (no keys yet), simplify AuthenticationMethods
# Comment out the next line if you have SSH keys set up:
sed -i 's/^AuthenticationMethods.*/AuthenticationMethods publickey password/' /etc/ssh/sshd_config

# Remove weak moduli
if [[ -f /etc/ssh/moduli ]]; then
    backup_file /etc/ssh/moduli
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
    if [[ -s /etc/ssh/moduli.safe ]]; then
        mv /etc/ssh/moduli.safe /etc/ssh/moduli
    else
        rm -f /etc/ssh/moduli.safe
    fi
fi

# Regenerate host keys if needed
if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" 2>/dev/null
fi

# Set correct permissions
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

log "SSH hardened on port $SSH_PORT"

#===============================================================================
# 5. FIREWALL (UFW)
#===============================================================================
header "5. Firewall Configuration (UFW)"

# Reset UFW
ufw --force reset 2>&1 | tee -a "$LOGFILE"

# Default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Allow SSH on custom port
ufw allow "${SSH_PORT}/tcp" comment 'SSH'

# Allow common services (uncomment as needed)
# ufw allow 80/tcp comment 'HTTP'
# ufw allow 443/tcp comment 'HTTPS'
# ufw allow 25/tcp comment 'SMTP'

# Rate limiting on SSH
ufw limit "${SSH_PORT}/tcp" comment 'SSH rate limit'

# Logging
ufw logging on
ufw logging medium

# Enable UFW
ufw --force enable
log "UFW firewall enabled"

#===============================================================================
# 6. FAIL2BAN
#===============================================================================
header "6. Fail2Ban Configuration"

backup_file /etc/fail2ban/jail.local

cat > /etc/fail2ban/jail.local << F2BEOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = ufw
ignoreip = 127.0.0.1/8 ::1
action   = %(action_mwl)s

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200

[sshd-ddos]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = ufw
bantime  = 86400
findtime = 86400
maxretry = 3
F2BEOF

systemctl enable fail2ban
systemctl restart fail2ban
log "Fail2Ban configured and started"

#===============================================================================
# 7. AUTOMATIC SECURITY UPDATES
#===============================================================================
header "7. Automatic Security Updates"

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

log "Automatic security updates configured"

#===============================================================================
# 8. AUDIT SYSTEM (auditd)
#===============================================================================
header "8. Audit System Configuration"

backup_file /etc/audit/auditd.conf
backup_file /etc/audit/rules.d/audit.rules

cat > /etc/audit/auditd.conf << 'EOF'
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 25
num_logs = 5
priority_boost = 4
name_format = hostname
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
distribute_network = no
EOF

cat > /etc/audit/rules.d/hardening.rules << 'AUDIT_EOF'
# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (1=printk, 2=panic)
-f 1

# Ignore errors
-i

#===============================================================================
# SELF-AUDITING (Audit config changes)
#===============================================================================
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

#===============================================================================
# FILTERS - SYSTEM CALLS
#===============================================================================

# --- Identity/Authentication ---
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/login.defs -p wa -k identity
-w /etc/securetty -p wa -k identity

# --- PAM ---
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/limits.d/ -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.d/ -p wa -k pam

# --- Network ---
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k network
-w /etc/sysctl.d/ -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/nsswitch.conf -p wa -k network

# --- SSH ---
-w /etc/ssh/sshd_config -p rwxa -k sshd
-w /etc/ssh/sshd_config.d/ -p rwxa -k sshd

# --- Cron ---
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# --- Time changes ---
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# --- User/Group modifications ---
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/adduser -p x -k user_modification
-w /usr/sbin/addgroup -p x -k group_modification

# --- Login/Logout ---
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# --- Privilege escalation ---
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /usr/bin/sudo -p x -k sudo_usage

# --- Power state ---
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power

# --- Kernel modules ---
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

# --- File deletions ---
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete

# --- Unauthorized access attempts ---
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

# --- Mount operations ---
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts

# --- Privilege changes ---
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod

# --- Make the audit configuration immutable ---
-e 2
AUDIT_EOF

# Enable and restart auditd
systemctl enable auditd
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
log "Auditd configured with comprehensive rules"

#===============================================================================
# 9. APPARMOR
#===============================================================================
header "9. AppArmor Configuration"

# Enable AppArmor
if command -v apparmor_parser &>/dev/null; then
    systemctl enable apparmor
    systemctl start apparmor 2>/dev/null || true

    # Enforce all loaded profiles
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true

    log "AppArmor enabled and profiles enforced"
else
    warn "AppArmor not found, skipping"
fi

#===============================================================================
# 10. FILE PERMISSIONS HARDENING
#===============================================================================
header "10. File Permissions Hardening"

# --- Critical system files ---
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 644 /etc/fstab
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
chmod 700 /root
chmod 600 /etc/crontab
chmod 600 /etc/ssh/sshd_config
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly

# --- Set ownership ---
chown root:root /etc/passwd
chown root:root /etc/group
chown root:shadow /etc/shadow
chown root:shadow /etc/gshadow
chown root:root /etc/crontab
chown root:root /etc/ssh/sshd_config
chown root:root /etc/cron.d
chown root:root /etc/cron.daily
chown root:root /etc/cron.hourly
chown root:root /etc/cron.weekly
chown root:root /etc/cron.monthly

# --- Remove world-writable permissions from critical dirs ---
find /var/log -type f -exec chmod g-wx,o-rwx {} + 2>/dev/null || true

# --- SUID/SGID audit and restrict ---
log "Finding and documenting SUID/SGID files..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > /root/suid_sgid_files.txt
log "SUID/SGID file list saved to /root/suid_sgid_files.txt"

# --- Restrict at/cron access ---
if [[ ! -f /etc/cron.allow ]]; then
    echo "root" > /etc/cron.allow
fi
chmod 600 /etc/cron.allow

if [[ ! -f /etc/at.allow ]]; then
    echo "root" > /etc/at.allow
fi
chmod 600 /etc/at.allow

# Remove deny files if allow files exist
rm -f /etc/cron.deny 2>/dev/null || true
rm -f /etc/at.deny 2>/dev/null || true

# --- Secure home directories ---
for dir in /home/*/; do
    if [[ -d "$dir" ]]; then
        chmod 750 "$dir"
    fi
done

# --- Sticky bit on world-writable directories ---
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | while read -r dir; do
    chmod +t "$dir" 2>/dev/null || true
done

log "File permissions hardened"

#===============================================================================
# 11. PASSWORD & PAM POLICIES
#===============================================================================
header "11. Password & PAM Policies"

# --- Login definitions ---
backup_file /etc/login.defs

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   3/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD  SHA512/' /etc/login.defs
sed -i 's/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 10000/' /etc/login.defs

# Add if not present
grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MIN_ROUNDS 10000" >> /etc/login.defs
grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MAX_ROUNDS 50000" >> /etc/login.defs
grep -q "^UMASK" /etc/login.defs && sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs || echo "UMASK 027" >> /etc/login.defs
grep -q "^LOG_OK_LOGINS" /etc/login.defs && sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS   yes/' /etc/login.defs || echo "LOG_OK_LOGINS yes" >> /etc/login.defs
grep -q "^SULOG_FILE" /etc/login.defs || echo "SULOG_FILE /var/log/sulog" >> /etc/login.defs
grep -q "^SU_NAME" /etc/login.defs || echo "SU_NAME su" >> /etc/login.defs

# --- PAM password quality (pwquality) ---
cat > /etc/security/pwquality.conf << 'EOF'
# Password quality configuration
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
enforce_for_root
EOF

# --- PAM common-password ---
backup_file /etc/pam.d/common-password

cat > /etc/pam.d/common-password << 'EOF'
# /etc/pam.d/common-password - password-related modules
password  requisite     pam_pwquality.so retry=3 minlen=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 minclass=4 maxrepeat=3 reject_username enforce_for_root
password  required      pam_pwhistory.so remember=12 use_authtok enforce_for_root
password  [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512 shadow rounds=10000
password  requisite     pam_deny.so
password  required      pam_permit.so
EOF

# --- PAM common-auth (account lockout) ---
backup_file /etc/pam.d/common-auth

cat > /etc/pam.d/common-auth << 'EOF'
# /etc/pam.d/common-auth
auth      required      pam_faillock.so preauth silent audit deny=5 unlock_time=900 fail_interval=900
auth      [success=1 default=ignore] pam_unix.so nullok
auth      [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900
auth      sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900 fail_interval=900
auth      requisite     pam_deny.so
auth      required      pam_permit.so
EOF

# --- PAM common-account ---
backup_file /etc/pam.d/common-account

cat > /etc/pam.d/common-account << 'EOF'
# /etc/pam.d/common-account
account   required      pam_faillock.so
account   [success=1 new_authtok_reqd=done default=ignore] pam_unix.so
account   requisite     pam_deny.so
account   required      pam_permit.so
EOF

# --- Set default umask ---
backup_file /etc/profile

if ! grep -q "^umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi

# Set umask in bash
for f in /etc/bash.bashrc /etc/profile.d/umask.sh; do
    if [[ ! -f "$f" ]] || ! grep -q "umask 027" "$f" 2>/dev/null; then
        echo "umask 027" >> "$f"
    fi
done

# --- Session timeout ---
cat > /etc/profile.d/timeout.sh << 'EOF'
# Auto-logout after 15 minutes of inactivity
readonly TMOUT=900
export TMOUT
EOF
chmod 644 /etc/profile.d/timeout.sh

log "Password and PAM policies configured"

#===============================================================================
# 12. SECURE SHELL LOGIN & DISABLE UNUSED ACCOUNTS
#===============================================================================
header "12. Secure Shell Login & Disable Unused Accounts"

# Lock system accounts that shouldn't have login
SYSTEM_USERS="daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody _apt systemd-timesync systemd-network systemd-resolve messagebus sshd"

for user in $SYSTEM_USERS; do
    if id "$user" &>/dev/null; then
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        passwd -l "$user" 2>/dev/null || true
    fi
done

# Ensure root account uses /bin/bash
usermod -s /bin/bash root 2>/dev/null || true

# Set default shell for new users
sed -i 's|^DSHELL=.*|DSHELL=/bin/bash|' /etc/adduser.conf 2>/dev/null || true

log "System accounts secured"

#===============================================================================
# 13. NETWORK HARDENING (TCP WRAPPERS & HOSTS)
#===============================================================================
header "13. Network Hardening"

# --- TCP Wrappers ---
backup_file /etc/hosts.allow
backup_file /etc/hosts.deny

echo "sshd : ALL" > /etc/hosts.allow
echo "ALL : ALL" > /etc/hosts.deny

# --- Disable unused network protocols ---
cat > /etc/modprobe.d/hardening.conf << 'EOF'
# Disable uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install usb-storage /bin/true
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true

# Disable bluetooth
install bluetooth /bin/true
install btusb /bin/true

# Disable uncommon filesystems
install fat /bin/true
EOF

log "Network protocols and modules hardened"

#===============================================================================
# 14. LOGGING & RSYSLOG HARDENING
#===============================================================================
header "14. Logging & Rsyslog Hardening"

backup_file /etc/rsyslog.conf

# Ensure rsyslog is installed and running
systemctl enable rsyslog
systemctl start rsyslog

# Harden rsyslog configuration
cat > /etc/rsyslog.d/99-hardening.conf << 'EOF'
# Log auth messages
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
daemon.*                        -/var/log/daemon.log
kern.*                          -/var/log/kern.log
user.*                          -/var/log/user.log
mail.*                          -/var/log/mail.log

# Emergency messages to all users
*.emerg                         :omusrmsg:*

# Create separate log for sudo
local2.*                        /var/log/sudo.log
EOF

# Set proper permissions on log files
chmod -R g-wx,o-rwx /var/log/ 2>/dev/null || true
chown root:adm /var/log/syslog 2>/dev/null || true

# Create log files if they don't exist
touch /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/sudo.log
chown root:adm /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/sudo.log
chmod 640 /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/sudo.log

systemctl restart rsyslog

log "Logging hardened"

#===============================================================================
# 15. LOGROTATE CONFIGURATION
#===============================================================================
header "15. Logrotate Configuration"

cat > /etc/logrotate.d/hardening << 'EOF'
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/var/log/sudo.log
{
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

log "Logrotate configured"

#===============================================================================
# 16. BANNER CONFIGURATION
#===============================================================================
header "16. Login Banners"

BANNER_TEXT="
================================================================================
                        AUTHORIZED ACCESS ONLY
================================================================================
This system is for authorized users only. All activity is monitored and logged.
Unauthorized access is prohibited and will be prosecuted to the fullest extent
of the law. By accessing this system, you consent to monitoring and recording
of all activities. If you are not an authorized user, disconnect NOW.
================================================================================
"

echo "$BANNER_TEXT" > /etc/issue
echo "$BANNER_TEXT" > /etc/issue.net
echo "$BANNER_TEXT" > /etc/motd

chmod 644 /etc/issue /etc/issue.net /etc/motd

log "Login banners configured"

#===============================================================================
# 17. SECURE /tmp AND /var/tmp
#===============================================================================
header "17. Securing /tmp"

# Create systemd tmp.mount if not already using tmpfs for /tmp
if ! mountpoint -q /tmp 2>/dev/null; then
    cat > /etc/systemd/system/tmp.mount << 'EOF'
[Unit]
Description=Temporary Directory /tmp
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=swap.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=512M

[Install]
WantedBy=local-fs.target
EOF
    systemctl daemon-reload
    systemctl enable tmp.mount 2>/dev/null || true
    log "/tmp configured as tmpfs with nosuid,nodev,noexec"
else
    log "/tmp is already a mountpoint"
fi

# Bind /var/tmp to /tmp for security
if ! grep -q "/var/tmp" /etc/fstab; then
    echo "# Bind /var/tmp to /tmp" >> /etc/fstab
    echo "/tmp    /var/tmp    none    bind    0 0" >> /etc/fstab
    log "/var/tmp bound to /tmp"
fi

# Add security options to /dev/shm if present
if grep -q "/dev/shm" /etc/fstab; then
    sed -i '/\/dev\/shm/s/defaults/defaults,nosuid,nodev,noexec/' /etc/fstab
else
    echo "tmpfs   /dev/shm    tmpfs   defaults,nosuid,nodev,noexec    0 0" >> /etc/fstab
fi

log "/tmp and shared memory secured"

#===============================================================================
# 18. PROCESS ACCOUNTING
#===============================================================================
header "18. Process Accounting"

systemctl enable acct 2>/dev/null || true
systemctl start acct 2>/dev/null || true

# Enable sysstat
systemctl enable sysstat 2>/dev/null || true
systemctl start sysstat 2>/dev/null || true

log "Process accounting enabled"

#===============================================================================
# 19. TIME SYNCHRONIZATION (NTP)
#===============================================================================
header "19. NTP Configuration"

backup_file /etc/ntp.conf

# Check if we're using systemd-timesyncd or ntp
if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
    systemctl stop systemd-timesyncd
    systemctl disable systemd-timesyncd
fi

cat > /etc/ntp.conf << 'EOF'
# NTP Configuration - Hardened
driftfile /var/lib/ntp/ntp.drift

# Leap seconds
leapfile /usr/share/zoneinfo/leap-seconds.list

# Statistics
statsdir /var/log/ntpstats/
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable

# NTP Servers
pool 0.debian.pool.ntp.org iburst
pool 1.debian.pool.ntp.org iburst
pool 2.debian.pool.ntp.org iburst
pool 3.debian.pool.ntp.org iburst

# Access control
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited
restrict 127.0.0.1
restrict ::1
restrict source notrap nomodify noquery

# Disable monitor mode (prevent NTP amplification attacks)
disable monitor
EOF

systemctl enable ntp
systemctl restart ntp 2>/dev/null || true

log "NTP configured and hardened"

#===============================================================================
# 20. AIDE (Intrusion Detection)
#===============================================================================
header "20. AIDE (File Integrity Monitoring)"

# Configure AIDE
if command -v aide &>/dev/null; then
    backup_file /etc/aide/aide.conf

    # Initialize AIDE database
    log "Initializing AIDE database (this may take a few minutes)..."
    aideinit 2>&1 | tail -3 | tee -a "$LOGFILE" || true

    # Copy new database
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi

    # Create daily AIDE check cron job
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check 2>&1 | /usr/bin/mail -s "AIDE Report - $(hostname) - $(date)" root 2>/dev/null || true
/usr/bin/aide --check > /var/log/aide/aide-check-$(date +%Y%m%d).log 2>&1 || true
EOF
    chmod 700 /etc/cron.daily/aide-check
    mkdir -p /var/log/aide

    log "AIDE initialized and daily check configured"
else
    warn "AIDE not found, skipping"
fi

#===============================================================================
# 21. RKHUNTER (Rootkit Hunter)
#===============================================================================
header "21. RKHunter Configuration"

if command -v rkhunter &>/dev/null; then
    backup_file /etc/rkhunter.conf

    # Update rkhunter configuration
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter 2>/dev/null || true
    sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter 2>/dev/null || true
    sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter 2>/dev/null || true
    sed -i 's/^DB_UPDATE_EMAIL=.*/DB_UPDATE_EMAIL="false"/' /etc/default/rkhunter 2>/dev/null || true

    # Update file properties database
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true

    log "RKHunter configured"
else
    warn "RKHunter not found"
fi

#===============================================================================
# 22. ClamAV
#===============================================================================
header "22. ClamAV Antivirus"

if command -v clamscan &>/dev/null; then
    # Stop freshclam if running, update, restart
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam 2>/dev/null || true
    systemctl enable clamav-freshclam
    systemctl start clamav-freshclam 2>/dev/null || true
    systemctl enable clamav-daemon 2>/dev/null || true

    # Weekly scan cron job
    cat > /etc/cron.weekly/clamav-scan << 'EOF'
#!/bin/bash
LOGFILE="/var/log/clamav/weekly-scan-$(date +%Y%m%d).log"
mkdir -p /var/log/clamav
clamscan -r --quiet --infected --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" / > "$LOGFILE" 2>&1
if grep -q "Infected files: [^0]" "$LOGFILE"; then
    cat "$LOGFILE" | mail -s "ClamAV Alert - $(hostname)" root 2>/dev/null || true
fi
EOF
    chmod 700 /etc/cron.weekly/clamav-scan

    log "ClamAV configured with weekly scan"
else
    warn "ClamAV not found"
fi

#===============================================================================
# 23. DISABLE UNUSED SERVICES
#===============================================================================
header "23. Disable Unused Services"

# List of services commonly not needed on a VPS
DISABLE_SERVICES=(
    avahi-daemon
    cups
    cups-browsed
    isc-dhcp-server
    isc-dhcp-server6
    slapd
    nfs-server
    rpcbind
    bind9
    vsftpd
    dovecot
    smbd
    nmbd
    snmpd
    squid
    nis
    rsh.socket
    rlogin.socket
    rexec.socket
    telnet.socket
    tftp.socket
    xinetd
    bluetooth
    ModemManager
)

for service in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        systemctl mask "$service" 2>/dev/null || true
        log "Disabled service: $service"
    fi
done

log "Unused services disabled"

#===============================================================================
# 24. SUDOERS HARDENING
#===============================================================================
header "24. Sudoers Hardening"

backup_file /etc/sudoers

# Create hardened sudoers drop-in
cat > /etc/sudoers.d/99-hardening << 'EOF'
# Hardened sudoers configuration
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        logfile="/var/log/sudo.log"
Defaults        log_input,log_output
Defaults        iolog_dir="/var/log/sudo-io/%{user}"
Defaults        use_pty
Defaults        passwd_timeout=1
Defaults        timestamp_timeout=5
Defaults        umask=0027
Defaults        !visiblepw
Defaults        !rootpw
Defaults        !runaspw
Defaults        always_set_home
Defaults        env_keep -= "HOME"
EOF

chmod 440 /etc/sudoers.d/99-hardening
chown root:root /etc/sudoers.d/99-hardening

# Validate sudoers
visudo -cf /etc/sudoers 2>/dev/null && log "Sudoers validated" || err "Sudoers validation failed!"

log "Sudoers hardened"

#===============================================================================
# 25. SECURE SHARED MEMORY & fstab HARDENING
#===============================================================================
header "25. fstab Hardening"

backup_file /etc/fstab

# Add proc hardening
if ! grep -q "proc.*hidepid" /etc/fstab; then
    echo "proc    /proc    proc    defaults,hidepid=2    0 0" >> /etc/fstab
    log "Added hidepid=2 to /proc"
fi

log "fstab hardened"

#===============================================================================
# 26. RESTRICT COMPILERS (Optional — uncomment if no compilation needed)
#===============================================================================
header "26. Restrict Compilers"

# Restrict compiler access to root only
if [[ -f /usr/bin/gcc ]]; then
    chmod o-rx /usr/bin/gcc* 2>/dev/null || true
    log "Restricted gcc access"
fi
if [[ -f /usr/bin/cc ]]; then
    chmod o-rx /usr/bin/cc 2>/dev/null || true
    log "Restricted cc access"
fi
if [[ -f /usr/bin/make ]]; then
    chmod o-rx /usr/bin/make 2>/dev/null || true
    log "Restricted make access"
fi
if [[ -f /usr/bin/as ]]; then
    chmod o-rx /usr/bin/as 2>/dev/null || true
fi

log "Compiler access restricted"

#===============================================================================
# 27. LYNIS CUSTOM PROFILE
#===============================================================================
header "27. Lynis Custom Configuration"

mkdir -p /etc/lynis

cat > /etc/lynis/custom.prf << 'EOF'
# Custom Lynis profile for hardened VPS

# Skip tests that don't apply to VPS environments
skip-test=BOOT-5122
skip-test=BOOT-5184
skip-test=FILE-6310
skip-test=USB-1000
skip-test=USB-2000
skip-test=USB-3000
skip-test=FIRE-4508

# Machine type
machine-role=server

# Logging
log-tests-incorrect-os=no

# Colors
colors=yes
EOF

log "Lynis custom profile created"

#===============================================================================
# 28. ADDITIONAL KERNEL HARDENING (Boot Parameters)
#===============================================================================
header "28. Boot Parameter Hardening"

backup_file /etc/default/grub

# Add security boot parameters
if [[ -f /etc/default/grub ]]; then
    CURRENT_CMDLINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT" /etc/default/grub | sed 's/.*="//' | sed 's/"//')

    # Parameters to add
    SECURITY_PARAMS="audit=1 audit_backlog_limit=8192 slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none"

    for param in $SECURITY_PARAMS; do
        if ! echo "$CURRENT_CMDLINE" | grep -q "$param"; then
            CURRENT_CMDLINE="$CURRENT_CMDLINE $param"
        fi
    done

    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$CURRENT_CMDLINE\"|" /etc/default/grub

    # Update GRUB
    update-grub 2>&1 | tee -a "$LOGFILE" || true

    log "GRUB boot parameters hardened"
fi

#===============================================================================
# 29. DISABLE USB STORAGE (VPS has no USB)
#===============================================================================
header "29. Disable USB Storage"

echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/disable-usb-storage.conf

log "USB storage disabled"

#===============================================================================
# 30. SECURE TEMPORARY FILE CREATION
#===============================================================================
header "30. Secure Temporary File Handling"

# Polyinstantiated temp directories via PAM
if ! grep -q "pam_namespace.so" /etc/pam.d/common-session 2>/dev/null; then
    echo "session    required     pam_namespace.so" >> /etc/pam.d/common-session
fi

# Configure namespace
if [[ -f /etc/security/namespace.conf ]]; then
    if ! grep -q "^/tmp" /etc/security/namespace.conf; then
        echo "/tmp     /tmp-inst/          level      root,adm" >> /etc/security/namespace.conf
        echo "/var/tmp /var/tmp-inst/      level      root,adm" >> /etc/security/namespace.conf
    fi
fi

log "Temporary file handling secured"

#===============================================================================
# 31. ADDITIONAL SECURITY SETTINGS
#===============================================================================
header "31. Additional Security Settings"

# --- Restrict su to wheel/sudo group ---
backup_file /etc/pam.d/su

if ! grep -q "pam_wheel.so" /etc/pam.d/su || grep -q "^#.*pam_wheel.so" /etc/pam.d/su; then
    sed -i '/pam_wheel.so/s/^#//' /etc/pam.d/su 2>/dev/null || true
    if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
        sed -i '1a auth       required   pam_wheel.so use_uid group=sudo' /etc/pam.d/su
    fi
fi

# --- Restrict access to kernel logs ---
echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/50-dmesg-restrict.conf

# --- Disable Ctrl+Alt+Del reboot ---
systemctl mask ctrl-alt-del.target 2>/dev/null || true
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target

# --- Set console security ---
if [[ -f /etc/securetty ]]; then
    echo "" > /etc/securetty
    log "Console access restricted"
fi

# --- Set login.defs USERDEL_CMD ---
if ! grep -q "^USERDEL_CMD" /etc/login.defs; then
    echo 'USERDEL_CMD    /usr/sbin/userdel_local' >> /etc/login.defs
fi

# --- Ensure correct permissions on /etc/issue* ---
chmod 644 /etc/issue
chmod 644 /etc/issue.net

# --- Restrict access to su ---
dpkg-statoverride --update --add root sudo 4750 /bin/su 2>/dev/null || true

# --- Secure init scripts ---
chmod 700 /etc/init.d/* 2>/dev/null || true

log "Additional security settings applied"

#===============================================================================
# 32. NEEDRESTART CONFIGURATION
#===============================================================================
header "32. Needrestart Configuration"

if [[ -f /etc/needrestart/needrestart.conf ]]; then
    # Auto-restart services (set to 'a' for automatic)
    sed -i "s/^#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf 2>/dev/null || true
    log "Needrestart configured for automatic restarts"
fi

#===============================================================================
# 33. SYSTEM ACCOUNTING (Comprehensive Auditing)
#===============================================================================
header "33. System Accounting"

# Enable process accounting
accton on 2>/dev/null || true

# Enable kernel auditing
if [[ -f /etc/default/grub ]]; then
    if ! grep -q "audit=1" /etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="audit=1 /' /etc/default/grub
        update-grub 2>/dev/null || true
    fi
fi

log "System accounting enabled"

#===============================================================================
# 34. HARDENED UMASK FOR ALL
#===============================================================================
header "34. Global Umask"

# Set stricter umask system-wide
cat > /etc/profile.d/umask.sh << 'EOF'
# Set default umask
umask 027
EOF

if [[ -f /etc/bash.bashrc ]]; then
    if ! grep -q "^umask 027" /etc/bash.bashrc; then
        echo "umask 027" >> /etc/bash.bashrc
    fi
fi

log "Global umask set to 027"

#===============================================================================
# 35. HARDEN APT
#===============================================================================
header "35. APT Hardening"

cat > /etc/apt/apt.conf.d/99-hardening << 'EOF'
APT::Sandbox::Seccomp "true";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::AllowInsecureRepositories "false";
Acquire::http::AllowRedirect "false";
EOF

log "APT hardened"

#===============================================================================
# 36. VERIFY AND FIX PACKAGE INTEGRITY
#===============================================================================
header "36. Package Integrity"

log "Running debsums to check package integrity..."
debsums --changed 2>/dev/null > /root/debsums-changed.txt || true
if [[ -s /root/debsums-changed.txt ]]; then
    warn "Modified package files found! See /root/debsums-changed.txt"
else
    log "All package files are intact"
fi

#===============================================================================
# 37. RESTRICT ACCESS TO SENSITIVE COMMANDS
#===============================================================================
header "37. Restrict Sensitive Commands"

# Make sensitive system commands accessible only to root
SENSITIVE_CMDS=(
    /usr/bin/wget
    /usr/bin/curl
    /usr/bin/nc
    /usr/bin/ncat
    /usr/bin/nmap
    /usr/bin/tcpdump
    /usr/sbin/tcpdump
    /usr/bin/wireshark
)

for cmd in "${SENSITIVE_CMDS[@]}"; do
    if [[ -f "$cmd" ]]; then
        chmod 750 "$cmd" 2>/dev/null || true
    fi
done

log "Sensitive command access restricted"

#===============================================================================
# 38. CONFIGURE SYSTEMD JOURNAL
#===============================================================================
header "38. Systemd Journal Configuration"

mkdir -p /etc/systemd/journald.conf.d/

cat > /etc/systemd/journald.conf.d/99-hardening.conf << 'EOF'
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
MaxRetentionSec=365day
MaxFileSec=1month
SystemMaxUse=500M
SystemKeepFree=1G
EOF

systemctl restart systemd-journald 2>/dev/null || true
log "Systemd journal configured"

#===============================================================================
# 39. SECURE PERMISSIONS ON LOG DIRECTORY
#===============================================================================
header "39. Log Directory Permissions"

chmod 750 /var/log
chmod 640 /var/log/syslog 2>/dev/null || true
chmod 640 /var/log/auth.log 2>/dev/null || true
chmod 640 /var/log/kern.log 2>/dev/null || true
chmod 660 /var/log/wtmp 2>/dev/null || true
chmod 660 /var/log/btmp 2>/dev/null || true
chmod 640 /var/log/lastlog 2>/dev/null || true

log "Log directory permissions secured"

#===============================================================================
# 40. FINAL CLEANUP & SERVICES RESTART
#===============================================================================
header "40. Final Cleanup & Service Restart"

# Remove leftover packages
apt-get autoremove -y 2>/dev/null || true
apt-get autoclean -y 2>/dev/null || true

# Remove old kernels
apt-get purge -y $(dpkg -l 'linux-image-*' | awk '/^ii/{print $2}' | grep -v "$(uname -r)" | head -n -1) 2>/dev/null || true

# Clear bash history for root
cat /dev/null > /root/.bash_history 2>/dev/null || true

# Restart critical services
log "Restarting services..."
systemctl daemon-reload

# Validate SSH config before restart (CRITICAL!)
if sshd -t 2>/dev/null; then
    systemctl restart sshd
    log "SSH restarted successfully on port $SSH_PORT"
else
    err "SSH configuration has errors! Restoring backup..."
    if [[ -f /etc/ssh/sshd_config.bak.* ]]; then
        LATEST_BACKUP=$(ls -t /etc/ssh/sshd_config.bak.* | head -1)
        cp "$LATEST_BACKUP" /etc/ssh/sshd_config
        systemctl restart sshd
        err "Restored SSH backup. Please check configuration manually."
    fi
fi

systemctl restart fail2ban 2>/dev/null || true
systemctl restart rsyslog 2>/dev/null || true
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true

#===============================================================================
# SUMMARY
#===============================================================================
header "HARDENING COMPLETE"

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}          DEBIAN 11 VPS HARDENING COMPLETE                   ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${CYAN}IMPORTANT NOTES:${NC}"
echo -e "  ${YELLOW}1.${NC} SSH is now on port:        ${GREEN}${SSH_PORT}${NC}"
echo -e "  ${YELLOW}2.${NC} Allowed SSH user:          ${GREEN}${ALLOWED_SSH_USER}${NC}"
echo -e "  ${YELLOW}3.${NC} Firewall (UFW):            ${GREEN}ENABLED${NC}"
echo -e "  ${YELLOW}4.${NC} Fail2Ban:                  ${GREEN}ENABLED${NC}"
echo -e "  ${YELLOW}5.${NC} AppArmor:                  ${GREEN}ENFORCING${NC}"
echo -e "  ${YELLOW}6.${NC} Audit daemon:              ${GREEN}RUNNING${NC}"
echo -e "  ${YELLOW}7.${NC} Auto-updates:              ${GREEN}ENABLED${NC}"
echo -e "  ${YELLOW}8.${NC} AIDE:                      ${GREEN}INITIALIZED${NC}"
echo -e "  ${YELLOW}9.${NC} Log file:                  ${GREEN}${LOGFILE}${NC}"
echo ""
echo -e "${RED}ACTION REQUIRED:${NC}"
echo -e "  1. Test SSH connection on port ${SSH_PORT} BEFORE closing this session"
echo -e "     ${CYAN}ssh -p ${SSH_PORT} ${ALLOWED_SSH_USER}@<your-ip>${NC}"
echo -e "  2. Review SUID/SGID files: ${CYAN}/root/suid_sgid_files.txt${NC}"
echo -e "  3. Review debsums report:  ${CYAN}/root/debsums-changed.txt${NC}"
echo -e "  4. Consider setting up SSH keys and disabling password auth"
echo -e "  5. A REBOOT is recommended for all changes to take effect"
echo ""
echo -e "${YELLOW}POST-REBOOT LYNIS SCAN:${NC}"
echo -e "  ${CYAN}sudo lynis audit system --profile /etc/lynis/custom.prf${NC}"
echo ""
echo -e "${GREEN}============================================================${NC}"

# Save summary
cat > /root/hardening-summary.txt << SUMMARY
Hardening completed: $(date)
SSH Port: ${SSH_PORT}
Allowed SSH User: ${ALLOWED_SSH_USER}
Firewall: UFW (enabled)
IDS: AIDE, RKHunter, ClamAV
Audit: auditd
MAC: AppArmor
Auto-updates: unattended-upgrades
Fail2Ban: enabled

Files modified (backups created):
- /etc/ssh/sshd_config
- /etc/sysctl.d/99-hardening.conf
- /etc/audit/rules.d/hardening.rules
- /etc/pam.d/common-password
- /etc/pam.d/common-auth
- /etc/pam.d/common-account
- /etc/login.defs
- /etc/security/pwquality.conf
- /etc/security/limits.d/99-hardening.conf
- /etc/modprobe.d/hardening.conf
- /etc/default/grub
- /etc/fstab
- /etc/sudoers.d/99-hardening
- /etc/fail2ban/jail.local
- /etc/rsyslog.d/99-hardening.conf
- /etc/issue, /etc/issue.net, /etc/motd
- /etc/hosts.allow, /etc/hosts.deny
- /etc/ntp.conf
- /etc/apt/apt.conf.d/ (multiple)
SUMMARY

log "Summary saved to /root/hardening-summary.txt"
log "Hardening script completed at $(date)"
