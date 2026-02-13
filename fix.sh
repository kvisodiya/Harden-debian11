#!/bin/bash
echo "Fixing Debian 11 hardening script..."

# 1. Remove tcp-wrappers from harden.sh if present
if grep -q "tcp-wrappers" harden.sh; then
    echo "[+] Removing deprecated tcp-wrappers..."
    sed -i 's/tcp-wrappers//g' harden.sh
fi

# 2. Clean apt cache
echo "[+] Cleaning APT cache..."
apt clean

# 3. Update package lists
echo "[+] Updating repositories..."
apt update

echo "[✓] Fix complete."
echo "You can now run:"
echo "sudo bash harden.sh"
