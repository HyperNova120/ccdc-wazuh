#!/bin/bash
# Wazuh Agent Installer for amd64 Linux
# Works with Debian/Ubuntu (DEB) and RHEL/CentOS (RPM)

# --- Configuration ---
WAZUH_MANAGER=$1             # Replace with Wazuh server IP or FQDN
WAZUH_AGENT_NAME=$(hostname) # auto gets machine name

# --- Version ---
WAZUH_VERSION="4.14.6-1"

# --- Detect Package Manager ---
if command -v dpkg >/dev/null 2>&1; then
  echo "Detected Debian/Ubuntu system..."
  wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}_amd64.deb
  sudo WAZUH_MANAGER="${WAZUH_MANAGER}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" dpkg -i ./wazuh-agent_${WAZUH_VERSION}_amd64.deb

elif command -v rpm >/dev/null 2>&1; then
  echo "Detected RHEL/CentOS system..."
  curl -o wazuh-agent-${WAZUH_VERSION}.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-${WAZUH_VERSION}.x86_64.rpm
  sudo WAZUH_MANAGER="${WAZUH_MANAGER}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" rpm -ihv wazuh-agent-${WAZUH_VERSION}.x86_64.rpm

else
  echo "Unsupported system. Must be Debian/Ubuntu or RHEL/CentOS on amd64."
  exit 1
fi
sed -i "s|MANAGER_IP|${WAZUH_MANAGER}|g" /var/ossec/etc/ossec.conf
# --- Enable and Start Agent ---
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "Wazuh agent installation complete."
echo "Manager: ${WAZUH_MANAGER}"
echo "Agent Name: ${WAZUH_AGENT_NAME}"
