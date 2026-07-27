#!/bin/bash
CONF="/var/ossec/etc/ossec.conf"
CONF_SEARCH="</ossec_config>"


insert_block_before_line() {
  local block="$1"
  local search="$2"
  local file="$3"

  awk -v block="$block" -v search="$search" '
        BEGIN { inserted = 0 }
        {
            if (!inserted && $0 ~ search) {
                print block
                inserted = 1
            }
            print
        }
    ' "$file" >"${file}.tmp" && mv "${file}.tmp" "$file"
}

# Replace all occurrences of a string in a file
# Usage: replace_string <file> <search_string> <replace_string>
replace_string() {
  local file="$1"
  local search="$2"
  local replace="$3"

  # Validate arguments
  if [[ -z "$file" || -z "$search" ]]; then
    echo "Error: Missing arguments." >&2
    echo "Usage: replace_string <file> <search_string> <replace_string>" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "Error: File '$file' not found." >&2
    return 1
  fi

  # Escape delimiter characters (using '|') in the search/replace strings to avoid sed errors
  local escaped_search=$(printf '%s\n' "$search" | sed 's|[/&|]|\\&|g')
  local escaped_replace=$(printf '%s\n' "$replace" | sed 's|[/&|]|\\&|g')

  # Use sed with the 'g' (global) flag to replace all instances
  if sed -i.bak "s|$escaped_search|$escaped_replace|g" "$file"; then
    rm -f "${file}.bak"
    echo "Successfully replaced all instances of '$search' in $file."
  else
    echo "Error: Failed to update file." >&2
    mv "${file}.bak" "$file"
    return 1
  fi
}

# Universal package installer function for Linux
# Usage: distro_install <package_name>
distro_install() {
    local pkg="$1"

    if [[ -z "$pkg" ]]; then
        echo "Error: No package name provided." >&2
        echo "Usage: distro_install <package_name>" >&2
        return 1
    }

    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y "$pkg"
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y "$pkg"
    elif command -v yum &> /dev/null; then
        sudo yum install -y "$pkg"
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm "$pkg"
    elif command -v zypper &> /dev/null; then
        sudo zypper install -y "$pkg"
    elif command -v apk &> /dev/null; then
        sudo apk add "$pkg"
    else
        echo "Error: No supported package manager found (apt, dnf, yum, pacman, zypper, apk)." >&2
        return 1
    fi
}

# easy add log files
# Usage: add_logfile <path> <log type>
add_logfile() {
    local path="$1"
    local type="$2"
    if [[ -z "$path" || -z "$type" ]]; then
        echo "Error: No path or type provided" >&2
        echo "Usage: add_logfile <path> <log type>" >&2
        return 1
    }
    local block=" <localfile>
      <log_format>$type</log_format>
      <location>$path</location>
    </localfile>
"
    insert_block_before_line "$block" "$CONF_SEARCH" "$CONF"
  }


# easy add wordles
add_wodle() {
    local name="$1"
    if [[ -z "$name" ]]; then
        echo "Error: No path or type provided" >&2
        echo "Usage: add_wodle <name>" >&2
        return 1
    }
    local block=' <wodle name=\"$name\">
      <disabled>no</disabled>
    </wodle>

'
    insert_block_before_line "$block" "$CONF_SEARCH" "$CONF"
}


add_FIM_file() {
    local path="$1"
    local block="  <syscheck>
    <directories realtime=\"yes\">$path</directories>
  </syscheck>
  
  "
    insert_block_before_line "$block" "$CONF_SEARCH" "$CONF"
}


# here because wazuh relies on auditd for better visibility
deploy_audit_rules() {
    local rules_file="/etc/audit/rules.d/ccdc.rules"
    cat << 'EOF' > "$rules_file"
-D
-b 8192
-f 1

# Monitor critical files and persistence
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/crontab -p wa -k persistence
-w /etc/cron.d/ -p wa -k persistence
-w /root/.ssh/ -p wa -k unauthorized_keys
EOF

    # Load rules dynamically
    if command -v augenrules &> /dev/null; then
        augenrules --load
    elif command -v auditctl &> /dev/null; then
        auditctl -R "$rules_file"
    fi
}

deploy_audit_rules

# here because why not
install_fail2ban() {
    distro_install fail2ban
    if systemctl list-unit-files | grep -q fail2ban; then
        systemctl enable --now fail2ban
        
        # Write a quick basic jail configuration for SSH
        cat << 'EOF' > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 3600
findtime = 600
EOF
        systemctl restart fail2ban
    fi
}

install_fail2ban




#ensure logging is running
if [[ command -v auditd ]]; then
    distro_install auditd
}


add_logfile "/var/log/auditd/auditd.log" "audit"
add_logfile "journald" "journald"
add_logfile "/var/lib/docker/containers/*/*.log" "json"
add_logfile "/var/log/auth.log" "syslog"
add_logfile "/var/log/secure" "syslog"
add_logfile "/var/log/syslog" "syslog"
add_logfile "/var/log/messages" "syslog"
add_logfile "/var/log/fail2ban.log" "syslog"


add_wodle "docker-listener"


# run checks every 30 mins
replace_string "$CONF" "<frequency>43200</frequency>" "<frequency>1800</frequency>"
replace_string "$CONF" "<interval>12h</interval>" "<inte>30m</interval>"


add_FIM_file "/bin"
add_FIM_file "/sbin"
add_FIM_file "/usr/bin"
add_FIM_file "/usr/sbin"
add_FIM_file "/etc/passwd"
add_FIM_file "/etc/shadow"
add_FIM_file "/etc/sudoers"
add_FIM_file "/etc/sudoers.d"
add_FIM_file "/var/www/html"
add_FIM_file "/etc/crontab"
add_FIM_file "/etc/cron.d"
add_FIM_file "/etc/cron.hourly"
add_FIM_file "/etc/cron.daily"
add_FIM_file "/etc/cron.weekly"
add_FIM_file "/etc/cron.monthly"
add_FIM_file "/etc/init.d"
add_FIM_file "/etc/systemd/system"
add_FIM_file "/root/.ssh"
add_FIM_file "/home/*/.ssh"


systemctl restart wazuh-agent
