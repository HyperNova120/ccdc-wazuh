#!/bin/bash
CONF="/var/ossec/etc/ossec.conf"
CONF_SEARCH="</ossec_config>"

TARGET_PATH=$1

if [ -z "$TARGET_PATH" ]; then
  echo "Error: You must provide a file or directory path."
  echo "Usage: $0 /path/to/file_or_directory"
  exit 1
fi

if command -v realpath >/dev/null 2>&1; then
  ABS_PATH=$(realpath -m -- "$TARGET_PATH")
elif command -v readlink >/dev/null 2>&1 && readlink -f "$TARGET_PATH" >/dev/null 2>&1; then
  ABS_PATH=$(readlink -f -- "$TARGET_PATH")
else
  # Pure bash fallback
  if [ -d "$TARGET_PATH" ]; then
    ABS_PATH=$(cd -P -- "$TARGET_PATH" && pwd -P)
  else
    ABS_PATH=$(cd -P -- "$(dirname -- "$TARGET_PATH")" && printf '%s/%s\n' "$(pwd -P)" "$(basename -- "$TARGET_PATH")")
  fi
fi

add_syscheck_path() {
  local path="$1"
  local block="  <syscheck>
    <directories realtime=\"yes\">$path</directories>
  </syscheck>"
  insert_block_before_line "$block" "$CONF_SEARCH" "$CONF"
}
add_syscheck_path "$ABS_PATH"
systemctl restart wazuh-agent
