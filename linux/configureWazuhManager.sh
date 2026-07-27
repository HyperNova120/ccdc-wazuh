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

addActiveResponse() {
  local name="$1"
  local exe="$2"
  local ruleIDs="$3"
  
  if [[ -z "$name" || -z "$exe" || -z "$ruleIDs" ]]; then
    echo "Error: Missing arguments." >&2
    echo "Usage: addActiveResponse <name> <exe> <ruleIDs>" >&2
  }
  local block=" <command>
      <name>$name</name>
      <executable>$exe</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>

    <active-response>
      <disabled>no</disabled>
      <command>$name</command>
      <location>local</location>
      <rules_id>$ruleIDs</rules_id>
    </active-response>
  "

  insert_block_before_line "$block" "$CONF_SEARCH" "$CONF"
}

replace_string "$CONF" "<logall>no</logall>" "<logall>yes</logall>"
replace_string "$CONF" "<logall_json>no</logall_json>" "<logall_json>yes</logall_json>"
sed -i '/module: wazuh/,/^[^ ]/ s/enabled: false/enabled: true/' /etc/filebeat/filebeat.yml
