#!/usr/bin/python3
# Copyright (C) 2015-2026, Wazuh Inc.
# Modified for automated Linux account locking on creation/trigger.

import os
import sys
import json
import datetime
import subprocess
from pathlib import PureWindowsPath, PurePosixPath
import platform

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
elif platform.system() == 'Darwin':
    LOG_FILE = "/Library/Ossec/logs/active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3
OS_SUCCESS = 0
OS_INVALID = -1


class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(
            ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime(
            '%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg + "\n")


def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(
            argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data
    command = data.get("command")

    if command == "add":
        message.command = ADD_COMMAND
    elif command == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({"version": 1, "origin": {
                          "name": argv[0], "module": "active-response"}, "command": "check_keys", "parameters": {"keys": keys}})
    write_debug_file(argv[0], keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(
            argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):
    write_debug_file(argv[0], "Started")

    msg = setup_and_check_message(argv)
    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        # Extract user information from alert data fields (adjust path based on your user-creation rule decoder)
        alert = msg.alert["parameters"]["alert"]

        # Example: pulling target username from data fields or parsing full_log.
        # Adjust 'dstuser' or 'user' depending on how your Wazuh decoder logs user creation.
        username = alert.get("data", {}).get(
            "dstuser") or alert.get("data", {}).get("user")

        if not username:
            write_debug_file(
                argv[0], "Error: Could not extract target username from alert.")
            sys.exit(OS_INVALID)

        keys = [username]

        action = send_keys_and_check_message(argv, keys)

        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        # Custom Action Add: Lock the Linux user account instantly
        try:
            subprocess.run(["passwd", "-l", username], check=True)
            write_debug_file(
                argv[0], f"Successfully locked user account: {username}")
        except subprocess.CalledProcessError as e:
            write_debug_file(argv[0], f"Failed to lock user {
                             username}: {str(e)}")

    elif msg.command == DELETE_COMMAND:
        # Custom Action Delete (Optional stateful rollback: unlocks account when timeout expires)
        alert = msg.alert["parameters"]["alert"]
        username = alert.get("data", {}).get(
            "dstuser") or alert.get("data", {}).get("user")

        if username:
            try:
                subprocess.run(["passwd", "-u", username], check=True)
                write_debug_file(
                    argv[0], f"Unlocked user account (timeout expired): {username}")
            except subprocess.CalledProcessError as e:
                write_debug_file(argv[0], f"Failed to unlock user {
                                 username}: {str(e)}")

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
