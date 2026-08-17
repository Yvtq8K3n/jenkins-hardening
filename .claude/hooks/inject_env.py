#!/usr/bin/env python3
"""
PreToolUse hook for Bash: injects .env credentials into every command.

Reads PreToolUse JSON from stdin, prepends 'source .env &&' to the command
if .env exists, and writes the updated JSON to stdout.
"""

import json
import sys
import os

data = json.load(sys.stdin)
cmd = data.get('tool_input', {}).get('command', '')

# Construct path to .env relative to this script's location
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '.env')

if os.path.exists(env_path):
    cmd = f'source {env_path} && ' + cmd

output = {
    'hookEventName': 'PreToolUse:Bash',
    'hookSpecificOutput': {
        'updatedInput': {
            'command': cmd
        }
    }
}

json.dump(output, sys.stdout)
