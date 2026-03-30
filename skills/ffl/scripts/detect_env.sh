#!/bin/bash
# ffl environment detection script
# Run this first thing to determine how to help the user.
#
# Output lines (always present):
#   FFL_INSTALLED=0|1
#   SANDBOX=0|1
#   ADVICE=<one of: use_mcp | run_cli | give_command_sandbox | install_then_run>
#
# ADVICE meanings:
#   use_mcp            - ffl-mcp MCP tools detected in tool list (Claude should use them directly)
#   run_cli            - ffl CLI is installed and reachable; Claude can run commands in shell
#   give_command_sandbox - sandboxed shell, no ffl; give user the command to run on their machine
#   install_then_run   - open network, ffl just not installed; install it then run

FFL_INSTALLED=0
SANDBOX=0

# Check if ffl CLI is available
if command -v ffl >/dev/null 2>&1; then
    FFL_INSTALLED=1
fi

# Sandbox detection: try to reach fastfilelink.com (blocked in sandboxed shells)
HTTP_CODE=$(curl -s --connect-timeout 3 --max-time 4 \
    https://fastfilelink.com/ -o /dev/null -w "%{http_code}" 2>/dev/null)

if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then
    SANDBOX=1
fi

echo "FFL_INSTALLED=$FFL_INSTALLED"
echo "SANDBOX=$SANDBOX"

# Recommend advice (MCP check is done by Claude looking at its tool list)
if [ "$FFL_INSTALLED" = "1" ]; then
    echo "ADVICE=run_cli"
elif [ "$SANDBOX" = "0" ]; then
    echo "ADVICE=install_then_run"
else
    echo "ADVICE=give_command_sandbox"
fi
