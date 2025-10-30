#!/bin/bash
set -e

echo "Starting FastMCP directly on port 8080..."
export PORT=8080
export HOST=0.0.0.0
export FASTMCP_BEHIND_PROXY=false

if [ "$ENABLE_MCP" = "true" ]; then
    echo "Running in MCP mode"
else
    echo "Running in API mode"
fi

exec python -m network_discovery
