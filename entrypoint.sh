#!/bin/bash
set -e

CERT_FILE="/certs/fullchain.pem"
KEY_FILE="/certs/privkey.pem"

if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    echo "Certificates found — starting Nginx with HTTPS..."
    nginx
    export PORT=8080
    export HOST=127.0.0.1
    export FASTMCP_BEHIND_PROXY=true
else
    echo "No certificates found — running FastMCP in HTTP mode on :8080"
    export PORT=8080
    export HOST=0.0.0.0
    export FASTMCP_BEHIND_PROXY=false
fi

if [ "$ENABLE_MCP" = "true" ]; then
    echo "Running in MCP mode"
else
    echo "Running in API mode"
fi

exec python -m network_discovery
