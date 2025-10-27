#!/bin/bash
set -e

# Start nginx in the background
echo "Starting nginx with SSL on port 8000..."
nginx

# Start the FastMCP server on internal port 8080
echo "Starting server on internal port 8080..."
# Override the environment variables for the internal server
export PORT=8080
export HOST=127.0.0.1

# Make sure FastMCP knows it's behind a proxy
export FASTMCP_BEHIND_PROXY=true

# Check if we're running in API or MCP mode
if [ "$ENABLE_MCP" = "true" ]; then
    echo "Running in MCP mode"
else
    echo "Running in API mode"
fi

# Execute the server in the foreground
exec python -m network_discovery
