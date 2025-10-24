"""
Network Discovery Service - Main Entry Point

This module serves as the main entry point for the Network Discovery Service.
It can run in either FastAPI mode or MCP mode based on environment variables.
"""

import os
import sys
import logging
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main entry point for the application."""
    # Get configuration from environment
    enable_mcp = os.getenv("ENABLE_MCP", "false").lower() in ("true", "1", "yes")
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    transport = os.getenv("TRANSPORT", "http").lower()
    base_path = os.getenv("BASE_PATH", "")
    
    if enable_mcp:
        logger.info("Starting Network Discovery Service in MCP mode")
        from network_discovery.mcp_server import main as mcp_main
        mcp_main(base_path=base_path)
    else:
        logger.info("Starting Network Discovery Service in FastAPI mode")
        from network_discovery.api import app
        uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()
