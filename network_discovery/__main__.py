"""
Network Discovery Service - Main Entry Point

This module serves as the main entry point for the Network Discovery Service.
It can run in either FastAPI mode or MCP mode based on environment variables.
Includes graceful shutdown handling for both modes.
"""

import os
import sys
import logging
import signal
import uvicorn
import asyncio
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global flag for shutdown
shutdown_event = asyncio.Event()

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    signal_name = signal.Signals(signum).name
    logger.info(f"Received signal {signal_name}, initiating graceful shutdown...")
    shutdown_event.set()

def setup_signal_handlers():
    """Set up signal handlers for graceful shutdown."""
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    logger.info("Signal handlers registered for graceful shutdown")

def main():
    """Main entry point for the application."""
    # Set up signal handlers
    setup_signal_handlers()
    
    # Get configuration from environment
    enable_mcp = os.getenv("ENABLE_MCP", "false").lower() in ("true", "1", "yes")
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    transport = os.getenv("TRANSPORT", "http").lower()
    base_path = os.getenv("BASE_PATH", "")
    
    if enable_mcp:
        logger.info("Starting Network Discovery Service in MCP mode")
        from network_discovery.mcp_server import main as mcp_main
        try:
            mcp_main(base_path=base_path)
        except KeyboardInterrupt:
            logger.info("MCP server stopped by user")
        except Exception as e:
            logger.error(f"MCP server error: {e}")
            sys.exit(1)
    else:
        logger.info("Starting Network Discovery Service in FastAPI mode")
        from network_discovery.api import app
        
        # Configure uvicorn to handle shutdown gracefully
        config = uvicorn.Config(
            app, 
            host=host, 
            port=port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        
        try:
            server.run()
        except KeyboardInterrupt:
            logger.info("FastAPI server stopped by user")
        except Exception as e:
            logger.error(f"FastAPI server error: {e}")
            sys.exit(1)
        finally:
            logger.info("Server shutdown complete")

if __name__ == "__main__":
    main()
