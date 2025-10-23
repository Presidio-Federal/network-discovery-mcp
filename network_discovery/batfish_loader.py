"""
Batfish loader module for network analysis.

This module loads Batfish snapshots from collected device configurations
and analyzes them using a Batfish instance.
"""

import asyncio
import logging
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests

# Import system modules needed for error reporting
import sys
import traceback

# Import our pybatfish patch
from network_discovery.pybatfish_patch import apply_patches
# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Try to import pybatfish, but don't fail if it's not available
BATFISH_AVAILABLE = False
try:
    # First try direct import
    import pybatfish
    
    # Then try to import using the modern Session API
    from pybatfish.client.session import Session
    
    # Apply our patches to fix URL construction
    apply_patches()
    
    # If we get here, everything imported successfully
    BATFISH_AVAILABLE = True
    logger.info(f"Successfully imported pybatfish version {pybatfish.__version__}")
    
except ImportError as e:
    error_msg = f"pybatfish module not available: {str(e)}"
    logger.error(error_msg)
    logger.error(f"Python path: {sys.path}")
    logger.error(f"Python version: {sys.version}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    
    # Try to get list of installed packages
    try:
        import subprocess
        result = subprocess.run(['pip', 'list'], capture_output=True, text=True)
        logger.error(f"Installed packages: {result.stdout}")
    except Exception as pkg_e:
        logger.error(f"Failed to list installed packages: {str(pkg_e)}")
        
except Exception as e:
    error_msg = f"Error importing pybatfish: {str(e)}"
    logger.error(error_msg)
    logger.error(f"Traceback: {traceback.format_exc()}")

from network_discovery.artifacts import (
    atomic_write_json,
    get_job_dir,
    log_error,
    read_json,
    update_status,
)
from network_discovery.config import DEFAULT_CONCURRENCY

logger = logging.getLogger(__name__)

async def build_batfish_snapshot(job_id: str) -> Dict:
    """
    Verify that the Batfish snapshot is ready.
    
    This function is kept for API compatibility, but now only verifies
    that the config files exist since they are written directly by
    the config_collector module.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Build results with job_id and status
    """
    try:
        # Get job directory
        job_dir = get_job_dir(job_id)
        
        # Check if batfish_snapshot/configs directory exists
        configs_dir = job_dir / "batfish_snapshot" / "configs"
        
        if not configs_dir.exists() or not configs_dir.is_dir():
            error_msg = f"Batfish configs directory not found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "batfish_loader", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Count config files
        config_files = list(configs_dir.glob("*.cfg"))
        device_count = len(config_files)
        
        if device_count == 0:
            error_msg = f"No config files found in batfish_snapshot/configs for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "batfish_loader", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Update status to built
        update_status(
            job_id,
            "batfish_loader",
            "built",
            snapshot_dir="batfish_snapshot/configs",
            device_count=device_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "built",
            "snapshot_dir": "batfish_snapshot/configs",
            "device_count": device_count
        }
    except Exception as e:
        error_msg = f"Failed to verify Batfish snapshot: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "batfish_loader", error_msg)
        
        # Update status to failed
        update_status(
            job_id,
            "batfish_loader",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }

def init_batfish(job_id: str, snapshot_path: str) -> Optional[Session]:
    """
    Initialize a Batfish Session, set the network, and load the snapshot.
    
    Args:
        job_id: Job identifier
        snapshot_path: Path to the snapshot directory
        
    Returns:
        Session: Initialized Batfish Session object or None if initialization fails
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot initialize Batfish session.")
        return None
        
    try:
        # Get Batfish host from environment or use default
        # Use just the hostname without port - pybatfish will use default ports
        host_env = os.getenv("BATFISH_HOST", "batfish")
            
        logger.info(f"Connecting to Batfish at {host_env}")
        
        # Initialize Session with proper host format
        # The Session constructor internally adds http:// prefix and uses default ports
        bf = Session(host=host_env)
        
        # Set network and initialize snapshot
        bf.set_network(job_id)
        bf.init_snapshot(snapshot_path, name="snapshot_latest", overwrite=True)
        
        logger.info("Batfish snapshot initialized successfully.")
        return bf
    except Exception as e:
        logger.error(f"Batfish initialization failed: {e}", exc_info=True)
        return None

async def load_batfish_snapshot(job_id: str, batfish_host: str = "batfish") -> Dict:
    """
    Load a Batfish snapshot into a Batfish instance.
    
    Args:
        job_id: Job identifier
        batfish_host: Batfish host URL
        
    Returns:
        Dict: Load results with job_id and status
    """
    import sys
    import traceback
    
    if not BATFISH_AVAILABLE:
        error_msg = "pybatfish module not available. Cannot load snapshot."
        logger.error(error_msg)
        logger.error(f"Python path: {sys.path}")
        logger.error(f"Python version: {sys.version}")
        logger.error(f"Installed packages: {os.popen('pip list').read()}")
        log_error(job_id, "batfish_loader", error_msg)
        return {
            "job_id": job_id,
            "status": "failed",
            "error": error_msg
        }
        
    try:
        # Get job directory
        job_dir = get_job_dir(job_id)
        logger.info(f"Job directory: {job_dir}")
        
        # Check if snapshot exists
        snapshot_dir = job_dir / "batfish_snapshot"
        logger.info(f"Snapshot directory: {snapshot_dir}")
        
        if not snapshot_dir.exists() or not snapshot_dir.is_dir():
            error_msg = f"Snapshot directory not found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "batfish_loader", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Check if configs directory exists
        configs_dir = snapshot_dir / "configs"
        logger.info(f"Configs directory: {configs_dir}")
        
        if not configs_dir.exists() or not configs_dir.is_dir():
            error_msg = f"Configs directory not found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "batfish_loader", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Count config files
        config_files = list(configs_dir.glob("*.cfg"))
        logger.info(f"Found {len(config_files)} config files")
        
        if len(config_files) == 0:
            error_msg = f"No config files found in {configs_dir}"
            logger.error(error_msg)
            log_error(job_id, "batfish_loader", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Update status to loading
        update_status(
            job_id,
            "batfish_loader",
            "loading",
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Override environment variable with parameter
        os.environ["BATFISH_HOST"] = batfish_host
        
        # This is a blocking operation, run it in a thread pool
        logger.info(f"Initializing Batfish snapshot from {snapshot_dir}")
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: init_batfish(job_id, str(snapshot_dir))
            )
            logger.info("Batfish snapshot initialized successfully")
        except Exception as e:
            error_msg = f"Failed to initialize Batfish snapshot: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            raise
        
        snapshot_name = "snapshot_latest"
        
        # Update status to loaded
        update_status(
            job_id,
            "batfish_loader",
            "loaded",
            snapshot=snapshot_name,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "loaded",
            "snapshot": snapshot_name
        }
    except Exception as e:
        error_msg = f"Failed to load Batfish snapshot: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        log_error(job_id, "batfish_loader", error_msg)
        
        # Update status to failed
        update_status(
            job_id,
            "batfish_loader",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }

async def get_topology(job_id: str, batfish_host: str = "batfish") -> Dict:
    """
    Get the network topology from Batfish.
    
    Args:
        job_id: Job identifier
        batfish_host: Batfish host URL
        
    Returns:
        Dict: Topology with job_id and edges
    """
    if not BATFISH_AVAILABLE:
        error_msg = "pybatfish module not available. Cannot get topology."
        logger.error(error_msg)
        log_error(job_id, "batfish_loader", error_msg)
        return {
            "job_id": job_id,
            "status": "failed",
            "error": error_msg
        }
        
    try:
        # Override environment variable with parameter
        os.environ["BATFISH_HOST"] = batfish_host
        
        # This is a blocking operation, run it in a thread pool
        logger.info(f"Getting layer3 topology for job {job_id}")
        loop = asyncio.get_event_loop()
        
        # Define the function to run in the thread pool
        def get_topology_data():
            # Initialize Batfish session
            # Use just the hostname without port - pybatfish will use default ports
            host_env = batfish_host
            logger.info(f"Initializing Batfish session with host: {host_env}")
            
            bf = Session(host=host_env)
            bf.set_network(job_id)
            
            # Get edges using the Session API
            edges_df = bf.q.edges().answer().frame()
            
            # Convert to records
            return edges_df.to_dict(orient="records")
        
        # Execute the function in the thread pool
        edges = await loop.run_in_executor(None, get_topology_data)
        
        return {
            "job_id": job_id,
            "status": "success",
            "edges": edges
        }
    except Exception as e:
        error_msg = f"Failed to get topology: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_error(job_id, "batfish_loader", error_msg)
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }