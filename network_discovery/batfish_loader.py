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

# No need for patches - using direct API calls
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
    
    # No patching needed - using direct API calls with correct port
    
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
        host_env = os.getenv("BATFISH_HOST", "batfish")
            
        logger.info(f"Connecting to Batfish at {host_env} on port 9996")
        
        # Initialize Session with proper host format and explicitly set port to 9996
        # The Session constructor internally adds http:// prefix
        bf = Session(host=host_env, port=9996)
        
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

def list_networks(batfish_host: str = "batfish") -> List[str]:
    """
    List all networks in Batfish.
    
    Args:
        batfish_host: Batfish host
        
    Returns:
        List[str]: List of network names
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot list networks.")
        return []
        
    try:
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish at {batfish_host} on port 9996")
        bf = Session(host=batfish_host, port=9996)
        
        # List networks
        networks = bf.list_networks()
        logger.info(f"Found {len(networks)} networks: {networks}")
        
        return networks
    except Exception as e:
        logger.error(f"Failed to list networks: {str(e)}", exc_info=True)
        return []

def list_snapshots(network_name: str, batfish_host: str = "batfish") -> List[str]:
    """
    List all snapshots in a network.
    
    Args:
        network_name: Network name
        batfish_host: Batfish host
        
    Returns:
        List[str]: List of snapshot names
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot list snapshots.")
        return []
        
    try:
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish at {batfish_host} on port 9996")
        bf = Session(host=batfish_host, port=9996)
        
        # Set network
        bf.set_network(network_name)
        
        # List snapshots
        snapshots = bf.list_snapshots()
        logger.info(f"Found {len(snapshots)} snapshots for network {network_name}: {snapshots}")
        
        return snapshots
    except Exception as e:
        logger.error(f"Failed to list snapshots: {str(e)}", exc_info=True)
        return []

def get_current_snapshot(network_name: str, batfish_host: str = "batfish") -> Optional[str]:
    """
    Get the current snapshot for a network.
    
    Args:
        network_name: Network name
        batfish_host: Batfish host
        
    Returns:
        Optional[str]: Current snapshot name or None if not set
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot get current snapshot.")
        return None
        
    try:
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish at {batfish_host} on port 9996")
        bf = Session(host=batfish_host, port=9996)
        
        # Set network
        bf.set_network(network_name)
        
        # Get current snapshot
        try:
            snapshot = bf.get_snapshot()
            logger.info(f"Current snapshot for network {network_name}: {snapshot}")
            return snapshot
        except ValueError:
            logger.info(f"No current snapshot set for network {network_name}")
            return None
    except Exception as e:
        logger.error(f"Failed to get current snapshot: {str(e)}", exc_info=True)
        return None

def delete_network(network_name: str, batfish_host: str = "batfish") -> bool:
    """
    Delete a network from Batfish.
    
    Args:
        network_name: Network name to delete
        batfish_host: Batfish host
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot delete network.")
        return False
        
    try:
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish at {batfish_host} on port 9996")
        bf = Session(host=batfish_host, port=9996)
        
        # Check if network exists
        networks = bf.list_networks()
        if network_name not in networks:
            logger.warning(f"Network {network_name} not found in Batfish")
            return False
        
        # Delete network
        bf.delete_network(network_name)
        logger.info(f"Deleted network {network_name}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to delete network: {str(e)}", exc_info=True)
        return False

def delete_all_networks(batfish_host: str = "batfish") -> Dict[str, Any]:
    """
    Delete all networks from Batfish.
    
    Args:
        batfish_host: Batfish host
        
    Returns:
        Dict: Result with deleted networks and status
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot delete networks.")
        return {"status": "failed", "error": "pybatfish module not available"}
        
    try:
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish at {batfish_host} on port 9996")
        bf = Session(host=batfish_host, port=9996)
        
        # Get list of networks
        networks = bf.list_networks()
        
        if not networks:
            logger.info("No networks found in Batfish")
            return {"status": "success", "message": "No networks found", "deleted": []}
        
        # Delete each network
        deleted_networks = []
        failed_networks = []
        
        for network in networks:
            try:
                bf.delete_network(network)
                deleted_networks.append(network)
                logger.info(f"Deleted network {network}")
            except Exception as e:
                failed_networks.append({"network": network, "error": str(e)})
                logger.error(f"Failed to delete network {network}: {str(e)}")
        
        result = {
            "status": "success" if not failed_networks else "partial",
            "deleted": deleted_networks,
        }
        
        if failed_networks:
            result["failed"] = failed_networks
            
        return result
    except Exception as e:
        logger.error(f"Failed to delete networks: {str(e)}", exc_info=True)
        return {"status": "failed", "error": str(e)}

def set_current_snapshot(network_name: str, snapshot_name: str, batfish_host: str = "batfish") -> bool:
    """
    Set the current snapshot for a network.
    
    Args:
        network_name: Network name
        snapshot_name: Snapshot name
        batfish_host: Batfish host
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not BATFISH_AVAILABLE:
        logger.error("pybatfish module not available. Cannot set current snapshot.")
        return False
        
    try:
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish at {batfish_host} on port 9996")
        bf = Session(host=batfish_host, port=9996)
        
        # Set network
        bf.set_network(network_name)
        
        # Set current snapshot
        bf.set_snapshot(snapshot_name)
        logger.info(f"Set current snapshot for network {network_name} to {snapshot_name}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to set current snapshot: {str(e)}", exc_info=True)
        return False

async def get_topology(network_name: str, batfish_host: str = "batfish", snapshot_name: str = "snapshot_latest") -> Dict:
    """
    Get the network topology from Batfish.
    
    Args:
        network_name: Network name (can be a job_id)
        batfish_host: Batfish host URL
        snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
        
    Returns:
        Dict: Topology with network_name and edges
    """
    if not BATFISH_AVAILABLE:
        error_msg = "pybatfish module not available. Cannot get topology."
        logger.error(error_msg)
        log_error(network_name, "batfish_loader", error_msg)
        return {
            "network_name": network_name,
            "status": "failed",
            "error": error_msg
        }
        
    try:
        # Override environment variable with parameter
        os.environ["BATFISH_HOST"] = batfish_host
        
        # This is a blocking operation, run it in a thread pool
        logger.info(f"Getting layer3 topology for network {network_name}, snapshot {snapshot_name}")
        loop = asyncio.get_event_loop()
        
        # Define the function to run in the thread pool
        def get_topology_data():
            # Initialize Batfish session
            host_env = batfish_host
            logger.info(f"Initializing Batfish session with host: {host_env} on port 9996")
            
            # Explicitly set port to 9996
            bf = Session(host=host_env, port=9996)
            
            # Check if network exists
            networks = bf.list_networks()
            if network_name not in networks:
                logger.warning(f"Network {network_name} not found in Batfish")
                return {"error": f"Network {network_name} not found in Batfish", "networks": networks}
            
            bf.set_network(network_name)
            
            # Check if snapshot exists
            snapshots = bf.list_snapshots()
            if snapshot_name not in snapshots and snapshot_name == "snapshot_latest":
                # If snapshot_latest doesn't exist but other snapshots do, use the first one
                if snapshots:
                    logger.info(f"Snapshot {snapshot_name} not found, using {snapshots[0]} instead")
                    snapshot_name_to_use = snapshots[0]
                else:
                    logger.warning(f"No snapshots found in network {network_name}")
                    return {"error": f"No snapshots found in network {network_name}", "snapshots": []}
            elif snapshot_name not in snapshots:
                logger.warning(f"Snapshot {snapshot_name} not found in network {network_name}")
                return {"error": f"Snapshot {snapshot_name} not found in network {network_name}", "snapshots": snapshots}
            else:
                snapshot_name_to_use = snapshot_name
            
            # Set the snapshot name - this is required before querying
            logger.info(f"Setting snapshot to: {snapshot_name_to_use}")
            bf.set_snapshot(snapshot_name_to_use)
            
            # Get edges using the Session API
            edges_df = bf.q.edges().answer().frame()
            
            # Convert Batfish Interface objects to strings to make them serializable
            if not edges_df.empty:
                if "Interface" in edges_df.columns:
                    edges_df["Interface"] = edges_df["Interface"].apply(lambda x: str(x) if x is not None else None)
                if "Remote_Interface" in edges_df.columns:
                    edges_df["Remote_Interface"] = edges_df["Remote_Interface"].apply(lambda x: str(x) if x is not None else None)
            
            # Convert to records
            return {
                "edges": edges_df.to_dict(orient="records"),
                "actual_snapshot": snapshot_name_to_use
            }
        
        # Execute the function in the thread pool
        result = await loop.run_in_executor(None, get_topology_data)
        
        # Check if there was an error
        if "error" in result:
            return {
                "network_name": network_name,
                "snapshot_name": snapshot_name,
                "status": "failed",
                "error": result["error"],
                "available": result.get("snapshots", result.get("networks", []))
            }
        
        return {
            "network_name": network_name,
            "snapshot_name": result.get("actual_snapshot", snapshot_name),
            "status": "success",
            "edges": result["edges"]
        }
    except Exception as e:
        error_msg = f"Failed to get topology: {str(e)}"
        logger.error(error_msg, exc_info=True)
        log_error(network_name, "batfish_loader", error_msg)
        
        return {
            "network_name": network_name,
            "snapshot_name": snapshot_name,
            "status": "failed",
            "error": str(e)
        }