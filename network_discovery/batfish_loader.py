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

# Try to import pybatfish, but don't fail if it's not available
try:
    from pybatfish.client.commands import (
        bf_init_snapshot,
        bf_set_network,
        bf_session
    )
    from pybatfish.question import bfq
    BATFISH_AVAILABLE = True
except ImportError:
    BATFISH_AVAILABLE = False
    logging.warning("pybatfish module not available. Batfish functionality will be limited.")

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

async def load_batfish_snapshot(job_id: str, batfish_host: str = "http://batfish:9997") -> Dict:
    """
    Load a Batfish snapshot into a Batfish instance.
    
    Args:
        job_id: Job identifier
        batfish_host: Batfish host URL
        
    Returns:
        Dict: Load results with job_id and status
    """
    if not BATFISH_AVAILABLE:
        error_msg = "pybatfish module not available. Cannot load snapshot."
        logger.error(error_msg)
        log_error(job_id, "batfish_loader", error_msg)
        return {
            "job_id": job_id,
            "status": "failed",
            "error": error_msg
        }
        
    try:
        # Get job directory
        job_dir = get_job_dir(job_id)
        
        # Check if snapshot exists
        snapshot_dir = job_dir / "batfish_snapshot"
        
        if not snapshot_dir.exists() or not snapshot_dir.is_dir():
            error_msg = f"Snapshot directory not found for job {job_id}"
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
        
        # Configure Batfish session
        bf_session.host = batfish_host
        
        # Set network and initialize snapshot
        bf_set_network(job_id)
        snapshot_name = "snapshot_latest"
        
        # This is a blocking operation, run it in a thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: bf_init_snapshot(str(snapshot_dir), name=snapshot_name, overwrite=True)
        )
        
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

async def get_topology(job_id: str, batfish_host: str = "http://batfish:9997") -> Dict:
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
        # Configure Batfish session
        bf_session.host = batfish_host
        
        # Set network
        bf_set_network(job_id)
        
        # Get edges
        # This is a blocking operation, run it in a thread pool
        loop = asyncio.get_event_loop()
        edges_df = await loop.run_in_executor(
            None,
            lambda: bfq.edges().answer().frame()
        )
        
        # Convert to records
        edges = edges_df.to_dict(orient="records")
        
        return {
            "job_id": job_id,
            "edges": edges
        }
    except Exception as e:
        error_msg = f"Failed to get topology: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "batfish_loader", error_msg)
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }