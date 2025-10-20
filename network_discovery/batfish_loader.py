"""
Batfish loader module for network analysis.

This module builds Batfish snapshots from collected device configurations
and loads them into a Batfish instance for analysis.
"""

import asyncio
import logging
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests
from pybatfish.client.commands import (
    bf_init_snapshot,
    bf_set_network,
    bf_session
)
from pybatfish.question import bfq

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
    Build a Batfish snapshot from collected device configurations.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Build results with job_id and status
    """
    try:
        # Get job directory
        job_dir = get_job_dir(job_id)
        
        # Get state directory
        state_dir = job_dir / "state"
        
        if not state_dir.exists() or not state_dir.is_dir():
            error_msg = f"State directory not found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "batfish_loader", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Create batfish_snapshot directory structure
        snapshot_dir = job_dir / "batfish_snapshot"
        configs_dir = snapshot_dir / "configs"
        configs_dir.mkdir(parents=True, exist_ok=True)
        
        # Update status to building
        update_status(
            job_id,
            "batfish_loader",
            "building",
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Process each state file
        device_count = 0
        
        for state_file in state_dir.glob("*.json"):
            try:
                # Read state file
                state_data = read_json(state_file)
                
                if not state_data or "running_config" not in state_data:
                    logger.warning(f"No running config found in {state_file}")
                    continue
                
                # Extract hostname and running config
                hostname = state_data.get("hostname", state_file.stem)
                running_config = state_data.get("running_config", "")
                
                if not running_config:
                    logger.warning(f"Empty running config for {hostname}")
                    continue
                
                # Write config file
                config_file = configs_dir / f"{hostname}.cfg"
                with open(config_file, "w") as f:
                    f.write(running_config)
                
                device_count += 1
                logger.info(f"Wrote config for {hostname}")
                
            except Exception as e:
                logger.error(f"Error processing {state_file}: {str(e)}")
        
        if device_count == 0:
            error_msg = f"No valid device configurations found for job {job_id}"
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
        error_msg = f"Failed to build Batfish snapshot: {str(e)}"
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
