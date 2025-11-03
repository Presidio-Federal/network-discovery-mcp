"""
Asynchronous task orchestration for network discovery.

This module provides background task execution for seeder, scanner, and fingerprinter operations.
"""

import asyncio
import logging
import os
import uuid
from typing import Dict, List, Optional

from network_discovery.scanner import add_subnets, scan_from_subnets, scan_from_targets
from network_discovery.seeder import collect_seed
from network_discovery.fingerprinter import fingerprint_job
from network_discovery.config_collector import collect_all_state, collect_single_state
from network_discovery.batfish_loader import build_batfish_snapshot, load_batfish_snapshot, get_topology

logger = logging.getLogger(__name__)

# Dictionary to track running tasks
_running_tasks: Dict[str, asyncio.Task] = {}

async def start_seeder(
    seed_host: str,
    creds: Dict,
    job_id: Optional[str] = None,
    methods: Optional[List[str]] = None
) -> Dict:
    """
    Start a seeder task in the background.
    
    Args:
        seed_host: Hostname or IP of the seed device
        creds: Dictionary with authentication credentials
        job_id: Optional job identifier (generated if not provided)
        methods: List of collection methods to use
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Generate job_id if not provided
    if not job_id:
        job_id = str(uuid.uuid4())
    
    # Create and start the task
    task = asyncio.create_task(_run_seeder(seed_host, creds, job_id, methods))
    _running_tasks[job_id] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Seeding started from {seed_host}"
    }

async def start_scanner(
    job_id: str,
    targets_path: Optional[str] = None,
    ports: Optional[List[int]] = None,
    concurrency: Optional[int] = None
) -> Dict:
    """
    Start a scanner task in the background.
    
    Args:
        job_id: Job identifier
        targets_path: Path to targets.json file
        ports: List of ports to scan
        concurrency: Maximum concurrent scans
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_scanner(job_id, targets_path, ports, concurrency))
    _running_tasks[job_id] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Scan started for job {job_id}"
    }

async def start_subnet_scanner(
    job_id: str,
    subnets: List[str],
    ports: Optional[List[int]] = None,
    concurrency: Optional[int] = None
) -> Dict:
    """
    Start a scanner task for specific subnets in the background.
    
    Args:
        job_id: Job identifier
        subnets: List of subnets to scan
        ports: List of ports to scan
        concurrency: Maximum concurrent scans
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_subnet_scanner(job_id, subnets, ports, concurrency))
    _running_tasks[job_id] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Subnet scan started for job {job_id}"
    }

async def start_add_subnets(job_id: str, subnets: List[str]) -> Dict:
    """
    Start a task to add subnets to an existing job.
    
    Args:
        job_id: Job identifier
        subnets: List of subnets to add
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_add_subnets(job_id, subnets))
    _running_tasks[f"{job_id}_add_subnets"] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Adding subnets to job {job_id}"
    }

def get_task_status(job_id: str) -> Dict:
    """
    Get the status of a task.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Task status information
    """
    task = _running_tasks.get(job_id)
    
    if not task:
        return {"job_id": job_id, "status": "unknown"}
    
    if task.done():
        try:
            result = task.result()
            return {"job_id": job_id, "status": "completed", "result": result}
        except Exception as e:
            return {"job_id": job_id, "status": "failed", "error": str(e)}
    else:
        return {"job_id": job_id, "status": "running"}

async def _run_seeder(
    seed_host: str,
    creds: Dict,
    job_id: str,
    methods: Optional[List[str]] = None
) -> Dict:
    """Run the seeder function."""
    try:
        return collect_seed(seed_host, creds, job_id, methods)
    except Exception as e:
        logger.error(f"Seeder task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(job_id, None)

async def _run_scanner(
    job_id: str,
    targets_path: Optional[str],
    ports: Optional[List[int]],
    concurrency: Optional[int]
) -> Dict:
    """Run the scanner function."""
    try:
        return await scan_from_targets(job_id, targets_path, ports, concurrency or 200)
    except Exception as e:
        logger.error(f"Scanner task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(job_id, None)

async def _run_subnet_scanner(
    job_id: str,
    subnets: List[str],
    ports: Optional[List[int]],
    concurrency: Optional[int]
) -> Dict:
    """Run the subnet scanner function."""
    try:
        return await scan_from_subnets(job_id, subnets, ports, concurrency or 200)
    except Exception as e:
        logger.error(f"Subnet scanner task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(job_id, None)

async def _run_add_subnets(job_id: str, subnets: List[str]) -> Dict:
    """Run the add_subnets function."""
    try:
        return await add_subnets(job_id, subnets)
    except Exception as e:
        logger.error(f"Add subnets task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(f"{job_id}_add_subnets", None)

async def start_fingerprinter(
    job_id: str,
    snmp_community: Optional[str] = None,
    concurrency: Optional[int] = None
) -> Dict:
    """
    Start a fingerprinter task in the background.
    
    Args:
        job_id: Job identifier
        snmp_community: Optional SNMP community string
        concurrency: Maximum concurrent fingerprinting operations
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_fingerprinter(job_id, snmp_community, concurrency))
    _running_tasks[f"{job_id}_fingerprinter"] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Fingerprinting started for job {job_id}"
    }

async def _run_fingerprinter(
    job_id: str,
    snmp_community: Optional[str],
    concurrency: Optional[int]
) -> Dict:
    """Run the fingerprinter function."""
    try:
        return await fingerprint_job(job_id, snmp_community, concurrency or 100)
    except Exception as e:
        logger.error(f"Fingerprinter task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(f"{job_id}_fingerprinter", None)

async def start_state_collector(
    job_id: str,
    creds: Dict,
    concurrency: Optional[int] = None
) -> Dict:
    """
    Start a state collector task in the background.
    
    Args:
        job_id: Job identifier
        creds: Dictionary with authentication credentials
        concurrency: Maximum concurrent connections
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_state_collector(job_id, creds, concurrency))
    _running_tasks[f"{job_id}_state_collector"] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"State collection started for job {job_id}"
    }

async def start_device_state_update(
    job_id: str,
    hostname: str,
    creds: Dict
) -> Dict:
    """
    Start a task to update a single device's state.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        creds: Dictionary with authentication credentials
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_device_state_update(job_id, hostname, creds))
    _running_tasks[f"{job_id}_device_update_{hostname}"] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"State update started for device {hostname}"
    }

async def _run_state_collector(
    job_id: str,
    creds: Dict,
    concurrency: Optional[int]
) -> Dict:
    """Run the state collector function."""
    try:
        return await collect_all_state(job_id, creds, concurrency or 25)
    except Exception as e:
        logger.error(f"State collector task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(f"{job_id}_state_collector", None)

async def _run_device_state_update(
    job_id: str,
    hostname: str,
    creds: Dict
) -> Dict:
    """Run the device state update function."""
    try:
        return await collect_single_state(job_id, creds, hostname)
    except Exception as e:
        logger.error(f"Device state update task failed for {hostname}: {str(e)}")
        return {"job_id": job_id, "status": "failed", "device_updated": hostname, "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(f"{job_id}_device_update_{hostname}", None)

async def start_batfish_snapshot_build(
    job_id: str
) -> Dict:
    """
    Start a Batfish snapshot build task in the background.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_batfish_snapshot_build(job_id))
    _running_tasks[f"{job_id}_batfish_build"] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Batfish snapshot build started for job {job_id}"
    }

async def start_batfish_snapshot_load(
    job_id: str,
    batfish_host: Optional[str] = None
) -> Dict:
    """
    Start a Batfish snapshot load task in the background.
    
    Args:
        job_id: Job identifier
        batfish_host: Batfish host URL
        
    Returns:
        Dict: Task information with job_id and status
    """
    # Create and start the task
    task = asyncio.create_task(_run_batfish_snapshot_load(job_id, batfish_host))
    _running_tasks[f"{job_id}_batfish_load"] = task
    
    return {
        "job_id": job_id,
        "status": "running",
        "message": f"Batfish snapshot load started for job {job_id}"
    }

async def _run_batfish_snapshot_build(
    job_id: str
) -> Dict:
    """Run the Batfish snapshot build function."""
    try:
        return await build_batfish_snapshot(job_id)
    except Exception as e:
        logger.error(f"Batfish snapshot build task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(f"{job_id}_batfish_build", None)

async def _run_batfish_snapshot_load(
    job_id: str,
    batfish_host: Optional[str]
) -> Dict:
    """Run the Batfish snapshot load function."""
    try:
        # Use environment variable if provided, otherwise use default
        host = batfish_host or os.environ.get("BATFISH_HOST", "http://batfish:9997")
        return await load_batfish_snapshot(job_id, host)
    except Exception as e:
        logger.error(f"Batfish snapshot load task failed: {str(e)}")
        return {"job_id": job_id, "status": "failed", "error": str(e)}
    finally:
        # Remove the task from running tasks
        _running_tasks.pop(f"{job_id}_batfish_load", None)

async def get_batfish_topology(
    network_name: str,
    batfish_host: Optional[str] = None,
    snapshot_name: Optional[str] = None
) -> Dict:
    """
    Get the network topology from Batfish.
    
    Args:
        network_name: Batfish network name (can be a job_id)
        batfish_host: Batfish host URL
        snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
        
    Returns:
        Dict: Topology with network_name and edges
    """
    try:
        # Use environment variable if provided, otherwise use default
        host = batfish_host or os.environ.get("BATFISH_HOST", "http://batfish:9997")
        actual_snapshot = snapshot_name or "snapshot_latest"
        
        return await get_topology(network_name, host, snapshot_name=actual_snapshot)
    except Exception as e:
        logger.error(f"Batfish topology retrieval failed: {str(e)}")
        return {"network_name": network_name, "status": "failed", "error": str(e)}
