"""Utilities for atomic file operations with artifacts."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

from network_discovery.config import get_job_dir

logger = logging.getLogger(__name__)

def atomic_write_json(data: Dict[str, Any], filepath: Union[str, Path]) -> bool:
    """
    Write JSON data atomically to a file.
    
    Args:
        data: Dictionary to serialize as JSON
        filepath: Target file path
        
    Returns:
        bool: True if successful, False otherwise
    """
    filepath = Path(filepath)
    tmp_path = filepath.with_suffix(f"{filepath.suffix}.tmp")
    
    try:
        # Write to temporary file first
        with open(tmp_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Atomic rename
        tmp_path.rename(filepath)
        logger.info(f"Successfully wrote {filepath}")
        return True
    except Exception as e:
        logger.error(f"Failed to write {filepath}: {str(e)}")
        return False

def read_json(filepath: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """
    Read JSON data from a file.
    
    Args:
        filepath: File path to read
        
    Returns:
        Dict or None: Parsed JSON data, or None if file doesn't exist or is invalid
    """
    filepath = Path(filepath)
    
    try:
        if not filepath.exists():
            logger.warning(f"File not found: {filepath}")
            return None
            
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to read {filepath}: {str(e)}")
        return None

def update_status(job_id: str, module: str, status: str, **kwargs) -> bool:
    """
    Update the status.json file for a job.
    
    Args:
        job_id: Job identifier
        module: Module name (e.g., 'seeder', 'scanner')
        status: Status string (e.g., 'running', 'completed', 'failed')
        **kwargs: Additional status information
        
    Returns:
        bool: True if successful, False otherwise
    """
    job_dir = get_job_dir(job_id)
    status_path = job_dir / "status.json"
    
    # Read existing status if available
    current_status = read_json(status_path) or {"job_id": job_id}
    
    # Update with new information
    module_status = {
        "status": status,
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }
    module_status.update(kwargs)
    
    current_status[module] = module_status
    
    return atomic_write_json(current_status, status_path)

def get_targets_path(job_id: str) -> Path:
    """Get the path to the targets.json file for a job."""
    return get_job_dir(job_id) / "targets.json"

def get_scan_path(job_id: str) -> Path:
    """Get the path to the ip_scan.json file for a job."""
    return get_job_dir(job_id) / "ip_scan.json"

def get_reachable_hosts_path(job_id: str) -> Path:
    """Get the path to the reachable_hosts.json file for a job."""
    return get_job_dir(job_id) / "reachable_hosts.json"

def get_device_state_path(job_id: str, hostname: str) -> Path:
    """
    Get the path to a device state file.
    
    Sanitizes the hostname to create a valid filename by replacing
    invalid characters like ':' with '_'.
    """
    # Sanitize hostname for use as a filename
    safe_hostname = hostname.replace(":", "_").replace("/", "_")
    
    # Ensure device_states directory exists
    device_states_dir = get_job_dir(job_id) / "device_states"
    device_states_dir.mkdir(parents=True, exist_ok=True)
    
    return device_states_dir / f"{safe_hostname}.json"

def log_error(job_id: str, module: str, error_msg: str, details: Optional[Dict] = None) -> bool:
    """
    Log an error to the error.json file.
    
    Args:
        job_id: Job identifier
        module: Module name (e.g., 'seeder', 'scanner')
        error_msg: Error message
        details: Additional error details
        
    Returns:
        bool: True if successful, False otherwise
    """
    job_dir = get_job_dir(job_id)
    error_path = job_dir / "error.json"
    
    # Read existing errors if available
    current_errors = read_json(error_path) or {"job_id": job_id, "errors": []}
    
    # Add new error
    error_entry = {
        "module": module,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": error_msg
    }
    
    if details:
        error_entry["details"] = details
        
    current_errors["errors"].append(error_entry)
    
    return atomic_write_json(current_errors, error_path)
