"""
Configuration module for network discovery.

This module handles configuration settings for the network discovery service.
"""

import os
import logging
from pathlib import Path
from typing import List

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Set specific loggers to DEBUG level
logging.getLogger('network_discovery.seeder').setLevel(logging.DEBUG)
logging.getLogger('network_discovery.scanner').setLevel(logging.DEBUG)
logging.getLogger('network_discovery.artifacts').setLevel(logging.DEBUG)
logging.getLogger('network_discovery.workers').setLevel(logging.DEBUG)
logging.getLogger('network_discovery.fingerprinter').setLevel(logging.DEBUG)
logging.getLogger('network_discovery.config_collector').setLevel(logging.DEBUG)
logging.getLogger('network_discovery.batfish_loader').setLevel(logging.DEBUG)

# Disable noisy third-party loggers
logging.getLogger('paramiko').setLevel(logging.WARNING)
logging.getLogger('netmiko').setLevel(logging.WARNING)
logging.getLogger('nornir').setLevel(logging.WARNING)

# Environment variables
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "/tmp/network_discovery_artifacts")
DEFAULT_PORTS = [int(p) for p in os.environ.get("DEFAULT_PORTS", "22").split(",")]  # Default to SSH only for speed
DEFAULT_CONCURRENCY = int(os.environ.get("DEFAULT_CONCURRENCY", "200"))
DEFAULT_CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "1.5"))
# Also define CONNECT_TIMEOUT for backward compatibility
CONNECT_TIMEOUT = DEFAULT_CONNECT_TIMEOUT
DEFAULT_SEEDER_METHODS = ["interfaces", "routing", "arp", "cdp", "lldp"]

def get_job_dir(job_id: str) -> Path:
    """
    Get the path to the job directory.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to job directory
    """
    job_dir = Path(ARTIFACT_DIR) / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    return job_dir

def get_device_states_dir(job_id: str) -> Path:
    """
    Get the path to the device states directory.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to device states directory
    """
    device_states_dir = get_job_dir(job_id) / "device_states"
    device_states_dir.mkdir(parents=True, exist_ok=True)
    return device_states_dir