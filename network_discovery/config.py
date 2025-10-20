"""Configuration settings for the network discovery service."""

import os
from pathlib import Path
from typing import List

# Artifact storage
ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "/tmp/network_discovery_artifacts")

# Scanner defaults
DEFAULT_PORTS = [int(p) for p in os.getenv("DEFAULT_PORTS", "22,443").split(",")]
DEFAULT_CONCURRENCY = int(os.getenv("DEFAULT_CONCURRENCY", "200"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "1.5"))

# Create artifact directory if it doesn't exist
Path(ARTIFACT_DIR).mkdir(parents=True, exist_ok=True)

# Default seeder methods
DEFAULT_SEEDER_METHODS = ["interfaces", "routing", "arp", "cdp", "lldp"]

def get_job_dir(job_id: str) -> Path:
    """Get the directory path for a job's artifacts."""
    job_dir = Path(ARTIFACT_DIR) / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    return job_dir

def get_device_states_dir(job_id: str) -> Path:
    """Get the directory path for a job's device states."""
    device_states_dir = get_job_dir(job_id) / "device_states"
    device_states_dir.mkdir(parents=True, exist_ok=True)
    return device_states_dir
