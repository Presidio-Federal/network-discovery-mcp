"""
Config collector module for retrieving device configurations.

This module retrieves each device's running configuration in parallel and stores
it as a separate JSON file under {job_dir}/state/{hostname}.json.
It also writes the raw configuration directly to {job_dir}/batfish_snapshot/configs/{hostname}.cfg
for immediate use by Batfish without requiring conversion.
"""

import asyncio
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import asyncssh
import netmiko
from ncclient import manager
import requests

from network_discovery.artifacts import (
    atomic_write_json,
    get_job_dir,
    log_error,
    read_json,
    update_status,
)
from network_discovery.config import DEFAULT_CONCURRENCY

logger = logging.getLogger(__name__)

# Commands to retrieve running configuration based on vendor
CONFIG_COMMANDS = {
    "Cisco": "show running-config",
    "Arista": "show running-config",
    "Juniper": "show configuration | display set",
    "Palo Alto": "show config running",
    "Fortinet": "show full-configuration",
    "Huawei": "display current-configuration",
    "Linux/Unix": "cat /etc/network/interfaces",  # Basic example, might need sudo
}

# Default command if vendor is unknown
DEFAULT_CONFIG_COMMAND = "show running-config"

async def collect_all_state(job_id: str, creds: Dict, concurrency: int = DEFAULT_CONCURRENCY) -> Dict:
    """
    Collect configuration state from all devices in parallel.
    
    Args:
        job_id: Job identifier
        creds: Dictionary with authentication credentials
        concurrency: Maximum concurrent connections
        
    Returns:
        Dict: Collection results with job_id and status
    """
    try:
        # Get fingerprints to identify devices
        fingerprints_path = get_fingerprints_path(job_id)
        fingerprints = read_json(fingerprints_path)
        
        if not fingerprints or "hosts" not in fingerprints:
            error_msg = f"No fingerprints found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "state_collector", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Update status to running
        update_status(
            job_id,
            "state_collector",
            "running",
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Ensure state directory exists
        state_dir = get_state_dir(job_id)
        state_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure batfish snapshot directory exists
        batfish_configs_dir = get_batfish_configs_dir(job_id)
        batfish_configs_dir.mkdir(parents=True, exist_ok=True)
        
        # Filter for reachable devices with known vendors
        devices = []
        for host in fingerprints["hosts"]:
            # Skip unreachable devices
            if not host.get("inference", {}).get("vendor"):
                continue
                
            # Create device info
            device = {
                "ip": host["ip"],
                "vendor": host["inference"]["vendor"],
                "hostname": host.get("hostname", host["ip"]),
                "protocols": host.get("inference", {}).get("protocols", [])
            }
            
            devices.append(device)
        
        if not devices:
            logger.warning(f"No suitable devices found for job {job_id}")
            
            # Update status
            update_status(
                job_id,
                "state_collector",
                "completed",
                device_count=0,
                result_dir="state/",
                completed_at=datetime.utcnow().isoformat() + "Z"
            )
            
            return {
                "job_id": job_id,
                "status": "completed",
                "device_count": 0,
                "result_dir": "state/"
            }
        
        # Collect configurations in parallel with concurrency limit
        semaphore = asyncio.Semaphore(concurrency)
        collection_tasks = [
            _collect_device_config(device, creds, job_id, semaphore)
            for device in devices
        ]
        
        collection_results = await asyncio.gather(*collection_tasks, return_exceptions=True)
        
        # Process results
        success_count = 0
        failed_count = 0
        
        for i, result in enumerate(collection_results):
            if isinstance(result, Exception):
                logger.error(f"Error collecting config from {devices[i]['hostname']}: {str(result)}")
                failed_count += 1
            elif result.get("status") == "success":
                success_count += 1
            else:
                failed_count += 1
        
        # Update batfish_loader status to indicate configs are ready for loading
        update_status(
            job_id,
            "batfish_loader",
            "built",
            snapshot_dir="batfish_snapshot/configs",
            device_count=success_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Update state_collector status
        update_status(
            job_id,
            "state_collector",
            "completed",
            device_count=len(devices),
            success_count=success_count,
            failed_count=failed_count,
            result_dir="state/",
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "device_count": len(devices),
            "success_count": success_count,
            "failed_count": failed_count,
            "result_dir": "state/"
        }
    except Exception as e:
        error_msg = f"Failed to collect device states: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "state_collector", error_msg)
        
        # Update status to failed
        update_status(
            job_id,
            "state_collector",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }

async def collect_single_state(job_id: str, creds: Dict, hostname: str) -> Dict:
    """
    Collect configuration state from a single device.
    
    Args:
        job_id: Job identifier
        creds: Dictionary with authentication credentials
        hostname: Device hostname or IP
        
    Returns:
        Dict: Collection results with job_id and status
    """
    try:
        # Get fingerprints to identify device
        fingerprints_path = get_fingerprints_path(job_id)
        fingerprints = read_json(fingerprints_path)
        
        if not fingerprints or "hosts" not in fingerprints:
            error_msg = f"No fingerprints found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "state_collector", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Find the device in fingerprints
        device = None
        for host in fingerprints["hosts"]:
            if host.get("hostname") == hostname or host["ip"] == hostname:
                device = {
                    "ip": host["ip"],
                    "vendor": host.get("inference", {}).get("vendor", "unknown"),
                    "hostname": host.get("hostname", host["ip"]),
                    "protocols": host.get("inference", {}).get("protocols", [])
                }
                break
        
        if not device:
            error_msg = f"Device {hostname} not found in fingerprints for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "state_collector", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Update status to running
        update_status(
            job_id,
            "state_collector",
            "running",
            device_updated=hostname,
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Ensure state directory exists
        state_dir = get_state_dir(job_id)
        state_dir.mkdir(parents=True, exist_ok=True)
        
        # Ensure batfish snapshot directory exists
        batfish_configs_dir = get_batfish_configs_dir(job_id)
        batfish_configs_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect configuration
        semaphore = asyncio.Semaphore(1)  # Single device, so semaphore of 1
        result = await _collect_device_config(device, creds, job_id, semaphore)
        
        if isinstance(result, Exception) or result.get("status") != "success":
            error_msg = str(result) if isinstance(result, Exception) else result.get("error", "Unknown error")
            logger.error(f"Failed to collect config from {hostname}: {error_msg}")
            
            # Update status to failed
            update_status(
                job_id,
                "state_collector",
                "failed",
                device_updated=hostname,
                error=error_msg,
                completed_at=datetime.utcnow().isoformat() + "Z"
            )
            
            return {
                "job_id": job_id,
                "status": "failed",
                "device_updated": hostname,
                "error": error_msg
            }
        
        # Update status
        update_status(
            job_id,
            "state_collector",
            "updated",
            device_updated=hostname,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "updated",
            "device_updated": hostname
        }
    except Exception as e:
        error_msg = f"Failed to collect state from {hostname}: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "state_collector", error_msg)
        
        # Update status to failed
        update_status(
            job_id,
            "state_collector",
            "failed",
            device_updated=hostname,
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "failed",
            "device_updated": hostname,
            "error": str(e)
        }

async def get_device_state(job_id: str, hostname: str) -> Dict:
    """
    Get device state from state file.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        
    Returns:
        Dict: Device state or error information
    """
    try:
        # Find the state file
        state_dir = get_state_dir(job_id)
        
        # Try with hostname first
        state_path = state_dir / f"{hostname}.json"
        
        # If not found, try to find by IP or sanitized hostname
        if not state_path.exists():
            # Look for any file that might match
            for file_path in state_dir.glob("*.json"):
                state_data = read_json(file_path)
                if state_data.get("hostname") == hostname or state_data.get("ip") == hostname:
                    state_path = file_path
                    break
        
        if not state_path.exists():
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"No state file found for device {hostname} in job {job_id}"
            }
        
        state_data = read_json(state_path)
        
        if not state_data:
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"State file for device {hostname} is empty or invalid"
            }
        
        return state_data
    except Exception as e:
        error_msg = f"Failed to get device state: {str(e)}"
        logger.error(error_msg)
        return {
            "job_id": job_id,
            "status": "error",
            "error": str(e)
        }

async def _collect_device_config(
    device: Dict,
    creds: Dict,
    job_id: str,
    semaphore: asyncio.Semaphore
) -> Dict:
    """
    Collect configuration from a single device.
    
    Args:
        device: Device information
        creds: Authentication credentials
        job_id: Job identifier
        semaphore: Concurrency semaphore
        
    Returns:
        Dict: Collection results
    """
    async with semaphore:
        try:
            ip = device["ip"]
            vendor = device["vendor"]
            hostname = device.get("hostname", ip)
            protocols = device.get("protocols", [])
            
            # Determine collection method based on protocols and vendor
            config = None
            protocol_used = None
            
            # Try SSH first if available
            if "ssh" in protocols:
                try:
                    config = await _collect_via_ssh(ip, creds, vendor)
                    protocol_used = "ssh"
                except Exception as e:
                    logger.debug(f"SSH collection failed for {ip}: {str(e)}")
            
            # Try NETCONF if SSH failed and it's supported
            if not config and vendor in ["Juniper", "Cisco"]:
                try:
                    config = await _collect_via_netconf(ip, creds, vendor)
                    protocol_used = "netconf"
                except Exception as e:
                    logger.debug(f"NETCONF collection failed for {ip}: {str(e)}")
            
            # Try RESTCONF as last resort for Cisco devices
            if not config and vendor == "Cisco" and "https" in protocols:
                try:
                    config = await _collect_via_restconf(ip, creds)
                    protocol_used = "restconf"
                except Exception as e:
                    logger.debug(f"RESTCONF collection failed for {ip}: {str(e)}")
            
            if not config:
                raise Exception(f"Failed to collect configuration from {ip} using any method")
            
            # Create state data
            state_data = {
                "hostname": hostname,
                "ip": ip,
                "vendor": vendor,
                "collected_at": datetime.utcnow().isoformat() + "Z",
                "protocol": protocol_used,
                "running_config": config
            }
            
            # Save state data to JSON
            state_path = get_state_path(job_id, hostname)
            atomic_write_json(state_data, state_path)
            
            # Write raw config directly to Batfish snapshot directory
            batfish_config_path = get_batfish_config_path(job_id, hostname)
            with open(batfish_config_path, "w") as f:
                f.write(config)
            
            return {
                "status": "success",
                "hostname": hostname,
                "state_path": str(state_path),
                "batfish_path": str(batfish_config_path)
            }
        except Exception as e:
            logger.error(f"Failed to collect config from {device.get('hostname', device['ip'])}: {str(e)}")
            return {
                "status": "failed",
                "hostname": device.get("hostname", device["ip"]),
                "error": str(e)
            }

async def _collect_via_ssh(ip: str, creds: Dict, vendor: str) -> str:
    """
    Collect configuration via SSH.
    
    Args:
        ip: Device IP address
        creds: Authentication credentials
        vendor: Device vendor
        
    Returns:
        str: Device configuration
    """
    # Parse IP and port
    if ":" in ip:
        host, port = ip.split(":", 1)
        port = int(port)
    else:
        host = ip
        port = 22
    
    # Get the appropriate command for this vendor
    command = CONFIG_COMMANDS.get(vendor, DEFAULT_CONFIG_COMMAND)
    
    # Connect via AsyncSSH
    async with asyncssh.connect(
        host=host,
        port=port,
        username=creds.get("username"),
        password=creds.get("password"),
        known_hosts=None
    ) as conn:
        result = await conn.run(command)
        if result.exit_status != 0:
            raise Exception(f"Command failed with exit status {result.exit_status}: {result.stderr}")
        
        return result.stdout

async def _collect_via_netconf(ip: str, creds: Dict, vendor: str) -> str:
    """
    Collect configuration via NETCONF.
    
    Args:
        ip: Device IP address
        creds: Authentication credentials
        vendor: Device vendor
        
    Returns:
        str: Device configuration
    """
    # Parse IP and port
    if ":" in ip:
        host, port_str = ip.split(":", 1)
        # NETCONF typically uses port 830
        port = 830
    else:
        host = ip
        port = 830
    
    # This needs to be run in a thread as ncclient is not async
    loop = asyncio.get_event_loop()
    config = await loop.run_in_executor(
        None,
        _netconf_get_config,
        host,
        port,
        creds,
        vendor
    )
    
    return config

def _netconf_get_config(host: str, port: int, creds: Dict, vendor: str) -> str:
    """
    Get configuration via NETCONF (synchronous).
    
    Args:
        host: Device hostname or IP
        port: NETCONF port
        creds: Authentication credentials
        vendor: Device vendor
        
    Returns:
        str: Device configuration
    """
    device_params = {"name": "default"}
    if vendor == "Juniper":
        device_params["name"] = "junos"
    elif vendor == "Cisco":
        device_params["name"] = "iosxe"
    
    with manager.connect(
        host=host,
        port=port,
        username=creds.get("username"),
        password=creds.get("password"),
        hostkey_verify=False,
        device_params=device_params,
        timeout=30
    ) as m:
        if vendor == "Juniper":
            config = m.get_config(source="running").data_xml
        else:
            config = m.get_config(source="running").data_xml
        
        return config

async def _collect_via_restconf(ip: str, creds: Dict) -> str:
    """
    Collect configuration via RESTCONF.
    
    Args:
        ip: Device IP address
        creds: Authentication credentials
        
    Returns:
        str: Device configuration
    """
    # Parse IP and port
    if ":" in ip:
        host, port_str = ip.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443
    else:
        host = ip
        port = 443
    
    # This needs to be run in a thread as requests is not async
    loop = asyncio.get_event_loop()
    config = await loop.run_in_executor(
        None,
        _restconf_get_config,
        host,
        port,
        creds
    )
    
    return config

def _restconf_get_config(host: str, port: int, creds: Dict) -> str:
    """
    Get configuration via RESTCONF (synchronous).
    
    Args:
        host: Device hostname or IP
        port: RESTCONF port
        creds: Authentication credentials
        
    Returns:
        str: Device configuration
    """
    url = f"https://{host}:{port}/restconf/data/Cisco-IOS-XE-native:native"
    
    headers = {
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json"
    }
    
    response = requests.get(
        url,
        auth=(creds.get("username"), creds.get("password")),
        headers=headers,
        verify=False
    )
    
    if response.status_code != 200:
        raise Exception(f"RESTCONF request failed with status code {response.status_code}: {response.text}")
    
    return response.text

def get_fingerprints_path(job_id: str) -> Path:
    """
    Get the path to the fingerprints.json file for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to fingerprints.json
    """
    return get_job_dir(job_id) / "fingerprints.json"

def get_state_dir(job_id: str) -> Path:
    """
    Get the path to the state directory for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to state directory
    """
    return get_job_dir(job_id) / "state"

def get_state_path(job_id: str, hostname: str) -> Path:
    """
    Get the path to a device state file.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        
    Returns:
        Path: Path to device state file
    """
    # Sanitize hostname for use as a filename
    safe_hostname = hostname.replace(":", "_").replace("/", "_")
    
    # Ensure state directory exists
    state_dir = get_state_dir(job_id)
    state_dir.mkdir(parents=True, exist_ok=True)
    
    return state_dir / f"{safe_hostname}.json"

def get_batfish_configs_dir(job_id: str) -> Path:
    """
    Get the path to the Batfish configs directory for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to Batfish configs directory
    """
    batfish_dir = get_job_dir(job_id) / "batfish_snapshot" / "configs"
    batfish_dir.mkdir(parents=True, exist_ok=True)
    return batfish_dir

def get_batfish_config_path(job_id: str, hostname: str) -> Path:
    """
    Get the path to a Batfish config file.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        
    Returns:
        Path: Path to Batfish config file
    """
    # Sanitize hostname for use as a filename
    safe_hostname = hostname.replace(":", "_").replace("/", "_")
    
    # Get Batfish configs directory
    configs_dir = get_batfish_configs_dir(job_id)
    
    return configs_dir / f"{safe_hostname}.cfg"