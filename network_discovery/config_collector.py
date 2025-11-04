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
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set

import asyncssh
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
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
from network_discovery.utils import retry_with_backoff, with_timeout

# Configure logger with more detailed format
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG level for maximum verbosity

# Add a stream handler if none exists
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Global variables for tracking progress
COLLECTION_STATUS = {}  # Stores per-job collection status

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

# Map our vendor names to Netmiko device types
VENDOR_TO_NETMIKO_TYPE = {
    "Cisco": "cisco_ios",  # Works for IOS, IOS-XE
    "Arista": "arista_eos",
    "Juniper": "juniper_junos",
    "Palo Alto": "paloalto_panos",
    "Fortinet": "fortinet",
    "Huawei": "huawei",
}

def extract_hostname_from_config(config: str, vendor: str, default_hostname: str) -> str:
    """
    Extract the hostname from device configuration.
    
    Args:
        config: Device configuration
        vendor: Device vendor
        default_hostname: Default hostname to use if extraction fails
        
    Returns:
        str: Extracted hostname or default_hostname if extraction fails
    """
    try:
        # Different vendors have different hostname formats
        if vendor == "Cisco" or vendor == "Arista":
            # Look for "hostname <name>" in config
            for line in config.splitlines():
                if line.strip().startswith("hostname "):
                    hostname = line.strip().split("hostname ", 1)[1].strip()
                    if hostname:
                        return hostname
        
        elif vendor == "Juniper":
            # Look for "set system host-name <name>" in config
            for line in config.splitlines():
                if "set system host-name" in line:
                    hostname = line.strip().split("host-name ", 1)[1].strip()
                    if hostname:
                        return hostname
        
        elif vendor == "Palo Alto":
            # Palo Alto uses "set deviceconfig system hostname <name>"
            for line in config.splitlines():
                if "hostname" in line.lower():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        hostname = parts[-1].strip()
                        if hostname:
                            return hostname
        
        # Add more vendor-specific hostname extraction as needed
        
        # If we couldn't extract the hostname, use the default
        return default_hostname
    except Exception as e:
        # If any error occurs during extraction, use the default hostname
        logger.warning(f"Failed to extract hostname from config: {str(e)}")
        return default_hostname

def update_collection_status(job_id: str, status: Dict) -> None:
    """
    Update the global collection status for a job.
    
    Args:
        job_id: Job identifier
        status: Status information to update
    """
    if job_id not in COLLECTION_STATUS:
        COLLECTION_STATUS[job_id] = {
            "job_id": job_id,
            "status": "initializing",
            "started_at": datetime.utcnow().isoformat() + "Z",
            "total_devices": 0,
            "completed_devices": 0,
            "failed_devices": 0,
            "in_progress_devices": 0,
            "pending_devices": 0,
            "device_statuses": {},
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }
    
    # Update with new status info
    COLLECTION_STATUS[job_id].update(status)
    
    # Always update the last_updated timestamp
    COLLECTION_STATUS[job_id]["last_updated"] = datetime.utcnow().isoformat() + "Z"
    
    # Log the update
    logger.debug(f"Updated collection status for job {job_id}: {status}")

def get_collection_status(job_id: str) -> Dict:
    """
    Get the current collection status for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Current collection status
    """
    if job_id not in COLLECTION_STATUS:
        return {
            "job_id": job_id,
            "status": "not_found",
            "message": f"No collection status found for job {job_id}"
        }
    
    return COLLECTION_STATUS[job_id]

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
    logger.info(f"Starting configuration collection for job {job_id} with concurrency {concurrency}")
    start_time = time.time()
    
    # Initialize collection status
    update_collection_status(job_id, {
        "status": "initializing",
        "started_at": datetime.utcnow().isoformat() + "Z",
    })
    
    try:
        # Get fingerprints to identify devices
        fingerprints_path = get_fingerprints_path(job_id)
        logger.info(f"Loading fingerprints from {fingerprints_path}")
        fingerprints = read_json(fingerprints_path)
        
        if not fingerprints or "hosts" not in fingerprints:
            error_msg = f"No fingerprints found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "state_collector", error_msg)
            
            update_collection_status(job_id, {
                "status": "failed",
                "error": error_msg,
                "completed_at": datetime.utcnow().isoformat() + "Z"
            })
            
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        logger.info(f"Found {len(fingerprints.get('hosts', []))} hosts in fingerprints")
        
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
        logger.debug(f"Created state directory at {state_dir}")
        
        # Ensure batfish snapshot directory exists
        batfish_configs_dir = get_batfish_configs_dir(job_id)
        batfish_configs_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created Batfish configs directory at {batfish_configs_dir}")
        
        # Filter for reachable devices with known vendors
        devices = []
        skipped_devices = 0
        
        for host in fingerprints["hosts"]:
            # Skip unreachable devices
            if not host.get("inference", {}).get("vendor"):
                logger.debug(f"Skipping device {host['ip']} - no vendor information")
                skipped_devices += 1
                continue
                
            # Create device info
            device = {
                "ip": host["ip"],
                "vendor": host["inference"]["vendor"],
                "hostname": host.get("hostname", host["ip"]),
                "protocols": host.get("inference", {}).get("protocols", [])
            }
            
            devices.append(device)
            logger.debug(f"Added device {device['hostname']} ({device['ip']}) to collection queue")
        
        logger.info(f"Identified {len(devices)} devices for configuration collection (skipped {skipped_devices})")
        
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
            
            update_collection_status(job_id, {
                "status": "completed",
                "total_devices": 0,
                "completed_devices": 0,
                "failed_devices": 0,
                "completed_at": datetime.utcnow().isoformat() + "Z"
            })
            
            return {
                "job_id": job_id,
                "status": "completed",
                "device_count": 0,
                "result_dir": "state/"
            }
        
        # Update collection status with device count
        update_collection_status(job_id, {
            "status": "collecting",
            "total_devices": len(devices),
            "pending_devices": len(devices),
            "device_statuses": {device["hostname"]: {"status": "pending", "ip": device["ip"], "vendor": device["vendor"]} for device in devices}
        })
        
        # Collect configurations in parallel with concurrency limit
        logger.info(f"Starting parallel collection for {len(devices)} devices with concurrency {concurrency}")
        semaphore = asyncio.Semaphore(concurrency)
        collection_tasks = [
            _collect_device_config(device, creds, job_id, semaphore)
            for device in devices
        ]
        
        logger.debug(f"Created {len(collection_tasks)} collection tasks")
        collection_results = await asyncio.gather(*collection_tasks, return_exceptions=True)
        logger.info(f"Completed all collection tasks")
        
        # Process results
        success_count = 0
        failed_count = 0
        
        for i, result in enumerate(collection_results):
            hostname = devices[i]["hostname"]
            if isinstance(result, Exception):
                logger.error(f"Error collecting config from {hostname}: {str(result)}")
                failed_count += 1
                
                # Update device status
                device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
                device_status.update({
                    "status": "failed",
                    "error": str(result),
                    "completed_at": datetime.utcnow().isoformat() + "Z"
                })
                COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
                
            elif result.get("status") == "success":
                logger.info(f"Successfully collected config from {hostname}")
                success_count += 1
                
                # Update device status
                device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
                device_status.update({
                    "status": "completed",
                    "state_path": result.get("state_path"),
                    "batfish_path": result.get("batfish_path"),
                    "completed_at": datetime.utcnow().isoformat() + "Z"
                })
                COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
                
            else:
                logger.warning(f"Collection failed for {hostname}: {result.get('error', 'Unknown error')}")
                failed_count += 1
                
                # Update device status
                device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
                device_status.update({
                    "status": "failed",
                    "error": result.get("error", "Unknown error"),
                    "completed_at": datetime.utcnow().isoformat() + "Z"
                })
                COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
        
        # Update collection status
        update_collection_status(job_id, {
            "status": "completed",
            "completed_devices": success_count,
            "failed_devices": failed_count,
            "in_progress_devices": 0,
            "pending_devices": 0,
            "completed_at": datetime.utcnow().isoformat() + "Z"
        })
        
        # Update batfish_loader status to indicate configs are ready for loading
        logger.info(f"Updating batfish_loader status to indicate configs are ready")
        update_status(
            job_id,
            "batfish_loader",
            "built",
            snapshot_dir="batfish_snapshot/configs",
            device_count=success_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Update state_collector status
        logger.info(f"Updating state_collector status to completed")
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
        
        # Calculate total time
        total_time = time.time() - start_time
        logger.info(f"Configuration collection completed in {total_time:.2f}s. Success: {success_count}, Failed: {failed_count}")
        
        return {
            "job_id": job_id,
            "status": "completed",
            "device_count": len(devices),
            "success_count": success_count,
            "failed_count": failed_count,
            "result_dir": "state/",
            "elapsed_time": f"{total_time:.2f}s"
        }
    except Exception as e:
        error_msg = f"Failed to collect device states: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        log_error(job_id, "state_collector", error_msg)
        
        # Update collection status
        update_collection_status(job_id, {
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.utcnow().isoformat() + "Z"
        })
        
        # Update status to failed
        update_status(
            job_id,
            "state_collector",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Calculate elapsed time
        total_time = time.time() - start_time
        logger.info(f"Configuration collection failed after {total_time:.2f}s")
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e),
            "elapsed_time": f"{total_time:.2f}s"
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
    ip = device["ip"]
    vendor = device["vendor"]
    hostname = device.get("hostname", ip)
    protocols = device.get("protocols", [])
    
    # Update device status to in_progress before acquiring semaphore
    if job_id in COLLECTION_STATUS:
        device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
        device_status.update({
            "status": "waiting",
            "ip": ip,
            "vendor": vendor,
            "protocols": protocols,
            "waiting_at": datetime.utcnow().isoformat() + "Z"
        })
        COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
        
        # Update counts
        COLLECTION_STATUS[job_id]["pending_devices"] = max(0, COLLECTION_STATUS[job_id].get("pending_devices", 0) - 1)
        COLLECTION_STATUS[job_id]["in_progress_devices"] = COLLECTION_STATUS[job_id].get("in_progress_devices", 0) + 1
    
    async with semaphore:
        start_time = time.time()
        logger.info(f"Starting configuration collection for {hostname} ({ip})")
        
        # Update device status to in_progress after acquiring semaphore
        if job_id in COLLECTION_STATUS:
            device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
            device_status.update({
                "status": "in_progress",
                "started_at": datetime.utcnow().isoformat() + "Z"
            })
            COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
        
        try:
            # Determine collection method based on protocols and vendor
            config = None
            protocol_used = None
            
            # Try SSH first if available
            if "ssh" in protocols:
                # Try Netmiko first for supported vendors (handles vendor quirks)
                if vendor in VENDOR_TO_NETMIKO_TYPE:
                    try:
                        logger.info(f"Attempting Netmiko (SSH) collection for {hostname} ({ip}) vendor={vendor}")
                        config = await _collect_via_netmiko(ip, creds, vendor)
                        protocol_used = "ssh_netmiko"
                        logger.info(f"Netmiko collection successful for {hostname} ({ip})")
                    except Exception as e:
                        logger.warning(f"Netmiko collection failed for {hostname} ({ip}): {str(e)}")
                        logger.debug(traceback.format_exc())
                        
                        # Fall back to raw AsyncSSH
                        try:
                            logger.info(f"Falling back to raw AsyncSSH for {hostname} ({ip})")
                            config = await _collect_via_ssh(ip, creds, vendor)
                            protocol_used = "ssh_asyncssh"
                            logger.info(f"AsyncSSH collection successful for {hostname} ({ip})")
                        except Exception as e2:
                            logger.warning(f"AsyncSSH collection also failed for {hostname} ({ip}): {str(e2)}")
                            logger.debug(traceback.format_exc())
                else:
                    # Vendor not in Netmiko mapping, use AsyncSSH directly
                    try:
                        logger.info(f"Attempting AsyncSSH collection for {hostname} ({ip}) vendor={vendor}")
                        config = await _collect_via_ssh(ip, creds, vendor)
                        protocol_used = "ssh_asyncssh"
                        logger.info(f"AsyncSSH collection successful for {hostname} ({ip})")
                    except Exception as e:
                        logger.warning(f"AsyncSSH collection failed for {hostname} ({ip}): {str(e)}")
                        logger.debug(traceback.format_exc())
            
            # Try NETCONF if SSH failed and it's supported
            if not config and vendor in ["Juniper", "Cisco"]:
                try:
                    logger.info(f"Attempting NETCONF collection for {hostname} ({ip})")
                    config = await _collect_via_netconf(ip, creds, vendor)
                    protocol_used = "netconf"
                    logger.info(f"NETCONF collection successful for {hostname} ({ip})")
                except Exception as e:
                    logger.warning(f"NETCONF collection failed for {hostname} ({ip}): {str(e)}")
                    logger.debug(traceback.format_exc())
            
            # Try RESTCONF as last resort for Cisco devices
            if not config and vendor == "Cisco" and "https" in protocols:
                try:
                    logger.info(f"Attempting RESTCONF collection for {hostname} ({ip})")
                    config = await _collect_via_restconf(ip, creds)
                    protocol_used = "restconf"
                    logger.info(f"RESTCONF collection successful for {hostname} ({ip})")
                except Exception as e:
                    logger.warning(f"RESTCONF collection failed for {hostname} ({ip}): {str(e)}")
                    logger.debug(traceback.format_exc())
            
            if not config:
                error_msg = f"Failed to collect configuration from {hostname} ({ip}) using any method"
                logger.error(error_msg)
                raise Exception(error_msg)
            
            # Extract actual hostname from config if possible
            actual_hostname = extract_hostname_from_config(config, vendor, hostname)
            logger.info(f"Extracted hostname from config: {actual_hostname} (original: {hostname})")
            
            # Create state data
            logger.info(f"Creating state data for {actual_hostname} ({ip})")
            state_data = {
                "hostname": actual_hostname,
                "ip": ip,
                "vendor": vendor,
                "collected_at": datetime.utcnow().isoformat() + "Z",
                "protocol": protocol_used,
                "running_config": config
            }
            
            # Save state data to JSON
            state_path = get_state_path(job_id, actual_hostname)
            logger.info(f"Saving state data to {state_path}")
            atomic_write_json(state_data, state_path)
            
            # Write raw config directly to Batfish snapshot directory
            batfish_config_path = get_batfish_config_path(job_id, actual_hostname)
            logger.info(f"Writing raw config to {batfish_config_path}")
            with open(batfish_config_path, "w") as f:
                f.write(config)
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            logger.info(f"Configuration collection for {hostname} completed in {elapsed_time:.2f}s")
            
            # Update device status
            if job_id in COLLECTION_STATUS:
                # Update status for both original hostname and actual hostname
                device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
                device_status.update({
                    "status": "completed",
                    "protocol": protocol_used,
                    "actual_hostname": actual_hostname,
                    "state_path": str(state_path),
                    "batfish_path": str(batfish_config_path),
                    "config_size": len(config),
                    "elapsed_time": f"{elapsed_time:.2f}s",
                    "completed_at": datetime.utcnow().isoformat() + "Z"
                })
                COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
                
                # Also add entry for actual hostname if different
                if actual_hostname != hostname:
                    COLLECTION_STATUS[job_id]["device_statuses"][actual_hostname] = device_status.copy()
                
                # Update counts
                COLLECTION_STATUS[job_id]["in_progress_devices"] = max(0, COLLECTION_STATUS[job_id].get("in_progress_devices", 0) - 1)
                COLLECTION_STATUS[job_id]["completed_devices"] = COLLECTION_STATUS[job_id].get("completed_devices", 0) + 1
            
            return {
                "status": "success",
                "hostname": actual_hostname,
                "original_ip": ip,
                "state_path": str(state_path),
                "batfish_path": str(batfish_config_path),
                "elapsed_time": f"{elapsed_time:.2f}s"
            }
        except Exception as e:
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            logger.error(f"Failed to collect config from {hostname} ({ip}) after {elapsed_time:.2f}s: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Update device status
            if job_id in COLLECTION_STATUS:
                device_status = COLLECTION_STATUS[job_id]["device_statuses"].get(hostname, {})
                device_status.update({
                    "status": "failed",
                    "error": str(e),
                    "elapsed_time": f"{elapsed_time:.2f}s",
                    "completed_at": datetime.utcnow().isoformat() + "Z"
                })
                COLLECTION_STATUS[job_id]["device_statuses"][hostname] = device_status
                
                # Update counts
                COLLECTION_STATUS[job_id]["in_progress_devices"] = max(0, COLLECTION_STATUS[job_id].get("in_progress_devices", 0) - 1)
                COLLECTION_STATUS[job_id]["failed_devices"] = COLLECTION_STATUS[job_id].get("failed_devices", 0) + 1
            
            return {
                "status": "failed",
                "hostname": hostname,
                "error": str(e),
                "elapsed_time": f"{elapsed_time:.2f}s"
            }

async def _collect_via_netmiko(ip: str, creds: Dict, vendor: str) -> str:
    """
    Collect configuration via Netmiko (handles vendor-specific quirks).
    
    Netmiko is better than raw AsyncSSH because it:
    - Handles terminal paging automatically
    - Manages enable mode for privilege escalation
    - Deals with vendor-specific prompts and timing
    - Has built-in error handling for each platform
    
    Args:
        ip: Device IP address
        creds: Authentication credentials
        vendor: Device vendor (from fingerprinting)
        
    Returns:
        str: Device configuration
    """
    start_time = time.time()
    
    # Parse IP and port
    if ":" in ip:
        host, port = ip.split(":", 1)
        port = int(port)
    else:
        host = ip
        port = 22
    
    # Get Netmiko device type
    device_type = VENDOR_TO_NETMIKO_TYPE.get(vendor)
    if not device_type:
        raise Exception(f"Vendor '{vendor}' not supported by Netmiko. Supported vendors: {list(VENDOR_TO_NETMIKO_TYPE.keys())}")
    
    # Get the command for this vendor
    command = CONFIG_COMMANDS.get(vendor, DEFAULT_CONFIG_COMMAND)
    
    logger.debug(f"Attempting Netmiko connection to {host}:{port} as device_type='{device_type}'")
    
    try:
        # Run Netmiko in thread pool since it's synchronous
        loop = asyncio.get_event_loop()
        
        def _netmiko_collect():
            device_params = {
                'device_type': device_type,
                'host': host,
                'port': port,
                'username': creds.get("username"),
                'password': creds.get("password"),
                'timeout': 30,
                'session_timeout': 60,
                'banner_timeout': 15,
                'conn_timeout': 30,
            }
            
            with ConnectHandler(**device_params) as net_connect:
                # Netmiko automatically handles:
                # - Terminal length 0 (disable paging)
                # - Enable mode (if needed)
                # - Timing and prompts
                config = net_connect.send_command(command, read_timeout=90)
                return config
        
        # Run in executor to avoid blocking
        config = await loop.run_in_executor(None, _netmiko_collect)
        
        elapsed_time = time.time() - start_time
        config_length = len(config)
        logger.debug(f"Netmiko collection from {host} completed in {elapsed_time:.2f}s, config size: {config_length} bytes")
        
        if config_length < 100:
            logger.warning(f"Config from {host} is suspiciously small ({config_length} bytes)")
        
        return config
        
    except NetmikoAuthenticationException as e:
        elapsed_time = time.time() - start_time
        error_msg = f"Authentication failed to {host}:{port} after {elapsed_time:.2f}s: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except NetmikoTimeoutException as e:
        elapsed_time = time.time() - start_time
        error_msg = f"Connection timeout to {host}:{port} after {elapsed_time:.2f}s: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        elapsed_time = time.time() - start_time
        error_msg = f"Netmiko collection from {host}:{port} failed after {elapsed_time:.2f}s: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

async def _collect_via_ssh(ip: str, creds: Dict, vendor: str) -> str:
    """
    Collect configuration via SSH.
    
    Args:
        ip: Device IP address
        creds: Authentication credentials
        vendor: Device vendor (from fingerprinting)
        
    Returns:
        str: Device configuration
        
    Note:
        This function does NOT retry on failures. Retries were causing issues:
        - Authentication failures don't benefit from retries (same credentials)
        - Retries can trigger rate limiting or account lockouts
        - Wastes time (3 attempts × 35s = 105s per device)
    """
    start_time = time.time()
    
    # Parse IP and port
    if ":" in ip:
        host, port = ip.split(":", 1)
        port = int(port)
        logger.debug(f"Parsed IP {ip} to host={host}, port={port}")
    else:
        host = ip
        port = 22
        logger.debug(f"Using default port 22 for {host}")
    
    try:
        logger.debug(f"Establishing SSH connection to {host}:{port}")
        
        # Connect via AsyncSSH with timeout
        conn = await with_timeout(
            asyncssh.connect(
                host=host,
                port=port,
                username=creds.get("username"),
                password=creds.get("password"),
                known_hosts=None,
                connect_timeout=30
            ),
            timeout=35,
            error_message=f"SSH connection to {host}:{port} timed out"
        )
        
        async with conn:
            connection_time = time.time() - start_time
            logger.debug(f"SSH connection established to {host}:{port} in {connection_time:.2f}s")
            
            # Get the appropriate command for this vendor
            command = CONFIG_COMMANDS.get(vendor, DEFAULT_CONFIG_COMMAND)
            logger.debug(f"Using command for {vendor}: '{command}'")
            
            logger.debug(f"Executing command on {host}: '{command}'")
            cmd_start_time = time.time()
            result = await conn.run(command)
            cmd_time = time.time() - cmd_start_time
            
            if result.exit_status != 0:
                error_msg = f"Command failed on {host} with exit status {result.exit_status}: {result.stderr}"
                logger.error(error_msg)
                raise Exception(error_msg)
            
            config_length = len(result.stdout)
            logger.debug(f"Command completed on {host} in {cmd_time:.2f}s, output size: {config_length} bytes")
            
            # Check if we got a reasonable config
            if config_length < 100:
                logger.warning(f"Config from {host} is suspiciously small ({config_length} bytes)")
                logger.debug(f"Config content: {result.stdout}")
            
            total_time = time.time() - start_time
            logger.debug(f"SSH collection from {host} completed in {total_time:.2f}s")
            
            return result.stdout
    except asyncssh.Error as e:
        elapsed_time = time.time() - start_time
        error_msg = f"SSH connection to {host}:{port} failed after {elapsed_time:.2f}s: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except Exception as e:
        elapsed_time = time.time() - start_time
        error_msg = f"SSH collection from {host}:{port} failed after {elapsed_time:.2f}s: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

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