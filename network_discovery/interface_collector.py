"""
Interface data collection module.

This module queries Batfish for detailed interface properties and stores them
as artifacts for use by visualization and analysis tools.
"""

import logging
import json
from typing import Dict, List, Optional, Any
from pathlib import Path

from pybatfish.client.session import Session

from network_discovery.config import get_job_dir

# Configure logger
logger = logging.getLogger(__name__)


def collect_interface_data(job_id: str, network_name: str = None, snapshot_name: str = None) -> Dict[str, Any]:
    """
    Collect detailed interface data from Batfish and store as artifact.
    
    Args:
        job_id: Job identifier
        network_name: Optional Batfish network name (defaults to job_id)
        snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
        
    Returns:
        Dict containing:
            - status: "success" or "error"
            - interface_count: Number of interfaces collected
            - devices: Dict of device -> interfaces mapping
            - interfaces: List of all interface records
            - error: Error message if status is "error"
    """
    try:
        # Determine network and snapshot names
        actual_network_name = network_name if network_name is not None else job_id
        actual_snapshot_name = snapshot_name if snapshot_name is not None else "snapshot_latest"
        
        logger.info(f"Collecting interface data for network: {actual_network_name}, snapshot: {actual_snapshot_name}")
        
        # Initialize Batfish session
        logger.info("Initializing Batfish session with host: batfish on port 9996")
        bf = Session(host="batfish", port=9996)
        
        # Check if network exists
        networks = bf.list_networks()
        if actual_network_name not in networks:
            error_msg = f"Network {actual_network_name} not found in Batfish. Available networks: {networks}"
            logger.error(error_msg)
            return {
                "status": "error",
                "error": error_msg,
                "interface_count": 0,
                "devices": {},
                "interfaces": []
            }
        
        # Set network
        bf.set_network(actual_network_name)
        
        # Check if snapshot exists
        snapshots = bf.list_snapshots()
        if actual_snapshot_name not in snapshots:
            error_msg = f"Snapshot {actual_snapshot_name} not found for network {actual_network_name}. Available snapshots: {snapshots}"
            logger.error(error_msg)
            return {
                "status": "error",
                "error": error_msg,
                "interface_count": 0,
                "devices": {},
                "interfaces": []
            }
        
        # Set snapshot
        bf.set_snapshot(actual_snapshot_name)
        logger.info(f"Using Batfish network: {actual_network_name}, snapshot: {actual_snapshot_name}")
        
        # Query interface properties
        logger.info("Querying Batfish for interface properties")
        iface_df = bf.q.interfaceProperties().answer().frame()
        logger.info(f"Retrieved {len(iface_df)} interface records from Batfish")
        
        # Convert DataFrame to list of dicts
        interfaces = []
        devices = {}
        
        for _, row in iface_df.iterrows():
            # Extract interface object - it's a Batfish Interface object with attributes
            interface_obj = row.get("Interface")
            if interface_obj:
                node = str(interface_obj.hostname) if hasattr(interface_obj, 'hostname') else ""
                interface_name = str(interface_obj.interface) if hasattr(interface_obj, 'interface') else ""
            else:
                node = ""
                interface_name = ""
            
            interface_data = {
                "node": node,
                "interface": interface_name,
                "active": bool(row.get("Active", False)),
                "primary_address": str(row.get("Primary_Address")) if row.get("Primary_Address") else None,
                "primary_network": str(row.get("Primary_Network")) if row.get("Primary_Network") else None,
                "description": str(row.get("Description")) if row.get("Description") else None,
                "vlan": int(row.get("VLAN")) if row.get("VLAN") and str(row.get("VLAN")).isdigit() else None,
                "vrf": str(row.get("VRF")) if row.get("VRF") else None,
                "bandwidth": float(row.get("Bandwidth")) if row.get("Bandwidth") else None,
                "mtu": int(row.get("MTU")) if row.get("MTU") else None,
                "admin_up": bool(row.get("Admin_Up", False)),
                "line_up": bool(row.get("Line_Up", False)),
                "switchport": bool(row.get("Switchport", False)),
                "switchport_mode": str(row.get("Switchport_Mode")) if row.get("Switchport_Mode") else None,
                "access_vlan": int(row.get("Access_VLAN")) if row.get("Access_VLAN") and str(row.get("Access_VLAN")).isdigit() else None,
                "allowed_vlans": str(row.get("Allowed_VLANs")) if row.get("Allowed_VLANs") else None,
                "native_vlan": int(row.get("Native_VLAN")) if row.get("Native_VLAN") and str(row.get("Native_VLAN")).isdigit() else None,
            }
            
            interfaces.append(interface_data)
            
            # Group by device
            node = interface_data["node"]
            if node not in devices:
                devices[node] = []
            devices[node].append(interface_data)
        
        # Prepare result
        result = {
            "status": "success",
            "network_name": actual_network_name,
            "snapshot_name": actual_snapshot_name,
            "interface_count": len(interfaces),
            "device_count": len(devices),
            "devices": devices,
            "interfaces": interfaces,
            "collected_at": None  # Will be set to ISO timestamp when saved
        }
        
        # Save to artifact
        artifact_path = get_job_dir(job_id) / "interfaces.json"
        logger.info(f"Saving interface data to {artifact_path}")
        
        # Add timestamp
        from datetime import datetime
        result["collected_at"] = datetime.utcnow().isoformat() + "Z"
        
        with open(artifact_path, 'w') as f:
            json.dump(result, f, indent=2)
        
        logger.info(f"Successfully collected and saved {len(interfaces)} interfaces from {len(devices)} devices")
        
        return result
        
    except Exception as e:
        error_msg = f"Failed to collect interface data: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            "status": "error",
            "error": error_msg,
            "interface_count": 0,
            "devices": {},
            "interfaces": []
        }


def get_interfaces_path(job_id: str) -> Path:
    """
    Get the path to the interfaces.json artifact.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path to interfaces.json
    """
    return get_job_dir(job_id) / "interfaces.json"


def load_interface_data(job_id: str) -> Optional[Dict[str, Any]]:
    """
    Load interface data from artifact.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Interface data dict or None if not found
    """
    try:
        interfaces_path = get_interfaces_path(job_id)
        
        if not interfaces_path.exists():
            logger.warning(f"Interface data not found at {interfaces_path}")
            return None
        
        with open(interfaces_path, 'r') as f:
            return json.load(f)
            
    except Exception as e:
        logger.error(f"Failed to load interface data: {str(e)}")
        return None


def get_device_interfaces(job_id: str, device_name: str) -> List[Dict[str, Any]]:
    """
    Get interfaces for a specific device.
    
    Args:
        job_id: Job identifier
        device_name: Device hostname
        
    Returns:
        List of interface data dicts for the device
    """
    data = load_interface_data(job_id)
    
    if not data or data.get("status") != "success":
        return []
    
    return data.get("devices", {}).get(device_name, [])


def get_interface_details(job_id: str, device_name: str, interface_name: str) -> Optional[Dict[str, Any]]:
    """
    Get details for a specific interface.
    
    Args:
        job_id: Job identifier
        device_name: Device hostname
        interface_name: Interface name
        
    Returns:
        Interface data dict or None if not found
    """
    device_interfaces = get_device_interfaces(job_id, device_name)
    
    for iface in device_interfaces:
        if iface.get("interface") == interface_name:
            return iface
    
    return None

