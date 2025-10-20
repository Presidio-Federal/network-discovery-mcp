"""
Seeder module for network discovery.

This module collects initial network knowledge from a seed device and produces
targets.json and device state files.
"""

import json
import logging
import os
import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv4Interface
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

from nornir import InitNornir
from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_send_command
from nornir.core.inventory import Host, Inventory
import tempfile
import yaml

from network_discovery.artifacts import (
    atomic_write_json,
    get_device_state_path,
    get_targets_path,
    log_error,
    update_status,
)
from network_discovery.config import DEFAULT_SEEDER_METHODS, get_device_states_dir, get_job_dir

logger = logging.getLogger(__name__)

def collect_seed(
    seed_host: str,
    creds: Dict,
    job_id: Optional[str] = None,
    methods: List[str] = DEFAULT_SEEDER_METHODS
) -> Dict:
    """
    Collect network information from a seed device.
    
    Args:
        seed_host: Hostname or IP of the seed device
        creds: Dictionary with authentication credentials
        job_id: Optional job identifier (generated if not provided)
        methods: List of collection methods to use
        
    Returns:
        Dict: Collection results with job_id and status
    """
    # Generate job_id if not provided
    if not job_id:
        job_id = str(uuid.uuid4())
    
    # Update status to running
    update_status(job_id, "seeder", "running", seed_host=seed_host)
    
    try:
        # Check if we have a local fixture
        fixture_path = Path("/workspace/configs") / seed_host
        if fixture_path.exists():
            logger.info(f"Using local fixture for {seed_host}")
            return _process_fixture(fixture_path, seed_host, job_id)
        
        # Otherwise connect to the device
        return _collect_from_device(seed_host, creds, job_id, methods)
    except Exception as e:
        error_msg = f"Seeder failed: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "seeder", error_msg)
        update_status(job_id, "seeder", "failed", error=str(e))
        return {"job_id": job_id, "status": "failed", "error": str(e)}

def _process_fixture(fixture_path: Path, seed_host: str, job_id: str) -> Dict:
    """Process a local fixture file."""
    try:
        with open(fixture_path, 'r') as f:
            device_data = json.load(f)
        
        # Extract targets from the fixture
        targets = _extract_targets(device_data, seed_host)
        
        # Save device state
        device_state_path = get_device_state_path(job_id, seed_host)
        atomic_write_json(device_data, device_state_path)
        
        # Save targets
        targets_path = get_targets_path(job_id)
        atomic_write_json(targets, targets_path)
        
        # Update status
        update_status(
            job_id, 
            "seeder", 
            "completed", 
            seed_host=seed_host,
            subnets_count=len(targets.get("subnets", [])),
            candidate_ips_count=len(targets.get("candidate_ips", [])),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "targets_path": str(targets_path)
        }
    except Exception as e:
        error_msg = f"Failed to process fixture: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "seeder", error_msg)
        update_status(job_id, "seeder", "failed", error=str(e))
        return {"job_id": job_id, "status": "failed", "error": str(e)}

def _collect_from_device(
    seed_host: str,
    creds: Dict,
    job_id: str,
    methods: List[str]
) -> Dict:
    """Collect data from a network device using Nornir/Netmiko."""
    # Parse seed_host to separate host and port if needed
    if ":" in seed_host:
        hostname, port = seed_host.split(":", 1)
        port = int(port)
    else:
        hostname = seed_host
        port = 22  # Default SSH port
    
    # Create temporary inventory files for Nornir
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create hosts.yaml
        hosts_file = Path(tmp_dir) / "hosts.yaml"
        host_key = hostname.replace(".", "_")  # Make a valid YAML key
        hosts_data = {
            host_key: {
                "hostname": hostname,
                "port": port,
                "username": creds.get("username"),
                "password": creds.get("password"),
                "platform": creds.get("platform", "cisco_ios"),
                "groups": ["default"]
            }
        }
        with open(hosts_file, 'w') as f:
            yaml.dump(hosts_data, f)
        
        # Create groups.yaml
        groups_file = Path(tmp_dir) / "groups.yaml"
        groups_data = {
            "default": {}
        }
        with open(groups_file, 'w') as f:
            yaml.dump(groups_data, f)
        
        # Create defaults.yaml
        defaults_file = Path(tmp_dir) / "defaults.yaml"
        defaults_data = {}
        with open(defaults_file, 'w') as f:
            yaml.dump(defaults_data, f)
        
        # Initialize Nornir with SimpleInventory
        nr = InitNornir(
            inventory={
                "plugin": "SimpleInventory",
                "options": {
                    "host_file": str(hosts_file),
                    "group_file": str(groups_file),
                    "defaults_file": str(defaults_file)
                }
            }
        )
        
        device_data = {"hostname": seed_host, "collected_at": datetime.utcnow().isoformat() + "Z"}
        
        # Print inventory hosts for debugging
        logger.info(f"Nornir inventory hosts: {list(nr.inventory.hosts.keys())}")
        
        # Collect data based on requested methods
        if "interfaces" in methods:
            try:
                result = nr.run(task=_collect_interfaces)
                for host, host_result in result.items():
                    if host_result.failed:
                        logger.warning(f"Failed to collect interfaces from {host}")
                    else:
                        device_data["interfaces"] = host_result.result
            except Exception as e:
                logger.error(f"Error collecting interfaces: {str(e)}")
        
        if "routing" in methods:
            try:
                # Try a simple command first to check connectivity
                test_result = nr.run(task=netmiko_send_command, command_string="show version")
                logger.info(f"Test command result: {test_result}")
                
                # Try to collect routing table with detailed error logging
                try:
                    result = nr.run(task=_collect_routing)
                    for host, host_result in result.items():
                        if host_result.failed:
                            logger.warning(f"Failed to collect routing from {host}")
                            # Log the exception if available
                            if hasattr(host_result, 'exception') and host_result.exception:
                                logger.error(f"Routing collection exception: {str(host_result.exception)}")
                        else:
                            device_data["routing"] = host_result.result
                except Exception as e:
                    logger.error(f"Error in routing collection task: {str(e)}")
                    
                # Use direct connection to get raw routing table
                try:
                    # Get connection from Nornir
                    host_key = list(nr.inventory.hosts.keys())[0]
                    host_obj = nr.inventory.hosts[host_key]
                    
                    # Create direct Netmiko connection
                    logger.info(f"Creating direct Netmiko connection to {host_obj.hostname}")
                    from netmiko import ConnectHandler
                    
                    connection_params = {
                        "device_type": creds.get("platform", "cisco_ios"),
                        "host": host_obj.hostname,
                        "username": creds.get("username"),
                        "password": creds.get("password"),
                        "port": host_obj.port or 22,
                    }
                    
                    with ConnectHandler(**connection_params) as conn:
                        # Get raw routing table
                        logger.info("Fetching raw routing table directly")
                        route_output = conn.send_command("show ip route")
                        logger.info(f"Raw routing table length: {len(route_output)} chars")
                        
                        # Parse the output
                        parsed_routes = _parse_raw_routing_table(route_output)
                        logger.info(f"Parsed {len(parsed_routes)} routes from raw output")
                        
                        # Store both the raw output and parsed routes
                        device_data["routing"] = {
                            "default": parsed_routes,
                            "raw_output": route_output,
                            "vrf": {}
                        }
                        
                        # Try to get VRF routing tables
                        try:
                            vrf_list_output = conn.send_command("show vrf")
                            if "% Invalid" not in vrf_list_output and len(vrf_list_output) > 0:
                                # Parse VRF list
                                vrf_names = []
                                for line in vrf_list_output.splitlines():
                                    parts = line.split()
                                    if len(parts) >= 1 and parts[0] not in ["Name", "Default", "---"] and not parts[0].startswith("-"):
                                        vrf_names.append(parts[0])
                                
                                # Get routing table for each VRF
                                for vrf in vrf_names:
                                    vrf_route_output = conn.send_command(f"show ip route vrf {vrf}")
                                    vrf_parsed_routes = _parse_raw_routing_table(vrf_route_output)
                                    device_data["routing"]["vrf"][vrf] = vrf_parsed_routes
                                    logger.info(f"Added {len(vrf_parsed_routes)} routes from VRF {vrf}")
                        except Exception as e:
                            logger.warning(f"Error getting VRF routing tables: {str(e)}")
                            
                except Exception as e:
                    logger.error(f"Error in direct routing table collection: {str(e)}")
            except Exception as e:
                logger.error(f"Error collecting routing (outer): {str(e)}")
        
        if "arp" in methods:
            try:
                result = nr.run(task=_collect_arp)
                for host, host_result in result.items():
                    if host_result.failed:
                        logger.warning(f"Failed to collect ARP from {host}")
                    else:
                        device_data["arp"] = host_result.result
            except Exception as e:
                logger.error(f"Error collecting ARP: {str(e)}")
        
        if "cdp" in methods:
            try:
                result = nr.run(task=_collect_cdp)
                for host, host_result in result.items():
                    if host_result.failed:
                        logger.warning(f"Failed to collect CDP from {host}")
                    else:
                        device_data["cdp"] = host_result.result
            except Exception as e:
                logger.error(f"Error collecting CDP: {str(e)}")
                
        if "lldp" in methods:
            try:
                result = nr.run(task=_collect_lldp)
                for host, host_result in result.items():
                    if host_result.failed:
                        logger.warning(f"Failed to collect LLDP from {host}")
                    else:
                        device_data["lldp"] = host_result.result
            except Exception as e:
                logger.error(f"Error collecting LLDP: {str(e)}")
    
    # Extract targets from collected data
    targets = _extract_targets(device_data, seed_host)
    
    # Save device state
    device_state_path = get_device_state_path(job_id, seed_host)
    atomic_write_json(device_data, device_state_path)
    
    # Save targets
    targets_path = get_targets_path(job_id)
    atomic_write_json(targets, targets_path)
    
    # Update status
    update_status(
        job_id, 
        "seeder", 
        "completed", 
        seed_host=seed_host,
        subnets_count=len(targets.get("subnets", [])),
        candidate_ips_count=len(targets.get("candidate_ips", [])),
        completed_at=datetime.utcnow().isoformat() + "Z"
    )
    
    return {
        "job_id": job_id,
        "status": "completed",
        "targets_path": str(targets_path)
    }

def _collect_interfaces(task: Task) -> Dict:
    """Collect interface information from a device."""
    result = task.run(
        task=netmiko_send_command, 
        command_string="show ip interface brief", 
        use_textfsm=True
    )
    
    interfaces = result.result
    
    # Collect detailed interface info for each interface
    detailed_interfaces = []
    for interface in interfaces:
        if interface.get("status") == "up":
            # Get detailed interface info
            detail = task.run(
                task=netmiko_send_command,
                command_string=f"show interface {interface['interface']}",
                use_textfsm=True
            )
            
            # Get IP address and subnet mask
            ip_info = task.run(
                task=netmiko_send_command,
                command_string=f"show ip interface {interface['interface']}",
                use_textfsm=True
            )
            
            if not detail.failed and detail.result:
                interface_detail = detail.result[0]
                
                # Add subnet mask information if available
                if not ip_info.failed and ip_info.result:
                    for ip_detail in ip_info.result:
                        if "mask" in ip_detail:
                            interface_detail["subnet"] = ip_detail.get("mask")
                
                detailed_interfaces.append(interface_detail)
    
    return {
        "summary": interfaces,
        "details": detailed_interfaces
    }

def _collect_routing(task: Task) -> Dict:
    """Collect routing table from a device."""
    # Get standard routing table
    result = task.run(
        task=netmiko_send_command, 
        command_string="show ip route", 
        use_textfsm=True
    )
    
    routes = result.result
    
    # Try to get more detailed routing information
    try:
        detailed_result = task.run(
            task=netmiko_send_command,
            command_string="show ip route detail",
            use_textfsm=True
        )
        if not detailed_result.failed and detailed_result.result:
            # Merge detailed information with standard routes if possible
            routes = detailed_result.result
    except Exception:
        pass
    
    # Collect VRF routing tables if available
    vrf_result = task.run(
        task=netmiko_send_command,
        command_string="show vrf",
        use_textfsm=True
    )
    
    vrf_routes = {}
    if not vrf_result.failed and vrf_result.result:
        for vrf in vrf_result.result:
            vrf_name = vrf.get("name")
            if vrf_name:
                # Get standard VRF routing table
                vrf_route_result = task.run(
                    task=netmiko_send_command,
                    command_string=f"show ip route vrf {vrf_name}",
                    use_textfsm=True
                )
                
                if not vrf_route_result.failed:
                    vrf_routes[vrf_name] = vrf_route_result.result
                    
                    # Try to get detailed VRF routing information
                    try:
                        vrf_detailed_result = task.run(
                            task=netmiko_send_command,
                            command_string=f"show ip route vrf {vrf_name} detail",
                            use_textfsm=True
                        )
                        if not vrf_detailed_result.failed and vrf_detailed_result.result:
                            vrf_routes[vrf_name] = vrf_detailed_result.result
                    except Exception:
                        pass
    
    return {
        "default": routes,
        "vrf": vrf_routes
    }

def _collect_arp(task: Task) -> Dict:
    """Collect ARP table from a device."""
    result = task.run(
        task=netmiko_send_command, 
        command_string="show ip arp", 
        use_textfsm=True
    )
    
    arp_entries = result.result
    
    # Collect VRF ARP tables if available
    vrf_result = task.run(
        task=netmiko_send_command,
        command_string="show vrf",
        use_textfsm=True
    )
    
    vrf_arp = {}
    if not vrf_result.failed and vrf_result.result:
        for vrf in vrf_result.result:
            vrf_name = vrf.get("name")
            if vrf_name:
                vrf_arp_result = task.run(
                    task=netmiko_send_command,
                    command_string=f"show ip arp vrf {vrf_name}",
                    use_textfsm=True
                )
                if not vrf_arp_result.failed:
                    vrf_arp[vrf_name] = vrf_arp_result.result
    
    return {
        "default": arp_entries,
        "vrf": vrf_arp
    }

def _collect_cdp(task: Task) -> List:
    """Collect CDP neighbors from a device."""
    result = task.run(
        task=netmiko_send_command, 
        command_string="show cdp neighbors detail", 
        use_textfsm=True
    )
    
    return result.result

def _collect_lldp(task: Task) -> List:
    """Collect LLDP neighbors from a device."""
    result = task.run(
        task=netmiko_send_command, 
        command_string="show lldp neighbors detail", 
        use_textfsm=True
    )
    
    return result.result

def _parse_raw_routing_table(route_output: str) -> List[Dict]:
    """
    Parse raw 'show ip route' output to extract all routes.
    
    Args:
        route_output: Raw output from 'show ip route' command
        
    Returns:
        List of parsed routes
    """
    routes = []
    current_route = None
    current_subnet_info = None
    
    # Process each line of the output
    for line in route_output.splitlines():
        line = line.strip()
        
        # Skip header lines and empty lines
        if not line or "Codes:" in line or "Gateway of last resort" in line:
            continue
        
        # Look for subnet information lines like "10.0.0.0/32 is subnetted, 7 subnets"
        if "is subnetted" in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if '/' in part:
                    prefix = part.split('/')[0]
                    mask = part.split('/')[1]
                    current_subnet_info = {
                        "prefix": prefix,
                        "mask": mask
                    }
                    logger.info(f"Found subnet info: {prefix}/{mask}")
                    break
            continue
        
        # Check for route entries starting with route type (B, C, S, O, etc.)
        if (line and (line[0].isalpha() or line[0] == '*')):
            # Start a new route entry
            parts = line.split()
            if len(parts) >= 3:
                # Extract the network
                network = None
                for part in parts:
                    if '/' in part:  # Has CIDR notation
                        network = part
                        break
                    elif '.' in part and not part.startswith('via'):  # IP without CIDR
                        network = part
                        break
                
                if network:
                    # Extract protocol and next hop
                    protocol = parts[0].strip('*')
                    
                    # Find next hop (via X.X.X.X)
                    next_hop = None
                    for i, part in enumerate(parts):
                        if part == "via" and i+1 < len(parts):
                            next_hop = parts[i+1].rstrip(',')
                            break
                    
                    # If we have subnet info and this is a host route, combine them
                    if current_subnet_info and '/' not in network:
                        # This might be a host route under a subnet declaration
                        if network.startswith(current_subnet_info["prefix"].rsplit('.', 1)[0]):
                            full_network = f"{network}/{current_subnet_info['mask']}"
                            logger.info(f"Combining subnet info: {network} -> {full_network}")
                        else:
                            full_network = network
                    else:
                        full_network = network
                    
                    current_route = {
                        "protocol": protocol,
                        "network": full_network,
                        "nexthop_ip": next_hop or ""
                    }
                    routes.append(current_route)
        
        # Check for indented continuation lines (additional routes)
        elif line.startswith(" ") and "via" in line and current_route:
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "via" and i+1 < len(parts):
                    next_hop = parts[i+1].rstrip(',')
                    # Create a new route with the same network but different next hop
                    new_route = {
                        "protocol": current_route["protocol"],
                        "network": current_route["network"],
                        "nexthop_ip": next_hop
                    }
                    routes.append(new_route)
    
    return routes

def _parse_via_routes(route_output: str) -> List[Dict]:
    """
    Parse output from 'show ip route | include via' to extract routes.
    
    Args:
        route_output: Output from the command
        
    Returns:
        List of parsed routes
    """
    routes = []
    
    for line in route_output.splitlines():
        line = line.strip()
        if "via" in line:
            parts = line.split()
            
            # Extract network
            network = None
            for part in parts:
                if '/' in part or ('.' in part and not part.startswith('via')):
                    network = part
                    break
            
            # Extract protocol
            protocol = ""
            if parts and parts[0].strip('*'):
                protocol = parts[0].strip('*')
            
            # Extract next hop
            next_hop = None
            for i, part in enumerate(parts):
                if part == "via" and i+1 < len(parts):
                    next_hop = parts[i+1].rstrip(',')
                    break
            
            if network and next_hop:
                routes.append({
                    "protocol": protocol,
                    "network": network,
                    "nexthop_ip": next_hop
                })
    
    return routes

def _extract_targets(device_data: Dict, seed_host: str) -> Dict:
    """
    Extract targets (subnets and candidate IPs) from device data.
    
    Args:
        device_data: Collected device data
        seed_host: Hostname or IP of the seed device
        
    Returns:
        Dict: Targets in the required schema format
    """
    subnets: Set[str] = set()
    candidate_ips: Set[str] = set()
    
    # Extract from interfaces
    if "interfaces" in device_data:
        for interface in device_data["interfaces"].get("summary", []):
            if interface.get("ip_address") and interface.get("ip_address") != "unassigned":
                try:
                    ip = interface.get("ip_address")
                    candidate_ips.add(ip)
                    
                    # Add connected subnet if we can determine it
                    for detail in device_data["interfaces"].get("details", []):
                        if detail.get("interface") == interface.get("interface"):
                            # Try to get subnet from prefix_length
                            if detail.get("ip_address") == ip and detail.get("prefix_length"):
                                try:
                                    # Create proper network address with subnet mask
                                    iface = IPv4Interface(f"{ip}/{detail.get('prefix_length')}")
                                    subnet = str(iface.network)
                                    subnets.add(subnet)
                                    logger.info(f"Added subnet from interface: {subnet}")
                                except Exception as e:
                                    logger.error(f"Failed to create subnet from {ip}/{detail.get('prefix_length')}: {str(e)}")
                            
                            # Try to get subnet from subnet field if available
                            elif detail.get("ip_address") == ip and detail.get("subnet"):
                                try:
                                    # Create proper network address with subnet mask
                                    iface = IPv4Interface(f"{ip}/{detail.get('subnet')}")
                                    subnet = str(iface.network)
                                    subnets.add(subnet)
                                    logger.info(f"Added subnet from interface: {subnet}")
                                except Exception as e:
                                    logger.error(f"Failed to create subnet from {ip}/{detail.get('subnet')}: {str(e)}")
                except Exception as e:
                    logger.error(f"Error processing interface: {str(e)}")
    
    # Extract from routing table
    if "routing" in device_data:
        # Log raw routing table if available
        if "raw_output" in device_data["routing"]:
            logger.info("Raw routing table available for extraction")
        
        # Process routes from default VRF
        for route in device_data["routing"].get("default", []):
            # Add all networks from the routing table
            if route.get("network"):
                network = route.get("network")
                # Handle both CIDR notation and non-CIDR notation
                if '/' in network:
                    subnets.add(network)
                    logger.info(f"Added subnet from routing table: {network}")
                else:
                    # For non-CIDR notation, try to infer the subnet
                    try:
                        # For host routes like "10.0.0.1" with no mask
                        if route.get("protocol") == "B" or route.get("protocol") == "O":
                            # For BGP/OSPF routes without explicit mask, try to infer from context
                            # This is a heuristic and might need adjustment
                            if network.count('.') == 3:  # IPv4 address
                                parts = network.split('.')
                                if len(parts) == 4:
                                    if parts[3] == '0':  # Likely a /24 network
                                        subnets.add(f"{network}/24")
                                        logger.info(f"Added inferred /24 subnet: {network}/24")
                                    else:  # Host route or other
                                        # For host routes, we'll add both the host and a potential subnet
                                        subnets.add(f"{network}/32")  # Host route
                                        base_network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                                        subnets.add(f"{base_network}/24")  # Potential subnet
                                        logger.info(f"Added host route and potential subnet: {network}/32 and {base_network}/24")
                    except Exception as e:
                        logger.error(f"Error inferring subnet for {network}: {str(e)}")
            
            # Add all next hop IPs to candidate IPs
            if route.get("nexthop_ip"):
                nexthop = route.get("nexthop_ip")
                candidate_ips.add(nexthop)
                logger.info(f"Added nexthop IP: {nexthop}")
        
        # Extract from VRF routing tables
        for vrf_routes in device_data["routing"].get("vrf", {}).values():
            for route in vrf_routes:
                # Add all networks from VRF routing tables
                if route.get("network"):
                    network = route.get("network")
                    if '/' in network:
                        subnets.add(network)
                        logger.info(f"Added subnet from VRF routing: {network}")
                    else:
                        # Similar logic as above for non-CIDR notation
                        try:
                            if network.count('.') == 3:
                                parts = network.split('.')
                                if len(parts) == 4:
                                    if parts[3] == '0':
                                        subnets.add(f"{network}/24")
                                    else:
                                        subnets.add(f"{network}/32")
                                        base_network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                                        subnets.add(f"{base_network}/24")
                        except Exception:
                            pass
                
                # Add all next hop IPs to candidate IPs
                if route.get("nexthop_ip"):
                    candidate_ips.add(route.get("nexthop_ip"))
    
    # Extract from ARP table
    if "arp" in device_data:
        for entry in device_data["arp"].get("default", []):
            if entry.get("address"):
                candidate_ips.add(entry.get("address"))
        
        # Extract from VRF ARP tables
        for vrf_entries in device_data["arp"].get("vrf", {}).values():
            for entry in vrf_entries:
                if entry.get("address"):
                    candidate_ips.add(entry.get("address"))
    
    # Extract from CDP neighbors
    if "cdp" in device_data:
        for neighbor in device_data.get("cdp", []):
            if neighbor.get("management_ip"):
                candidate_ips.add(neighbor.get("management_ip"))
    
    # Extract from LLDP neighbors
    if "lldp" in device_data:
        for neighbor in device_data.get("lldp", []):
            if neighbor.get("management_ip"):
                candidate_ips.add(neighbor.get("management_ip"))
    
    # Build targets dictionary in the required schema
    return {
        "job_id": device_data.get("job_id", str(uuid.uuid4())),
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "seed_host": seed_host,
        "subnets": sorted(list(subnets)),
        "candidate_ips": sorted(list(candidate_ips))
    }
