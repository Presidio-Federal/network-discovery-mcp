"""
Seeder module for network discovery.

This module collects initial network knowledge from a seed device and produces
targets.json and device state files.
"""

import json
import logging
import os
import sys
import uuid
import traceback
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
import socket
import time

from network_discovery.artifacts import (
    atomic_write_json,
    get_device_state_path,
    get_targets_path,
    log_error,
    update_status,
)
from network_discovery.config import DEFAULT_SEEDER_METHODS, get_device_states_dir, get_job_dir

# Configure logger with more detailed format
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG level for maximum verbosity

# Add a stream handler if none exists
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

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
    logger.info(f"Processing seed host: {seed_host}")
    if ":" in seed_host:
        hostname, port = seed_host.split(":", 1)
        port = int(port)
        logger.info(f"Parsed hostname: {hostname}, port: {port}")
    else:
        hostname = seed_host
        port = 22  # Default SSH port
        logger.info(f"Using hostname: {hostname} with default port: {port}")
        
    # Verify DNS resolution and basic connectivity
    try:
        logger.info(f"Attempting to resolve hostname: {hostname}")
        ip_addr = socket.gethostbyname(hostname)
        logger.info(f"Resolved {hostname} to IP: {ip_addr}")
        
        # Try a basic socket connection to verify reachability
        logger.info(f"Testing TCP connectivity to {ip_addr}:{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        start_time = time.time()
        result = s.connect_ex((ip_addr, port))
        connect_time = time.time() - start_time
        s.close()
        
        if result == 0:
            logger.info(f"TCP connection successful to {ip_addr}:{port} in {connect_time:.2f}s")
        else:
            logger.warning(f"TCP connection failed to {ip_addr}:{port} with error code: {result}")
    except socket.gaierror:
        logger.error(f"Hostname resolution failed for {hostname}")
    except Exception as e:
        logger.error(f"Connection test failed: {str(e)}")
    
    # Create temporary inventory files for Nornir
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create hosts.yaml
        hosts_file = Path(tmp_dir) / "hosts.yaml"
        host_key = hostname.replace(".", "_")  # Make a valid YAML key
        
        # Log credentials being used (without exposing password)
        logger.info(f"Using credentials - Username: {creds.get('username')}, Platform: {creds.get('platform', 'cisco_ios')}")
        
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
        
        logger.info(f"Writing Nornir hosts file to {hosts_file}")
        with open(hosts_file, 'w') as f:
            yaml.dump(hosts_data, f)
            
        logger.debug(f"Hosts file content (without password): {host_key}: {{hostname: {hostname}, port: {port}, username: {creds.get('username')}, platform: {creds.get('platform', 'cisco_ios')}, groups: [default]}}")
        
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
        logger.info("Initializing Nornir with SimpleInventory")
        try:
            nr = InitNornir(
                inventory={
                    "plugin": "SimpleInventory",
                    "options": {
                        "host_file": str(hosts_file),
                        "group_file": str(groups_file),
                        "defaults_file": str(defaults_file)
                    }
                },
                logging={
                    "enabled": True,
                    "level": "DEBUG",
                    "to_console": True,
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                }
            )
            logger.info("Nornir initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Nornir: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise
        
        device_data = {"hostname": seed_host, "collected_at": datetime.utcnow().isoformat() + "Z"}
        
        # Print inventory hosts for debugging
        host_keys = list(nr.inventory.hosts.keys())
        logger.info(f"Nornir inventory hosts: {host_keys}")
        if not host_keys:
            logger.error("No hosts found in Nornir inventory!")
        
        # Verify Nornir host configuration
        for host_name, host_obj in nr.inventory.hosts.items():
            logger.info(f"Host '{host_name}' configuration:")
            logger.info(f"  Hostname: {host_obj.hostname}")
            logger.info(f"  Platform: {host_obj.platform}")
            logger.info(f"  Port: {host_obj.port}")
            logger.info(f"  Username: {host_obj.username}")
            logger.info(f"  Password set: {'Yes' if host_obj.password else 'No'}")
        
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
                logger.info("Running test command 'show version' to verify connectivity")
                try:
                    test_result = nr.run(task=netmiko_send_command, command_string="show version")
                    
                    # Log detailed test command results
                    for host, host_result in test_result.items():
                        if host_result.failed:
                            logger.error(f"Test command failed on {host}: {host_result.exception}")
                        else:
                            logger.info(f"Test command succeeded on {host}")
                            logger.debug(f"Test command output sample (first 100 chars): {str(host_result.result)[:100]}...")
                except Exception as e:
                    logger.error(f"Exception running test command: {str(e)}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                
                # Try to collect routing table with detailed error logging
                logger.info("Attempting to collect routing table via Nornir task")
                try:
                    result = nr.run(task=_collect_routing)
                    logger.info(f"Routing collection task completed with status: {'failed' if result.failed else 'success'}")
                    
                    for host, host_result in result.items():
                        if host_result.failed:
                            logger.error(f"Failed to collect routing from {host}")
                            # Log the exception if available
                            if hasattr(host_result, 'exception') and host_result.exception:
                                logger.error(f"Routing collection exception: {str(host_result.exception)}")
                                logger.error(f"Exception traceback: {traceback.format_exc()}")
                        else:
                            logger.info(f"Successfully collected routing table from {host}")
                            if host_result.result:
                                route_count = len(host_result.result.get("default", []))
                                vrf_count = len(host_result.result.get("vrf", {}))
                                logger.info(f"Collected {route_count} routes from default VRF and data from {vrf_count} VRFs")
                            device_data["routing"] = host_result.result
                except Exception as e:
                    logger.error(f"Error in routing collection task: {str(e)}")
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    
                # Use direct connection to get raw routing table
                logger.info("Attempting direct Netmiko connection for routing table collection")
                try:
                    # Get connection from Nornir
                    if not nr.inventory.hosts:
                        logger.error("No hosts in Nornir inventory for direct connection")
                        raise ValueError("Empty Nornir inventory")
                        
                    host_key = list(nr.inventory.hosts.keys())[0]
                    host_obj = nr.inventory.hosts[host_key]
                    
                    # Create direct Netmiko connection
                    logger.info(f"Creating direct Netmiko connection to {host_obj.hostname}:{host_obj.port or 22}")
                    from netmiko import ConnectHandler
                    
                    connection_params = {
                        "device_type": creds.get("platform", "cisco_ios"),
                        "host": host_obj.hostname,
                        "username": creds.get("username"),
                        "password": creds.get("password"),
                        "port": host_obj.port or 22,
                        "session_log": "netmiko_session.log",  # Log the session for debugging
                        "verbose": True
                    }
                    
                    logger.info(f"Connection parameters: device_type={connection_params['device_type']}, host={connection_params['host']}, port={connection_params['port']}, username={connection_params['username']}")
                    
                    try:
                        logger.info("Establishing Netmiko connection...")
                        conn = ConnectHandler(**connection_params)
                        logger.info("Netmiko connection established successfully")
                        
                        # Get raw routing table
                        logger.info("Sending command: show ip route")
                        route_output = conn.send_command("show ip route")
                        logger.info(f"Raw routing table received, length: {len(route_output)} chars")
                        if len(route_output) < 100:
                            logger.warning(f"Routing table output suspiciously short: '{route_output}'")
                        else:
                            logger.debug(f"First 200 chars of routing table: {route_output[:200]}...")
                        
                        # Parse the output
                        logger.info("Parsing raw routing table output")
                        parsed_routes = _parse_raw_routing_table(route_output)
                        logger.info(f"Successfully parsed {len(parsed_routes)} routes from raw output")
                        
                        # Store both the raw output and parsed routes
                        device_data["routing"] = {
                            "default": parsed_routes,
                            "raw_output": route_output,
                            "vrf": {}
                        }
                        logger.info("Routing data stored in device_data dictionary")
                        
                        # Close the connection
                        logger.info("Closing Netmiko connection")
                        conn.disconnect()
                        logger.info("Netmiko connection closed")
                    except Exception as conn_error:
                        logger.error(f"Error during Netmiko connection or command execution: {str(conn_error)}")
                        logger.error(f"Connection traceback: {traceback.format_exc()}")
                        
                        # Try to get VRF routing tables
                        try:
                            logger.info("Attempting to collect VRF information")
                            vrf_list_output = conn.send_command("show vrf")
                            logger.info(f"VRF list command output length: {len(vrf_list_output)}")
                            
                            if "% Invalid" not in vrf_list_output and len(vrf_list_output) > 0:
                                logger.info("VRF command successful, parsing VRF names")
                                # Parse VRF list
                                vrf_names = []
                                for line in vrf_list_output.splitlines():
                                    parts = line.split()
                                    if len(parts) >= 1 and parts[0] not in ["Name", "Default", "---"] and not parts[0].startswith("-"):
                                        vrf_names.append(parts[0])
                                
                                logger.info(f"Found {len(vrf_names)} VRFs: {', '.join(vrf_names)}")
                                
                                # Get routing table for each VRF
                                for vrf in vrf_names:
                                    logger.info(f"Collecting routing table for VRF: {vrf}")
                                    vrf_route_output = conn.send_command(f"show ip route vrf {vrf}")
                                    logger.info(f"VRF {vrf} routing table length: {len(vrf_route_output)}")
                                    
                                    vrf_parsed_routes = _parse_raw_routing_table(vrf_route_output)
                                    logger.info(f"Parsed {len(vrf_parsed_routes)} routes from VRF {vrf}")
                                    
                                    device_data["routing"]["vrf"][vrf] = vrf_parsed_routes
                                    logger.info(f"Added {len(vrf_parsed_routes)} routes from VRF {vrf} to device data")
                            else:
                                logger.info("No VRFs found or command not supported on this device")
                        except Exception as e:
                            logger.warning(f"Error getting VRF routing tables: {str(e)}")
                            logger.warning(f"VRF error traceback: {traceback.format_exc()}")
                            
                except Exception as e:
                    logger.error(f"Error in direct routing table collection: {str(e)}")
                    logger.error(f"Direct collection traceback: {traceback.format_exc()}")
            except Exception as e:
                logger.error(f"Error collecting routing (outer): {str(e)}")
                logger.error(f"Outer routing collection traceback: {traceback.format_exc()}")
        
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
    logger.info("Starting to parse raw routing table output")
    routes = []
    current_route = None
    current_subnet_info = None
    
    # Process each line of the output
    line_count = 0
    for line in route_output.splitlines():
        line_count += 1
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
                    logger.debug(f"Found subnet info: {prefix}/{mask} at line {line_count}")
                    break
            continue
            
        # Debug log every 20 lines to track progress
        if line_count % 20 == 0:
            logger.debug(f"Parsing routing table line {line_count}: {line[:30]}...")
            logger.debug(f"Current route count: {len(routes)}")
        
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
                        logger.debug(f"Found network with CIDR: {part}")
                        break
                    elif '.' in part and not part.startswith('via'):  # IP without CIDR
                        network = part
                        logger.debug(f"Found network without CIDR: {part}")
                        break
                
                if network:
                    # Extract protocol and next hop
                    protocol = parts[0].strip('*')
                    logger.debug(f"Route protocol: {protocol}")
                    
                    # Find next hop (via X.X.X.X)
                    next_hop = None
                    for i, part in enumerate(parts):
                        if part == "via" and i+1 < len(parts):
                            next_hop = parts[i+1].rstrip(',')
                            logger.debug(f"Found next hop: {next_hop}")
                            break
                    
                    # If we have subnet info and this is a host route, combine them
                    if current_subnet_info and '/' not in network:
                        # This might be a host route under a subnet declaration
                        if network.startswith(current_subnet_info["prefix"].rsplit('.', 1)[0]):
                            full_network = f"{network}/{current_subnet_info['mask']}"
                            logger.debug(f"Combining subnet info: {network} -> {full_network}")
                        else:
                            full_network = network
                            logger.debug(f"Network doesn't match current subnet prefix, using as is: {network}")
                    else:
                        full_network = network
                        if '/' not in full_network:
                            logger.debug(f"No subnet info available for {network}, using as is")
                    
                    # Skip default routes - don't scan the entire internet!
                    if full_network in ["0.0.0.0/0", "::/0"]:
                        logger.info(f"Skipping default route: {full_network}")
                        continue
                    
                    # Log the route we're adding
                    logger.debug(f"Adding route: {protocol} {full_network} via {next_hop or 'direct'}")
                    
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
                    logger.debug(f"Found additional next hop: {next_hop} for network: {current_route['network']}")
                    
                    # Create a new route with the same network but different next hop
                    new_route = {
                        "protocol": current_route["protocol"],
                        "network": current_route["network"],
                        "nexthop_ip": next_hop
                    }
                    routes.append(new_route)
                    logger.debug(f"Added alternative path: {current_route['protocol']} {current_route['network']} via {next_hop}")
    
    logger.info(f"Finished parsing routing table. Found {len(routes)} total routes.")
    
    # Log a summary of the routes by protocol
    protocol_counts = {}
    for route in routes:
        proto = route.get("protocol", "unknown")
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    for proto, count in protocol_counts.items():
        logger.info(f"Protocol {proto}: {count} routes")
        
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
            
            # Skip default routes - don't scan the entire internet!
            if network in ["0.0.0.0/0", "::/0"]:
                logger.debug(f"Skipping default route: {network}")
                continue
            
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
    logger.info("Starting target extraction from device data")
    subnets: Set[str] = set()
    candidate_ips: Set[str] = set()
    
    # Extract from interfaces
    if "interfaces" in device_data:
        logger.info("Processing interfaces data for target extraction")
        interface_count = len(device_data["interfaces"].get("summary", []))
        logger.info(f"Found {interface_count} interfaces to process")
        
        for interface in device_data["interfaces"].get("summary", []):
            if interface.get("ip_address") and interface.get("ip_address") != "unassigned":
                try:
                    ip = interface.get("ip_address")
                    interface_name = interface.get("interface", "unknown")
                    logger.info(f"Processing interface {interface_name} with IP {ip}")
                    candidate_ips.add(ip)
                    logger.debug(f"Added candidate IP from interface: {ip}")
                    
                    # Add connected subnet if we can determine it
                    for detail in device_data["interfaces"].get("details", []):
                        if detail.get("interface") == interface.get("interface"):
                            logger.debug(f"Found detailed info for interface {interface_name}")
                            
                            # Try to get subnet from prefix_length
                            if detail.get("ip_address") == ip and detail.get("prefix_length"):
                                try:
                                    # Create proper network address with subnet mask
                                    prefix_length = detail.get("prefix_length")
                                    logger.debug(f"Using prefix length {prefix_length} for interface {interface_name}")
                                    iface = IPv4Interface(f"{ip}/{prefix_length}")
                                    subnet = str(iface.network)
                                    subnets.add(subnet)
                                    logger.info(f"Added subnet from interface {interface_name}: {subnet}")
                                except Exception as e:
                                    logger.error(f"Failed to create subnet from {ip}/{detail.get('prefix_length')}: {str(e)}")
                                    logger.error(f"Subnet creation error traceback: {traceback.format_exc()}")
                            
                            # Try to get subnet from subnet field if available
                            elif detail.get("ip_address") == ip and detail.get("subnet"):
                                try:
                                    # Create proper network address with subnet mask
                                    subnet_mask = detail.get("subnet")
                                    logger.debug(f"Using subnet mask {subnet_mask} for interface {interface_name}")
                                    iface = IPv4Interface(f"{ip}/{subnet_mask}")
                                    subnet = str(iface.network)
                                    subnets.add(subnet)
                                    logger.info(f"Added subnet from interface {interface_name}: {subnet}")
                                except Exception as e:
                                    logger.error(f"Failed to create subnet from {ip}/{detail.get('subnet')}: {str(e)}")
                                    logger.error(f"Subnet creation error traceback: {traceback.format_exc()}")
                except Exception as e:
                    logger.error(f"Error processing interface: {str(e)}")
                    logger.error(f"Interface processing error traceback: {traceback.format_exc()}")
    
    # Extract from routing table
    if "routing" in device_data:
        logger.info("Processing routing table data for target extraction")
        
        # Log raw routing table if available
        if "raw_output" in device_data["routing"]:
            raw_length = len(device_data["routing"].get("raw_output", ""))
            logger.info(f"Raw routing table available for extraction ({raw_length} chars)")
        
        # Process routes from default VRF
        default_routes = device_data["routing"].get("default", [])
        logger.info(f"Processing {len(default_routes)} routes from default VRF")
        
        for route in default_routes:
            # Add all networks from the routing table
            if route.get("network"):
                network = route.get("network")
                protocol = route.get("protocol", "unknown")
                
                # Handle both CIDR notation and non-CIDR notation
                if '/' in network:
                    subnets.add(network)
                    logger.info(f"Added subnet from routing table ({protocol}): {network}")
                else:
                    # For non-CIDR notation, try to infer the subnet
                    try:
                        # For host routes like "10.0.0.1" with no mask
                        if protocol == "B" or protocol == "O":
                            # For BGP/OSPF routes without explicit mask, try to infer from context
                            logger.debug(f"Attempting to infer subnet for {protocol} route: {network}")
                            
                            # This is a heuristic and might need adjustment
                            if network.count('.') == 3:  # IPv4 address
                                parts = network.split('.')
                                if len(parts) == 4:
                                    if parts[3] == '0':  # Likely a /24 network
                                        inferred_network = f"{network}/24"
                                        subnets.add(inferred_network)
                                        logger.info(f"Added inferred /24 subnet for {protocol} route: {inferred_network}")
                                    else:  # Host route or other
                                        # For host routes, we'll add both the host and a potential subnet
                                        host_route = f"{network}/32"
                                        base_network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                                        
                                        subnets.add(host_route)  # Host route
                                        subnets.add(base_network)  # Potential subnet
                                        
                                        logger.info(f"Added host route and potential subnet for {protocol} route: {host_route} and {base_network}")
                    except Exception as e:
                        logger.error(f"Error inferring subnet for {network}: {str(e)}")
                        logger.error(f"Subnet inference error traceback: {traceback.format_exc()}")
            
            # Add all next hop IPs to candidate IPs
            if route.get("nexthop_ip"):
                nexthop = route.get("nexthop_ip")
                candidate_ips.add(nexthop)
                logger.debug(f"Added nexthop IP from routing table: {nexthop}")
        
        # Extract from VRF routing tables
        vrf_count = len(device_data["routing"].get("vrf", {}))
        logger.info(f"Processing routes from {vrf_count} VRFs")
        
        for vrf_name, vrf_routes in device_data["routing"].get("vrf", {}).items():
            logger.info(f"Processing {len(vrf_routes)} routes from VRF: {vrf_name}")
            
            for route in vrf_routes:
                # Add all networks from VRF routing tables
                if route.get("network"):
                    network = route.get("network")
                    protocol = route.get("protocol", "unknown")
                    
                    if '/' in network:
                        subnets.add(network)
                        logger.info(f"Added subnet from VRF {vrf_name} ({protocol}): {network}")
                    else:
                        # Similar logic as above for non-CIDR notation
                        try:
                            if network.count('.') == 3:
                                parts = network.split('.')
                                if len(parts) == 4:
                                    if parts[3] == '0':
                                        inferred_network = f"{network}/24"
                                        subnets.add(inferred_network)
                                        logger.info(f"Added inferred /24 subnet from VRF {vrf_name}: {inferred_network}")
                                    else:
                                        host_route = f"{network}/32"
                                        base_network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                                        
                                        subnets.add(host_route)
                                        subnets.add(base_network)
                                        
                                        logger.info(f"Added host route and potential subnet from VRF {vrf_name}: {host_route} and {base_network}")
                        except Exception as e:
                            logger.error(f"Error inferring subnet for VRF route {network}: {str(e)}")
                
                # Add all next hop IPs to candidate IPs
                if route.get("nexthop_ip"):
                    nexthop = route.get("nexthop_ip")
                    candidate_ips.add(nexthop)
                    logger.debug(f"Added nexthop IP from VRF {vrf_name}: {nexthop}")
    
    # Extract from ARP table
    if "arp" in device_data:
        logger.info("Processing ARP table data for target extraction")
        arp_entries = device_data["arp"].get("default", [])
        logger.info(f"Processing {len(arp_entries)} ARP entries from default table")
        
        for entry in arp_entries:
            if entry.get("address"):
                ip = entry.get("address")
                candidate_ips.add(ip)
                logger.debug(f"Added candidate IP from ARP table: {ip}")
        
        # Extract from VRF ARP tables
        vrf_count = len(device_data["arp"].get("vrf", {}))
        logger.info(f"Processing ARP entries from {vrf_count} VRFs")
        
        for vrf_name, vrf_entries in device_data["arp"].get("vrf", {}).items():
            logger.info(f"Processing {len(vrf_entries)} ARP entries from VRF: {vrf_name}")
            
            for entry in vrf_entries:
                if entry.get("address"):
                    ip = entry.get("address")
                    candidate_ips.add(ip)
                    logger.debug(f"Added candidate IP from VRF {vrf_name} ARP table: {ip}")
    
    # Extract from CDP neighbors
    if "cdp" in device_data:
        cdp_neighbors = device_data.get("cdp", [])
        logger.info(f"Processing {len(cdp_neighbors)} CDP neighbors for target extraction")
        
        for neighbor in cdp_neighbors:
            if neighbor.get("management_ip"):
                ip = neighbor.get("management_ip")
                candidate_ips.add(ip)
                logger.info(f"Added candidate IP from CDP neighbor {neighbor.get('destination_host', 'unknown')}: {ip}")
    
    # Extract from LLDP neighbors
    if "lldp" in device_data:
        lldp_neighbors = device_data.get("lldp", [])
        logger.info(f"Processing {len(lldp_neighbors)} LLDP neighbors for target extraction")
        
        for neighbor in lldp_neighbors:
            if neighbor.get("management_ip"):
                ip = neighbor.get("management_ip")
                candidate_ips.add(ip)
                logger.info(f"Added candidate IP from LLDP neighbor {neighbor.get('neighbor', 'unknown')}: {ip}")
    
    # Build targets dictionary in the required schema
    subnet_count = len(subnets)
    ip_count = len(candidate_ips)
    logger.info(f"Target extraction complete. Found {subnet_count} subnets and {ip_count} candidate IPs")
    
    # Log a sample of the extracted targets
    if subnet_count > 0:
        sample_size = min(5, subnet_count)
        subnet_sample = list(subnets)[:sample_size]
        logger.info(f"Sample of extracted subnets: {', '.join(subnet_sample)}")
    
    if ip_count > 0:
        sample_size = min(5, ip_count)
        ip_sample = list(candidate_ips)[:sample_size]
        logger.info(f"Sample of extracted candidate IPs: {', '.join(ip_sample)}")
    
    return {
        "job_id": device_data.get("job_id", str(uuid.uuid4())),
        "collected_at": datetime.utcnow().isoformat() + "Z",
        "seed_host": seed_host,
        "subnets": sorted(list(subnets)),
        "candidate_ips": sorted(list(candidate_ips))
    }
