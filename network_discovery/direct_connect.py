"""
Direct connection module for network discovery.

This module provides direct connection functions to network devices,
bypassing Nornir for troubleshooting purposes.
"""

import logging
from typing import Dict, List, Optional, Any
from netmiko import ConnectHandler

logger = logging.getLogger(__name__)

def direct_collect_routing(
    hostname: str,
    username: str,
    password: str,
    port: int = 22,
    device_type: str = "cisco_ios"
) -> Dict[str, Any]:
    """
    Collect routing information directly using Netmiko.
    
    Args:
        hostname: Device hostname or IP
        username: Username for authentication
        password: Password for authentication
        port: SSH port
        device_type: Netmiko device type
        
    Returns:
        Dict: Collected routing information
    """
    logger.debug(f"Attempting direct connection to {hostname}:{port} with device_type={device_type}")
    
    try:
        # Connection parameters
        device = {
            'device_type': device_type,
            'host': hostname,
            'username': username,
            'password': password,
            'port': port,
            'timeout': 10,  # Increase timeout
            'session_log': 'netmiko_session.log',  # Log all session activity
            'verbose': True  # Enable verbose logging
        }
        
        # Connect to the device
        logger.debug(f"Connecting to {hostname}...")
        with ConnectHandler(**device) as conn:
            logger.debug(f"Connected to {hostname}")
            
            # Get device prompt
            prompt = conn.find_prompt()
            logger.debug(f"Device prompt: {prompt}")
            
            # Test basic command
            logger.debug("Testing basic command...")
            version = conn.send_command("show version | include Version")
            logger.debug(f"Version output: {version}")
            
            # Get routing table
            logger.debug("Collecting routing table...")
            route_output = conn.send_command("show ip route")
            logger.debug(f"Routing table length: {len(route_output)} chars")
            
            # Get VRF list
            logger.debug("Checking for VRFs...")
            vrf_output = conn.send_command("show vrf")
            
            result = {
                "default": parse_raw_routing_table(route_output),
                "raw_output": route_output,
                "vrf": {}
            }
            
            # Process VRFs if available
            if "% Invalid" not in vrf_output and len(vrf_output) > 10:
                logger.debug(f"VRF output: {vrf_output}")
                vrf_names = []
                for line in vrf_output.splitlines():
                    parts = line.split()
                    if len(parts) >= 1 and parts[0] not in ["Name", "Default", "---"] and not parts[0].startswith("-"):
                        vrf_names.append(parts[0])
                
                logger.debug(f"Found VRFs: {vrf_names}")
                
                # Get routing table for each VRF
                for vrf in vrf_names:
                    logger.debug(f"Collecting routing for VRF {vrf}...")
                    vrf_route_output = conn.send_command(f"show ip route vrf {vrf}")
                    logger.debug(f"VRF {vrf} routing table length: {len(vrf_route_output)} chars")
                    result["vrf"][vrf] = parse_raw_routing_table(vrf_route_output)
            
            return result
    
    except Exception as e:
        logger.error(f"Error in direct_collect_routing: {str(e)}", exc_info=True)
        return {"error": str(e)}

def parse_raw_routing_table(route_output: str) -> List[Dict]:
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
    
    logger.debug(f"Parsing routing table output ({len(route_output)} chars)")
    
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
                    logger.debug(f"Found subnet info: {prefix}/{mask}")
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
                            logger.debug(f"Combining subnet info: {network} -> {full_network}")
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
                    logger.debug(f"Added route: {current_route}")
        
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
                    logger.debug(f"Added alternative route: {new_route}")
    
    logger.debug(f"Parsed {len(routes)} routes from routing table")
    return routes
