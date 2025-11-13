"""
Network graph builder module.

This module builds a comprehensive network graph that includes both network devices
(from Batfish) and endpoints (servers, workstations, etc.) discovered via scanning
and fingerprinting.

The graph connects endpoints to network devices using subnet inference, creating a
complete view of the network topology.
"""

import logging
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from pathlib import Path

from network_discovery.artifacts import (
    get_topology_path,
    get_reachable_hosts_path,
    get_network_graph_path,
    read_json,
    atomic_write_json,
    get_job_dir
)
from network_discovery.fingerprinter import get_fingerprints_path
from network_discovery.interface_collector import load_interface_data

logger = logging.getLogger(__name__)


def ip_in_subnet(ip_address: str, subnet: str) -> bool:
    """
    Check if an IP address is within a subnet.
    
    Args:
        ip_address: IP address to check (e.g., "10.0.1.50")
        subnet: Subnet in CIDR notation (e.g., "10.0.1.0/24")
        
    Returns:
        bool: True if IP is in subnet
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        network = ipaddress.ip_network(subnet, strict=False)
        return ip in network
    except (ValueError, ipaddress.AddressValueError):
        return False


def classify_endpoint_type(host: Dict) -> str:
    """
    Classify an endpoint based on fingerprint data.
    
    Args:
        host: Host data from fingerprints
        
    Returns:
        str: Endpoint subtype (linux_server, windows_workstation, etc.)
    """
    inference = host.get('inference', {})
    vendor = inference.get('vendor', '').lower()
    protocols = inference.get('protocols', [])
    ports = host.get('ports', {})
    
    # Check for server indicators
    if 'linux' in vendor or 'ubuntu' in vendor or 'debian' in vendor or 'centos' in vendor or 'redhat' in vendor:
        # Linux server if has SSH + other services
        if 'ssh' in protocols and (len(protocols) > 1 or len(ports) > 1):
            return 'linux_server'
        else:
            return 'linux_workstation'
    
    elif 'windows' in vendor or 'microsoft' in vendor:
        # Windows server if has RDP or SMB
        port_list = [str(p) for p in ports.keys()] if isinstance(ports, dict) else []
        if '3389' in port_list or '445' in port_list:
            return 'windows_server'
        else:
            return 'windows_workstation'
    
    elif 'vmware' in vendor or 'esxi' in vendor:
        return 'virtualization_host'
    
    elif 'hp' in vendor or 'epson' in vendor or 'canon' in vendor:
        # Check for printer ports
        port_list = [str(p) for p in ports.keys()] if isinstance(ports, dict) else []
        if '9100' in port_list or '515' in port_list:
            return 'network_printer'
    
    # Check by open ports if vendor unknown
    port_list = [str(p) for p in ports.keys()] if isinstance(ports, dict) else []
    if '9100' in port_list or '515' in port_list:
        return 'network_printer'
    
    return 'unknown_endpoint'


def parse_interface_name(interface_str: str) -> tuple:
    """
    Parse interface string from Batfish edges.
    
    Args:
        interface_str: Interface string like "device@interface" or "device[interface]"
        
    Returns:
        tuple: (device_name, interface_name)
    """
    if "@" in interface_str:
        return interface_str.split("@", 1)
    elif "[" in interface_str:
        parts = interface_str.split("[")
        device = parts[0]
        interface = interface_str.split("[")[1].replace("]", "") if len(parts) > 1 else interface_str
        return device, interface
    else:
        return interface_str, interface_str


async def build_network_graph(job_id: str) -> Dict[str, Any]:
    """
    Build comprehensive network graph from all artifacts.
    
    This function:
    1. Loads Batfish topology (network device connections)
    2. Loads fingerprints (all discovered hosts)
    3. Loads interface data (subnets and IPs)
    4. Identifies endpoints (devices not in Batfish)
    5. Infers endpoint connections using subnet matching
    6. Builds subnet map for organization
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict containing complete network graph with devices, connections, and subnets
    """
    logger.info(f"Building network graph for job {job_id}")
    start_time = datetime.utcnow()
    
    try:
        # Initialize graph structure
        graph = {
            'job_id': job_id,
            'created_at': start_time.isoformat() + 'Z',
            'version': '1.0',
            'method': 'subnet_inference',
            'devices': {},
            'connections': [],
            'subnets': {},
            'statistics': {}
        }
        
        # Load all artifacts
        artifacts_loaded = await _load_artifacts(job_id)
        
        # Step 1: Add network devices from Batfish topology
        logger.info("Adding network devices from Batfish topology")
        _add_network_devices(
            graph, 
            artifacts_loaded['topology'],
            artifacts_loaded['interfaces'],
            artifacts_loaded['fingerprints']
        )
        
        # Step 2: Add physical connections from Batfish edges
        logger.info("Adding physical connections from Batfish edges")
        _add_physical_connections(graph, artifacts_loaded['topology'])
        
        # Step 3: Add endpoints from fingerprints
        logger.info("Adding endpoints from fingerprints")
        _add_endpoints(graph, artifacts_loaded['fingerprints'], artifacts_loaded['reachable'])
        
        # Step 4: Infer endpoint connections using subnet matching
        logger.info("Inferring endpoint connections using subnet matching")
        _infer_endpoint_connections(graph, artifacts_loaded['interfaces'])
        
        # Step 5: Build subnet map
        logger.info("Building subnet map")
        _build_subnet_map(graph, artifacts_loaded['interfaces'])
        
        # Step 6: Calculate statistics
        _calculate_statistics(graph)
        
        # Calculate build duration
        end_time = datetime.utcnow()
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        # Add metadata
        graph['metadata'] = {
            'build_duration_ms': duration_ms,
            'data_sources': {
                'batfish_topology': artifacts_loaded['topology'] is not None,
                'batfish_interfaces': artifacts_loaded['interfaces'] is not None,
                'fingerprints': artifacts_loaded['fingerprints'] is not None,
                'reachable_hosts': artifacts_loaded['reachable'] is not None,
                'arp_tables': False  # Not yet implemented
            },
            'inference_methods': ['subnet_match'],
            'next_enhancements': ['arp_collection', 'mac_table_correlation']
        }
        
        # Save graph as artifact
        graph_path = get_network_graph_path(job_id)
        logger.info(f"Saving network graph to {graph_path}")
        atomic_write_json(graph, graph_path)
        
        # Verify file was created
        if not graph_path.exists():
            raise RuntimeError(f"Network graph file was not created at {graph_path}")
        
        file_size = graph_path.stat().st_size
        logger.info(f"Network graph saved successfully: {graph_path} ({file_size} bytes)")
        
        logger.info(f"Network graph built successfully in {duration_ms}ms")
        logger.info(f"Total devices: {graph['statistics']['total_devices']} "
                   f"({graph['statistics']['network_devices']} network, "
                   f"{graph['statistics']['endpoints']} endpoints)")
        
        return {
            'job_id': job_id,
            'status': 'success',
            'graph_path': str(graph_path),
            'statistics': graph['statistics'],
            'build_duration_ms': duration_ms
        }
        
    except Exception as e:
        error_msg = f"Failed to build network graph: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return {
            'job_id': job_id,
            'status': 'failed',
            'error': error_msg
        }


async def _load_artifacts(job_id: str) -> Dict[str, Any]:
    """
    Load all required artifacts for graph building.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict containing all loaded artifacts
    """
    logger.info(f"Loading artifacts for job {job_id}")
    
    artifacts = {
        'topology': None,
        'interfaces': None,
        'fingerprints': None,
        'reachable': None
    }
    
    # Load Batfish topology (edges)
    try:
        topology_path = get_topology_path(job_id)
        if topology_path.exists():
            artifacts['topology'] = read_json(topology_path)
            logger.info(f"Loaded topology with {len(artifacts['topology'].get('edges', []))} edges")
        else:
            logger.warning(f"Topology file not found at {topology_path}")
    except Exception as e:
        logger.warning(f"Could not load topology: {str(e)}")
    
    # Load interface data
    try:
        artifacts['interfaces'] = load_interface_data(job_id)
        if artifacts['interfaces'] and artifacts['interfaces'].get('status') == 'success':
            logger.info(f"Loaded {artifacts['interfaces'].get('interface_count', 0)} interfaces")
        else:
            logger.warning("Interface data not available or incomplete")
    except Exception as e:
        logger.warning(f"Could not load interface data: {str(e)}")
    
    # Load fingerprints
    try:
        fingerprints_path = get_fingerprints_path(job_id)
        if fingerprints_path.exists():
            artifacts['fingerprints'] = read_json(fingerprints_path)
            logger.info(f"Loaded fingerprints for {len(artifacts['fingerprints'].get('hosts', []))} hosts")
        else:
            logger.warning(f"Fingerprints file not found at {fingerprints_path}")
    except Exception as e:
        logger.warning(f"Could not load fingerprints: {str(e)}")
    
    # Load reachable hosts
    try:
        reachable_path = get_reachable_hosts_path(job_id)
        if reachable_path.exists():
            artifacts['reachable'] = read_json(reachable_path)
            logger.info(f"Loaded {len(artifacts['reachable'].get('hosts', []))} reachable hosts")
        else:
            logger.warning(f"Reachable hosts file not found at {reachable_path}")
    except Exception as e:
        logger.warning(f"Could not load reachable hosts: {str(e)}")
    
    return artifacts


def _add_network_devices(
    graph: Dict,
    topology: Optional[Dict],
    interfaces: Optional[Dict],
    fingerprints: Optional[Dict]
) -> None:
    """
    Add network devices from Batfish topology to the graph.
    
    Args:
        graph: Graph structure to update
        topology: Batfish topology data
        interfaces: Interface data from Batfish
        fingerprints: Fingerprint data for enrichment
    """
    if not topology or 'edges' not in topology:
        logger.warning("No topology data available, skipping network devices")
        return
    
    # Build fingerprint map for quick lookup
    fingerprint_map = {}
    if fingerprints and 'hosts' in fingerprints:
        for host in fingerprints['hosts']:
            ip = host.get('ip')
            hostname = host.get('hostname', ip)
            if ip:
                fingerprint_map[ip] = host
            if hostname:
                fingerprint_map[hostname] = host
    
    # Extract devices from edges
    devices_seen = set()
    
    for edge in topology['edges']:
        # Parse source device
        if 'Interface' in edge:
            source_device, source_intf = parse_interface_name(str(edge['Interface']))
            if source_device not in devices_seen:
                _create_network_device(graph, source_device, edge, interfaces, fingerprint_map, is_source=True)
                devices_seen.add(source_device)
        
        # Parse target device
        if 'Remote_Interface' in edge:
            target_device, target_intf = parse_interface_name(str(edge['Remote_Interface']))
            if target_device not in devices_seen:
                _create_network_device(graph, target_device, edge, interfaces, fingerprint_map, is_source=False)
                devices_seen.add(target_device)
    
    logger.info(f"Added {len(devices_seen)} network devices to graph")


def _create_network_device(
    graph: Dict,
    device_name: str,
    edge: Dict,
    interfaces: Optional[Dict],
    fingerprint_map: Dict,
    is_source: bool
) -> None:
    """
    Create a network device entry in the graph.
    
    Args:
        graph: Graph structure to update
        device_name: Device hostname
        edge: Edge data from Batfish
        interfaces: Interface data
        fingerprint_map: Map of fingerprints by IP/hostname
        is_source: Whether this is the source device in the edge
    """
    # Get device info from fingerprints if available
    device_info = fingerprint_map.get(device_name, {})
    inference = device_info.get('inference', {})
    
    # Extract IP from edge if available
    ip_key = 'IPs' if is_source else 'Remote_IPs'
    ips = edge.get(ip_key, [])
    ip_address = ips[0] if ips else device_name
    
    # Try to get better IP from fingerprints
    if device_info.get('ip'):
        ip_address = device_info['ip']
    
    # Determine device subtype
    vendor = inference.get('vendor', 'unknown').lower()
    if 'cisco' in vendor:
        subtype = 'router' if 'router' in device_name.lower() else 'switch'
    elif 'juniper' in vendor:
        subtype = 'router'
    elif 'arista' in vendor:
        subtype = 'switch'
    elif 'palo alto' in vendor or 'paloalto' in vendor:
        subtype = 'firewall'
    elif 'fortinet' in vendor:
        subtype = 'firewall'
    else:
        # Guess from hostname
        name_lower = device_name.lower()
        if 'router' in name_lower or 'core' in name_lower or 'edge' in name_lower:
            subtype = 'router'
        elif 'switch' in name_lower or 'access' in name_lower:
            subtype = 'switch'
        elif 'firewall' in name_lower or 'fw' in name_lower:
            subtype = 'firewall'
        else:
            subtype = 'unknown'
    
    # Get interfaces for this device
    device_interfaces = []
    if interfaces and interfaces.get('status') == 'success':
        device_interfaces_data = interfaces.get('devices', {}).get(device_name, [])
        for iface in device_interfaces_data:
            device_interfaces.append({
                'name': iface.get('interface'),
                'ip_address': iface.get('primary_address', '').split('/')[0] if iface.get('primary_address') else None,
                'subnet_mask': iface.get('primary_address', '').split('/')[1] if iface.get('primary_address') and '/' in iface.get('primary_address', '') else None,
                'subnet': iface.get('primary_address') if iface.get('primary_address') else None,
                'description': iface.get('description'),
                'status': 'up' if iface.get('active') else 'down',
                'vlan': iface.get('vlan'),
                'vrf': iface.get('vrf', 'default')
            })
    
    # Create device entry
    graph['devices'][device_name] = {
        'type': 'network_device',
        'subtype': subtype,
        'hostname': device_name,
        'ip_address': ip_address,
        'vendor': inference.get('vendor', 'unknown'),
        'model': inference.get('model', 'unknown'),
        'platform': inference.get('vendor', 'unknown'),
        'confidence': inference.get('confidence', 1.0),
        'source': 'batfish',
        'management_ip': ip_address,
        'interfaces': device_interfaces
    }


def _add_physical_connections(graph: Dict, topology: Optional[Dict]) -> None:
    """
    Add physical connections from Batfish edges to the graph.
    
    Args:
        graph: Graph structure to update
        topology: Batfish topology data
    """
    if not topology or 'edges' not in topology:
        logger.warning("No topology data available, skipping physical connections")
        return
    
    connection_id = 1
    
    for edge in topology['edges']:
        if 'Interface' not in edge or 'Remote_Interface' not in edge:
            continue
        
        source_device, source_intf = parse_interface_name(str(edge['Interface']))
        target_device, target_intf = parse_interface_name(str(edge['Remote_Interface']))
        
        # Extract IPs
        source_ips = edge.get('IPs', [])
        target_ips = edge.get('Remote_IPs', [])
        
        # Determine subnet from IPs
        subnet = None
        if source_ips and target_ips:
            try:
                # Try to infer subnet from the two IPs
                ip1 = ipaddress.ip_address(source_ips[0])
                ip2 = ipaddress.ip_address(target_ips[0])
                # For point-to-point links, assume /30
                if isinstance(ip1, ipaddress.IPv4Address):
                    subnet = f"{ip1}/{30}"
            except:
                pass
        
        connection = {
            'id': f"conn-{connection_id:03d}",
            'source': source_device,
            'target': target_device,
            'type': 'physical',
            'source_interface': source_intf,
            'target_interface': target_intf,
            'source_ip': source_ips[0] if source_ips else None,
            'target_ip': target_ips[0] if target_ips else None,
            'subnet': subnet,
            'confidence': 1.0,
            'method': 'batfish_layer3_edges',
            'bidirectional': True
        }
        
        graph['connections'].append(connection)
        connection_id += 1
    
    logger.info(f"Added {len(graph['connections'])} physical connections to graph")


def _add_endpoints(
    graph: Dict,
    fingerprints: Optional[Dict],
    reachable: Optional[Dict]
) -> None:
    """
    Add endpoints (non-network devices) to the graph.
    
    Args:
        graph: Graph structure to update
        fingerprints: Fingerprint data
        reachable: Reachable hosts data
    """
    if not fingerprints or 'hosts' not in fingerprints:
        logger.warning("No fingerprints available, skipping endpoints")
        return
    
    # Get list of network devices already in graph
    network_devices = set(graph['devices'].keys())
    
    endpoints_added = 0
    
    for host in fingerprints['hosts']:
        ip = host.get('ip')
        hostname = host.get('hostname', f"endpoint-{ip}")
        
        # Skip if this is a network device
        if hostname in network_devices or ip in network_devices:
            continue
        
        # Check if any network device has this IP
        is_network_device = False
        for device in graph['devices'].values():
            if device.get('ip_address') == ip or device.get('management_ip') == ip:
                is_network_device = True
                break
        
        if is_network_device:
            continue
        
        # This is an endpoint!
        inference = host.get('inference', {})
        
        # Classify endpoint type
        subtype = classify_endpoint_type(host)
        
        # Get services from open ports
        ports = host.get('ports', {})
        services = []
        if isinstance(ports, dict):
            for port, status in ports.items():
                if status == 'open':
                    services.append({
                        'port': int(port),
                        'protocol': 'tcp',
                        'service': _guess_service_name(int(port))
                    })
        
        # Create endpoint entry
        graph['devices'][hostname] = {
            'type': 'endpoint',
            'subtype': subtype,
            'hostname': hostname,
            'ip_address': ip,
            'vendor': inference.get('vendor', 'unknown'),
            'model': inference.get('model', 'unknown'),
            'platform': inference.get('vendor', 'unknown'),
            'confidence': inference.get('confidence', 0.0),
            'source': 'fingerprint' if inference else 'scan_only',
            'protocols': inference.get('protocols', []),
            'open_ports': ports,
            'services': services,
            'interfaces': [
                {
                    'name': 'eth0',
                    'ip_address': ip,
                    'subnet': None,  # Will be filled during inference
                    'inferred_gateway': None
                }
            ]
        }
        
        endpoints_added += 1
    
    logger.info(f"Added {endpoints_added} endpoints to graph")


def _guess_service_name(port: int) -> str:
    """
    Guess service name from port number.
    
    Args:
        port: Port number
        
    Returns:
        str: Service name
    """
    port_map = {
        22: 'ssh',
        23: 'telnet',
        80: 'http',
        443: 'https',
        3306: 'mysql',
        5432: 'postgresql',
        6379: 'redis',
        27017: 'mongodb',
        3389: 'ms-wbt-server',
        445: 'microsoft-ds',
        139: 'netbios-ssn',
        515: 'printer',
        9100: 'jetdirect',
        161: 'snmp',
        162: 'snmptrap'
    }
    return port_map.get(port, f'port-{port}')


def _infer_endpoint_connections(
    graph: Dict,
    interfaces: Optional[Dict]
) -> None:
    """
    Infer endpoint connections using subnet matching.
    
    Args:
        graph: Graph structure to update
        interfaces: Interface data from Batfish
    """
    if not interfaces or interfaces.get('status') != 'success':
        logger.warning("No interface data available, skipping endpoint connection inference")
        return
    
    # Build subnet map: {subnet: {device, interface, gateway_ip}}
    subnet_map = {}
    
    for device_name, device_interfaces in interfaces.get('devices', {}).items():
        for iface in device_interfaces:
            primary_addr = iface.get('primary_address')
            if primary_addr and '/' in primary_addr:
                # This interface has an IP and subnet
                ip_addr, mask = primary_addr.split('/')
                subnet = f"{ipaddress.ip_network(primary_addr, strict=False)}"
                
                subnet_map[subnet] = {
                    'device': device_name,
                    'interface': iface.get('interface'),
                    'gateway_ip': ip_addr,
                    'vlan': iface.get('vlan')
                }
    
    logger.info(f"Built subnet map with {len(subnet_map)} subnets")
    
    # Match endpoints to subnets
    connection_id = len(graph['connections']) + 1
    connections_added = 0
    
    for device_name, device in graph['devices'].items():
        if device['type'] != 'endpoint':
            continue
        
        endpoint_ip = device['ip_address']
        
        # Find matching subnet
        matched = False
        for subnet, network_info in subnet_map.items():
            if ip_in_subnet(endpoint_ip, subnet):
                # Create inferred connection
                connection = {
                    'id': f"conn-{connection_id:03d}",
                    'source': device_name,
                    'target': network_info['device'],
                    'type': 'inferred',
                    'source_interface': 'eth0',
                    'target_interface': network_info['interface'],
                    'source_ip': endpoint_ip,
                    'target_ip': network_info['gateway_ip'],
                    'subnet': subnet,
                    'confidence': 0.80,
                    'method': 'subnet_match',
                    'inference_reason': f"Endpoint IP {endpoint_ip} matches subnet {subnet} on {network_info['device']}:{network_info['interface']}",
                    'bidirectional': False
                }
                
                graph['connections'].append(connection)
                connection_id += 1
                connections_added += 1
                
                # Update endpoint interface with subnet info
                if device['interfaces']:
                    device['interfaces'][0]['subnet'] = subnet
                    device['interfaces'][0]['inferred_gateway'] = network_info['gateway_ip']
                
                matched = True
                break
        
        if not matched:
            logger.debug(f"No subnet match found for endpoint {device_name} ({endpoint_ip})")
    
    logger.info(f"Added {connections_added} inferred endpoint connections")


def _build_subnet_map(graph: Dict, interfaces: Optional[Dict]) -> None:
    """
    Build subnet map for organization.
    
    Args:
        graph: Graph structure to update
        interfaces: Interface data from Batfish
    """
    if not interfaces or interfaces.get('status') != 'success':
        logger.warning("No interface data available, skipping subnet map")
        return
    
    # Build subnets from interface data
    for device_name, device_interfaces in interfaces.get('devices', {}).items():
        for iface in device_interfaces:
            primary_addr = iface.get('primary_address')
            if primary_addr and '/' in primary_addr:
                ip_addr, mask = primary_addr.split('/')
                subnet = str(ipaddress.ip_network(primary_addr, strict=False))
                
                if subnet not in graph['subnets']:
                    graph['subnets'][subnet] = {
                        'network': subnet,
                        'gateway_device': device_name,
                        'gateway_interface': iface.get('interface'),
                        'gateway_ip': ip_addr,
                        'vlan': iface.get('vlan'),
                        'description': iface.get('description'),
                        'network_devices': [],
                        'endpoints': [],
                        'total_hosts': 0
                    }
    
    # Assign devices to subnets
    for device_name, device in graph['devices'].items():
        device_ip = device.get('ip_address')
        
        for subnet, subnet_info in graph['subnets'].items():
            if device_ip and ip_in_subnet(device_ip, subnet):
                if device['type'] == 'network_device':
                    subnet_info['network_devices'].append(device_name)
                else:
                    subnet_info['endpoints'].append(device_name)
                subnet_info['total_hosts'] += 1
    
    logger.info(f"Built subnet map with {len(graph['subnets'])} subnets")


def _calculate_statistics(graph: Dict) -> None:
    """
    Calculate graph statistics.
    
    Args:
        graph: Graph structure to update
    """
    stats = {
        'total_devices': len(graph['devices']),
        'network_devices': 0,
        'endpoints': 0,
        'linux_servers': 0,
        'linux_workstations': 0,
        'windows_servers': 0,
        'windows_workstations': 0,
        'network_printers': 0,
        'unknown_endpoints': 0,
        'physical_connections': 0,
        'inferred_connections': 0,
        'total_connections': len(graph['connections']),
        'total_subnets': len(graph['subnets']),
        'subnets_with_endpoints': 0
    }
    
    # Count device types
    for device in graph['devices'].values():
        if device['type'] == 'network_device':
            stats['network_devices'] += 1
        else:
            stats['endpoints'] += 1
            subtype = device.get('subtype', 'unknown')
            if subtype == 'linux_server':
                stats['linux_servers'] += 1
            elif subtype == 'linux_workstation':
                stats['linux_workstations'] += 1
            elif subtype == 'windows_server':
                stats['windows_servers'] += 1
            elif subtype == 'windows_workstation':
                stats['windows_workstations'] += 1
            elif subtype == 'network_printer':
                stats['network_printers'] += 1
            else:
                stats['unknown_endpoints'] += 1
    
    # Count connection types
    for connection in graph['connections']:
        if connection['type'] == 'physical':
            stats['physical_connections'] += 1
        elif connection['type'] == 'inferred':
            stats['inferred_connections'] += 1
    
    # Count subnets with endpoints
    for subnet_info in graph['subnets'].values():
        if subnet_info['endpoints']:
            stats['subnets_with_endpoints'] += 1
    
    graph['statistics'] = stats
    
    logger.info(f"Statistics: {stats['total_devices']} devices "
               f"({stats['network_devices']} network, {stats['endpoints']} endpoints), "
               f"{stats['total_connections']} connections "
               f"({stats['physical_connections']} physical, {stats['inferred_connections']} inferred)")

