"""
IP Scanner module for network discovery.

This module probes IPs/subnets for management reachability only.
It explicitly does NOT read device_states/ files - scanner must only
use targets.json or explicitly provided subnets.

Scanner explicitly must not read device_states directory for security isolation.
"""

import asyncio
import json
import logging
import os
import socket
import ssl
import subprocess
import time
import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from network_discovery.artifacts import (
    atomic_write_json,
    get_scan_path,
    get_targets_path,
    get_reachable_hosts_path,
    log_error,
    read_json,
    update_status,
)
from network_discovery.config import (
    CONNECT_TIMEOUT,
    DEFAULT_CONCURRENCY,
    DEFAULT_PORTS,
    get_job_dir,
)

logger = logging.getLogger(__name__)

# Check if fping is available
FPING_AVAILABLE = False
try:
    subprocess.run(["fping", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    FPING_AVAILABLE = True
    logger.info("fping is available and will be used for reachability checks")
except (subprocess.SubprocessError, FileNotFoundError):
    logger.info("fping not available, using Python-based reachability checks")


async def scan_from_targets(
    job_id: str,
    targets_path: Optional[str] = None,
    ports: Optional[List[int]] = None,
    concurrency: int = DEFAULT_CONCURRENCY
) -> Dict:
    """
    Scan IPs from a targets.json file.
    
    Args:
        job_id: Job identifier
        targets_path: Path to targets.json file (default: {job_dir}/targets.json)
        ports: List of ports to scan (default: [22, 443])
        concurrency: Maximum concurrent scans
        
    Note: scanner is ignoring device_states directory as per security policy
        
    Returns:
        Dict: Scan results with job_id and status
    """
    # Set default ports if not provided
    if ports is None:
        ports = DEFAULT_PORTS
    
    # Use default targets path if not provided
    if targets_path is None:
        targets_path = str(get_targets_path(job_id))
    
    # Update status to running
    update_status(job_id, "scanner", "running", started_at=datetime.utcnow().isoformat() + "Z")
    
    try:
        # Load targets
        targets = read_json(targets_path)
        if not targets:
            error_msg = f"Failed to load targets from {targets_path}"
            logger.error(error_msg)
            log_error(job_id, "scanner", error_msg)
            update_status(job_id, "scanner", "failed", error=error_msg)
            return {"job_id": job_id, "status": "failed", "error": error_msg}
        
        # IMPORTANT: Scanner explicitly must not read device_states
        # This is a security measure to ensure separation of concerns
        device_states_dir = get_job_dir(job_id) / "device_states"
        if device_states_dir.exists():
            logger.info("Scanner is ignoring device_states directory as per security policy")
        
        # Extract IPs to scan
        ips_to_scan = set(targets.get("candidate_ips", []))
        
        # Expand subnets to individual IPs
        for subnet in targets.get("subnets", []):
            try:
                network = ip_network(subnet)
                # Only add hosts from reasonably sized networks
                if network.num_addresses <= 1024:  # Limit to avoid scanning huge ranges
                    ips_to_scan.update(str(ip) for ip in network.hosts())
            except ValueError:
                logger.warning(f"Invalid subnet: {subnet}")
        
        # Perform the scan
        scan_results = await _scan_ips(list(ips_to_scan), ports, concurrency)
        
        # Build scan output
        scan_output = {
            "job_id": job_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "targets_count": len(ips_to_scan),
            "hosts": scan_results
        }
        
        # Save scan results
        scan_path = get_scan_path(job_id)
        atomic_write_json(scan_output, scan_path)
        
        # Create and save reachable hosts file
        reachable_hosts = [host for host in scan_results if host.get("reachable", False)]
        reachable_output = {
            "job_id": job_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "reachable_count": len(reachable_hosts),
            "hosts": reachable_hosts
        }
        reachable_path = get_reachable_hosts_path(job_id)
        atomic_write_json(reachable_output, reachable_path)
        
        # Update status
        reachable_count = len(reachable_hosts)
        update_status(
            job_id, 
            "scanner", 
            "completed", 
            hosts_scanned=len(scan_results),
            hosts_reachable=reachable_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "scan_path": str(scan_path),
            "hosts_scanned": len(scan_results),
            "hosts_reachable": reachable_count
        }
    except Exception as e:
        error_msg = f"Scanner failed: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "scanner", error_msg)
        update_status(job_id, "scanner", "failed", error=str(e))
        return {"job_id": job_id, "status": "failed", "error": str(e)}

async def scan_from_subnets(
    job_id: str,
    subnets: List[str],
    ports: Optional[List[int]] = None,
    concurrency: int = DEFAULT_CONCURRENCY
) -> Dict:
    """
    Scan IPs from explicitly provided subnets.
    
    Args:
        job_id: Job identifier
        subnets: List of subnets to scan
        ports: List of ports to scan (default: [22, 443])
        concurrency: Maximum concurrent scans
        
    Returns:
        Dict: Scan results with job_id and status
    """
    # Set default ports if not provided
    if ports is None:
        ports = DEFAULT_PORTS
    
    # Update status to running
    update_status(job_id, "scanner", "running", started_at=datetime.utcnow().isoformat() + "Z")
    
    try:
        # Extract IPs to scan from subnets
        ips_to_scan = set()
        for subnet in subnets:
            try:
                network = ip_network(subnet)
                # Only add hosts from reasonably sized networks
                if network.num_addresses <= 1024:  # Limit to avoid scanning huge ranges
                    ips_to_scan.update(str(ip) for ip in network.hosts())
            except ValueError:
                logger.warning(f"Invalid subnet: {subnet}")
        
        if not ips_to_scan:
            error_msg = "No valid IPs to scan from provided subnets"
            logger.error(error_msg)
            log_error(job_id, "scanner", error_msg)
            update_status(job_id, "scanner", "failed", error=error_msg)
            return {"job_id": job_id, "status": "failed", "error": error_msg}
        
        # Perform the scan
        scan_results = await _scan_ips(list(ips_to_scan), ports, concurrency)
        
        # Build scan output
        scan_output = {
            "job_id": job_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "targets_count": len(ips_to_scan),
            "hosts": scan_results
        }
        
        # Save scan results
        scan_path = get_scan_path(job_id)
        atomic_write_json(scan_output, scan_path)
        
        # Create and save reachable hosts file
        reachable_hosts = [host for host in scan_results if host.get("reachable", False)]
        reachable_output = {
            "job_id": job_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "reachable_count": len(reachable_hosts),
            "hosts": reachable_hosts
        }
        reachable_path = get_reachable_hosts_path(job_id)
        atomic_write_json(reachable_output, reachable_path)
        
        # Update status
        reachable_count = len(reachable_hosts)
        update_status(
            job_id, 
            "scanner", 
            "completed", 
            hosts_scanned=len(scan_results),
            hosts_reachable=reachable_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "scan_path": str(scan_path),
            "hosts_scanned": len(scan_results),
            "hosts_reachable": reachable_count
        }
    except Exception as e:
        error_msg = f"Scanner failed: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "scanner", error_msg)
        update_status(job_id, "scanner", "failed", error=str(e))
        return {"job_id": job_id, "status": "failed", "error": str(e)}

async def add_subnets(job_id: str, subnets: List[str]) -> Dict:
    """
    Add new subnets to an existing targets.json file.
    
    Args:
        job_id: Job identifier
        subnets: List of subnets to add
        
    Returns:
        Dict: Result with job_id and status
    """
    try:
        targets_path = get_targets_path(job_id)
        targets = read_json(targets_path)
        
        if not targets:
            error_msg = f"Failed to load targets from {targets_path}"
            logger.error(error_msg)
            log_error(job_id, "scanner", error_msg)
            return {"job_id": job_id, "status": "failed", "error": error_msg}
        
        # Add new subnets
        existing_subnets = set(targets.get("subnets", []))
        new_subnets = set(subnets)
        combined_subnets = existing_subnets.union(new_subnets)
        
        # Update targets
        targets["subnets"] = sorted(list(combined_subnets))
        targets["updated_at"] = datetime.utcnow().isoformat() + "Z"
        
        # Save updated targets
        atomic_write_json(targets, targets_path)
        
        return {
            "job_id": job_id,
            "status": "completed",
            "subnets_added": len(new_subnets - existing_subnets),
            "total_subnets": len(combined_subnets)
        }
    except Exception as e:
        error_msg = f"Failed to add subnets: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "scanner", error_msg)
        return {"job_id": job_id, "status": "failed", "error": str(e)}

def get_scan(job_id: str) -> Dict:
    """
    Get scan results for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Scan results or error
    """
    try:
        scan_path = get_scan_path(job_id)
        scan_results = read_json(scan_path)
        
        if not scan_results:
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"No scan results found for job {job_id}"
            }
        
        return scan_results
    except Exception as e:
        error_msg = f"Failed to get scan results: {str(e)}"
        logger.error(error_msg)
        return {"job_id": job_id, "status": "error", "error": str(e)}

def get_reachable_hosts(job_id: str) -> Dict:
    """
    Get only reachable hosts from scan results.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Only reachable hosts or error
    """
    try:
        # Get full scan results
        scan_results = get_scan(job_id)
        
        # Check if scan results were found
        if scan_results.get("status") in ["not_found", "error"]:
            return scan_results
        
        # Extract only reachable hosts
        reachable_hosts = [host for host in scan_results.get("hosts", []) 
                          if host.get("reachable", False)]
        
        # Create reachable hosts output
        return {
            "job_id": job_id,
            "scanned_at": scan_results.get("scanned_at", datetime.utcnow().isoformat() + "Z"),
            "reachable_count": len(reachable_hosts),
            "hosts": reachable_hosts
        }
    except Exception as e:
        error_msg = f"Failed to get reachable hosts: {str(e)}"
        logger.error(error_msg)
        return {"job_id": job_id, "status": "error", "error": str(e)}

async def _scan_ips(ips: List[str], ports: List[int], concurrency: int) -> List[Dict]:
    """
    Scan a list of IPs for open ports.
    
    Args:
        ips: List of IP addresses to scan
        ports: List of ports to check
        concurrency: Maximum concurrent scans
        
    Returns:
        List[Dict]: Scan results for each IP
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    # First check reachability with fping if available
    reachable_ips = set()
    if FPING_AVAILABLE and ips:
        reachable_ips = await _check_reachability_fping(ips)
    
    # Create tasks for each IP
    tasks = []
    for ip in ips:
        # Only scan for open ports if the IP is reachable or if fping is not available
        if not FPING_AVAILABLE or ip in reachable_ips:
            task = _scan_ip_with_semaphore(ip, ports, semaphore)
            tasks.append(task)
    
    # Wait for all tasks to complete
    if tasks:
        scan_results = await asyncio.gather(*tasks)
        results.extend(scan_results)
    
    # Add unreachable IPs to results
    if FPING_AVAILABLE:
        for ip in ips:
            if ip not in reachable_ips:
                results.append({
                    "ip": ip,
                    "reachable": False,
                    "ports": {str(port): "closed" for port in ports}
                })
    
    return results

async def _check_reachability_fping(ips: List[str]) -> Set[str]:
    """
    Check IP reachability using fping.
    
    Args:
        ips: List of IP addresses to check
        
    Returns:
        Set[str]: Set of reachable IP addresses
    """
    reachable_ips = set()
    
    # Split into chunks to avoid command line length limits
    chunk_size = 100
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i:i+chunk_size]
        
        # Run fping
        cmd = ["fping", "-a", "-q"]
        cmd.extend(chunk)
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, _ = await proc.communicate()
        
        # Parse output (one reachable IP per line)
        for line in stdout.decode().strip().split("\n"):
            ip = line.strip()
            if ip:
                reachable_ips.add(ip)
    
    return reachable_ips

async def _scan_ip_with_semaphore(ip: str, ports: List[int], semaphore: asyncio.Semaphore) -> Dict:
    """Scan an IP with a semaphore to limit concurrency."""
    async with semaphore:
        return await _scan_ip(ip, ports)

async def _scan_ip(ip: str, ports: List[int]) -> Dict:
    """
    Scan an IP for open ports.
    
    Args:
        ip: IP address to scan
        ports: List of ports to check
        
    Returns:
        Dict: Scan results for the IP
    """
    start_time = time.time()
    port_results = {}
    banner = None
    
    # Check each port
    for port in ports:
        is_open, port_banner = await _check_port(ip, port)
        port_results[str(port)] = "open" if is_open else "closed"
        
        # Store the first banner we find
        if is_open and port_banner and not banner:
            banner = port_banner
    
    # Calculate latency
    latency_ms = int((time.time() - start_time) * 1000 / len(ports))
    
    # Build result
    result = {
        "ip": ip,
        "reachable": any(status == "open" for status in port_results.values()),
        "latency_ms": latency_ms,
        "ports": port_results
    }
    
    if banner:
        result["banner"] = banner
    
    return result

async def _check_port(ip: str, port: int) -> Tuple[bool, Optional[str]]:
    """
    Check if a port is open and get a banner if available.
    
    Args:
        ip: IP address to check
        port: Port number to check
        
    Returns:
        Tuple[bool, Optional[str]]: (is_open, banner)
    """
    try:
        # Create a socket and set a timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=CONNECT_TIMEOUT
        )
        
        # Port is open, try to get a banner
        banner = None
        
        try:
            if port == 22:
                # Try to get SSH banner
                banner_data = await asyncio.wait_for(reader.read(100), timeout=1.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                
                # Only keep the first line of SSH banner
                if banner:
                    banner = banner.split('\n')[0]
            
            elif port == 443:
                # Close the current connection
                writer.close()
                await writer.wait_closed()
                
                # Try to get HTTPS certificate CN
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                try:
                    ssl_reader, ssl_writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, ssl=ssl_context),
                        timeout=CONNECT_TIMEOUT
                    )
                    
                    # Get the certificate
                    cert = ssl_writer.get_extra_info('peercert')
                    if cert:
                        for attr in cert.get('subject', []):
                            if attr[0][0] == 'commonName':
                                banner = f"CN={attr[0][1]}"
                                break
                    
                    ssl_writer.close()
                    await ssl_writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            pass
        
        # Close the connection
        if port != 443:  # Already closed for HTTPS
            writer.close()
            await writer.wait_closed()
        
        return True, banner
    
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False, None
