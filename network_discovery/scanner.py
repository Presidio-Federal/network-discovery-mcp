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
import sys
import time
import traceback
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
        logger.info(f"Loading targets from {targets_path}")
        targets = read_json(targets_path)
        if not targets:
            error_msg = f"Failed to load targets from {targets_path}"
            logger.error(error_msg)
            log_error(job_id, "scanner", error_msg)
            update_status(job_id, "scanner", "failed", error=error_msg)
            return {"job_id": job_id, "status": "failed", "error": error_msg}
        
        logger.info(f"Successfully loaded targets for job {job_id}")
        
        # IMPORTANT: Scanner explicitly must not read device_states
        # This is a security measure to ensure separation of concerns
        device_states_dir = get_job_dir(job_id) / "device_states"
        if device_states_dir.exists():
            logger.info("Scanner is ignoring device_states directory as per security policy")
        
        # Extract IPs to scan
        candidate_ips = targets.get("candidate_ips", [])
        logger.info(f"Found {len(candidate_ips)} candidate IPs in targets file")
        ips_to_scan = set(candidate_ips)
        
        # Expand subnets to individual IPs
        subnets = targets.get("subnets", [])
        logger.info(f"Found {len(subnets)} subnets in targets file")
        
        for subnet in subnets:
            try:
                logger.debug(f"Processing subnet: {subnet}")
                network = ip_network(subnet)
                # Only add hosts from reasonably sized networks
                if network.num_addresses <= 1024:  # Limit to avoid scanning huge ranges
                    host_ips = [str(ip) for ip in network.hosts()]
                    ips_to_scan.update(host_ips)
                    logger.info(f"Added {len(host_ips)} IPs from subnet {subnet}")
                else:
                    logger.warning(f"Skipping subnet {subnet} - too large ({network.num_addresses} addresses)")
            except ValueError:
                logger.warning(f"Invalid subnet format: {subnet}")
        
        # Perform the scan
        logger.info(f"Starting scan of {len(ips_to_scan)} IPs with {len(ports)} ports at concurrency {concurrency}")
        start_time = time.time()
        scan_results = await _scan_ips(list(ips_to_scan), ports, concurrency)
        scan_duration = time.time() - start_time
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Build scan output
        logger.info(f"Processing scan results for {len(scan_results)} hosts")
        scan_output = {
            "job_id": job_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "targets_count": len(ips_to_scan),
            "hosts": scan_results
        }
        
        # Save scan results
        scan_path = get_scan_path(job_id)
        logger.info(f"Saving scan results to {scan_path}")
        atomic_write_json(scan_output, scan_path)
        logger.info(f"Scan results saved successfully")
        
        # Create and save reachable hosts file
        logger.info("Extracting reachable hosts from scan results")
        reachable_hosts = [host for host in scan_results if host.get("reachable", False)]
        logger.info(f"Found {len(reachable_hosts)} reachable hosts out of {len(scan_results)} total hosts")
        
        reachable_output = {
            "job_id": job_id,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "reachable_count": len(reachable_hosts),
            "hosts": reachable_hosts
        }
        
        reachable_path = get_reachable_hosts_path(job_id)
        logger.info(f"Saving reachable hosts to {reachable_path}")
        atomic_write_json(reachable_output, reachable_path)
        logger.info("Reachable hosts saved successfully")
        
        # Update status
        reachable_count = len(reachable_hosts)
        logger.info(f"Updating job status: {reachable_count} reachable hosts out of {len(scan_results)} scanned")
        update_status(
            job_id, 
            "scanner", 
            "completed", 
            hosts_scanned=len(scan_results),
            hosts_reachable=reachable_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        logger.info(f"Job {job_id} scan completed successfully")
        
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
        logger.info(f"Updating job status: {reachable_count} reachable hosts out of {len(scan_results)} scanned")
        update_status(
            job_id, 
            "scanner", 
            "completed", 
            hosts_scanned=len(scan_results),
            hosts_reachable=reachable_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        logger.info(f"Job {job_id} scan completed successfully")
        
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
    logger.info(f"Starting scan of {len(ips)} IPs for ports {ports} with concurrency {concurrency}")
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    # First check reachability with fping if available
    reachable_ips = set()
    if FPING_AVAILABLE and ips:
        logger.info(f"Using fping to pre-check reachability of {len(ips)} IPs")
        start_time = time.time()
        reachable_ips = await _check_reachability_fping(ips)
        duration = time.time() - start_time
        logger.info(f"fping completed in {duration:.2f}s, found {len(reachable_ips)} reachable IPs")
    else:
        logger.info("fping not available, will check each IP individually")
    
    # Create tasks for each IP
    tasks = []
    scan_count = 0
    for ip in ips:
        # Only scan for open ports if the IP is reachable or if fping is not available
        if not FPING_AVAILABLE or ip in reachable_ips:
            task = _scan_ip_with_semaphore(ip, ports, semaphore)
            tasks.append(task)
            scan_count += 1
    
    logger.info(f"Created {scan_count} scan tasks")
    
    # Wait for all tasks to complete
    if tasks:
        logger.info(f"Starting port scan for {len(tasks)} IPs")
        start_time = time.time()
        scan_results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        logger.info(f"Port scanning completed in {duration:.2f}s")
        
        # Count open ports
        open_ports = sum(1 for result in scan_results for port, status in result.get("ports", {}).items() if status == "open")
        logger.info(f"Found {open_ports} open ports across {len(scan_results)} hosts")
        
        results.extend(scan_results)
    
    # Add unreachable IPs to results
    if FPING_AVAILABLE:
        unreachable_count = 0
        for ip in ips:
            if ip not in reachable_ips:
                results.append({
                    "ip": ip,
                    "reachable": False,
                    "ports": {str(port): "closed" for port in ports}
                })
                unreachable_count += 1
        
        if unreachable_count > 0:
            logger.info(f"Added {unreachable_count} unreachable IPs to results")
    
    logger.info(f"Scan completed for {len(results)} hosts")
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
    chunk_size = 250  # Increased from 100 for better performance
    total_chunks = (len(ips) + chunk_size - 1) // chunk_size
    logger.info(f"Splitting {len(ips)} IPs into {total_chunks} chunks of {chunk_size} for fping")
    
    for i in range(0, len(ips), chunk_size):
        chunk_num = i // chunk_size + 1
        chunk = ips[i:i+chunk_size]
        logger.debug(f"Processing chunk {chunk_num}/{total_chunks} with {len(chunk)} IPs")
        
        # Run fping with fast timeout
        cmd = ["fping", "-a", "-q", "-t", "200"]  # 200ms timeout for faster scanning
        cmd.extend(chunk)
        
        try:
            start_time = time.time()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            duration = time.time() - start_time
            
            # Parse output (one reachable IP per line)
            reachable_in_chunk = 0
            for line in stdout.decode().strip().split("\n"):
                ip = line.strip()
                if ip:
                    reachable_ips.add(ip)
                    reachable_in_chunk += 1
            
            logger.debug(f"Chunk {chunk_num} completed in {duration:.2f}s, found {reachable_in_chunk} reachable IPs")
            
            # Log any errors from stderr
            stderr_output = stderr.decode().strip()
            if stderr_output and not stderr_output.startswith("ICMP"):  # Ignore normal ICMP unreachable messages
                logger.debug(f"fping stderr for chunk {chunk_num}: {stderr_output}")
                
        except Exception as e:
            logger.error(f"Error running fping on chunk {chunk_num}: {str(e)}")
            logger.error(traceback.format_exc())
    
    logger.info(f"fping found {len(reachable_ips)} reachable IPs out of {len(ips)} total")
    return reachable_ips

async def _scan_ip_with_semaphore(ip: str, ports: List[int], semaphore: asyncio.Semaphore) -> Dict:
    """Scan an IP with a semaphore to limit concurrency."""
    async with semaphore:
        return await _scan_ip(ip, ports)

async def _scan_ip(ip: str, ports: List[int]) -> Dict:
    """
    Scan an IP for open ports in parallel.
    
    Args:
        ip: IP address to scan
        ports: List of ports to check
        
    Returns:
        Dict: Scan results for the IP
    """
    logger.debug(f"Scanning IP {ip} for {len(ports)} ports in parallel")
    start_time = time.time()
    
    # Check all ports in parallel
    port_check_tasks = [_check_port(ip, port) for port in ports]
    port_check_results = await asyncio.gather(*port_check_tasks, return_exceptions=True)
    
    # Process results
    port_results = {}
    open_ports = 0
    
    for port, result in zip(ports, port_check_results):
        # Handle exceptions from port checks
        if isinstance(result, Exception):
            logger.debug(f"Port check failed for {ip}:{port}: {str(result)}")
            port_results[str(port)] = "closed"
            continue
        
        # Result is just True/False now (no banner)
        is_open = result
        port_results[str(port)] = "open" if is_open else "closed"
        
        if is_open:
            open_ports += 1
            logger.debug(f"Port {port} is OPEN on {ip}")
    
    # Calculate latency (average per port, but they ran in parallel)
    scan_duration = time.time() - start_time
    latency_ms = int(scan_duration * 1000)  # Total time for parallel scan
    
    # Build result (no banner - fingerprinting will collect that)
    is_reachable = any(status == "open" for status in port_results.values())
    result = {
        "ip": ip,
        "reachable": is_reachable,
        "latency_ms": latency_ms,
        "ports": port_results
    }
    
    status = "reachable" if is_reachable else "unreachable"
    logger.debug(f"IP {ip} parallel scan completed in {scan_duration:.3f}s - {status} with {open_ports}/{len(ports)} open ports")
    
    return result

async def _check_port(ip: str, port: int) -> bool:
    """
    Check if a port is open (optimized for speed - NO banner collection).
    
    Scanner's job: Find open ports quickly.
    Fingerprinter's job: Collect banners and identify devices.
    
    Args:
        ip: IP address to check
        port: Port number to check
        
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # Create a socket and set a timeout
        logger.debug(f"Checking {ip}:{port} with timeout {CONNECT_TIMEOUT}s")
        start_time = time.time()
        
        try:
            reader, writer = await with_timeout(
                asyncio.open_connection(ip, port),
                timeout=CONNECT_TIMEOUT,
                error_message=f"Connection to {ip}:{port} timed out"
            )
            connection_time = time.time() - start_time
            logger.debug(f"Connection to {ip}:{port} successful in {connection_time:.3f}s")
            
            # Port is open - close immediately and return
            writer.close()
            await writer.wait_closed()
            
            return True
            
        except asyncio.TimeoutError:
            logger.debug(f"Connection to {ip}:{port} timed out after {CONNECT_TIMEOUT}s")
            return False
        except ConnectionRefusedError:
            logger.debug(f"Connection to {ip}:{port} refused")
            return False
        except OSError as e:
            logger.debug(f"OS error connecting to {ip}:{port}: {str(e)}")
            return False
            
    except Exception as e:
        logger.debug(f"Unexpected error checking {ip}:{port}: {str(e)}")
        return False
