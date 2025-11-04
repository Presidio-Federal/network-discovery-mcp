"""
Fingerprinter module for network device identification.

This module analyzes hosts discovered by the scanner and infers likely vendor,
model, and management protocol without logging in.
"""

import asyncio
import logging
import re
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any

import asyncssh
import aiohttp

# Import PySNMP if available, but make it optional
try:
    from pysnmp.hlapi.asyncio import (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("PySNMP asyncio module not available. SNMP fingerprinting will be disabled.")

from network_discovery.artifacts import (
    atomic_write_json,
    get_scan_path,
    log_error,
    read_json,
    update_status,
)
from network_discovery.config import DEFAULT_CONCURRENCY

logger = logging.getLogger(__name__)

# Fingerprint database for device identification
FINGERPRINT_DB = {
    "ssh_banners": {
        # Cisco patterns
        r"^SSH-2.0-Cisco-1.25": {"vendor": "Cisco", "model": "IOS"},
        r"^SSH-2.0-Cisco-2.0": {"vendor": "Cisco", "model": "IOS-XE"},
        r"^SSH-2.0-Cisco": {"vendor": "Cisco"},
        
        # Arista patterns - EOS uses OpenSSH but with specific versions
        r"^SSH-2.0-OpenSSH_7\.[4-9].*Arista": {"vendor": "Arista", "model": "EOS"},
        r"^SSH-2.0-OpenSSH_8\..*Arista": {"vendor": "Arista", "model": "EOS"},
        r"^SSH-2.0-Arista": {"vendor": "Arista", "model": "EOS"},
        
        # Juniper patterns - JUNOS specific
        r"^SSH-2.0-JUNOS": {"vendor": "Juniper", "model": "JUNOS"},
        r"^SSH-2.0-Juniper": {"vendor": "Juniper", "model": "JUNOS"},
        
        # Palo Alto patterns
        r"^SSH-2.0-PanOS": {"vendor": "Palo Alto", "model": "PAN-OS"},
        r"^SSH-2.0-Palo Alto": {"vendor": "Palo Alto", "model": "PAN-OS"},
        r"^SSH-2.0-PAN-OS": {"vendor": "Palo Alto", "model": "PAN-OS"},
        
        # Other vendors
        r"^SSH-2.0-Fortinet": {"vendor": "Fortinet"},
        r"^SSH-2.0-HUAWEI": {"vendor": "Huawei"},
        r"^SSH-2.0-Nokia": {"vendor": "Nokia"},
        
        # Linux patterns (lower priority - should come last)
        r"^SSH-2.0-OpenSSH.*Debian": {"vendor": "Debian Linux"},
        r"^SSH-2.0-OpenSSH.*Ubuntu": {"vendor": "Ubuntu Linux"},
        r"^SSH-2.0-OpenSSH": {"vendor": "Linux/Unix"},
    },
    "http_server": {
        # Cisco
        "IOS-XE": {"vendor": "Cisco", "model": "IOS-XE"},
        "IOS": {"vendor": "Cisco", "model": "IOS"},
        "NX-OS": {"vendor": "Cisco", "model": "NX-OS"},
        "Cisco-ASA": {"vendor": "Cisco", "model": "ASA"},
        
        # Arista - typically uses nginx with EOS branding
        "Arista-EOS": {"vendor": "Arista", "model": "EOS"},
        "Arista": {"vendor": "Arista", "model": "EOS"},
        "nginx/Arista": {"vendor": "Arista", "model": "EOS"},
        
        # Juniper - Web UI
        "Juniper-HTTP": {"vendor": "Juniper", "model": "JUNOS"},
        "Juniper": {"vendor": "Juniper", "model": "JUNOS"},
        "lighttpd/Juniper": {"vendor": "Juniper", "model": "JUNOS"},
        
        # Palo Alto - pan-os web server
        "PAN-OS": {"vendor": "Palo Alto", "model": "PAN-OS"},
        "Palo Alto": {"vendor": "Palo Alto", "model": "PAN-OS"},
        "pan-os": {"vendor": "Palo Alto", "model": "PAN-OS"},
        
        # Other vendors
        "Fortinet": {"vendor": "Fortinet"},
        "HUAWEI": {"vendor": "Huawei"},
        
        # Generic servers (lower priority)
        "nginx": {"vendor": "NGINX"},
        "Apache": {"vendor": "Apache"},
        "Microsoft-IIS": {"vendor": "Microsoft", "model": "IIS"},
    },
    "snmp_sysdescr": {
        # Cisco
        "Cisco IOS": {"vendor": "Cisco", "model": "IOS"},
        "Cisco IOS-XE": {"vendor": "Cisco", "model": "IOS-XE"},
        "Cisco NX-OS": {"vendor": "Cisco", "model": "NX-OS"},
        
        # Arista - EOS identifies itself clearly
        "Arista Networks EOS": {"vendor": "Arista", "model": "EOS"},
        "Arista": {"vendor": "Arista", "model": "EOS"},
        
        # Juniper - JUNOS identification
        "Juniper Networks, Inc. junos": {"vendor": "Juniper", "model": "JUNOS"},
        "JUNOS": {"vendor": "Juniper", "model": "JUNOS"},
        "Juniper": {"vendor": "Juniper", "model": "JUNOS"},
        
        # Palo Alto - PAN-OS identification  
        "Palo Alto Networks": {"vendor": "Palo Alto", "model": "PAN-OS"},
        "PAN-OS": {"vendor": "Palo Alto", "model": "PAN-OS"},
        
        # Other vendors
        "Fortinet": {"vendor": "Fortinet"},
        "HUAWEI": {"vendor": "Huawei"},
        "Linux": {"vendor": "Linux/Unix"},
    },
    "tls_cn": {
        "cisco": {"vendor": "Cisco"},
        "ios": {"vendor": "Cisco"},
        "juniper": {"vendor": "Juniper"},
        "junos": {"vendor": "Juniper"},
        "arista": {"vendor": "Arista"},
        "eos": {"vendor": "Arista"},
        "paloalto": {"vendor": "Palo Alto"},
        "palo alto": {"vendor": "Palo Alto"},
        "pan-os": {"vendor": "Palo Alto"},
        "fortinet": {"vendor": "Fortinet"},
        "huawei": {"vendor": "Huawei"},
    }
}

async def fingerprint_job(
    job_id: str, 
    snmp_community: Optional[str] = None, 
    concurrency: int = DEFAULT_CONCURRENCY
) -> Dict:
    """
    Fingerprint hosts from a scan job.
    
    Args:
        job_id: Job identifier
        snmp_community: Optional SNMP community string
        concurrency: Maximum concurrent fingerprinting operations
        
    Returns:
        Dict: Fingerprinting results with job_id and status
    """
    try:
        # Get scan results
        scan_path = get_scan_path(job_id)
        scan_results = read_json(scan_path)
        
        if not scan_results:
            error_msg = f"No scan results found for job {job_id}"
            logger.error(error_msg)
            log_error(job_id, "fingerprinter", error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Update status to running
        update_status(
            job_id,
            "fingerprinter",
            "running",
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Extract reachable hosts
        reachable_hosts = [host for host in scan_results.get("hosts", []) 
                          if host.get("reachable", False)]
        
        if not reachable_hosts:
            logger.warning(f"No reachable hosts found in scan results for job {job_id}")
            
            # Create empty fingerprints
            fingerprints = {
                "job_id": job_id,
                "fingerprinted_at": datetime.utcnow().isoformat() + "Z",
                "hosts": []
            }
            
            # Save fingerprints
            fingerprints_path = get_fingerprints_path(job_id)
            atomic_write_json(fingerprints, fingerprints_path)
            
            # Update status
            update_status(
                job_id,
                "fingerprinter",
                "completed",
                hosts_count=0,
                fingerprinted_count=0,
                completed_at=datetime.utcnow().isoformat() + "Z"
            )
            
            return {
                "job_id": job_id,
                "status": "completed",
                "fingerprints_path": str(fingerprints_path),
                "hosts_count": 0,
                "fingerprinted_count": 0
            }
        
        # Fingerprint hosts with concurrency limit
        semaphore = asyncio.Semaphore(concurrency)
        fingerprint_tasks = [
            _fingerprint_host(host, semaphore, snmp_community)
            for host in reachable_hosts
        ]
        
        fingerprint_results = await asyncio.gather(*fingerprint_tasks, return_exceptions=True)
        
        # Process results
        hosts_data = []
        fingerprinted_count = 0
        
        for i, result in enumerate(fingerprint_results):
            if isinstance(result, Exception):
                logger.error(f"Error fingerprinting host {reachable_hosts[i]['ip']}: {str(result)}")
                # Add minimal info for failed hosts
                hosts_data.append({
                    "ip": reachable_hosts[i]["ip"],
                    "error": str(result)
                })
            else:
                hosts_data.append(result)
                if "inference" in result:
                    fingerprinted_count += 1
        
        # Create fingerprints output
        fingerprints = {
            "job_id": job_id,
            "fingerprinted_at": datetime.utcnow().isoformat() + "Z",
            "hosts": hosts_data
        }
        
        # Save fingerprints
        fingerprints_path = get_fingerprints_path(job_id)
        atomic_write_json(fingerprints, fingerprints_path)
        
        # Update status
        update_status(
            job_id,
            "fingerprinter",
            "completed",
            hosts_count=len(hosts_data),
            fingerprinted_count=fingerprinted_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "fingerprints_path": str(fingerprints_path),
            "hosts_count": len(hosts_data),
            "fingerprinted_count": fingerprinted_count
        }
    except Exception as e:
        error_msg = f"Failed to fingerprint hosts: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "fingerprinter", error_msg)
        
        # Update status to failed
        update_status(
            job_id,
            "fingerprinter",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }

async def _fingerprint_host(
    host: Dict, 
    semaphore: asyncio.Semaphore,
    snmp_community: Optional[str]
) -> Dict:
    """
    Fingerprint a single host.
    
    Args:
        host: Host information from scan results
        semaphore: Concurrency semaphore
        snmp_community: Optional SNMP community string
        
    Returns:
        Dict: Host fingerprint data
    """
    async with semaphore:
        ip = host["ip"]
        ports = host.get("ports", {})
        evidence = {}
        
        # Extract existing SSH banner if available
        if "banner" in host:
            evidence["ssh_banner"] = host["banner"]
        
        # Check SSH (port 22)
        if ports.get("22") == "open" and "banner" not in host:
            try:
                ssh_banner = await _get_ssh_banner(ip)
                if ssh_banner:
                    evidence["ssh_banner"] = ssh_banner
            except Exception as e:
                logger.debug(f"Failed to get SSH banner from {ip}: {str(e)}")
        
        # Check HTTPS (port 443)
        if ports.get("443") == "open":
            try:
                tls_info = await _get_tls_info(ip)
                if tls_info.get("cn"):
                    evidence["tls_cn"] = tls_info["cn"]
                if tls_info.get("server"):
                    evidence["http_server"] = tls_info["server"]
            except Exception as e:
                logger.debug(f"Failed to get TLS info from {ip}: {str(e)}")
        
        # Check SNMP if community string provided
        if snmp_community:
            try:
                snmp_info = await _get_snmp_info(ip, snmp_community)
                if snmp_info.get("sysDescr"):
                    evidence["snmp_sysdescr"] = snmp_info["sysDescr"]
                if snmp_info.get("sysObjectID"):
                    evidence["snmp_sysoid"] = snmp_info["sysObjectID"]
            except Exception as e:
                logger.debug(f"Failed to get SNMP info from {ip}: {str(e)}")
        
        # Infer device type from evidence
        inference = _infer_device_type(evidence)
        
        # Build result
        result = {
            "ip": ip,
            "evidence": evidence
        }
        
        if inference:
            result["inference"] = inference
        
        return result

async def _get_ssh_banner(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Get SSH banner from a host without authentication.
    
    Args:
        ip: IP address
        timeout: Connection timeout in seconds
        
    Returns:
        str or None: SSH banner or None if not available
    """
    try:
        # Use asyncssh to get the banner
        banner = await asyncio.wait_for(
            asyncssh.get_server_banner(ip),
            timeout=timeout
        )
        return banner
    except asyncio.TimeoutError:
        logger.debug(f"SSH banner retrieval timed out for {ip}")
        return None
    except Exception as e:
        logger.debug(f"Failed to get SSH banner from {ip}: {str(e)}")
        return None

async def _get_tls_info(ip: str, port: int = 443, timeout: float = 2.0) -> Dict:
    """
    Get TLS certificate information and HTTP server header.
    
    Args:
        ip: IP address
        port: HTTPS port (default: 443)
        timeout: Connection timeout in seconds
        
    Returns:
        Dict: TLS and HTTP server information
    """
    result = {}
    
    # Get TLS certificate info
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context),
            timeout=timeout
        )
        
        # Get the certificate
        cert = writer.get_extra_info('peercert')
        if cert:
            for attr in cert.get('subject', []):
                if attr[0][0] == 'commonName':
                    result["cn"] = attr[0][1]
                    break
        
        # Try to get HTTP server header
        try:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            # Extract Server header
            server_match = re.search(r'Server: ([^\r\n]+)', response_text)
            if server_match:
                result["server"] = server_match.group(1)
        except Exception:
            pass
        
        # Close the connection
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        
        return result
    except Exception as e:
        logger.debug(f"Failed to get TLS info from {ip}: {str(e)}")
        return result

async def _get_snmp_info(ip: str, community: str, port: int = 161, timeout: float = 2.0) -> Dict:
    """
    Get SNMP system description and object ID.
    
    Args:
        ip: IP address
        community: SNMP community string
        port: SNMP port (default: 161)
        timeout: Connection timeout in seconds
        
    Returns:
        Dict: SNMP information
    """
    result = {}
    
    # Skip SNMP if not available
    if not SNMP_AVAILABLE:
        logger.debug("SNMP functionality not available. Skipping SNMP fingerprinting.")
        return result
    
    try:
        # Create SNMP engine
        snmp_engine = SnmpEngine()
        
        # Get sysDescr.0
        error_indication, error_status, error_index, var_binds = await getCmd(
            snmp_engine,
            CommunityData(community),
            UdpTransportTarget((ip, port), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        )
        
        if error_indication or error_status:
            logger.debug(f"SNMP error for {ip}: {error_indication or error_status}")
        else:
            for var_bind in var_binds:
                result["sysDescr"] = str(var_bind[1])
        
        # Get sysObjectID.0
        error_indication, error_status, error_index, var_binds = await getCmd(
            snmp_engine,
            CommunityData(community),
            UdpTransportTarget((ip, port), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysObjectID', 0))
        )
        
        if error_indication or error_status:
            logger.debug(f"SNMP error for {ip}: {error_indication or error_status}")
        else:
            for var_bind in var_binds:
                result["sysObjectID"] = str(var_bind[1])
        
        return result
    except Exception as e:
        logger.debug(f"Failed to get SNMP info from {ip}: {str(e)}")
        return result

def _infer_device_type(evidence: Dict) -> Dict:
    """
    Infer device type from collected evidence.
    
    Args:
        evidence: Evidence collected from the device
        
    Returns:
        Dict: Inference with vendor, model, protocols and confidence
    """
    inference = {
        "vendor": "unknown",
        "model": "unknown",
        "protocols": [],
        "confidence": 0.0
    }
    
    # Track matched vendors for confidence scoring
    vendor_matches = {}
    model_matches = {}
    
    # Check SSH banner
    if "ssh_banner" in evidence:
        inference["protocols"].append("ssh")
        banner = evidence["ssh_banner"]
        
        for pattern, info in FINGERPRINT_DB["ssh_banners"].items():
            if re.search(pattern, banner):
                vendor = info.get("vendor")
                if vendor:
                    vendor_matches[vendor] = vendor_matches.get(vendor, 0) + 0.4
                
                model = info.get("model")
                if model:
                    model_matches[model] = model_matches.get(model, 0) + 0.4
    
    # Check HTTP server header
    if "http_server" in evidence:
        inference["protocols"].append("https")
        server = evidence["http_server"]
        
        for pattern, info in FINGERPRINT_DB["http_server"].items():
            if pattern in server:
                vendor = info.get("vendor")
                if vendor:
                    vendor_matches[vendor] = vendor_matches.get(vendor, 0) + 0.2
                
                model = info.get("model")
                if model:
                    model_matches[model] = model_matches.get(model, 0) + 0.2
    
    # Check TLS CN
    if "tls_cn" in evidence:
        cn = evidence["tls_cn"].lower()
        
        for pattern, info in FINGERPRINT_DB["tls_cn"].items():
            if pattern in cn:
                vendor = info.get("vendor")
                if vendor:
                    vendor_matches[vendor] = vendor_matches.get(vendor, 0) + 0.2
                
                model = info.get("model")
                if model:
                    model_matches[model] = model_matches.get(model, 0) + 0.2
    
    # Check SNMP sysDescr
    if "snmp_sysdescr" in evidence:
        inference["protocols"].append("snmp")
        sysdescr = evidence["snmp_sysdescr"]
        
        for pattern, info in FINGERPRINT_DB["snmp_sysdescr"].items():
            if pattern in sysdescr:
                vendor = info.get("vendor")
                if vendor:
                    vendor_matches[vendor] = vendor_matches.get(vendor, 0) + 0.4
                
                model = info.get("model")
                if model:
                    model_matches[model] = model_matches.get(model, 0) + 0.4
    
    # Determine most likely vendor and model
    if vendor_matches:
        top_vendor = max(vendor_matches.items(), key=lambda x: x[1])
        inference["vendor"] = top_vendor[0]
        inference["confidence"] = min(top_vendor[1], 1.0)  # Cap at 1.0
    
    if model_matches:
        top_model = max(model_matches.items(), key=lambda x: x[1])
        inference["model"] = top_model[0]
    
    # Deduplicate protocols
    inference["protocols"] = list(set(inference["protocols"]))
    
    return inference

def get_fingerprints_path(job_id: str) -> str:
    """
    Get the path to the fingerprints.json file for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        str: Path to fingerprints.json
    """
    from pathlib import Path
    from network_discovery.config import get_job_dir
    
    return get_job_dir(job_id) / "fingerprints.json"

def get_fingerprints(job_id: str) -> Dict:
    """
    Get fingerprinting results for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict: Fingerprinting results or error information
    """
    try:
        fingerprints_path = get_fingerprints_path(job_id)
        fingerprints = read_json(fingerprints_path)
        
        if not fingerprints:
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"No fingerprinting results found for job {job_id}"
            }
        
        return fingerprints
    except Exception as e:
        error_msg = f"Failed to get fingerprinting results: {str(e)}"
        logger.error(error_msg)
        return {
            "job_id": job_id,
            "status": "error",
            "error": str(e)
        }
