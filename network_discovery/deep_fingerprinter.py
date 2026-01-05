"""
Deep fingerprinting module for authenticated device identification.

This module performs authenticated fingerprinting on devices that couldn't be
reliably identified through passive methods (SSH banners, HTTPS, SNMP).
It logs in and runs vendor-agnostic commands to determine the actual device type.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional

import asyncssh

from network_discovery.artifacts import (
    atomic_write_json,
    get_job_dir,
    log_error,
    read_json,
    update_status,
)
from network_discovery.config import DEFAULT_CONCURRENCY
from network_discovery.ssh_pool import get_ssh_pool

logger = logging.getLogger(__name__)

# SSH connection options for legacy device support
# Supports older devices with deprecated algorithms (ssh-rsa, etc.)
LEGACY_SSH_OPTIONS = {
    'server_host_key_algs': [
        'ssh-rsa',              # Legacy (required for ASAv, old IOS)
        'rsa-sha2-256',         # Modern RSA
        'rsa-sha2-512',
        'ssh-ed25519',          # Modern EdDSA
        'ecdsa-sha2-nistp256',  # Modern ECDSA
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521'
    ],
    'kex_algs': [
        'diffie-hellman-group-exchange-sha256',
        'diffie-hellman-group14-sha256',
        'diffie-hellman-group16-sha512',
        'diffie-hellman-group18-sha512',
        'diffie-hellman-group14-sha1',   # Legacy (required for old devices)
        'diffie-hellman-group1-sha1'     # Very old (required for very old devices)
    ],
    'encryption_algs': [
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com',
        'aes128-cbc',            # Legacy
        'aes192-cbc',            # Legacy
        'aes256-cbc',            # Legacy
        '3des-cbc'               # Very old (required for very old devices)
    ],
    'mac_algs': [
        'hmac-sha2-256',
        'hmac-sha2-512',
        'hmac-sha1'              # Legacy
    ]
}

# OS detection patterns (same as config_collector but for fingerprinting)
OS_DETECTION_PATTERNS = {
    "show version": {
        # Cisco IOS/IOS-XE
        r"Cisco IOS Software": {"vendor": "Cisco", "model": "IOS"},
        r"Cisco IOS XE Software": {"vendor": "Cisco", "model": "IOS-XE"},
        r"Cisco Nexus Operating System": {"vendor": "Cisco", "model": "NX-OS"},
        r"Cisco Adaptive Security Appliance": {"vendor": "Cisco", "model": "ASA"},
        
        # Arista EOS
        r"Arista .* EOS": {"vendor": "Arista", "model": "EOS"},
        r"Arista vEOS": {"vendor": "Arista", "model": "EOS"},
        
        # Juniper JUNOS
        r"JUNOS": {"vendor": "Juniper", "model": "JUNOS"},
        r"Juniper Networks": {"vendor": "Juniper", "model": "JUNOS"},
        
        # Palo Alto PAN-OS - Enhanced patterns
        r"PAN-OS": {"vendor": "Palo Alto", "model": "PAN-OS"},
        r"Palo Alto Networks": {"vendor": "Palo Alto", "model": "PAN-OS"},
        r"sw-version:\s*\d+\.\d+": {"vendor": "Palo Alto", "model": "PAN-OS"},  # Version info pattern
        r"model:\s*(PA-|VM-)": {"vendor": "Palo Alto", "model": "PAN-OS"},  # Model starts with PA- or VM-
        r"devicename:\s*\S+": {"vendor": "Palo Alto", "model": "PAN-OS"},  # show system info has devicename field
        
        # Fortinet
        r"FortiGate": {"vendor": "Fortinet", "model": "FortiOS"},
        
        # Huawei
        r"Huawei Versatile Routing Platform": {"vendor": "Huawei", "model": "VRP"},
        r"HUAWEI": {"vendor": "Huawei", "model": "VRP"},
    }
}


async def deep_fingerprint_job(
    job_id: str,
    creds: Dict,
    confidence_threshold: float = 0.6,
    concurrency: int = DEFAULT_CONCURRENCY
) -> Dict:
    """
    Perform deep fingerprinting on low-confidence devices.
    
    This function:
    1. Reads existing fingerprints
    2. Identifies devices with confidence below threshold or vendor="unknown"
    3. Authenticates and runs 'show version' to detect actual OS
    4. Updates fingerprints with corrected information
    
    Args:
        job_id: Job identifier
        creds: Authentication credentials
        confidence_threshold: Re-fingerprint devices below this confidence (default: 0.6)
        concurrency: Maximum concurrent connections
        
    Returns:
        Dict: Deep fingerprinting results
    """
    try:
        logger.info(f"Starting deep fingerprinting for job {job_id}")
        
        # Read existing fingerprints
        fingerprints_path = get_fingerprints_path(job_id)
        fingerprints = read_json(fingerprints_path)
        
        if not fingerprints or "hosts" not in fingerprints:
            error_msg = f"No fingerprints found for job {job_id}"
            logger.error(error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Find devices that need deep fingerprinting
        candidates = []
        for host in fingerprints["hosts"]:
            inference = host.get("inference", {})
            confidence = inference.get("confidence", 0.0)
            vendor = inference.get("vendor", "unknown")
            
            # Check if device needs deep fingerprinting
            needs_deep_fp = (
                vendor == "unknown" or 
                vendor == "Linux/Unix" or  # Generic OpenSSH devices
                confidence < confidence_threshold
            )
            
            if needs_deep_fp and host.get("ip"):
                candidates.append({
                    "ip": host["ip"],
                    "current_vendor": vendor,
                    "current_confidence": confidence,
                    "evidence": host.get("evidence", {})
                })
        
        logger.info(f"Found {len(candidates)} devices needing deep fingerprinting")
        
        if not candidates:
            return {
                "job_id": job_id,
                "status": "completed",
                "message": "No devices need deep fingerprinting",
                "devices_checked": 0,
                "devices_updated": 0
            }
        
        # Update status
        update_status(
            job_id,
            "deep_fingerprinter",
            "running",
            candidates_count=len(candidates),
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Deep fingerprint devices in parallel
        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            _deep_fingerprint_device(device, creds, semaphore)
            for device in candidates
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and update fingerprints
        updated_count = 0
        failed_count = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Deep fingerprint failed for {candidates[i]['ip']}: {str(result)}")
                failed_count += 1
                continue
            
            if result.get("detected"):
                # Update the host in fingerprints
                ip = candidates[i]["ip"]
                for host in fingerprints["hosts"]:
                    if host["ip"] == ip:
                        # Update inference with detected information
                        host["inference"].update({
                            "vendor": result["vendor"],
                            "model": result["model"],
                            "confidence": 1.0,  # High confidence from authenticated detection
                            "detection_method": "deep_fingerprint"
                        })
                        # Keep evidence for audit trail
                        host["evidence"]["deep_fingerprint"] = result.get("version_output", "")[:500]
                        updated_count += 1
                        logger.info(f"Updated {ip}: {result['vendor']} {result['model']}")
                        break
        
        # Save updated fingerprints
        atomic_write_json(fingerprints, fingerprints_path)
        
        # Update status
        update_status(
            job_id,
            "deep_fingerprinter",
            "completed",
            devices_checked=len(candidates),
            devices_updated=updated_count,
            devices_failed=failed_count,
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "devices_checked": len(candidates),
            "devices_updated": updated_count,
            "devices_failed": failed_count,
            "fingerprints_path": str(fingerprints_path)
        }
        
    except Exception as e:
        error_msg = f"Deep fingerprinting failed: {str(e)}"
        logger.error(error_msg)
        log_error(job_id, "deep_fingerprinter", error_msg)
        
        update_status(
            job_id,
            "deep_fingerprinter",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e)
        }


async def _deep_fingerprint_device(
    device: Dict,
    creds: Dict,
    semaphore: asyncio.Semaphore
) -> Dict:
    """
    Deep fingerprint a single device via authentication using connection pooling.
    
    Args:
        device: Device information
        creds: Authentication credentials
        semaphore: Concurrency semaphore
        
    Returns:
        Dict: Detection results
    """
    async with semaphore:
        ip = device["ip"]
        
        try:
            logger.debug(f"Deep fingerprinting {ip}")
            
            # Parse IP and port
            if ":" in ip:
                host, port = ip.split(":", 1)
                port = int(port)
            else:
                host = ip
                port = 22
            
            # Get pooled connection (reuses if available)
            pool = get_ssh_pool()
            pooled_conn = await pool.get_connection(
                    host=host,
                    port=port,
                    username=creds.get("username"),
                    password=creds.get("password"),
                connect_timeout=10
            )
            
            logger.debug(f"Got pooled connection to {ip} (reused={pooled_conn.use_count > 1})")
            
            try:
                conn = pooled_conn.connection
                
                # Determine which commands to try based on device vendor hint
                current_vendor = device.get("current_vendor", "unknown").lower()
                
                if "palo alto" in current_vendor or "pan" in current_vendor:
                    # Palo Alto ONLY supports 'show system info', not 'show version'
                    commands_to_try = ["show system info"]
                    logger.info(f"Detected Palo Alto hint for {ip}, using only 'show system info'")
                elif "fortinet" in current_vendor or "forti" in current_vendor:
                    # Fortinet uses 'get system status'
                    commands_to_try = ["get system status"]
                    logger.info(f"Detected Fortinet hint for {ip}, using only 'get system status'")
                else:
                    # Try common commands for Cisco/Juniper/Arista/etc
                    commands_to_try = [
                        "show version",           # Cisco, Juniper, Arista
                        "show system info",       # Palo Alto (fallback)
                        "get system status"       # Fortinet (fallback)
                    ]
                    logger.info(f"No vendor hint for {ip}, trying all commands: {commands_to_try}")
                
                output = ""
                successful_command = None
                
                for cmd in commands_to_try:
                    logger.debug(f"Trying command '{cmd}' on {ip}")
                    cmd_output = None
                    cmd_succeeded = False
                    
                    # Try direct command execution first (faster)
                    try:
                result = await asyncio.wait_for(
                            conn.run(cmd),
                    timeout=10
                )
                
                        # Check if we got valid output from direct execution
                        if result.exit_status == 0 and result.stdout and len(result.stdout) > 50:
                            # Make sure it's not an error message
                            if "Invalid user" not in result.stdout and "Permission denied" not in result.stdout:
                                cmd_output = result.stdout
                                cmd_succeeded = True
                                logger.debug(f"Command '{cmd}' succeeded on {ip} via direct execution")
                            else:
                                logger.debug(f"Direct execution of '{cmd}' returned error message, will try interactive")
                        else:
                            logger.debug(f"Direct execution of '{cmd}' failed with exit status {result.exit_status}")
                    except Exception as e:
                        logger.debug(f"Direct execution of '{cmd}' failed on {ip}: {str(e)}")
                    
                    # If direct execution didn't work, try interactive session (for Palo Alto)
                    if not cmd_succeeded:
                        try:
                            logger.info(f"Trying interactive session for '{cmd}' on {ip}")
                            # Palo Alto REQUIRES a PTY for CLI automation
                            async with conn.create_process(term_type='vt100') as process:
                                logger.info(f"Interactive process created for '{cmd}' on {ip}")
                                
                                # Send command immediately
                                process.stdin.write(f"{cmd}\n")
                                await process.stdin.drain()
                                logger.info(f"Command sent to {ip}, now reading output...")
                                
                                # Read ALL available output immediately
                                # Don't sleep - Palo Alto will close connection if we don't read!
                                cmd_output = ""
                                try:
                                    # Read in a loop until channel closes or no more data
                                    while True:
                                        try:
                                            chunk = await asyncio.wait_for(
                                                process.stdout.read(4096),
                                                timeout=10  # Long timeout for slow devices
                                            )
                                            if chunk:
                                                cmd_output += chunk
                                                logger.info(f"Read {len(chunk)} bytes, total now {len(cmd_output)}")
                                            else:
                                                # Empty read means EOF
                                                logger.info(f"Got EOF, stopping read loop")
                                                break
                                        except asyncio.TimeoutError:
                                            # No more data available
                                            logger.info(f"Timeout waiting for more data, total read: {len(cmd_output)}")
                                            break
                                except Exception as read_err:
                                    logger.error(f"Error reading output: {read_err}", exc_info=True)
                                
                                logger.info(f"Interactive session returned {len(cmd_output)} bytes for '{cmd}' on {ip}")
                                if cmd_output:
                                    logger.info(f"First 200 chars: {cmd_output[:200]}")
                                else:
                                    logger.warning(f"Interactive session returned EMPTY output for '{cmd}' on {ip}")
                                
                                # Check if output is an error message
                                if cmd_output and ("Invalid user" in cmd_output or "Permission denied" in cmd_output or "Invalid syntax" in cmd_output):
                                    logger.debug(f"Interactive '{cmd}' returned error on {ip}, trying next command")
                                    continue  # Skip to next command
                                
                                if cmd_output and len(cmd_output) > 50:
                                    cmd_succeeded = True
                                    logger.debug(f"Command '{cmd}' succeeded on {ip} via interactive session")
                        except Exception as e2:
                            logger.error(f"Interactive execution of '{cmd}' failed on {ip}: {str(e2)}", exc_info=True)
                    
                    # If we got valid output, stop trying commands
                    if cmd_succeeded and cmd_output:
                        output = cmd_output
                        successful_command = cmd
                        break
                
                if not output:
                    logger.warning(f"All commands failed on {ip}")
                    # Return connection to pool before returning error
                    await pool.return_connection(pooled_conn)
                    return {
                        "ip": ip,
                        "detected": False,
                        "reason": "No command succeeded"
                    }
                    
                    # Match against patterns
                logger.debug(f"Attempting to match patterns for {ip}, output length: {len(output)}")
                    for pattern, info in OS_DETECTION_PATTERNS["show version"].items():
                        if re.search(pattern, output, re.IGNORECASE | re.MULTILINE):
                        logger.info(f"Detected {ip} as {info['vendor']} {info.get('model', 'unknown')} using command '{successful_command}' (pattern: {pattern[:50]})")
                        # Return connection to pool
                        await pool.return_connection(pooled_conn)
                            return {
                                "ip": ip,
                                "detected": True,
                                "vendor": info["vendor"],
                                "model": info.get("model", "unknown"),
                                "version_output": output[:1000],  # First 1000 chars for evidence
                            "method": successful_command
                            }
                
                logger.warning(f"No pattern matched for {ip} in output from '{successful_command}'")
                logger.warning(f"Output preview (first 300 chars): {output[:300]}")
                # Return connection to pool
                await pool.return_connection(pooled_conn)
                return {
                    "ip": ip,
                    "detected": False,
                    "reason": "No matching pattern in output",
                    "output_preview": output[:500]
                }
            
            except Exception as cmd_error:
                # On command execution error, close connection (may be corrupted)
                logger.warning(f"Command execution failed for {ip}, closing connection")
                await pool.close_connection(pooled_conn)
                raise
                
        except asyncssh.Error as e:
            logger.debug(f"SSH failed for {ip}: {str(e)}")
            return {
                "ip": ip,
                "detected": False,
                "reason": f"SSH authentication failed: {str(e)}"
            }
        except asyncio.TimeoutError:
            logger.debug(f"Timeout connecting to {ip}")
            return {
                "ip": ip,
                "detected": False,
                "reason": "Connection timeout"
            }
        except Exception as e:
            logger.debug(f"Deep fingerprint failed for {ip}: {str(e)}")
            return {
                "ip": ip,
                "detected": False,
                "reason": str(e)
            }


def get_fingerprints_path(job_id: str):
    """Get path to fingerprints file."""
    return get_job_dir(job_id) / "fingerprints.json"

