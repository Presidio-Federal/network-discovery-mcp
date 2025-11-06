"""
Credential validation module for network discovery.

This module provides quick credential validation before starting
expensive network discovery operations.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional
import asyncssh

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

# Vendor-specific test commands (lightweight commands that verify access)
VALIDATION_COMMANDS = {
    "cisco_ios": "show version | include Software",
    "cisco_nxos": "show version | include Software",
    "cisco_xr": "show version brief",
    "arista_eos": "show version | grep Software",
    "juniper_junos": "show version brief",
    "default": "show version"
}


async def validate_credentials(
    host: str,
    username: str,
    password: str,
    platform: str = "cisco_ios",
    port: int = 22,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Quickly validate credentials against a device.
    
    This is a fast pre-check (5-15 seconds) to verify credentials work
    BEFORE starting expensive discovery operations that could take 30+ minutes.
    
    Args:
        host: Device hostname or IP
        username: SSH username
        password: SSH password
        platform: Device platform (cisco_ios, juniper_junos, etc.)
        port: SSH port (default: 22)
        timeout: Connection timeout in seconds (default: 10)
        
    Returns:
        Dict with validation results:
        {
            "valid": bool,
            "latency_ms": int,
            "vendor": str,
            "platform_correct": bool,
            "can_read_config": bool,
            "error": str (if failed),
            "suggestion": str (if failed)
        }
    """
    start_time = time.time()
    
    result = {
        "host": host,
        "platform_tested": platform,
        "valid": False,
        "latency_ms": 0,
        "vendor": "unknown",
        "platform_correct": False,
        "can_read_config": False,
    }
    
    # Parse host:port if provided
    if ":" in host:
        host, port_str = host.split(":", 1)
        port = int(port_str)
    
    logger.info(f"Validating credentials for {host}:{port} (platform: {platform})")
    
    try:
        # Attempt SSH connection
        logger.debug(f"Connecting to {host}:{port} with username '{username}'")
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                known_hosts=None,
                connect_timeout=timeout,
                **LEGACY_SSH_OPTIONS  # Support legacy devices
            ),
            timeout=timeout + 5
        )
        
        connection_time = time.time() - start_time
        logger.debug(f"SSH connection established to {host} in {connection_time:.2f}s")
        
        async with conn:
            # Try to execute a simple command
            command = VALIDATION_COMMANDS.get(platform, VALIDATION_COMMANDS["default"])
            logger.debug(f"Executing validation command: '{command}'")
            
            cmd_start = time.time()
            cmd_result = await asyncio.wait_for(
                conn.run(command),
                timeout=timeout
            )
            cmd_time = time.time() - cmd_start
            
            if cmd_result.exit_status != 0:
                logger.warning(f"Command failed on {host} with exit status {cmd_result.exit_status}")
                result["valid"] = False
                result["error"] = f"Command execution failed: {cmd_result.stderr}"
                result["suggestion"] = f"Device may not support platform '{platform}' - try a different platform"
                result["platform_correct"] = False
            else:
                # Success!
                output = cmd_result.stdout
                logger.info(f"Command succeeded on {host}, output length: {len(output)} bytes")
                
                result["valid"] = True
                result["can_read_config"] = True
                result["platform_correct"] = True
                
                # Try to detect vendor from output
                vendor = _detect_vendor_from_output(output)
                result["vendor"] = vendor
                
                # Verify platform matches vendor
                if vendor != "unknown":
                    if vendor.lower() in platform.lower():
                        result["platform_correct"] = True
                    else:
                        result["platform_correct"] = False
                        result["suggestion"] = f"Device appears to be {vendor}, but platform is set to {platform}"
            
            total_time = time.time() - start_time
            result["latency_ms"] = int(total_time * 1000)
            
            logger.info(f"Credential validation for {host} completed in {total_time:.2f}s - Valid: {result['valid']}")
            return result
            
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        logger.error(f"Connection to {host}:{port} timed out after {elapsed:.2f}s")
        result["error"] = f"Connection timeout after {elapsed:.1f}s"
        result["suggestion"] = "Check network connectivity and firewall rules"
        result["latency_ms"] = int(elapsed * 1000)
        return result
        
    except asyncssh.PermissionDenied as e:
        elapsed = time.time() - start_time
        logger.error(f"Authentication failed for {host}: {str(e)}")
        result["error"] = "Authentication failed - invalid username or password"
        result["suggestion"] = f"Verify credentials for user '{username}' on this device"
        result["latency_ms"] = int(elapsed * 1000)
        return result
        
    except asyncssh.ConnectionLost as e:
        elapsed = time.time() - start_time
        logger.error(f"Connection lost to {host}: {str(e)}")
        result["error"] = "Connection lost during validation"
        result["suggestion"] = "Device may have reset connection - check device logs"
        result["latency_ms"] = int(elapsed * 1000)
        return result
        
    except asyncssh.Error as e:
        elapsed = time.time() - start_time
        logger.error(f"SSH error for {host}: {str(e)}")
        result["error"] = f"SSH error: {str(e)}"
        result["suggestion"] = "Verify SSH is enabled and accessible on the device"
        result["latency_ms"] = int(elapsed * 1000)
        return result
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Unexpected error validating {host}: {str(e)}")
        result["error"] = f"Unexpected error: {str(e)}"
        result["suggestion"] = "Check device accessibility and credentials"
        result["latency_ms"] = int(elapsed * 1000)
        return result


def _detect_vendor_from_output(output: str) -> str:
    """
    Detect vendor from command output.
    
    Args:
        output: Command output string
        
    Returns:
        Detected vendor name or "unknown"
    """
    output_lower = output.lower()
    
    # Check for common vendor strings
    if "cisco" in output_lower:
        if "nx-os" in output_lower:
            return "cisco_nxos"
        elif "ios-xr" in output_lower or "iosxr" in output_lower:
            return "cisco_xr"
        else:
            return "cisco_ios"
    
    elif "juniper" in output_lower or "junos" in output_lower:
        return "juniper_junos"
    
    elif "arista" in output_lower:
        return "arista_eos"
    
    elif "palo alto" in output_lower:
        return "paloalto_panos"
    
    elif "fortinet" in output_lower or "fortigate" in output_lower:
        return "fortinet"
    
    elif "hp " in output_lower or "hewlett" in output_lower:
        return "hp_procurve"
    
    else:
        return "unknown"


async def validate_credentials_batch(
    devices: list[Dict[str, Any]],
    username: str,
    password: str,
    concurrency: int = 5
) -> Dict[str, Any]:
    """
    Validate credentials against multiple devices in parallel.
    
    Useful for testing credentials against a sample of devices
    before starting full discovery.
    
    Args:
        devices: List of device dicts with 'host' and optional 'platform'
        username: SSH username
        password: SSH password
        concurrency: Max parallel validations (default: 5)
        
    Returns:
        Dict with overall results:
        {
            "total_devices": int,
            "valid_count": int,
            "invalid_count": int,
            "success_rate": float,
            "results": [validation results per device]
        }
    """
    logger.info(f"Validating credentials against {len(devices)} devices")
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def validate_with_semaphore(device: Dict) -> Dict:
        async with semaphore:
            return await validate_credentials(
                host=device.get("host"),
                username=username,
                password=password,
                platform=device.get("platform", "cisco_ios"),
                port=device.get("port", 22)
            )
    
    tasks = [validate_with_semaphore(device) for device in devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Process results
    valid_count = 0
    invalid_count = 0
    processed_results = []
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Validation failed for device {devices[i].get('host')}: {str(result)}")
            invalid_count += 1
            processed_results.append({
                "host": devices[i].get("host"),
                "valid": False,
                "error": str(result)
            })
        else:
            if result.get("valid"):
                valid_count += 1
            else:
                invalid_count += 1
            processed_results.append(result)
    
    success_rate = valid_count / len(devices) if devices else 0.0
    
    return {
        "total_devices": len(devices),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "success_rate": round(success_rate, 3),
        "results": processed_results
    }

