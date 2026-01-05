"""
Config parser module for converting raw CLI configs to structured data.

This module takes the raw configurations collected by config_collector.py
and parses them into structured JSON format using vendor-specific parsers.

Output structure:
    {job_dir}/parsed_configs/{hostname}.json - Structured configuration data
"""

import asyncio
import logging
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from network_discovery.artifacts import (
    atomic_write_json,
    get_job_dir,
    log_error,
    read_json,
    update_status,
)
from network_discovery.config import DEFAULT_CONCURRENCY
from network_discovery.parsers import get_parser

logger = logging.getLogger(__name__)


async def parse_all_configs(job_id: str, concurrency: int = DEFAULT_CONCURRENCY) -> Dict:
    """
    Parse all collected configurations into structured data.
    
    This function reads raw configs from the state directory and parses them
    into structured JSON format using vendor-specific parsers.
    
    Args:
        job_id: Job identifier
        concurrency: Maximum concurrent parsing operations
        
    Returns:
        Dict: Parsing results with job_id, status, and counts
    """
    logger.info(f"Starting configuration parsing for job {job_id} with concurrency {concurrency}")
    start_time = time.time()
    
    try:
        # Update status
        update_status(
            job_id,
            "config_parser",
            "running",
            started_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Get the state directory where raw configs are stored
        state_dir = get_state_dir(job_id)
        if not state_dir.exists():
            error_msg = f"State directory not found for job {job_id}. Run config collection first."
            logger.error(error_msg)
            log_error(job_id, "config_parser", error_msg)
            
            update_status(
                job_id,
                "config_parser",
                "failed",
                error=error_msg,
                completed_at=datetime.utcnow().isoformat() + "Z"
            )
            
            return {
                "job_id": job_id,
                "status": "failed",
                "error": error_msg
            }
        
        # Find all device state files
        state_files = list(state_dir.glob("*.json"))
        logger.info(f"Found {len(state_files)} device state files to parse")
        
        if not state_files:
            logger.warning(f"No device state files found for job {job_id}")
            
            update_status(
                job_id,
                "config_parser",
                "completed",
                device_count=0,
                result_dir="parsed_configs/",
                completed_at=datetime.utcnow().isoformat() + "Z"
            )
            
            return {
                "job_id": job_id,
                "status": "completed",
                "device_count": 0,
                "result_dir": "parsed_configs/"
            }
        
        # Ensure parsed_configs directory exists
        parsed_dir = get_parsed_configs_dir(job_id)
        parsed_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created parsed configs directory at {parsed_dir}")
        
        # Parse configurations in parallel with concurrency limit
        logger.info(f"Starting parallel parsing for {len(state_files)} devices with concurrency {concurrency}")
        semaphore = asyncio.Semaphore(concurrency)
        parsing_tasks = [
            _parse_device_config(state_file, job_id, semaphore)
            for state_file in state_files
        ]
        
        logger.debug(f"Created {len(parsing_tasks)} parsing tasks")
        parsing_results = await asyncio.gather(*parsing_tasks, return_exceptions=True)
        logger.info(f"Completed all parsing tasks")
        
        # Process results
        success_count = 0
        failed_count = 0
        
        for i, result in enumerate(parsing_results):
            state_file = state_files[i]
            if isinstance(result, Exception):
                logger.error(f"Error parsing config from {state_file.name}: {str(result)}")
                failed_count += 1
            elif result.get("status") == "success":
                logger.info(f"Successfully parsed config from {state_file.name}")
                success_count += 1
            else:
                logger.warning(f"Parsing failed for {state_file.name}: {result.get('error', 'Unknown error')}")
                failed_count += 1
        
        # Calculate total time
        total_time = time.time() - start_time
        logger.info(f"Configuration parsing completed in {total_time:.2f}s. Success: {success_count}, Failed: {failed_count}")
        
        # Update status
        update_status(
            job_id,
            "config_parser",
            "completed",
            device_count=len(state_files),
            success_count=success_count,
            failed_count=failed_count,
            result_dir="parsed_configs/",
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        return {
            "job_id": job_id,
            "status": "completed",
            "device_count": len(state_files),
            "success_count": success_count,
            "failed_count": failed_count,
            "result_dir": "parsed_configs/",
            "elapsed_time": f"{total_time:.2f}s"
        }
        
    except Exception as e:
        error_msg = f"Failed to parse device configs: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        log_error(job_id, "config_parser", error_msg)
        
        # Update status to failed
        update_status(
            job_id,
            "config_parser",
            "failed",
            error=str(e),
            completed_at=datetime.utcnow().isoformat() + "Z"
        )
        
        # Calculate elapsed time
        total_time = time.time() - start_time
        logger.info(f"Configuration parsing failed after {total_time:.2f}s")
        
        return {
            "job_id": job_id,
            "status": "failed",
            "error": str(e),
            "elapsed_time": f"{total_time:.2f}s"
        }


async def parse_single_config(job_id: str, hostname: str) -> Dict:
    """
    Parse a single device configuration into structured data.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        
    Returns:
        Dict: Parsing results with job_id and status
    """
    logger.info(f"Parsing configuration for device {hostname} in job {job_id}")
    
    try:
        # Find the state file
        state_dir = get_state_dir(job_id)
        state_path = state_dir / f"{hostname}.json"
        
        # If not found by exact hostname, try to find it
        if not state_path.exists():
            for file_path in state_dir.glob("*.json"):
                state_data = read_json(file_path)
                if state_data.get("hostname") == hostname or state_data.get("ip") == hostname:
                    state_path = file_path
                    break
        
        if not state_path.exists():
            error_msg = f"No state file found for device {hostname} in job {job_id}"
            logger.error(error_msg)
            return {
                "job_id": job_id,
                "status": "failed",
                "device": hostname,
                "error": error_msg
            }
        
        # Parse the configuration
        semaphore = asyncio.Semaphore(1)
        result = await _parse_device_config(state_path, job_id, semaphore)
        
        if isinstance(result, Exception) or result.get("status") != "success":
            error_msg = str(result) if isinstance(result, Exception) else result.get("error", "Unknown error")
            logger.error(f"Failed to parse config for {hostname}: {error_msg}")
            return {
                "job_id": job_id,
                "status": "failed",
                "device": hostname,
                "error": error_msg
            }
        
        logger.info(f"Successfully parsed config for {hostname}")
        return {
            "job_id": job_id,
            "status": "success",
            "device": hostname,
            "parsed_path": result.get("parsed_path")
        }
        
    except Exception as e:
        error_msg = f"Failed to parse config for {hostname}: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return {
            "job_id": job_id,
            "status": "failed",
            "device": hostname,
            "error": str(e)
        }


async def get_parsed_config(job_id: str, hostname: str) -> Dict:
    """
    Get parsed configuration for a device.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        
    Returns:
        Dict: Parsed configuration or error information
    """
    try:
        # Find the parsed config file
        parsed_dir = get_parsed_configs_dir(job_id)
        parsed_path = parsed_dir / f"{hostname}.json"
        
        # If not found by exact hostname, try to find it
        if not parsed_path.exists():
            for file_path in parsed_dir.glob("*.json"):
                parsed_data = read_json(file_path)
                if parsed_data.get("hostname") == hostname or parsed_data.get("ip") == hostname:
                    parsed_path = file_path
                    break
        
        if not parsed_path.exists():
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"No parsed config found for device {hostname} in job {job_id}. Run config parsing first."
            }
        
        parsed_data = read_json(parsed_path)
        
        if not parsed_data:
            return {
                "job_id": job_id,
                "status": "not_found",
                "message": f"Parsed config file for device {hostname} is empty or invalid"
            }
        
        return parsed_data
        
    except Exception as e:
        error_msg = f"Failed to get parsed config: {str(e)}"
        logger.error(error_msg)
        return {
            "job_id": job_id,
            "status": "error",
            "error": str(e)
        }


async def _parse_device_config(
    state_file: Path,
    job_id: str,
    semaphore: asyncio.Semaphore
) -> Dict:
    """
    Parse a single device configuration.
    
    Args:
        state_file: Path to device state file
        job_id: Job identifier
        semaphore: Concurrency semaphore
        
    Returns:
        Dict: Parsing results
    """
    async with semaphore:
        start_time = time.time()
        hostname = state_file.stem
        
        try:
            logger.info(f"Parsing configuration for {hostname}")
            
            # Read the state file
            state_data = read_json(state_file)
            if not state_data:
                raise Exception(f"State file {state_file} is empty or invalid")
            
            # Extract required fields
            raw_config = state_data.get("running_config")
            if not raw_config:
                raise Exception(f"No running_config found in state file for {hostname}")
            
            vendor = state_data.get("vendor", "unknown")
            model = state_data.get("model", "")
            ip = state_data.get("ip", hostname)
            actual_hostname = state_data.get("hostname", hostname)
            
            # Get the appropriate parser
            try:
                parser = get_parser(vendor, model)
            except ValueError as e:
                logger.warning(f"No parser available for {vendor}, skipping {hostname}: {str(e)}")
                return {
                    "status": "skipped",
                    "hostname": actual_hostname,
                    "reason": f"No parser available for vendor: {vendor}"
                }
            
            # Parse the configuration
            logger.debug(f"Using {parser.get_parser_name()} parser for {actual_hostname}")
            parse_result = parser.parse(raw_config, actual_hostname, ip)
            
            # Save parsed configuration
            parsed_path = get_parsed_config_path(job_id, actual_hostname)
            logger.info(f"Saving parsed config to {parsed_path}")
            atomic_write_json(parse_result.to_dict(), parsed_path)
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            logger.info(f"Parsing for {actual_hostname} completed in {elapsed_time:.2f}s")
            
            # Check for errors/warnings
            if parse_result.parsing_errors:
                logger.warning(f"Parsing errors for {actual_hostname}: {parse_result.parsing_errors}")
            if parse_result.parsing_warnings:
                logger.debug(f"Parsing warnings for {actual_hostname}: {parse_result.parsing_warnings}")
            
            return {
                "status": "success",
                "hostname": actual_hostname,
                "parsed_path": str(parsed_path),
                "errors": parse_result.parsing_errors,
                "warnings": parse_result.parsing_warnings,
                "elapsed_time": f"{elapsed_time:.2f}s"
            }
            
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Failed to parse config for {hostname} after {elapsed_time:.2f}s: {str(e)}")
            logger.error(traceback.format_exc())
            
            return {
                "status": "failed",
                "hostname": hostname,
                "error": str(e),
                "elapsed_time": f"{elapsed_time:.2f}s"
            }


def get_state_dir(job_id: str) -> Path:
    """
    Get the path to the state directory for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to state directory
    """
    return get_job_dir(job_id) / "state"


def get_parsed_configs_dir(job_id: str) -> Path:
    """
    Get the path to the parsed configs directory for a job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Path: Path to parsed configs directory
    """
    parsed_dir = get_job_dir(job_id) / "parsed_configs"
    parsed_dir.mkdir(parents=True, exist_ok=True)
    return parsed_dir


def get_parsed_config_path(job_id: str, hostname: str) -> Path:
    """
    Get the path to a parsed config file.
    
    Args:
        job_id: Job identifier
        hostname: Device hostname or IP
        
    Returns:
        Path: Path to parsed config file
    """
    # Sanitize hostname for use as a filename
    safe_hostname = hostname.replace(":", "_").replace("/", "_")
    
    # Get parsed configs directory
    parsed_dir = get_parsed_configs_dir(job_id)
    
    return parsed_dir / f"{safe_hostname}.json"

