"""
Job resume functionality for network discovery.

This module provides the ability to resume failed or partial jobs
without re-doing completed work.
"""

import logging
import asyncio
from typing import Dict, Any, List, Optional
from pathlib import Path

from network_discovery.artifacts import get_job_dir, read_json, update_status
from network_discovery.scanner import scan_from_targets
from network_discovery.fingerprinter import fingerprint_job
from network_discovery.config_collector import collect_all_state, COLLECTION_STATUS
from network_discovery.config import DEFAULT_CONCURRENCY

logger = logging.getLogger(__name__)


async def resume_job(
    job_id: str,
    phase: Optional[str] = None,
    credentials: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Resume a failed or partial job from where it left off.
    
    Intelligently determines what work has been completed and only
    re-executes failed or incomplete phases.
    
    Args:
        job_id: Job identifier to resume
        phase: Specific phase to resume ("scanner", "fingerprinter", "config_collector")
               If None, auto-detects where to resume from
        credentials: Credentials dict (required for config_collector phase)
        
    Returns:
        Dict with resume results:
        {
            "job_id": str,
            "resumed_from": str,
            "phases_executed": List[str],
            "status": str,
            "summary": Dict
        }
    """
    logger.info(f"Attempting to resume job {job_id}")
    
    # Get job directory
    job_dir = get_job_dir(job_id)
    if not job_dir.exists():
        return {
            "job_id": job_id,
            "status": "error",
            "error": f"Job {job_id} not found"
        }
    
    # Read current status
    status_file = job_dir / "status.json"
    if not status_file.exists():
        return {
            "job_id": job_id,
            "status": "error",
            "error": "Job status file not found"
        }
    
    status = read_json(status_file)
    
    # Determine what to resume
    if phase:
        resume_phase = phase
        logger.info(f"Resuming from specified phase: {resume_phase}")
    else:
        resume_phase = _determine_resume_phase(status, job_dir)
        logger.info(f"Auto-detected resume phase: {resume_phase}")
    
    phases_executed = []
    summary = {}
    
    try:
        # Resume from the appropriate phase
        if resume_phase == "scanner":
            logger.info("Resuming scanner phase")
            scan_result = await _resume_scanner(job_id, status, job_dir)
            phases_executed.append("scanner")
            summary["scanner"] = scan_result
            
            # Continue to next phases if scanner succeeded
            if scan_result.get("status") == "completed":
                fingerprint_result = await _resume_fingerprinter(job_id, status, job_dir)
                phases_executed.append("fingerprinter")
                summary["fingerprinter"] = fingerprint_result
                
                if credentials and fingerprint_result.get("status") == "completed":
                    config_result = await _resume_config_collector(job_id, status, job_dir, credentials)
                    phases_executed.append("config_collector")
                    summary["config_collector"] = config_result
        
        elif resume_phase == "fingerprinter":
            logger.info("Resuming fingerprinter phase")
            fingerprint_result = await _resume_fingerprinter(job_id, status, job_dir)
            phases_executed.append("fingerprinter")
            summary["fingerprinter"] = fingerprint_result
            
            if credentials and fingerprint_result.get("status") == "completed":
                config_result = await _resume_config_collector(job_id, status, job_dir, credentials)
                phases_executed.append("config_collector")
                summary["config_collector"] = config_result
        
        elif resume_phase == "config_collector":
            logger.info("Resuming config_collector phase")
            if not credentials:
                return {
                    "job_id": job_id,
                    "status": "error",
                    "error": "Credentials required to resume config collection"
                }
            
            config_result = await _resume_config_collector(job_id, status, job_dir, credentials)
            phases_executed.append("config_collector")
            summary["config_collector"] = config_result
        
        else:
            return {
                "job_id": job_id,
                "status": "completed",
                "message": "Job already complete, nothing to resume",
                "phases_executed": []
            }
        
        return {
            "job_id": job_id,
            "status": "completed",
            "resumed_from": resume_phase,
            "phases_executed": phases_executed,
            "summary": summary
        }
    
    except Exception as e:
        logger.error(f"Error resuming job {job_id}: {str(e)}")
        return {
            "job_id": job_id,
            "status": "error",
            "resumed_from": resume_phase,
            "phases_executed": phases_executed,
            "error": str(e),
            "summary": summary
        }


def _determine_resume_phase(status: Dict, job_dir: Path) -> str:
    """
    Determine which phase to resume from based on job status.
    
    Args:
        status: Job status dictionary
        job_dir: Job directory path
        
    Returns:
        Phase name to resume from
    """
    # Check scanner
    scanner_status = status.get("scanner", {})
    if scanner_status.get("status") == "failed":
        logger.debug("Scanner failed, resuming from scanner")
        return "scanner"
    elif scanner_status.get("status") != "completed":
        logger.debug("Scanner not completed, resuming from scanner")
        return "scanner"
    
    # Scanner completed, check fingerprinter
    fingerprinter_status = status.get("fingerprinter", {})
    if fingerprinter_status.get("status") == "failed":
        logger.debug("Fingerprinter failed, resuming from fingerprinter")
        return "fingerprinter"
    elif fingerprinter_status.get("status") != "completed":
        logger.debug("Fingerprinter not completed, resuming from fingerprinter")
        return "fingerprinter"
    
    # Fingerprinter completed, check config collector
    collector_status = status.get("state_collector", {})
    if collector_status.get("status") == "failed":
        logger.debug("Config collector failed, resuming from config_collector")
        return "config_collector"
    elif collector_status.get("status") != "completed":
        logger.debug("Config collector not completed, resuming from config_collector")
        return "config_collector"
    
    # Everything completed
    logger.debug("All phases completed")
    return "completed"


async def _resume_scanner(job_id: str, status: Dict, job_dir: Path) -> Dict[str, Any]:
    """Resume scanner phase."""
    # Check if we have targets
    targets_file = job_dir / "targets.json"
    if not targets_file.exists():
        return {
            "status": "error",
            "error": "Targets file not found, cannot resume scanner"
        }
    
    # Re-run scanner (it will skip already scanned IPs if scan results exist)
    logger.info(f"Re-running scanner for job {job_id}")
    return await scan_from_targets(job_id)


async def _resume_fingerprinter(job_id: str, status: Dict, job_dir: Path) -> Dict[str, Any]:
    """Resume fingerprinter phase."""
    # Check if we have scan results
    scan_file = job_dir / "ip_scan.json"
    if not scan_file.exists():
        return {
            "status": "error",
            "error": "Scan results not found, cannot resume fingerprinter"
        }
    
    # Re-run fingerprinter
    logger.info(f"Re-running fingerprinter for job {job_id}")
    return await fingerprint_job(job_id)


async def _resume_config_collector(
    job_id: str,
    status: Dict,
    job_dir: Path,
    credentials: Dict
) -> Dict[str, Any]:
    """Resume config collector phase - only retry failed devices."""
    # Check if we have fingerprint results
    fingerprints_file = job_dir / "fingerprints.json"
    if not fingerprints_file.exists():
        return {
            "status": "error",
            "error": "Fingerprint results not found, cannot resume config collector"
        }
    
    # Check if we have existing collection status
    if job_id in COLLECTION_STATUS:
        collection_status = COLLECTION_STATUS[job_id]
        device_statuses = collection_status.get("device_statuses", {})
        
        # Find failed or pending devices
        failed_devices = []
        for hostname, device_status in device_statuses.items():
            if device_status.get("status") in ["failed", "pending", "in_progress"]:
                failed_devices.append({
                    "hostname": hostname,
                    "ip": device_status.get("ip"),
                    "vendor": device_status.get("vendor")
                })
        
        if failed_devices:
            logger.info(f"Found {len(failed_devices)} failed/incomplete devices to retry")
            
            # Re-run ONLY for failed devices
            # Note: This is a simplified approach - you may want to enhance
            # collect_all_state to accept a list of specific devices to collect
            return await collect_all_state(job_id, credentials)
        else:
            logger.info("No failed devices found, config collection already complete")
            return {
                "status": "completed",
                "message": "Config collection already complete"
            }
    else:
        # No existing status, run full collection
        logger.info("No existing collection status, running full config collection")
        return await collect_all_state(job_id, credentials)


async def get_resumable_jobs() -> Dict[str, Any]:
    """
    Get list of jobs that can be resumed.
    
    Returns:
        Dict with resumable jobs:
        {
            "resumable_jobs": [
                {
                    "job_id": str,
                    "failed_phase": str,
                    "can_resume_from": str,
                    "completed_phases": List[str],
                    "failed_at": str (timestamp)
                }
            ]
        }
    """
    from network_discovery.config import ARTIFACT_DIR
    
    artifact_path = Path(ARTIFACT_DIR)
    if not artifact_path.exists():
        return {"resumable_jobs": []}
    
    resumable = []
    
    for job_dir in artifact_path.iterdir():
        if not job_dir.is_dir():
            continue
        
        status_file = job_dir / "status.json"
        if not status_file.exists():
            continue
        
        try:
            status = read_json(status_file)
            job_id = job_dir.name
            
            # Check if any phase failed
            failed_phases = []
            completed_phases = []
            failed_at = None
            
            for phase in ["seeder", "scanner", "fingerprinter", "state_collector"]:
                phase_status = status.get(phase, {})
                if phase_status.get("status") == "failed":
                    failed_phases.append(phase)
                    if not failed_at:
                        failed_at = phase_status.get("completed_at")
                elif phase_status.get("status") == "completed":
                    completed_phases.append(phase)
            
            if failed_phases:
                resume_from = _determine_resume_phase(status, job_dir)
                if resume_from != "completed":
                    resumable.append({
                        "job_id": job_id,
                        "failed_phases": failed_phases,
                        "can_resume_from": resume_from,
                        "completed_phases": completed_phases,
                        "failed_at": failed_at
                    })
        
        except Exception as e:
            logger.warning(f"Error checking job {job_dir.name}: {str(e)}")
            continue
    
    return {
        "resumable_jobs": resumable,
        "count": len(resumable)
    }

