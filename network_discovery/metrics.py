"""
Metrics collection for network discovery operations.

This module provides metrics and statistics useful for monitoring,
decision-making, and optimization by AI agents.
"""

import logging
import os
import psutil
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

from network_discovery.config import ARTIFACT_DIR
from network_discovery.artifacts import get_job_dir, read_json

logger = logging.getLogger(__name__)


def get_system_health() -> Dict[str, Any]:
    """
    Get current system health and resource utilization.
    
    Returns:
        Dict containing system metrics and health status
    """
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        memory_available_gb = memory.available / (1024 ** 3)
        
        # Disk metrics
        disk = psutil.disk_usage(ARTIFACT_DIR)
        disk_free_gb = disk.free / (1024 ** 3)
        
        # Determine health status
        health_issues = []
        if cpu_percent > 90:
            health_issues.append("CPU usage very high (>90%)")
        if memory.percent > 90:
            health_issues.append("Memory usage very high (>90%)")
        if disk.percent > 90:
            health_issues.append("Disk usage very high (>90%)")
        
        health_status = "healthy" if not health_issues else "degraded"
        
        return {
            "status": health_status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cpu": {
                "usage_percent": round(cpu_percent, 1),
                "cores": cpu_count,
                "status": "ok" if cpu_percent < 80 else "high"
            },
            "memory": {
                "usage_percent": round(memory.percent, 1),
                "available_gb": round(memory_available_gb, 2),
                "total_gb": round(memory.total / (1024 ** 3), 2),
                "status": "ok" if memory.percent < 80 else "high"
            },
            "disk": {
                "usage_percent": round(disk.percent, 1),
                "free_gb": round(disk_free_gb, 2),
                "total_gb": round(disk.total / (1024 ** 3), 2),
                "status": "ok" if disk.percent < 80 else "high"
            },
            "issues": health_issues,
            "ready_for_scan": health_status == "healthy" and cpu_percent < 80
        }
    except Exception as e:
        logger.error(f"Error getting system health: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "ready_for_scan": False
        }


def get_job_statistics(job_id: str) -> Dict[str, Any]:
    """
    Get detailed statistics for a specific job.
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict containing job statistics and metrics
    """
    try:
        job_dir = get_job_dir(job_id)
        
        if not job_dir.exists():
            return {
                "status": "not_found",
                "error": f"Job {job_id} not found"
            }
        
        # Read status file
        status_path = job_dir / "status.json"
        status = read_json(status_path) if status_path.exists() else {}
        
        # Read scan results
        scan_path = job_dir / "ip_scan.json"
        scan_data = read_json(scan_path) if scan_path.exists() else {}
        
        # Read fingerprint results
        fingerprints_path = job_dir / "fingerprints.json"
        fingerprints = read_json(fingerprints_path) if fingerprints_path.exists() else {}
        
        # Calculate statistics
        stats = {
            "job_id": job_id,
            "status": _get_overall_status(status),
            "modules": {},
            "timing": {},
            "results": {}
        }
        
        # Module statuses
        for module in ["seeder", "scanner", "fingerprinter", "state_collector", "batfish_loader"]:
            if module in status:
                module_status = status[module]
                stats["modules"][module] = {
                    "status": module_status.get("status", "unknown"),
                    "completed_at": module_status.get("completed_at"),
                    "error": module_status.get("error")
                }
        
        # Scanner statistics
        if scan_data:
            hosts = scan_data.get("hosts", [])
            reachable = [h for h in hosts if h.get("reachable")]
            stats["results"]["scanning"] = {
                "total_hosts": len(hosts),
                "reachable_hosts": len(reachable),
                "unreachable_hosts": len(hosts) - len(reachable),
                "success_rate": round(len(reachable) / len(hosts), 3) if hosts else 0
            }
        
        # Fingerprinting statistics
        if fingerprints:
            fp_hosts = fingerprints.get("hosts", [])
            identified = [h for h in fp_hosts if h.get("inference", {}).get("vendor") != "unknown"]
            stats["results"]["fingerprinting"] = {
                "total_hosts": len(fp_hosts),
                "identified_hosts": len(identified),
                "identification_rate": round(len(identified) / len(fp_hosts), 3) if fp_hosts else 0
            }
            
            # Vendor breakdown
            vendor_counts = defaultdict(int)
            for host in fp_hosts:
                vendor = host.get("inference", {}).get("vendor", "unknown")
                vendor_counts[vendor] += 1
            stats["results"]["vendors"] = dict(vendor_counts)
        
        # Config collection statistics
        state_dir = job_dir / "state"
        if state_dir.exists():
            config_files = list(state_dir.glob("*.json"))
            stats["results"]["config_collection"] = {
                "configs_collected": len(config_files)
            }
        
        # Batfish statistics
        batfish_dir = job_dir / "batfish_snapshot" / "configs"
        if batfish_dir.exists():
            batfish_configs = list(batfish_dir.glob("*.cfg"))
            stats["results"]["batfish"] = {
                "snapshot_ready": True,
                "config_files": len(batfish_configs)
            }
        
        # Calculate timing if available
        if "seeder" in status and "completed_at" in status["seeder"]:
            seeder_time = status["seeder"].get("completed_at")
            stats["timing"]["seeder_completed"] = seeder_time
        
        if "scanner" in status and "completed_at" in status["scanner"]:
            scanner_time = status["scanner"].get("completed_at")
            stats["timing"]["scanner_completed"] = scanner_time
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting job statistics for {job_id}: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }


def get_recent_jobs(hours: int = 24, limit: int = 50) -> Dict[str, Any]:
    """
    Get statistics about recent jobs.
    
    Args:
        hours: Look back this many hours
        limit: Maximum number of jobs to analyze
        
    Returns:
        Dict containing recent job statistics
    """
    try:
        artifact_path = Path(ARTIFACT_DIR)
        if not artifact_path.exists():
            return {
                "status": "no_data",
                "message": "No jobs found"
            }
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all job directories
        job_dirs = [d for d in artifact_path.iterdir() if d.is_dir()]
        
        # Filter by modification time and limit
        recent_jobs = []
        for job_dir in job_dirs:
            # Check modification time
            mod_time = datetime.fromtimestamp(job_dir.stat().st_mtime)
            if mod_time > cutoff_time:
                recent_jobs.append(job_dir)
        
        # Sort by modification time (newest first) and limit
        recent_jobs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
        recent_jobs = recent_jobs[:limit]
        
        # Analyze jobs
        total_jobs = len(recent_jobs)
        completed_jobs = 0
        failed_jobs = 0
        running_jobs = 0
        
        failed_job_ids = []
        
        for job_dir in recent_jobs:
            status_file = job_dir / "status.json"
            if status_file.exists():
                status = read_json(status_file)
                overall_status = _get_overall_status(status)
                
                if overall_status == "completed":
                    completed_jobs += 1
                elif overall_status == "failed":
                    failed_jobs += 1
                    failed_job_ids.append(job_dir.name)
                elif overall_status == "running":
                    running_jobs += 1
        
        success_rate = round(completed_jobs / total_jobs, 3) if total_jobs > 0 else 0
        
        return {
            "status": "success",
            "period_hours": hours,
            "total_jobs": total_jobs,
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "running_jobs": running_jobs,
            "success_rate": success_rate,
            "failed_job_ids": failed_job_ids[:10],  # Limit to first 10
            "health": "good" if success_rate > 0.8 else "degraded" if success_rate > 0.5 else "poor"
        }
        
    except Exception as e:
        logger.error(f"Error getting recent jobs: {str(e)}")
        return {
            "status": "error",
            "error": str(e)
        }


def get_recommendations() -> Dict[str, Any]:
    """
    Get recommendations for optimization and troubleshooting.
    
    Returns:
        Dict containing recommendations and suggestions
    """
    recommendations = []
    warnings = []
    
    try:
        # Check system health
        health = get_system_health()
        
        if health.get("cpu", {}).get("usage_percent", 0) > 80:
            warnings.append({
                "type": "high_cpu",
                "severity": "medium",
                "message": "CPU usage is high. Consider reducing scan concurrency.",
                "action": "Reduce DEFAULT_CONCURRENCY from 200 to 100"
            })
        
        if health.get("memory", {}).get("usage_percent", 0) > 80:
            warnings.append({
                "type": "high_memory",
                "severity": "medium",
                "message": "Memory usage is high. Monitor for memory leaks.",
                "action": "Review long-running jobs and restart service if needed"
            })
        
        if health.get("disk", {}).get("usage_percent", 0) > 80:
            warnings.append({
                "type": "high_disk",
                "severity": "high",
                "message": "Disk usage is high. Clean up old job artifacts.",
                "action": f"Delete old jobs from {ARTIFACT_DIR}"
            })
        
        # Check recent job performance
        recent = get_recent_jobs(hours=24)
        
        if recent.get("success_rate", 1.0) < 0.5:
            warnings.append({
                "type": "low_success_rate",
                "severity": "high",
                "message": f"Success rate is only {recent.get('success_rate', 0)*100:.0f}% in the last 24 hours.",
                "action": "Check network connectivity and device credentials"
            })
        
        if recent.get("failed_jobs", 0) > 5:
            warnings.append({
                "type": "frequent_failures",
                "severity": "medium",
                "message": f"{recent.get('failed_jobs')} jobs failed in the last 24 hours.",
                "action": "Review failed job logs for common issues"
            })
        
        # Generate positive recommendations
        if not warnings:
            recommendations.append({
                "type": "system_healthy",
                "message": "System is running well with no issues detected."
            })
        
        if health.get("ready_for_scan"):
            recommendations.append({
                "type": "ready",
                "message": "System resources are available for new scans."
            })
        
        # Best practices
        if recent.get("total_jobs", 0) > 0:
            recommendations.append({
                "type": "optimization",
                "message": "Use fingerprinting results to optimize credential selection.",
                "benefit": "Reduces authentication failures and speeds up config collection"
            })
        
        return {
            "status": "success",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "overall_health": "good" if not warnings else "needs_attention",
            "warnings": warnings,
            "recommendations": recommendations,
            "quick_actions": _get_quick_actions(warnings)
        }
        
    except Exception as e:
        logger.error(f"Error generating recommendations: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "warnings": [],
            "recommendations": []
        }


def _get_overall_status(status_data: Dict) -> str:
    """
    Determine overall job status from module statuses.
    
    Args:
        status_data: Status dictionary from status.json
        
    Returns:
        Overall status string
    """
    if not status_data:
        return "unknown"
    
    # Check if any module failed
    for module, data in status_data.items():
        if isinstance(data, dict) and data.get("status") == "failed":
            return "failed"
    
    # Check if any module is running
    for module, data in status_data.items():
        if isinstance(data, dict) and data.get("status") == "running":
            return "running"
    
    # Check if all key modules completed
    key_modules = ["seeder", "scanner"]
    completed_count = 0
    for module in key_modules:
        if module in status_data:
            if isinstance(status_data[module], dict) and status_data[module].get("status") == "completed":
                completed_count += 1
    
    if completed_count == len(key_modules):
        return "completed"
    
    return "in_progress"


def _get_quick_actions(warnings: List[Dict]) -> List[str]:
    """
    Generate quick action suggestions based on warnings.
    
    Args:
        warnings: List of warning dictionaries
        
    Returns:
        List of quick action strings
    """
    actions = []
    
    warning_types = [w["type"] for w in warnings]
    
    if "high_cpu" in warning_types or "high_memory" in warning_types:
        actions.append("Wait 5-10 minutes before starting new scans")
    
    if "high_disk" in warning_types:
        actions.append("Clean up old job artifacts to free space")
    
    if "low_success_rate" in warning_types or "frequent_failures" in warning_types:
        actions.append("Review recent failed jobs to identify common issues")
        actions.append("Verify network connectivity to target devices")
        actions.append("Check device credentials are correct")
    
    if not actions:
        actions.append("System is healthy - safe to proceed with operations")
    
    return actions

