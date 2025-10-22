"""
API endpoints for network discovery service.

This module provides FastAPI endpoints for seeder, scanner, and fingerprinter operations.
"""

import logging
import os
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Union

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from network_discovery.artifacts import get_job_dir, read_json
from network_discovery.config import DEFAULT_CONCURRENCY, DEFAULT_PORTS, DEFAULT_SEEDER_METHODS
from network_discovery.scanner import get_scan, get_reachable_hosts
from network_discovery.fingerprinter import get_fingerprints
from network_discovery.direct_connect import direct_collect_routing
from network_discovery.workers import (
    start_add_subnets,
    start_scanner,
    start_seeder,
    start_subnet_scanner,
    start_fingerprinter,
    start_state_collector,
    start_device_state_update,
    start_batfish_snapshot_build,
    start_batfish_snapshot_load,
    get_batfish_topology,
)
from network_discovery.config_collector import get_device_state

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Network Discovery Service",
    description="API for network discovery and port scanning",
    version="0.1.0"
)

# Pydantic models for request validation
class Credentials(BaseModel):
    username: str
    password: str
    platform: str = "cisco_ios"

class SeedRequest(BaseModel):
    seed_host: str
    credentials: Credentials
    job_id: Optional[str] = None
    methods: List[str] = Field(default_factory=lambda: DEFAULT_SEEDER_METHODS.copy())

class ScanRequest(BaseModel):
    job_id: str
    targets_path: Optional[str] = None
    ports: List[int] = Field(default_factory=lambda: DEFAULT_PORTS.copy())
    concurrency: int = DEFAULT_CONCURRENCY

class SubnetScanRequest(BaseModel):
    job_id: Optional[str] = None
    subnets: List[str]
    ports: List[int] = Field(default_factory=lambda: DEFAULT_PORTS.copy())
    concurrency: int = DEFAULT_CONCURRENCY

class AddSubnetsRequest(BaseModel):
    job_id: str
    subnets: List[str]
    
class FingerprintRequest(BaseModel):
    job_id: str
    snmp_community: Optional[str] = None
    concurrency: int = DEFAULT_CONCURRENCY
    
class StateCollectorRequest(BaseModel):
    job_id: str
    credentials: Credentials
    concurrency: int = 25
    
class DeviceStateUpdateRequest(BaseModel):
    job_id: str
    credentials: Credentials
    
class BatfishBuildRequest(BaseModel):
    job_id: str
    
class BatfishLoadRequest(BaseModel):
    job_id: str
    batfish_host: Optional[str] = None

class DebugRoutingRequest(BaseModel):
    hostname: str
    username: str
    password: str
    port: int = 22
    platform: str = "cisco_ios"

# API endpoints
@app.post("/v1/seed", response_model=Dict)
async def seed_device(request: SeedRequest):
    """
    Start a seeder operation from a device.
    
    This endpoint collects network information from a seed device and produces
    targets.json and device state files.
    """
    try:
        result = await start_seeder(
            request.seed_host,
            request.credentials.dict(),
            request.job_id,
            request.methods
        )
        return result
    except Exception as e:
        logger.error(f"Error in seed endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/scan", response_model=Dict)
async def scan_targets(request: ScanRequest):
    """
    Start a scanner operation using existing job targets.
    
    This endpoint scans IPs from a targets.json file for open management ports.
    """
    try:
        result = await start_scanner(
            request.job_id,
            request.targets_path,
            request.ports,
            request.concurrency
        )
        return result
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/scan/from-subnets", response_model=Dict)
async def scan_from_subnets(request: SubnetScanRequest):
    """
    Start a scanner operation directly from provided subnets.
    
    This endpoint scans IPs from explicitly provided subnets for open management ports.
    """
    try:
        # Generate job_id if not provided
        job_id = request.job_id or str(uuid.uuid4())
        
        result = await start_subnet_scanner(
            job_id,
            request.subnets,
            request.ports,
            request.concurrency
        )
        return result
    except Exception as e:
        logger.error(f"Error in scan_from_subnets endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/scan/add-subnets", response_model=Dict)
async def add_subnets_to_job(request: AddSubnetsRequest):
    """
    Add new subnets to an existing job's targets.
    
    This endpoint merges new subnets into targets.json and can trigger re-scan
    for only new ranges.
    """
    try:
        result = await start_add_subnets(request.job_id, request.subnets)
        return result
    except Exception as e:
        logger.error(f"Error in add_subnets endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/status/{job_id}", response_model=Dict)
async def get_job_status(job_id: str):
    """
    Get the status of a job.
    
    This endpoint returns the status of both seeder and scanner modules for a job.
    """
    try:
        job_dir = get_job_dir(job_id)
        status_path = job_dir / "status.json"
        
        if not status_path.exists():
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        
        status = read_json(status_path)
        if not status:
            raise HTTPException(status_code=500, detail=f"Failed to read status for job {job_id}")
        
        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in status endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/artifacts/{job_id}/{filename}")
async def get_artifact(job_id: str, filename: str):
    """
    Get an artifact file for a job.
    
    This endpoint safely serves artifact files from a job's directory.
    """
    try:
        job_dir = get_job_dir(job_id)
        
        # Security check - prevent path traversal
        if ".." in filename or filename.startswith("/"):
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        # Handle device_states subdirectory
        if filename.startswith("device_states/"):
            file_path = job_dir / filename
        else:
            file_path = job_dir / filename
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"Artifact {filename} not found")
        
        return FileResponse(str(file_path))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in artifacts endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/scan/{job_id}", response_model=Dict)
async def get_scan_results(job_id: str):
    """
    Get scan results for a job.
    
    This endpoint returns the latest ip_scan.json for a job.
    """
    try:
        scan_results = get_scan(job_id)
        
        if scan_results.get("status") == "not_found":
            raise HTTPException(status_code=404, detail=f"Scan results not found for job {job_id}")
        
        if scan_results.get("status") == "error":
            raise HTTPException(status_code=500, detail=scan_results.get("error", "Unknown error"))
        
        return scan_results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_scan endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/scan/{job_id}/reachable", response_model=Dict)
async def get_reachable_scan_results(job_id: str):
    """
    Get only reachable hosts from scan results.
    
    This endpoint returns only the hosts that were reachable during scanning,
    filtering out all unreachable hosts to provide a more concise result.
    """
    try:
        reachable_results = get_reachable_hosts(job_id)
        
        if reachable_results.get("status") == "not_found":
            raise HTTPException(status_code=404, detail=f"Scan results not found for job {job_id}")
        
        if reachable_results.get("status") == "error":
            raise HTTPException(status_code=500, detail=reachable_results.get("error", "Unknown error"))
        
        return reachable_results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_reachable_hosts endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/fingerprint", response_model=Dict)
async def fingerprint_hosts(request: FingerprintRequest):
    """
    Start a fingerprinting operation for a job.
    
    This endpoint analyzes hosts discovered by the scanner and infers likely vendor,
    model, and management protocol without logging in.
    """
    try:
        result = await start_fingerprinter(
            request.job_id,
            request.snmp_community,
            request.concurrency
        )
        return result
    except Exception as e:
        logger.error(f"Error in fingerprint endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/fingerprint/{job_id}", response_model=Dict)
async def get_fingerprint_results(job_id: str):
    """
    Get fingerprinting results for a job.
    
    This endpoint returns the latest fingerprints.json for a job.
    """
    try:
        fingerprint_results = get_fingerprints(job_id)
        
        if fingerprint_results.get("status") == "not_found":
            raise HTTPException(status_code=404, detail=f"Fingerprint results not found for job {job_id}")
        
        if fingerprint_results.get("status") == "error":
            raise HTTPException(status_code=500, detail=fingerprint_results.get("error", "Unknown error"))
        
        return fingerprint_results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_fingerprint endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/state/collect", response_model=Dict)
async def collect_device_states(request: StateCollectorRequest):
    """
    Collect all device states in parallel.
    
    This endpoint retrieves each device's running configuration in parallel and stores
    it as a separate JSON file under {job_dir}/state/{hostname}.json.
    """
    try:
        result = await start_state_collector(
            request.job_id,
            request.credentials.dict(),
            request.concurrency
        )
        return result
    except Exception as e:
        logger.error(f"Error in state collector endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/state/{hostname}", response_model=Dict)
async def get_device_state_endpoint(hostname: str, job_id: str):
    """
    Get a device's state.
    
    This endpoint returns the state JSON for a specific device.
    """
    try:
        state_results = await get_device_state(job_id, hostname)
        
        if state_results.get("status") == "not_found":
            raise HTTPException(status_code=404, detail=f"State for device {hostname} not found in job {job_id}")
        
        if state_results.get("status") == "error":
            raise HTTPException(status_code=500, detail=state_results.get("error", "Unknown error"))
        
        return state_results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_device_state endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/state/update/{hostname}", response_model=Dict)
async def update_device_state(hostname: str, request: DeviceStateUpdateRequest):
    """
    Re-collect and update state for one device.
    
    This endpoint re-collects and updates the state for a specific device.
    """
    try:
        result = await start_device_state_update(
            request.job_id,
            request.credentials.dict(),
            hostname
        )
        return result
    except Exception as e:
        logger.error(f"Error in update_device_state endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/batfish/build", response_model=Dict)
async def build_batfish_snapshot(request: BatfishBuildRequest):
    """
    Build a Batfish snapshot from collected device configurations.
    
    This endpoint converts state JSON files to .cfg files for Batfish.
    """
    try:
        result = await start_batfish_snapshot_build(request.job_id)
        return result
    except Exception as e:
        logger.error(f"Error in build_batfish_snapshot endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/batfish/load", response_model=Dict)
async def load_batfish_snapshot(request: BatfishLoadRequest):
    """
    Load a Batfish snapshot into the Batfish server.
    
    This endpoint loads a previously built snapshot into Batfish for analysis.
    """
    try:
        result = await start_batfish_snapshot_load(
            request.job_id,
            request.batfish_host
        )
        return result
    except Exception as e:
        logger.error(f"Error in load_batfish_snapshot endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/batfish/topology", response_model=Dict)
async def get_topology(job_id: str, batfish_host: Optional[str] = None):
    """
    Get the network topology from Batfish.
    
    This endpoint returns a JSON topology of all device adjacencies.
    """
    try:
        result = await get_batfish_topology(job_id, batfish_host)
        
        if result.get("status") == "failed":
            raise HTTPException(status_code=500, detail=result.get("error", "Unknown error"))
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_topology endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Debug endpoints
@app.post("/debug/routing", response_model=Dict)
async def debug_routing(request: DebugRoutingRequest):
    """
    Debug endpoint to directly test routing collection from a device.
    
    This endpoint uses a direct Netmiko connection to collect routing information.
    """
    try:
        result = direct_collect_routing(
            request.hostname,
            request.username,
            request.password,
            request.port,
            request.platform
        )
        return result
    except Exception as e:
        logger.error(f"Error in debug_routing endpoint: {str(e)}")
        return {"error": str(e), "traceback": str(e.__traceback__)}