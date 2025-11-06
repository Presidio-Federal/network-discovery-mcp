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
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, SecretStr

from network_discovery.artifacts import get_job_dir, read_json
from network_discovery.config import DEFAULT_CONCURRENCY, DEFAULT_PORTS, DEFAULT_SEEDER_METHODS
from network_discovery.scanner import get_scan, get_reachable_hosts
from network_discovery.fingerprinter import get_fingerprints
from network_discovery.deep_fingerprinter import deep_fingerprint_job
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
from network_discovery.config_collector import get_device_state, get_collection_status
from network_discovery.batfish_loader import (
    BATFISH_AVAILABLE,
    list_networks,
    list_snapshots,
    get_current_snapshot,
    set_current_snapshot,
    delete_network,
    delete_all_networks
)
from network_discovery.topology_visualizer import generate_topology_html
from network_discovery.tools.get_artifact_content import get_artifact_content
from network_discovery.interface_collector import collect_interface_data, load_interface_data, get_device_interfaces, get_interface_details

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Network Discovery Service",
    description="API for network discovery and port scanning",
    version="0.1.0"
)

# Health check endpoints
@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    
    Returns basic service health status.
    """
    return {
        "status": "healthy",
        "service": "network-discovery",
        "version": "0.1.0"
    }

@app.get("/ready")
async def readiness_check():
    """
    Readiness check endpoint.
    
    Checks if the service is ready to accept requests by validating:
    - Artifact directory is writable
    - Batfish is available (if enabled)
    """
    checks = {
        "artifact_dir": False,
        "batfish": None
    }
    
    # Check artifact directory
    try:
        from network_discovery.config import ARTIFACT_DIR
        artifact_path = Path(ARTIFACT_DIR)
        artifact_path.mkdir(parents=True, exist_ok=True)
        
        # Try to write a test file
        test_file = artifact_path / ".health_check"
        test_file.write_text("ok")
        test_file.unlink()
        checks["artifact_dir"] = True
    except Exception as e:
        logger.error(f"Artifact directory check failed: {str(e)}")
        checks["artifact_dir"] = False
    
    # Check Batfish availability
    try:
        from network_discovery.batfish_loader import BATFISH_AVAILABLE
        checks["batfish"] = BATFISH_AVAILABLE
    except Exception as e:
        logger.warning(f"Batfish availability check failed: {str(e)}")
        checks["batfish"] = False
    
    # Service is ready if artifact_dir is accessible
    # Batfish is optional
    is_ready = checks["artifact_dir"]
    
    if is_ready:
        return {
            "status": "ready",
            "checks": checks
        }
    else:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "checks": checks
            }
        )

# Pydantic models for request validation
class Credentials(BaseModel):
    username: str
    password: SecretStr
    platform: Optional[str] = None  # Optional: uses fingerprint data if not provided
    enable_secret: Optional[SecretStr] = None  # Optional: enable password (defaults to password if not provided)
    
    class Config:
        json_encoders = {
            SecretStr: lambda v: "***MASKED***" if v else None
        }
    
    def get_dict_with_secrets(self) -> dict:
        """Get dictionary with actual password values for internal use only."""
        result = {
            "username": self.username,
            "password": self.password.get_secret_value(),
            "platform": self.platform
        }
        if self.enable_secret:
            result["enable_secret"] = self.enable_secret.get_secret_value()
        return result

class CredentialChain(BaseModel):
    """Chain of credentials to try in order until one succeeds."""
    credentials: List[Credentials]
    
    class Config:
        json_encoders = {
            SecretStr: lambda v: "***MASKED***" if v else None
        }
    
    def get_list_with_secrets(self) -> List[dict]:
        """Get list of credential dicts with actual password values."""
        return [cred.get_dict_with_secrets() for cred in self.credentials]

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

class DeepFingerprintRequest(BaseModel):
    job_id: str
    credentials: Union[Credentials, CredentialChain]  # Accept single or chain
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0, description="Re-fingerprint devices below this confidence threshold")
    concurrency: int = DEFAULT_CONCURRENCY
    
class StateCollectorRequest(BaseModel):
    job_id: str
    credentials: Union[Credentials, CredentialChain]  # Accept single or chain
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
            request.credentials.get_dict_with_secrets(),
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

@app.post("/v1/fingerprint/deep", response_model=Dict)
async def deep_fingerprint_devices(request: DeepFingerprintRequest):
    """
    Perform deep fingerprinting on low-confidence or unknown devices.
    
    This endpoint authenticates to devices that couldn't be reliably identified
    through passive methods (SSH banners, HTTPS, SNMP) and runs 'show version'
    to determine the actual device type.
    
    **When to use this:**
    - After regular fingerprinting shows devices as "Linux/Unix" or "unknown"
    - When confidence scores are low (< 0.6)
    - When you need accurate vendor detection for config collection
    
    **What it does:**
    1. Identifies devices with low confidence or unknown vendor
    2. Authenticates via SSH using provided credentials
    3. Runs 'show version' command
    4. Updates fingerprints with detected OS information
    
    **Example scenario:**
    - Arista devices show as "Linux/Unix" (SSH banner: OpenSSH_8.7)
    - Deep fingerprint logs in, runs 'show version'
    - Detects "Arista EOS" and updates fingerprints
    - Config collection now knows it's Arista
    
    **Example request:**
    ```json
    {
      "job_id": "net-disc-123",
      "credentials": {
        "username": "admin",
        "password": "password"
      },
      "confidence_threshold": 0.6,
      "concurrency": 50
    }
    ```
    
    **Response:**
    ```json
    {
      "job_id": "net-disc-123",
      "status": "completed",
      "devices_checked": 5,
      "devices_updated": 3,
      "devices_failed": 2
    }
    ```
    """
    try:
        # Convert credentials to dict format (use first if chain provided)
        if isinstance(request.credentials, CredentialChain):
            creds = request.credentials.get_list_with_secrets()[0]  # Use first for now
        else:
            creds = request.credentials.get_dict_with_secrets()
        
        result = await deep_fingerprint_job(
            request.job_id,
            creds,
            request.confidence_threshold,
            request.concurrency
        )
        
        if result.get("status") == "failed":
            raise HTTPException(status_code=500, detail=result.get("error", "Unknown error"))
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in deep_fingerprint endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/state/collect", response_model=Dict)
async def collect_device_states(request: StateCollectorRequest):
    """
    Collect all device states in parallel with credential fallback support.
    
    This endpoint retrieves each device's running configuration in parallel and stores
    it as a separate JSON file under {job_dir}/state/{hostname}.json.
    
    Supports both single credentials and credential chains:
    - Single: {"credentials": {"username": "admin", "password": "pass"}}
    - Chain: {"credentials": {"credentials": [{"username": "admin", "password": "pass"}, {"username": "cisco", "password": "cisco"}]}}
    """
    try:
        # Convert credentials to list format
        if isinstance(request.credentials, CredentialChain):
            creds = request.credentials.get_list_with_secrets()
        else:
            creds = [request.credentials.get_dict_with_secrets()]
        
        result = await start_state_collector(
            request.job_id,
            creds,  # Pass as list
            request.concurrency
        )
        return result
    except Exception as e:
        logger.error(f"Error in state collector endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/state/collection-status/{job_id}", response_model=Dict)
async def get_config_collection_status(job_id: str):
    """
    Get detailed status of the configuration collection process.
    
    This endpoint returns detailed status information about the configuration
    collection process, including per-device status and progress metrics.
    """
    try:
        status = get_collection_status(job_id)
        
        if status.get("status") == "not_found":
            raise HTTPException(status_code=404, detail=f"No collection status found for job {job_id}")
        
        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_config_collection_status endpoint: {str(e)}")
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
            hostname,
            request.credentials.get_dict_with_secrets()
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
async def get_topology(job_id: str = None, network_name: str = None, snapshot_name: str = None, batfish_host: Optional[str] = None):
    """
    Get the network topology from Batfish.
    
    This endpoint returns a JSON topology of all device adjacencies.
    
    Args:
        job_id: Optional job identifier (used as network name if network_name not provided)
        network_name: Optional Batfish network name (overrides job_id if provided)
        snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
        batfish_host: Optional Batfish host (defaults to "batfish")
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
    
    if job_id is None and network_name is None:
        raise HTTPException(status_code=400, detail="Either job_id or network_name must be provided")
    
    try:
        # Use network_name if provided, otherwise use job_id
        actual_network_name = network_name if network_name is not None else job_id
        
        # Get the topology using the appropriate parameters
        result = await get_batfish_topology(
            actual_network_name, 
            batfish_host=batfish_host,
            snapshot_name=snapshot_name
        )
        
        if result.get("status") == "failed":
            raise HTTPException(status_code=500, detail=result.get("error", "Unknown error"))
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_topology endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/batfish/topology/html")
async def get_topology_html(job_id: str = None, network_name: str = None, snapshot_name: str = None, output_dir: str = None):
    """
    Generate and return an interactive HTML visualization of the network topology.
    
    This endpoint creates a D3.js-based force-directed graph of the network topology
    and returns it as a downloadable HTML file.
    
    Args:
        job_id: Optional job identifier (used as network name if network_name not provided)
        network_name: Optional Batfish network name (overrides job_id if provided)
        snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
        output_dir: Optional output directory for the HTML file
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
    
    if job_id is None and network_name is None:
        raise HTTPException(status_code=400, detail="Either job_id or network_name must be provided")
    
    try:
        # Generate the HTML using the provided parameters
        html_path = generate_topology_html(
            job_id=job_id, 
            network_name=network_name, 
            snapshot_name=snapshot_name,
            output_dir=output_dir
        )
        return FileResponse(html_path, media_type="text/html", filename="topology.html")
    except Exception as e:
        logger.error(f"Error in get_topology_html endpoint: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# Artifact content endpoint
@app.get("/v1/artifacts/{job_id}/{filename}")
async def get_artifact_file(job_id: str, filename: str):
    """
    Retrieve an artifact file from the job directory.
    
    This endpoint returns the content of an artifact file from the job directory.
    The response format depends on the file type:
    - Text files (HTML, JSON, TXT) are returned as raw text with the appropriate MIME type
    - Binary files are returned as base64-encoded JSON
    
    Args:
        job_id: Job identifier
        filename: Name of the file to retrieve
    """
    response_data, mime_type, status_code = get_artifact_content(job_id, filename)
    
    if status_code != 200:
        # Return error response
        return JSONResponse(content=response_data, status_code=status_code)
    
    if mime_type and mime_type != "application/json":
        # Return raw content with appropriate MIME type
        return Response(content=response_data["content"], media_type=mime_type)
    
    # Return JSON response
    return response_data

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

@app.get("/debug/batfish-status", response_model=Dict)
async def debug_batfish_status():
    """
    Check if pybatfish is available.
    
    This endpoint returns the status of the pybatfish module.
    """
    try:
        # Try to import pybatfish directly
        import sys
        import importlib
        import importlib.util
        
        # Check if pybatfish is installed
        pybatfish_spec = importlib.util.find_spec("pybatfish")
        pybatfish_installed = pybatfish_spec is not None
        
        # Check if we can import the required modules
        session_available = False
        question_available = False
        
        if pybatfish_installed:
            try:
                from pybatfish.client.session import Session
                session_available = True
            except ImportError:
                pass
                
            try:
                from pybatfish.question import bfq
                question_available = True
            except ImportError:
                pass
        
        # Get Python path
        python_path = sys.path
        
        return {
            "batfish_available": BATFISH_AVAILABLE,
            "pybatfish_installed": pybatfish_installed,
            "session_available": session_available,
            "question_available": question_available,
            "python_path": python_path
        }
    except Exception as e:
        logger.error(f"Error in debug_batfish_status endpoint: {str(e)}")
        return {
            "batfish_available": False,
            "error": str(e)
        }

# Batfish Network Management Endpoints
@app.get("/v1/batfish/networks", response_model=List[str])
async def get_networks(batfish_host: str = "batfish"):
    """
    List all networks in Batfish.
    
    This endpoint returns a list of all networks in Batfish.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        networks = list_networks(batfish_host)
        return networks
    except Exception as e:
        logger.error(f"Error in get_networks endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/batfish/networks/{network_name}", response_model=Dict)
async def set_network(network_name: str, batfish_host: str = "batfish"):
    """
    Set the current network in Batfish.
    
    This endpoint sets the current network in Batfish.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        # We don't have a direct set_network function, but we can use list_snapshots
        # which will set the network and return the snapshots
        snapshots = list_snapshots(network_name, batfish_host)
        return {
            "network": network_name,
            "snapshots": snapshots
        }
    except Exception as e:
        logger.error(f"Error in set_network endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/v1/batfish/networks/{network_name}", response_model=Dict)
async def delete_batfish_network(network_name: str, batfish_host: str = "batfish"):
    """
    Delete a network from Batfish.
    
    This endpoint deletes a network from Batfish.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        success = delete_network(network_name, batfish_host)
        if success:
            return {
                "status": "success",
                "message": f"Network {network_name} deleted successfully"
            }
        else:
            return {
                "status": "failed",
                "message": f"Failed to delete network {network_name}"
            }
    except Exception as e:
        logger.error(f"Error in delete_batfish_network endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/v1/batfish/networks", response_model=Dict)
async def delete_all_batfish_networks(batfish_host: str = "batfish"):
    """
    Delete all networks from Batfish.
    
    This endpoint deletes all networks from Batfish.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        result = delete_all_networks(batfish_host)
        return result
    except Exception as e:
        logger.error(f"Error in delete_all_batfish_networks endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/batfish/networks/{network_name}/snapshots", response_model=List[str])
async def get_snapshots(network_name: str, batfish_host: str = "batfish"):
    """
    List all snapshots in a network.
    
    This endpoint returns a list of all snapshots in a network.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        snapshots = list_snapshots(network_name, batfish_host)
        return snapshots
    except Exception as e:
        logger.error(f"Error in get_snapshots endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/batfish/networks/{network_name}/snapshot", response_model=Dict)
async def get_snapshot(network_name: str, batfish_host: str = "batfish"):
    """
    Get the current snapshot for a network.
    
    This endpoint returns the current snapshot for a network.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        snapshot = get_current_snapshot(network_name, batfish_host)
        if snapshot is None:
            return {"network": network_name, "snapshot": None, "status": "no_snapshot_set"}
        return {"network": network_name, "snapshot": snapshot, "status": "success"}
    except Exception as e:
        logger.error(f"Error in get_snapshot endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/batfish/networks/{network_name}/snapshot/{snapshot_name}", response_model=Dict)
async def set_snapshot(network_name: str, snapshot_name: str, batfish_host: str = "batfish"):
    """
    Set the current snapshot for a network.
    
    This endpoint sets the current snapshot for a network.
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
        
    try:
        success = set_current_snapshot(network_name, snapshot_name, batfish_host)
        if not success:
            raise HTTPException(status_code=500, detail=f"Failed to set snapshot {snapshot_name} for network {network_name}")
        return {"network": network_name, "snapshot": snapshot_name, "status": "success"}
    except Exception as e:
        logger.error(f"Error in set_snapshot endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Interface Collection Endpoints
# ============================================================================

@app.post("/v1/interfaces/collect", response_model=Dict)
async def collect_interfaces(
    job_id: str = Query(..., description="Job ID to collect interfaces for"),
    network_name: Optional[str] = Query(None, description="Optional Batfish network name (defaults to job_id)"),
    snapshot_name: Optional[str] = Query(None, description="Optional Batfish snapshot name (defaults to 'snapshot_latest')")
):
    """
    Collect interface data from Batfish and store as artifact.
    
    This endpoint queries Batfish for detailed interface properties and stores
    them in interfaces.json for later use by visualization and analysis tools.
    
    Returns:
        - status: "success" or "error"
        - interface_count: Number of interfaces collected
        - device_count: Number of devices with interfaces
        - network_name: Batfish network name used
        - snapshot_name: Batfish snapshot name used
        - collected_at: ISO timestamp of collection
    """
    if not BATFISH_AVAILABLE:
        raise HTTPException(status_code=503, detail="Batfish functionality is not available")
    
    try:
        result = collect_interface_data(
            job_id=job_id,
            network_name=network_name,
            snapshot_name=snapshot_name
        )
        
        if result.get("status") == "error":
            raise HTTPException(status_code=500, detail=result.get("error", "Unknown error"))
        
        # Return summary (without full interface list for brevity)
        return {
            "status": result["status"],
            "interface_count": result["interface_count"],
            "device_count": result["device_count"],
            "network_name": result["network_name"],
            "snapshot_name": result["snapshot_name"],
            "collected_at": result["collected_at"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in collect_interfaces endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/interfaces/{job_id}", response_model=Dict)
async def get_interfaces(job_id: str):
    """
    Get all interface data for a job.
    
    Returns the complete interfaces.json artifact including all devices and interfaces.
    """
    try:
        data = load_interface_data(job_id)
        
        if not data:
            raise HTTPException(status_code=404, detail=f"Interface data not found for job {job_id}")
        
        return data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_interfaces endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/interfaces/{job_id}/devices/{device_name}", response_model=List[Dict])
async def get_device_interfaces_api(job_id: str, device_name: str):
    """
    Get all interfaces for a specific device.
    
    Returns a list of interface records for the specified device.
    """
    try:
        interfaces = get_device_interfaces(job_id, device_name)
        
        if not interfaces:
            raise HTTPException(
                status_code=404,
                detail=f"No interfaces found for device {device_name} in job {job_id}"
            )
        
        return interfaces
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_device_interfaces_api endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/interfaces/{job_id}/devices/{device_name}/interfaces/{interface_name}", response_model=Dict)
async def get_interface_details_api(job_id: str, device_name: str, interface_name: str):
    """
    Get details for a specific interface.
    
    Returns detailed properties for a single interface.
    """
    try:
        interface = get_interface_details(job_id, device_name, interface_name)
        
        if not interface:
            raise HTTPException(
                status_code=404,
                detail=f"Interface {interface_name} not found on device {device_name} in job {job_id}"
            )
        
        return interface
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_interface_details_api endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))