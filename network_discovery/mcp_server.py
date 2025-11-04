"""
MCP Server implementation for network discovery service.

This module provides a FastMCP server that exposes the network discovery
functionality through the Model Context Protocol (MCP).
"""

import os
import sys
import logging
import uuid
from typing import Dict, List, Any, Optional

from fastmcp import FastMCP, Context

# Import network discovery functionality
from network_discovery.workers import (
    start_seeder,
    start_scanner,
    start_subnet_scanner,
    start_add_subnets,
    start_fingerprinter,
    start_state_collector,
    start_device_state_update,
    start_batfish_snapshot_build,
    start_batfish_snapshot_load,
    get_batfish_topology,
)
from network_discovery.scanner import get_scan, get_reachable_hosts
from network_discovery.fingerprinter import get_fingerprints
from network_discovery.deep_fingerprinter import deep_fingerprint_job
from network_discovery.config_collector import get_device_state, get_collection_status
from network_discovery.batfish_loader import (
    list_networks,
    list_snapshots,
    get_current_snapshot,
    set_current_snapshot,
    delete_network,
    delete_all_networks
)
from network_discovery.topology_visualizer import generate_topology_html
from network_discovery.config import DEFAULT_CONCURRENCY, DEFAULT_PORTS, DEFAULT_SEEDER_METHODS
from network_discovery.artifacts import get_job_dir, read_json
from network_discovery.tools.get_artifact_content import get_artifact_content as retrieve_artifact_content
from network_discovery.metrics import (
    get_system_health,
    get_job_statistics,
    get_recent_jobs,
    get_recommendations
)
from network_discovery.credential_validator import (
    validate_credentials,
    validate_credentials_batch
)
from network_discovery.job_resume import (
    resume_job,
    get_resumable_jobs
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_server() -> FastMCP:
    """Create and configure the FastMCP server.
    
    Returns:
        Configured FastMCP server instance
    """
    # Initialize FastMCP server
    mcp = FastMCP(
        name="Network Discovery MCP Server",
        version="1.0.0"
    )
    
    # === Seeder Tools ===
    @mcp.tool
    async def seed_device(
        seed_host: str,
        username: str,
        password: str,
        platform: str = "cisco_ios",
        job_id: Optional[str] = None,
        methods: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Start a seeder operation from a device.
        
        This tool collects network information from a seed device and produces
        targets.json and device state files.
        
        Args:
            seed_host: Hostname or IP of the seed device
            username: Username for authentication
            password: Password for authentication
            platform: Device platform (default: cisco_ios)
            job_id: Optional job identifier (generated if not provided)
            methods: Collection methods to use (default: all available methods)
        """
        try:
            # Use default methods if not specified
            if methods is None:
                methods = DEFAULT_SEEDER_METHODS.copy()
            
            # Create credentials dict
            credentials = {
                "username": username,
                "password": password,
                "platform": platform
            }
            
            result = await start_seeder(
                seed_host,
                credentials,
                job_id,
                methods
            )
            return result
        except Exception as e:
            logger.error(f"Error in seed_device tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Scanner Tools ===
    @mcp.tool
    async def scan_targets(
        job_id: str,
        targets_path: Optional[str] = None,
        ports: Optional[List[int]] = None,
        concurrency: int = DEFAULT_CONCURRENCY
    ) -> Dict[str, Any]:
        """Start a scanner operation using existing job targets.
        
        This tool scans IPs from a targets.json file for open management ports.
        
        Args:
            job_id: Job identifier
            targets_path: Optional path to targets file
            ports: Ports to scan (default: 22, 23, 80, 443)
            concurrency: Number of concurrent scans (default: 100)
        """
        try:
            # Use default ports if not specified
            if ports is None:
                ports = DEFAULT_PORTS.copy()
            
            result = await start_scanner(
                job_id,
                targets_path,
                ports,
                concurrency
            )
            return result
        except Exception as e:
            logger.error(f"Error in scan_targets tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def scan_from_subnets(
        subnets: List[str],
        job_id: Optional[str] = None,
        ports: Optional[List[int]] = None,
        concurrency: int = DEFAULT_CONCURRENCY
    ) -> Dict[str, Any]:
        """Start a scanner operation directly from provided subnets.
        
        This tool scans IPs from explicitly provided subnets for open management ports.
        
        Args:
            subnets: List of subnets to scan (CIDR notation)
            job_id: Optional job identifier (generated if not provided)
            ports: Ports to scan (default: 22, 23, 80, 443)
            concurrency: Number of concurrent scans (default: 100)
        """
        try:
            # Generate job_id if not provided
            if job_id is None:
                job_id = str(uuid.uuid4())
            
            # Use default ports if not specified
            if ports is None:
                ports = DEFAULT_PORTS.copy()
            
            result = await start_subnet_scanner(
                job_id,
                subnets,
                ports,
                concurrency
            )
            return result
        except Exception as e:
            logger.error(f"Error in scan_from_subnets tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def add_subnets_to_job(
        job_id: str,
        subnets: List[str]
    ) -> Dict[str, Any]:
        """Add new subnets to an existing job's targets.
        
        This tool merges new subnets into targets.json and can trigger re-scan
        for only new ranges.
        
        Args:
            job_id: Job identifier
            subnets: List of subnets to add (CIDR notation)
        """
        try:
            result = await start_add_subnets(job_id, subnets)
            return result
        except Exception as e:
            logger.error(f"Error in add_subnets_to_job tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_scan_results(job_id: str) -> Dict[str, Any]:
        """Get scan results for a job.
        
        This tool returns the scan results for a job, including reachable hosts
        and their open ports.
        
        Args:
            job_id: Job identifier
        """
        try:
            result = get_scan(job_id)
            return result
        except Exception as e:
            logger.error(f"Error in get_scan_results tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_reachable_scan_results(job_id: str) -> Dict[str, Any]:
        """Get only reachable hosts from scan results.
        
        This tool returns only the reachable hosts from scan results,
        filtering out unreachable hosts.
        
        Args:
            job_id: Job identifier
        """
        try:
            result = get_reachable_hosts(job_id)
            return result
        except Exception as e:
            logger.error(f"Error in get_reachable_scan_results tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Fingerprinter Tools ===
    @mcp.tool
    async def fingerprint_hosts(
        job_id: str,
        snmp_community: Optional[str] = None,
        concurrency: int = DEFAULT_CONCURRENCY
    ) -> Dict[str, Any]:
        """Start a fingerprinting operation for a job.
        
        This tool analyzes hosts discovered by the scanner and infers likely vendor,
        model, and management protocol without logging in.
        
        Args:
            job_id: Job identifier
            snmp_community: Optional SNMP community string
            concurrency: Number of concurrent operations (default: 100)
        """
        try:
            result = await start_fingerprinter(
                job_id,
                snmp_community,
                concurrency
            )
            return result
        except Exception as e:
            logger.error(f"Error in fingerprint_hosts tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_fingerprint_results(job_id: str) -> Dict[str, Any]:
        """Get fingerprinting results for a job.
        
        This tool returns the fingerprinting results for a job, including
        inferred vendors, models, and protocols.
        
        Args:
            job_id: Job identifier
        """
        try:
            result = get_fingerprints(job_id)
            return result
        except Exception as e:
            logger.error(f"Error in get_fingerprint_results tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def deep_fingerprint_devices(
        job_id: str,
        username: str,
        password: str,
        confidence_threshold: float = 0.6,
        concurrency: int = DEFAULT_CONCURRENCY
    ) -> Dict[str, Any]:
        """Perform deep fingerprinting on low-confidence or unknown devices.
        
        This tool authenticates to devices that couldn't be reliably identified
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
        
        Args:
            job_id: Job identifier
            username: SSH username
            password: SSH password
            confidence_threshold: Re-fingerprint devices below this confidence (default: 0.6)
            concurrency: Number of concurrent connections (default: 100)
            
        Returns:
            {
                "job_id": "net-disc-123",
                "status": "completed",
                "devices_checked": 5,
                "devices_updated": 3,
                "devices_failed": 2
            }
        """
        try:
            creds = {
                "username": username,
                "password": password
            }
            
            result = await deep_fingerprint_job(
                job_id,
                creds,
                confidence_threshold,
                concurrency
            )
            return result
        except Exception as e:
            logger.error(f"Error in deep_fingerprint_devices tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Config Collector Tools ===
    @mcp.tool
    async def collect_device_configs(
        job_id: str,
        username: str,
        password: str,
        concurrency: int = 25
    ) -> Dict[str, Any]:
        """Collect device configurations using fingerprint data.
        
        This tool retrieves device configurations from all reachable devices
        and stores them in state files. The system automatically uses vendor
        information from the fingerprinting phase to select the correct commands.
        
        **How it works:**
        1. Reads fingerprints to determine each device's vendor
        2. Uses vendor-specific commands automatically:
           - Cisco: "show running-config"
           - Arista: "show running-config"
           - Juniper: "show configuration | display set"
           - Palo Alto: "show config running"
        3. Saves configurations to state files
        
        **Note:** Platform detection is automatic from fingerprints.
        If you need to correct vendor identification first, run the
        deep_fingerprint_devices tool before this.
        
        Args:
            job_id: Job identifier
            username: Username for SSH authentication
            password: Password for SSH authentication
            concurrency: Number of concurrent operations (default: 25)
            
        Returns:
            {
                "job_id": "...",
                "status": "completed",
                "device_count": 42,
                "success_count": 38,
                "failed_count": 4
            }
        """
        try:
            credentials = {
                "username": username,
                "password": password
            }
            
            result = await start_state_collector(
                job_id,
                credentials,
                concurrency
            )
            return result
        except Exception as e:
            logger.error(f"Error in collect_device_configs tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_device_config(
        job_id: str,
        hostname: str
    ) -> Dict[str, Any]:
        """Get configuration for a specific device.
        
        This tool returns the configuration for a specific device.
        
        Args:
            job_id: Job identifier
            hostname: Device hostname
        """
        try:
            result = get_device_state(job_id, hostname)
            return result
        except Exception as e:
            logger.error(f"Error in get_device_config tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def update_device_config(
        job_id: str,
        hostname: str,
        username: str,
        password: str,
        platform: str = "cisco_ios"
    ) -> Dict[str, Any]:
        """Update configuration for a specific device.
        
        This tool re-collects the configuration for a specific device.
        
        Args:
            job_id: Job identifier
            hostname: Device hostname
            username: Username for authentication
            password: Password for authentication
            platform: Device platform (default: cisco_ios)
        """
        try:
            credentials = {
                "username": username,
                "password": password,
                "platform": platform
            }
            
            result = await start_device_state_update(
                job_id,
                hostname,
                credentials
            )
            return result
        except Exception as e:
            logger.error(f"Error in update_device_config tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_collection_status_info(job_id: str) -> Dict[str, Any]:
        """Get status of configuration collection.
        
        This tool returns the status of the configuration collection process.
        
        Args:
            job_id: Job identifier
        """
        try:
            result = get_collection_status(job_id)
            return result
        except Exception as e:
            logger.error(f"Error in get_collection_status_info tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Batfish Tools ===
    @mcp.tool
    async def build_batfish_snapshot(job_id: str) -> Dict[str, Any]:
        """Build a Batfish snapshot.
        
        This tool builds a Batfish snapshot from collected device configurations.
        
        Args:
            job_id: Job identifier
        """
        try:
            result = await start_batfish_snapshot_build(job_id)
            return result
        except Exception as e:
            logger.error(f"Error in build_batfish_snapshot tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def load_batfish_snapshot(
        job_id: str,
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Load a Batfish snapshot.
        
        This tool loads a Batfish snapshot into a Batfish instance.
        
        Args:
            job_id: Job identifier
            batfish_host: Optional Batfish host URL
        """
        try:
            result = await start_batfish_snapshot_load(job_id, batfish_host)
            return result
        except Exception as e:
            logger.error(f"Error in load_batfish_snapshot tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_topology(
        job_id: Optional[str] = None,
        network_name: Optional[str] = None,
        snapshot_name: Optional[str] = None,
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get the network topology from Batfish.
        
        This tool returns a JSON topology of all device adjacencies.
        
        Args:
            job_id: Optional job identifier (used as network name if network_name not provided)
            network_name: Optional Batfish network name (overrides job_id if provided)
            snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
            batfish_host: Optional Batfish host URL
        """
        try:
            # Validate input parameters
            if job_id is None and network_name is None:
                return {
                    "status": "failed",
                    "error": "Either job_id or network_name must be provided"
                }
                
            # Determine which network name to use
            actual_network_name = network_name if network_name is not None else job_id
            
            # Get the topology using the appropriate parameters
            result = await get_batfish_topology(
                actual_network_name, 
                batfish_host=batfish_host,
                snapshot_name=snapshot_name
            )
            return result
        except Exception as e:
            logger.error(f"Error in get_topology tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def generate_topology_visualization(
        job_id: Optional[str] = None,
        network_name: Optional[str] = None,
        snapshot_name: Optional[str] = None,
        output_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate an interactive HTML visualization of the network topology.
        
        This tool creates a D3.js-based force-directed graph of the network topology
        and returns the path to the HTML file.
        
        Args:
            job_id: Optional job identifier (used as network name if network_name not provided)
            network_name: Optional Batfish network name (overrides job_id if provided)
            snapshot_name: Optional Batfish snapshot name (defaults to "snapshot_latest")
            output_dir: Optional output directory for the HTML file
        """
        try:
            # Validate input parameters
            if job_id is None and network_name is None:
                return {
                    "status": "failed",
                    "error": "Either job_id or network_name must be provided"
                }
            
            # Generate the HTML using the provided parameters
            html_path = generate_topology_html(
                job_id=job_id,
                network_name=network_name,
                snapshot_name=snapshot_name,
                output_dir=output_dir
            )
            
            # Determine which identifier to return in the response
            identifier = network_name if network_name is not None else job_id
            
            return {
                "identifier": identifier,
                "status": "success",
                "path": html_path,
                "message": f"Topology visualization generated at {html_path}"
            }
        except Exception as e:
            logger.error(f"Error in generate_topology_visualization tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_artifact_content(
        job_id: str,
        filename: str
    ) -> Dict[str, Any]:
        """Retrieve an artifact file from /artifacts/{job_id}/ and return its content.
        
        This tool retrieves the content of an artifact file from the job directory.
        The response format depends on the file type:
        - Text files (HTML, JSON, TXT) are returned as text with UTF-8 encoding
        - Binary files are returned as base64-encoded
        
        Args:
            job_id: Job identifier
            filename: Name of the file to retrieve (e.g., topology.html, scan.json)
        """
        try:
            response_data, _, status_code = retrieve_artifact_content(job_id, filename)
            
            if status_code != 200:
                # Return error response
                return response_data
            
            # Return the response data (already in the correct format)
            return response_data
        except Exception as e:
            logger.error(f"Error in get_artifact_content tool: {str(e)}")
            return {"error": str(e), "success": False}
            
    @mcp.tool
    async def delete_batfish_network(
        network_name: str,
        batfish_host: str = "batfish"
    ) -> Dict[str, Any]:
        """Delete a specific Batfish network.
        
        This tool deletes a single network from Batfish.
        
        Args:
            network_name: Name of the network to delete (can be a job_id)
            batfish_host: Optional Batfish host (defaults to "batfish")
        """
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
            logger.error(f"Error in delete_batfish_network tool: {str(e)}")
            return {"error": str(e), "success": False}
            
    @mcp.tool
    async def clear_batfish_networks(
        batfish_host: str = "batfish"
    ) -> Dict[str, Any]:
        """Delete all networks from Batfish.
        
        This tool deletes all networks from the Batfish server, clearing up space
        and removing any stale or unused networks.
        
        Args:
            batfish_host: Optional Batfish host (defaults to "batfish")
        """
        try:
            result = delete_all_networks(batfish_host)
            return result
        except Exception as e:
            logger.error(f"Error in clear_batfish_networks tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def list_batfish_networks(
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """List all Batfish networks.
        
        This tool returns a list of all networks in Batfish.
        
        Args:
            batfish_host: Optional Batfish host URL
        """
        try:
            networks = list_networks(batfish_host or "batfish")
            return {
                "status": "success",
                "networks": networks
            }
        except Exception as e:
            logger.error(f"Error in list_batfish_networks tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def set_batfish_network(
        network_name: str,
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Set current Batfish network.
        
        This tool sets the current network in Batfish.
        
        Args:
            network_name: Network name
            batfish_host: Optional Batfish host URL
        """
        try:
            host = batfish_host or "batfish"
            snapshots = list_snapshots(network_name, host)
            return {
                "network": network_name,
                "snapshots": snapshots,
                "status": "success"
            }
        except Exception as e:
            logger.error(f"Error in set_batfish_network tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def list_batfish_snapshots(
        network_name: str,
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """List all snapshots in a network.
        
        This tool returns a list of all snapshots in a network.
        
        Args:
            network_name: Network name
            batfish_host: Optional Batfish host URL
        """
        try:
            snapshots = list_snapshots(network_name, batfish_host or "batfish")
            return {
                "network": network_name,
                "snapshots": snapshots,
                "status": "success"
            }
        except Exception as e:
            logger.error(f"Error in list_batfish_snapshots tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_current_batfish_snapshot(
        network_name: str,
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get current snapshot for a network.
        
        This tool returns the current snapshot for a network.
        
        Args:
            network_name: Network name
            batfish_host: Optional Batfish host URL
        """
        try:
            snapshot = get_current_snapshot(network_name, batfish_host or "batfish")
            return {
                "network": network_name,
                "snapshot": snapshot,
                "status": "success"
            }
        except Exception as e:
            logger.error(f"Error in get_current_batfish_snapshot tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def set_current_batfish_snapshot(
        network_name: str,
        snapshot_name: str,
        batfish_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Set current snapshot for a network.
        
        This tool sets the current snapshot for a network.
        
        Args:
            network_name: Network name
            snapshot_name: Snapshot name
            batfish_host: Optional Batfish host URL
        """
        try:
            success = set_current_snapshot(
                network_name,
                snapshot_name,
                batfish_host or "batfish"
            )
            
            if success:
                return {
                    "network": network_name,
                    "snapshot": snapshot_name,
                    "status": "success"
                }
            else:
                return {
                    "network": network_name,
                    "snapshot": snapshot_name,
                    "status": "failed",
                    "error": "Failed to set current snapshot"
                }
        except Exception as e:
            logger.error(f"Error in set_current_batfish_snapshot tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Metrics and Monitoring Tools ===
    @mcp.tool
    async def check_system_health() -> Dict[str, Any]:
        """Check system health and resource availability.
        
        This tool provides real-time information about system resources and health status.
        Use this before starting large scans to ensure the system is ready.
        
        Returns metrics for:
        - CPU usage and availability
        - Memory usage and availability
        - Disk space usage
        - Overall health status
        - Whether the system is ready for new scans
        """
        try:
            health = get_system_health()
            return health
        except Exception as e:
            logger.error(f"Error in check_system_health tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_job_stats(job_id: str) -> Dict[str, Any]:
        """Get detailed statistics and metrics for a specific job.
        
        This tool provides comprehensive information about a job's execution,
        including module statuses, timing, and results. Use this to monitor
        job progress and diagnose issues.
        
        Args:
            job_id: Job identifier to get statistics for
            
        Returns:
            Detailed job statistics including:
            - Overall status
            - Module statuses (seeder, scanner, fingerprinter, etc.)
            - Scan results (reachable hosts, success rates)
            - Fingerprinting results (identified devices, vendor breakdown)
            - Configuration collection results
            - Timing information
        """
        try:
            stats = get_job_statistics(job_id)
            return stats
        except Exception as e:
            logger.error(f"Error in get_job_stats tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_recent_job_history(hours: int = 24, limit: int = 50) -> Dict[str, Any]:
        """Get statistics about recent job executions.
        
        This tool analyzes recent jobs to identify trends, success rates, and
        potential issues. Use this to understand system performance over time.
        
        Args:
            hours: Look back this many hours (default: 24)
            limit: Maximum number of jobs to analyze (default: 50)
            
        Returns:
            Statistics including:
            - Total jobs in time period
            - Completed, failed, and running job counts
            - Success rate
            - List of failed job IDs
            - Overall health assessment
        """
        try:
            history = get_recent_jobs(hours=hours, limit=limit)
            return history
        except Exception as e:
            logger.error(f"Error in get_recent_job_history tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    @mcp.tool
    async def get_system_recommendations() -> Dict[str, Any]:
        """Get intelligent recommendations for optimization and troubleshooting.
        
        This tool analyzes system state, recent job performance, and resource
        utilization to provide actionable recommendations. Use this to:
        - Identify potential issues before they impact operations
        - Get suggestions for optimization
        - Understand system health trends
        - Receive quick action items
        
        Returns:
            Recommendations including:
            - Warnings about resource usage or failures
            - Optimization suggestions
            - Quick actions to resolve issues
            - Overall health assessment
        """
        try:
            recommendations = get_recommendations()
            return recommendations
        except Exception as e:
            logger.error(f"Error in get_system_recommendations tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Credential Validation Tools ===
    @mcp.tool
    async def validate_device_credentials(
        seed_host: str,
        username: str,
        password: str,
        platform: str = "cisco_ios",
        port: int = 22
    ) -> Dict[str, Any]:
        """Validate credentials against a device before starting discovery.
        
        This is a quick pre-check (5-15 seconds) to verify credentials work
        BEFORE starting expensive discovery operations that could take 30+ minutes.
        
        Use this tool BEFORE starting network discovery to:
        - Verify credentials are correct
        - Detect platform mismatches early
        - Fail fast instead of wasting time on wrong credentials
        
        Args:
            seed_host: Device hostname or IP (can include port as host:port)
            username: SSH username
            password: SSH password
            platform: Device platform (cisco_ios, juniper_junos, arista_eos, etc.)
            port: SSH port (default: 22, ignored if host includes port)
            
        Returns:
            Validation result:
            {
                "valid": true/false,
                "latency_ms": 234,
                "vendor": "cisco_ios",
                "platform_correct": true,
                "can_read_config": true,
                "error": "..." (if failed),
                "suggestion": "..." (if failed)
            }
            
        Example Usage:
            AI Agent: "Let me validate credentials before starting..."
            → validate_device_credentials("192.168.1.1", "admin", "password")
            → Result: {"valid": false, "error": "Authentication failed"}
            AI Agent: "Invalid credentials detected. Please verify password."
        """
        try:
            result = await validate_credentials(
                host=seed_host,
                username=username,
                password=password,
                platform=platform,
                port=port
            )
            return result
        except Exception as e:
            logger.error(f"Error in validate_device_credentials tool: {str(e)}")
            return {
                "valid": False,
                "error": str(e),
                "suggestion": "Check device accessibility and network connectivity"
            }
    
    @mcp.tool
    async def validate_credentials_multiple(
        devices: List[Dict[str, Any]],
        username: str,
        password: str,
        concurrency: int = 5
    ) -> Dict[str, Any]:
        """Validate credentials against multiple devices in parallel.
        
        Useful for testing credentials against a sample of devices before
        starting full network discovery. This helps detect credential issues
        early across different device types or subnets.
        
        Args:
            devices: List of devices, each with 'host' and optional 'platform', 'port'
                     Example: [{"host": "192.168.1.1", "platform": "cisco_ios"}]
            username: SSH username
            password: SSH password
            concurrency: Max parallel validations (default: 5)
            
        Returns:
            Batch validation results:
            {
                "total_devices": 5,
                "valid_count": 4,
                "invalid_count": 1,
                "success_rate": 0.800,
                "results": [per-device validation results]
            }
            
        Example Usage:
            AI Agent: "Testing credentials against 5 sample devices..."
            → validate_credentials_multiple([...], "admin", "password")
            → Result: success_rate 0.200 (only 20% worked)
            AI Agent: "Credentials work on only 1/5 devices. May be wrong for most devices."
        """
        try:
            result = await validate_credentials_batch(
                devices=devices,
                username=username,
                password=password,
                concurrency=concurrency
            )
            return result
        except Exception as e:
            logger.error(f"Error in validate_credentials_multiple tool: {str(e)}")
            return {"error": str(e), "success": False}
    
    # === Job Resume Tools ===
    @mcp.tool
    async def resume_failed_job(
        job_id: str,
        phase: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        platform: Optional[str] = None
    ) -> Dict[str, Any]:
        """Resume a failed or partial job without re-doing completed work.
        
        This is CRITICAL for large network discovery - if a job fails after
        scanning 500 devices and collecting 200 configs, you can resume and
        only retry the failed portions instead of starting over.
        
        The tool intelligently:
        - Detects what phases completed successfully
        - Skips completed work
        - Retries only failed or incomplete phases
        - Preserves all successful results
        
        Args:
            job_id: Job identifier to resume
            phase: Specific phase to resume from (optional, auto-detects if not provided)
                   Options: "scanner", "fingerprinter", "config_collector"
            username: SSH username (required if resuming config collection)
            password: SSH password (required if resuming config collection)
            platform: Device platform (optional, default: cisco_ios)
            
        Returns:
            Resume results:
            {
                "job_id": str,
                "status": "completed",
                "resumed_from": "config_collector",
                "phases_executed": ["config_collector"],
                "summary": {
                    "config_collector": {
                        "success_count": 200,
                        "failed_count": 50
                    }
                }
            }
            
        Example Usage:
            Scenario: Job collected 200/450 configs then failed
            
            AI Agent: "Job failed during config collection. Let me resume..."
            → resume_failed_job(job_id, username="admin", password="pwd")
            → Only retries the 250 failed devices
            AI Agent: "Resumed collection. Now have 425/450 configs (95% success)."
        """
        try:
            # Build credentials dict if provided
            credentials = None
            if username and password:
                credentials = {
                    "username": username,
                    "password": password,
                    "platform": platform or "cisco_ios"
                }
            
            result = await resume_job(
                job_id=job_id,
                phase=phase,
                credentials=credentials
            )
            return result
        except Exception as e:
            logger.error(f"Error in resume_failed_job tool: {str(e)}")
            return {
                "job_id": job_id,
                "status": "error",
                "error": str(e)
            }
    
    @mcp.tool
    async def list_resumable_jobs() -> Dict[str, Any]:
        """Get list of jobs that can be resumed.
        
        This tool scans all jobs and identifies which ones failed or
        are incomplete and can be resumed. Useful for AI agents to
        proactively offer to resume failed jobs.
        
        Returns:
            List of resumable jobs:
            {
                "resumable_jobs": [
                    {
                        "job_id": "net-disc-123",
                        "failed_phases": ["config_collector"],
                        "can_resume_from": "config_collector",
                        "completed_phases": ["seeder", "scanner", "fingerprinter"],
                        "failed_at": "2025-11-02T12:34:56Z"
                    }
                ],
                "count": 1
            }
            
        Example Usage:
            AI Agent: "Checking for any failed jobs that can be resumed..."
            → list_resumable_jobs()
            → Result: 1 resumable job found
            AI Agent: "I found a failed job from earlier. It completed scanning 
                      and fingerprinting but failed during config collection. 
                      Would you like me to resume it?"
        """
        try:
            result = await get_resumable_jobs()
            return result
        except Exception as e:
            logger.error(f"Error in list_resumable_jobs tool: {str(e)}")
            return {"error": str(e), "resumable_jobs": [], "count": 0}
    
    return mcp


# Create module-level server instance for FastMCP CLI
mcp = create_server()


def main(base_path: str = ""):
    """Main entry point for the MCP server.
    
    Args:
        base_path: Optional base path for the MCP endpoint (e.g., "/api")
    """
    # Get configuration from environment
    transport = os.getenv("TRANSPORT", "http").lower()
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    
    # Construct MCP path with base path if provided
    mcp_path = f"{base_path}/mcp" if base_path else "/mcp"
    mcp_path = mcp_path.replace("//", "/")  # Handle case where base_path ends with slash
    
    logger.info(f"Starting Network Discovery MCP Server with transport: {transport}")
    logger.info(f"MCP endpoint will be available at: {host}:{port}{mcp_path}")
    
    try:
        if transport == "stdio":
            # STDIO transport for local development
            mcp.run(transport="stdio")
        elif transport == "sse":
            # Server-Sent Events transport (legacy)
            mcp.run(transport="sse", host=host, port=port)
        else:
            # HTTP Stream transport (default, recommended)
            mcp.run(transport="http", host=host, port=port, path=mcp_path)
            
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
