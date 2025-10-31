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
from network_discovery.config_collector import get_device_state, get_collection_status
from network_discovery.batfish_loader import (
    list_networks,
    list_snapshots,
    get_current_snapshot,
    set_current_snapshot
)
from network_discovery.topology_visualizer import generate_topology_html
from network_discovery.config import DEFAULT_CONCURRENCY, DEFAULT_PORTS, DEFAULT_SEEDER_METHODS
from network_discovery.artifacts import get_job_dir, read_json
from network_discovery.tools.get_artifact_content import get_artifact_content

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
    
    # === Config Collector Tools ===
    @mcp.tool
    async def collect_device_configs(
        job_id: str,
        username: str,
        password: str,
        platform: str = "cisco_ios",
        concurrency: int = 25
    ) -> Dict[str, Any]:
        """Collect device configurations.
        
        This tool retrieves device configurations from all reachable devices
        and stores them in state files.
        
        Args:
            job_id: Job identifier
            username: Username for authentication
            password: Password for authentication
            platform: Device platform (default: cisco_ios)
            concurrency: Number of concurrent operations (default: 25)
        """
        try:
            credentials = {
                "username": username,
                "password": password,
                "platform": platform
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
            response_data, _, status_code = get_artifact_content(job_id, filename)
            
            if status_code != 200:
                # Return error response
                return response_data
            
            # Return the response data (already in the correct format)
            return response_data
        except Exception as e:
            logger.error(f"Error in get_artifact_content tool: {str(e)}")
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
