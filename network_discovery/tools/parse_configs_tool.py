"""
MCP tool for parsing device configurations into structured data.
"""

from mcp.types import Tool, TextContent
from typing import Any
import json

from network_discovery.config_parser import parse_all_configs, parse_single_config, get_parsed_config


# Tool definition
parse_configs_tool = Tool(
    name="parse_configs",
    description="""
Parse collected device configurations into structured JSON format.

This tool takes the raw CLI configurations collected by config_collector and parses
them into structured data using vendor-specific parsers (Cisco, Arista, Juniper, Palo Alto).

The structured output includes:
- Interfaces (IPs, VLANs, descriptions, status)
- VLANs (names, IDs, status)
- Routing (OSPF, BGP, static routes)
- ACLs/Security policies
- NTP/DNS servers
- SNMP configuration
- Users and AAA
- And much more...

Output is saved to: {job_dir}/parsed_configs/{hostname}.json

Usage:
- Parse all devices: parse_configs(job_id="abc123")
- Parse single device: parse_configs(job_id="abc123", hostname="router-01")

Returns:
- success_count: Number of successfully parsed devices
- failed_count: Number of devices that failed parsing
- result_dir: Directory containing parsed configs
    """.strip(),
    inputSchema={
        "type": "object",
        "properties": {
            "job_id": {
                "type": "string",
                "description": "Job ID to parse configurations for"
            },
            "hostname": {
                "type": "string",
                "description": "(Optional) Specific device hostname to parse. If omitted, parses all devices."
            }
        },
        "required": ["job_id"]
    }
)


async def handle_parse_configs(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle parse_configs tool execution.
    
    Args:
        arguments: Tool arguments containing job_id and optional hostname
        
    Returns:
        List of TextContent with parsing results
    """
    job_id = arguments.get("job_id")
    hostname = arguments.get("hostname")
    
    if not job_id:
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "job_id is required"
            }, indent=2)
        )]
    
    # Parse single device or all devices
    if hostname:
        result = await parse_single_config(job_id, hostname)
    else:
        result = await parse_all_configs(job_id)
    
    return [TextContent(
        type="text",
        text=json.dumps(result, indent=2)
    )]


# Tool definition for getting parsed config
get_parsed_config_tool = Tool(
    name="get_parsed_config",
    description="""
Get the parsed (structured) configuration for a specific device.

This tool retrieves the structured configuration data that was parsed from
raw CLI output. The structured data is much easier to query and analyze than
raw CLI text.

Returns structured data including:
- System information (hostname, domain, IPs)
- Interfaces with all configuration details
- VLANs and their properties
- Routing protocols (OSPF, BGP) configuration
- Static routes
- ACLs and security policies
- NTP/DNS servers
- SNMP configuration
- Users and authentication
- Vendor-specific features

Usage: get_parsed_config(job_id="abc123", hostname="router-01")

Note: You must run parse_configs first to generate the structured data.
    """.strip(),
    inputSchema={
        "type": "object",
        "properties": {
            "job_id": {
                "type": "string",
                "description": "Job ID to get parsed config from"
            },
            "hostname": {
                "type": "string",
                "description": "Device hostname or IP address"
            }
        },
        "required": ["job_id", "hostname"]
    }
)


async def handle_get_parsed_config(arguments: dict[str, Any]) -> list[TextContent]:
    """
    Handle get_parsed_config tool execution.
    
    Args:
        arguments: Tool arguments containing job_id and hostname
        
    Returns:
        List of TextContent with parsed configuration
    """
    job_id = arguments.get("job_id")
    hostname = arguments.get("hostname")
    
    if not job_id or not hostname:
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "Both job_id and hostname are required"
            }, indent=2)
        )]
    
    result = await get_parsed_config(job_id, hostname)
    
    return [TextContent(
        type="text",
        text=json.dumps(result, indent=2)
    )]

