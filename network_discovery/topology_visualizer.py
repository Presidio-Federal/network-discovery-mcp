"""
Topology visualization module for network analysis.

This module generates interactive HTML visualizations of network topologies
using Batfish data and D3.js.
"""

import logging
import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, date

from pybatfish.client.session import Session

# Configure logger
logger = logging.getLogger(__name__)

# Custom JSON encoder to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        # Handle objects with dict method
        if hasattr(obj, 'dict') and callable(obj.dict):
            return obj.dict()
        # Handle other custom objects
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)

def generate_topology_html(job_id: str) -> str:
    """
    Generate an interactive HTML visualization of the network topology.
    
    Args:
        job_id: Job identifier
        
    Returns:
        str: Path to the generated HTML file
    """
    try:
        logger.info(f"Generating topology HTML for job {job_id}")
        
        # Initialize Batfish session
        logger.info("Initializing Batfish session with host: batfish on port 9996")
        bf = Session(host="batfish", port=9996)
        
        # Set network to the job_id
        bf.set_network(job_id)
        
        # Set the snapshot name
        snapshot_name = "snapshot_latest"
        logger.info(f"Setting snapshot to: {snapshot_name}")
        bf.set_snapshot(snapshot_name)
        
        # Get edges using the Session API
        logger.info("Retrieving network edges from Batfish")
        edges_df = bf.q.edges().answer().frame()
        
        if edges_df.empty:
            logger.warning("No edges found in the topology")
            # Create a minimal data structure with a message
            topology_data = {
                "devices": {},
                "connections": []
            }
        else:
            # Create a data structure for the visualization
            devices = {}
            connections = []
            
            # Process edges to extract devices and connections
            for _, row in edges_df.iterrows():
                if "Interface" in row and "Remote_Interface" in row:
                    # Extract source device and interface
                    source_interface = str(row["Interface"])
                    if "@" in source_interface:
                        source_device, source_intf = source_interface.split("@", 1)
                    else:
                        source_parts = source_interface.split("[")
                        source_device = source_parts[0]
                        source_intf = source_interface
                    
                    # Extract target device and interface
                    remote_interface = str(row["Remote_Interface"])
                    if "@" in remote_interface:
                        target_device, target_intf = remote_interface.split("@", 1)
                    else:
                        target_parts = remote_interface.split("[")
                        target_device = target_parts[0]
                        target_intf = remote_interface
                    
                    # Add devices to the dictionary if they don't exist
                    if source_device not in devices:
                        # Try to determine device type from hostname
                        device_type = "cisco_xe"  # Default
                        if "switch" in source_device.lower():
                            device_type = "switch"
                        elif "router" in source_device.lower():
                            device_type = "router"
                        elif "core" in source_device.lower():
                            device_type = "router"
                        elif "edge" in source_device.lower():
                            device_type = "router"
                            
                        devices[source_device] = {
                            "hostname": source_device,
                            "ip_address": source_device,  # Use hostname as IP if we don't have real IP
                            "platform": "cisco",  # Default platform
                            "device_type": device_type,
                            "discovery_status": "discovered",
                            "interfaces": []
                        }
                    
                    if target_device not in devices:
                        # Try to determine device type from hostname
                        device_type = "cisco_xe"  # Default
                        if "switch" in target_device.lower():
                            device_type = "switch"
                        elif "router" in target_device.lower():
                            device_type = "router"
                        elif "core" in target_device.lower():
                            device_type = "router"
                        elif "edge" in target_device.lower():
                            device_type = "router"
                            
                        devices[target_device] = {
                            "hostname": target_device,
                            "ip_address": target_device,  # Use hostname as IP if we don't have real IP
                            "platform": "cisco",  # Default platform
                            "device_type": device_type,
                            "discovery_status": "discovered",
                            "interfaces": []
                        }
                    
                    # Add interfaces to devices
                    source_interface_obj = {
                        "name": source_intf,
                        "ip_address": None,
                        "subnet_mask": None,
                        "mac_address": None,
                        "description": None,
                        "status": "up",
                        "vlan": None,
                        "connected_to": f"{target_device}:{target_intf}",
                        "is_trunk": False,
                        "secondary_ips": []
                    }
                    
                    target_interface_obj = {
                        "name": target_intf,
                        "ip_address": None,
                        "subnet_mask": None,
                        "mac_address": None,
                        "description": None,
                        "status": "up",
                        "vlan": None,
                        "connected_to": f"{source_device}:{source_intf}",
                        "is_trunk": False,
                        "secondary_ips": []
                    }
                    
                    # Check if interface already exists before adding
                    source_intf_exists = False
                    for intf in devices[source_device]["interfaces"]:
                        if intf["name"] == source_intf:
                            source_intf_exists = True
                            break
                    
                    target_intf_exists = False
                    for intf in devices[target_device]["interfaces"]:
                        if intf["name"] == target_intf:
                            target_intf_exists = True
                            break
                    
                    if not source_intf_exists:
                        devices[source_device]["interfaces"].append(source_interface_obj)
                    
                    if not target_intf_exists:
                        devices[target_device]["interfaces"].append(target_interface_obj)
                    
                    # Add connection
                    connections.append({
                        "source": source_device,
                        "target": target_device,
                        "source_port": source_intf,
                        "target_port": target_intf
                    })
            
            # Create the final topology data structure
            topology_data = {
                "devices": devices,
                "connections": connections
            }
        
        # Ensure artifacts directory exists
        html_dir = f"/artifacts/{job_id}"
        os.makedirs(html_dir, exist_ok=True)
        html_path = f"{html_dir}/topology.html"
        
        # Generate HTML with D3.js visualization
        logger.info(f"Writing HTML to {html_path}")
        
        # HTML template with D3.js visualization
        html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Network Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        #topology { width: 100%; height: 800px; border: 1px solid #ddd; background-color: white; border-radius: 5px; }
        .node { cursor: pointer; }
        .link { stroke: #666; stroke-opacity: 0.6; stroke-width: 2px; }
        .node text { 
            font-size: 12px; 
            font-weight: bold; 
            text-shadow: 0 0 3px white, 0 0 3px white, 0 0 3px white; /* Text outline for better readability */
        }
        .tooltip { 
            position: absolute; 
            background: white; 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            padding: 0; /* Padding is handled in the HTML */
            pointer-events: none;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            max-width: 500px;
            font-size: 12px;
            z-index: 1000;
        }
        /* Style for interface lists */
        .tooltip ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .tooltip li {
            margin-bottom: 3px;
        }
        .legend {
            position: absolute;
            top: 20px;
            right: 20px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }
        h1 { margin-top: 0; }
    </style>
</head>
<body>
    <h1>Network Topology Visualization</h1>
    <div id="topology"></div>
    <div class="legend">
        <h3>Legend</h3>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #69b3a2;"></div>
            <div>Discovered</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #ff7f7f;"></div>
            <div>Failed</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #cccccc;"></div>
            <div>Unreachable</div>
        </div>
    </div>
    <script>
        // Topology data
        const data = """ + json.dumps(topology_data, cls=DateTimeEncoder) + """;
        
        // Create nodes and links for D3
        const nodes = [];
        const links = [];
        
        // Add nodes
        for (const [ip, device] of Object.entries(data.devices)) {
            const hostname = device.hostname || ip;
            // Clean up hostname if it contains error message
                const cleanHostname = hostname.startsWith('^') || hostname.includes('Invalid input') ? 
                    (device.platform || device.device_type || 'Unknown Device') : hostname;
            const status = device.discovery_status || 'unknown';
            
            nodes.push({
                id: ip,
                hostname: cleanHostname,
                ip: ip,
                platform: device.platform || 'unknown',
                device_type: device.device_type || 'unknown',
                status: status,
                interfaces: device.interfaces || []
            });
        }
        
        // Add links
        for (const conn of (data.connections || [])) {
            if (conn.source && conn.target) {
                links.push({
                    source: conn.source,
                    target: conn.target,
                    sourcePort: conn.source_port || '',
                    targetPort: conn.target_port || ''
                });
            }
        }
        
        // Create D3 force simulation
        const width = window.innerWidth - 40; // Account for padding
        const height = 800;
        
        // Add debug information at the top of the visualization
        d3.select("#topology").append("div")
            .style("margin-bottom", "20px")
            .style("padding", "10px")
            .style("background-color", "#f8f9fa")
            .style("border", "1px solid #ddd")
            .style("border-radius", "4px")
            .html(`
                <h3 style="margin-top:0">Visualization Debug Info</h3>
                <p><strong>Nodes found:</strong> ${nodes.length} (should see ${Object.keys(data.devices).length} devices)</p>
                <p><strong>Links found:</strong> ${links.length} (should see ${data.connections.length} connections)</p>
                <p><strong>Device IPs:</strong> ${nodes.map(n => n.id).join(', ')}</p>
                <details>
                    <summary>View node data</summary>
                    <pre style="max-height:200px;overflow:auto">${JSON.stringify(nodes, null, 2)}</pre>
                </details>
            `);
            
        // Initialize force simulation with much stronger forces to ensure better spacing
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(150)) // Increased distance between linked nodes
            .force("charge", d3.forceManyBody().strength(-800)) // Stronger repulsion
            .force("collide", d3.forceCollide().radius(60).strength(1)) // Larger collision radius
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("x", d3.forceX(width / 2).strength(0.05)) // Reduced strength to allow more spreading
            .force("y", d3.forceY(height / 2).strength(0.05)) // Reduced strength to allow more spreading
            .alphaDecay(0.003) // Even slower cooling for better layout
            .alpha(1)
            .alphaTarget(0)
            .velocityDecay(0.2) // Lower decay for more movement
            .restart() // Restart with high energy
        
        const svg = d3.select("#topology")
            .append("svg")
            .attr("width", "100%")
            .attr("height", height)
            .attr("viewBox", [0, 0, width, height]);
        
        // Add zoom functionality
        const g = svg.append("g");
        svg.call(d3.zoom()
            .extent([[0, 0], [width, height]])
            .scaleExtent([0.1, 8])
            .on("zoom", (event) => {
                g.attr("transform", event.transform);
            }));
            
        // Define device icons and markers
        const defs = svg.append("defs");
        
        // Add arrowhead marker for links
        defs.append("marker")
            .attr("id", "arrowhead")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 25) // Position away from node
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("fill", "#999");
        
        // Router icon
        defs.append("svg:symbol")
            .attr("id", "router")
            .attr("viewBox", "0 0 100 100")
            .append("svg:path")
            .attr("d", "M20,20 L80,20 L80,80 L20,80 Z M10,50 L20,50 M80,50 L90,50 M50,10 L50,20 M50,80 L50,90")
            .attr("stroke", "black")
            .attr("stroke-width", "5")
            .attr("fill", "none");
            
        // Switch icon
        defs.append("svg:symbol")
            .attr("id", "switch")
            .attr("viewBox", "0 0 100 100")
            .append("svg:path")
            .attr("d", "M20,20 L80,20 L80,80 L20,80 Z M10,30 L20,30 M10,50 L20,50 M10,70 L20,70 M80,30 L90,30 M80,50 L90,50 M80,70 L90,70")
            .attr("stroke", "black")
            .attr("stroke-width", "5")
            .attr("fill", "none");
            
        // Generic device icon
        defs.append("svg:symbol")
            .attr("id", "device")
            .attr("viewBox", "0 0 100 100")
            .append("svg:path")
            .attr("d", "M20,20 L80,20 L80,80 L20,80 Z")
            .attr("stroke", "black")
            .attr("stroke-width", "5")
            .attr("fill", "none");
        
        // Create links with stronger visibility
        const link = g.append("g")
            .selectAll("line")
            .data(links)
            .enter()
            .append("line")
            .attr("class", "link")
            .attr("stroke", "#333")
            .attr("stroke-width", 2)
            .attr("marker-end", "url(#arrowhead)");
        
        // Create link labels with better visibility
        const linkText = g.append("g")
            .selectAll("text")
            .data(links)
            .enter()
            .append("text")
            .attr("font-size", "10px")
            .attr("font-weight", "bold")
            .attr("text-anchor", "middle")
            .attr("dy", -5)
            .attr("fill", "#333")
            .each(function() {
                // Add white background to text for better readability
                const text = d3.select(this);
                const parent = d3.select(this.parentNode);
                
                parent.append("rect")
                    .attr("width", function() { 
                        return text.node().getBBox().width + 6; 
                    })
                    .attr("height", function() { 
                        return text.node().getBBox().height + 4; 
                    })
                    .attr("x", function() { 
                        return text.node().getBBox().x - 3; 
                    })
                    .attr("y", function() { 
                        return text.node().getBBox().y - 2; 
                    })
                    .attr("fill", "white")
                    .attr("stroke", "none")
                    .lower(); // Put rectangle behind text
            })
            .text(d => `${d.sourcePort} - ${d.targetPort}`);
        
        // Create nodes
        const node = g.append("g")
            .selectAll("g")
            .data(nodes)
            .enter()
            .append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // Background for nodes
        node.append("circle")
            .attr("r", 30) // Larger radius
            .attr("stroke", "#333")
            .attr("stroke-width", 2)
            .attr("fill", d => {
                if (d.discovery_status === 'discovered') return "#69b3a2";
                if (d.discovery_status === 'failed') return "#ff7f7f";
                if (d.discovery_status === 'unreachable') return "#cccccc";
                return "#b8b8b8";
            });
            
        // Device icons
        node.append("use")
            .attr("xlink:href", d => {
                const type = (d.device_type || "").toLowerCase();
                if (type.includes('router') || type.includes('ios') || type.includes('xe') || type.includes('xr')) {
                    return "#router";
                } else if (type.includes('switch') || type.includes('nxos') || type.includes('eos')) {
                    return "#switch";
                } else {
                    return "#device";
                }
            })
            .attr("width", 40) // Larger icon
            .attr("height", 40)
            .attr("x", -20)
            .attr("y", -20);
        
        // Node labels with background for better readability
        const labels = node.append("g");
        
        // Label background
        labels.append("rect")
            .attr("y", 35)
            .attr("x", d => -d.hostname.length * 4 - 5) // Adjust width based on text length
            .attr("width", d => d.hostname.length * 8 + 10)
            .attr("height", 20)
            .attr("rx", 5)
            .attr("ry", 5)
            .attr("fill", "white")
            .attr("fill-opacity", 0.8)
            .attr("stroke", "#333")
            .attr("stroke-width", 1);
        
        // Node label text
        labels.append("text")
            .attr("dy", 50)
            .attr("text-anchor", "middle")
            .attr("font-weight", "bold")
            .attr("font-size", "12px")
            .text(d => d.hostname);
        
        // Tooltip
        const tooltip = d3.select("body")
            .append("div")
            .attr("class", "tooltip")
            .style("opacity", 0);
        
        node.on("mouseover", function(event, d) {
            tooltip.transition()
                .duration(200)
                .style("opacity", .9);
                
            let interfaceList = '';
            if (d.interfaces && d.interfaces.length > 0) {
                interfaceList = '<h4>Interfaces:</h4><ul style="padding-left: 20px; margin-top: 5px;">';
                d.interfaces.forEach(intf => {
                    // Extract interface name from the full string
                    let intfName = intf.name;
                    if (intfName.includes('[')) {
                        intfName = intfName.split('[')[1].replace(']', '');
                    }
                    
                    // Extract connected device from the full string
                    let connectedTo = '';
                    if (intf.connected_to) {
                        const parts = intf.connected_to.split(':');
                        if (parts.length > 1) {
                            const deviceName = parts[0];
                            let intfName = parts[1];
                            if (intfName.includes('[')) {
                                intfName = intfName.split('[')[1].replace(']', '');
                            }
                            connectedTo = ` → <strong>${deviceName}</strong> (${intfName})`;
                        }
                    }
                    
                    interfaceList += `<li><strong>${intfName}</strong>${intf.ip_address ? ' - ' + intf.ip_address : ''}${connectedTo}</li>`;
                });
                interfaceList += '</ul>';
            }
            
            // Build neighbor list if available
            let neighborList = '';
            const deviceNeighbors = [];
            data.connections.forEach(conn => {
                if (conn.source === d.id) {
                    const targetDevice = data.devices[conn.target];
                    if (targetDevice) {
                        const targetName = targetDevice.hostname || conn.target;
                        deviceNeighbors.push({
                            name: targetName,
                            local_port: conn.source_port,
                            remote_port: conn.target_port
                        });
                    }
                } else if (conn.target === d.id) {
                    const sourceDevice = data.devices[conn.source];
                    if (sourceDevice) {
                        const sourceName = sourceDevice.hostname || conn.source;
                        deviceNeighbors.push({
                            name: sourceName,
                            local_port: conn.target_port,
                            remote_port: conn.source_port
                        });
                    }
                }
            });
            
            if (deviceNeighbors.length > 0) {
                neighborList = '<h4>Connected Devices:</h4><ul>';
                deviceNeighbors.forEach(neighbor => {
                    neighborList += `<li>${neighbor.name} (${neighbor.local_port} → ${neighbor.remote_port})</li>`;
                });
                neighborList += '</ul>';
            }
            
            tooltip.html(`
                <div style="padding: 15px; max-width: 400px; max-height: 600px; overflow-y: auto; background-color: white; border: 1px solid #ccc; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.2);">
                    <h3 style="margin-top: 0; color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 8px; font-size: 16px;">${d.hostname}</h3>
                    <div style="display: grid; grid-template-columns: auto 1fr; gap: 5px; margin-bottom: 10px;">
                        <div><strong>IP:</strong></div>
                        <div>${d.ip_address || d.hostname}</div>
                        <div><strong>Platform:</strong></div>
                        <div>${d.platform || 'Unknown'}</div>
                        <div><strong>Type:</strong></div>
                        <div>${d.device_type || 'Unknown'}</div>
                        <div><strong>Status:</strong></div>
                        <div>${d.discovery_status || 'Unknown'}</div>
                    </div>
                    ${neighborList}
                    ${interfaceList}
                </div>
            `)
            .style("left", (event.pageX + 10) + "px")
            .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            tooltip.transition()
                .duration(500)
                .style("opacity", 0);
        });
        
        // Update positions on simulation tick
        simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            linkText
                .attr("x", d => (d.source.x + d.target.x) / 2)
                .attr("y", d => (d.source.y + d.target.y) / 2);
            
            node
                .attr("transform", d => `translate(${d.x},${d.y})`);
        });
        
        // Drag functions
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    </script>
</body>
</html>
"""
        
        # Write HTML file
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        return html_path
    
    except Exception as e:
        logger.error(f"Failed to generate topology HTML: {str(e)}", exc_info=True)
        
        # Create a simple error HTML file
        html_dir = f"/artifacts/{job_id}"
        os.makedirs(html_dir, exist_ok=True)
        html_path = f"{html_dir}/topology.html"
        
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Topology Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 50px; }}
                .error {{ color: red; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Topology Visualization Error</h1>
            <div class="error">
                <p>Failed to generate topology visualization:</p>
                <pre>{str(e)}</pre>
            </div>
        </body>
        </html>
        """
        
        with open(html_path, 'w') as f:
            f.write(error_html)
        
        return html_path