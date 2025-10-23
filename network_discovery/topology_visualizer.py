"""
Topology visualization module for network analysis.

This module generates interactive HTML visualizations of network topologies
using Batfish data and Plotly.
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

import networkx as nx
import plotly.graph_objects as go

from pybatfish.client.session import Session

# Configure logger
logger = logging.getLogger(__name__)

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
            # Create a minimal graph with a message
            G = nx.Graph()
            G.add_node("No network edges found")
        else:
            # Create a graph from the edges
            logger.info("Building network graph from edges")
            G = nx.Graph()
            
            for _, row in edges_df.iterrows():
                # Extract node names from interface names (remove interface details in brackets)
                if "Interface" in row and "Remote_Interface" in row:
                    n1 = str(row["Interface"]).split("[")[0] if row["Interface"] else "Unknown"
                    n2 = str(row["Remote_Interface"]).split("[")[0] if row["Remote_Interface"] else "Unknown"
                    
                    if n1 != "Unknown" and n2 != "Unknown":
                        G.add_edge(n1, n2)
        
        # Generate layout
        logger.info("Generating force-directed layout")
        pos = nx.spring_layout(G, seed=42)
        
        # Create edge traces
        edge_traces = [
            go.Scatter(
                x=[pos[e[0]][0], pos[e[1]][0], None],
                y=[pos[e[0]][1], pos[e[1]][1], None],
                mode="lines",
                line=dict(width=1, color="lightgray"),
                hoverinfo="none"
            ) for e in G.edges()
        ]
        
        # Create node trace
        node_trace = go.Scatter(
            x=[pos[n][0] for n in G.nodes()],
            y=[pos[n][1] for n in G.nodes()],
            text=[n for n in G.nodes()],
            mode="markers+text",
            textposition="bottom center",
            marker=dict(size=16, color="dodgerblue", line=dict(width=1, color="white")),
            hoverinfo="text"
        )
        
        # Create figure
        fig = go.Figure(data=edge_traces + [node_trace])
        fig.update_layout(
            showlegend=False,
            hovermode="closest",
            margin=dict(l=0, r=0, t=0, b=0),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            title="Network Topology"
        )
        
        # Ensure artifacts directory exists
        html_dir = f"/artifacts/{job_id}"
        os.makedirs(html_dir, exist_ok=True)
        html_path = f"{html_dir}/topology.html"
        
        # Write HTML file
        logger.info(f"Writing HTML to {html_path}")
        fig.write_html(html_path, include_plotlyjs="cdn", full_html=True)
        
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
        
        with open(html_path, "w") as f:
            f.write(error_html)
        
        return html_path
