# Network Discovery MCP

A modular, containerized network discovery service for automated network mapping and analysis.

## Overview

Network Discovery MCP is a comprehensive solution for discovering, mapping, and analyzing network infrastructure. Starting from a single seed device, it automatically discovers the entire network topology, collects device configurations, and generates interactive visualizations.

### Key Features

- **Automated Network Discovery**: Map your entire network from a single seed device
- **Configuration Collection**: Retrieve and store device configurations securely
- **Topology Visualization**: Generate interactive HTML network maps
- **Network Analysis**: Leverage Batfish for advanced network analysis
- **AI Integration**: Built-in Model Context Protocol (MCP) support for AI agents

### Running Modes

The service can run in two distinct modes:

1. **REST API Mode** (Default): Traditional HTTP API endpoints for:
   - Integration with existing tools and workflows
   - Running via GitHub Actions or CI/CD pipelines
   - Programmatic access from any language or system

2. **MCP Mode**: Model Context Protocol server for:
   - Direct integration with AI agents
   - Autonomous network discovery operations
   - Tool-based interaction model for AI systems

Both modes provide identical functionality but with different integration patterns. We recommend using Docker Compose for deployment as both modes depend on the Batfish container for network analysis and visualization.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/username/network-discovery-mcp.git
cd network-discovery-mcp

# Start in REST API mode (default)
docker compose up -d

# OR start in MCP mode
docker compose -f docker-compose.mcp.yml up -d
```

### Components

The service consists of six main modules working together:

1. **SEEDER**: Starts from a known device (seed) and collects potential subnets and candidate IPs via interfaces, VRFs, ARP, CDP/LLDP, and routing tables.
2. **IP-SCANNER**: Probes for open management ports (default: 22 and 443) across candidate IPs or subnets.
3. **FINGERPRINTER**: Analyzes hosts discovered by the scanner and infers likely vendor, model, and management protocol without logging in.
4. **CONFIG-COLLECTOR**: Retrieves each device's running configuration in parallel and stores it as a separate JSON file.
5. **BATFISH-LOADER**: Builds and loads Batfish snapshots for network analysis and topology extraction.
6. **TOPOLOGY-VISUALIZER**: Generates interactive HTML visualizations of network topologies using Batfish data.

## Deployment Options

### Docker Compose (Recommended)

The recommended way to deploy Network Discovery MCP is using Docker Compose, which automatically sets up both the network discovery service and the required Batfish container.

#### REST API Mode (Default)

Run the container in REST API mode:

```bash
# Start both network-discovery and batfish containers
docker compose up -d
```

Access the API documentation at: http://localhost:8000/docs

#### MCP Mode for AI Integration

Run the container in MCP mode for direct AI agent integration:

```bash
# Start both containers with MCP enabled (HTTP mode)
docker compose -f docker-compose.mcp.yml up -d
```

Access the MCP server at: http://localhost:8080/mcp

##### HTTPS Support for MCP

For AI agents that require HTTPS, you can mount your SSL certificates:

1. Uncomment and modify these lines in `docker-compose.mcp.yml`:

```yaml
volumes:
  - ./artifacts:/artifacts
  - /etc/ssl/certs/fullchain.pem:/certs/fullchain.pem:ro
  - /etc/ssl/private/privkey.pem:/certs/privkey.pem:ro
ports:
  - "8080:8080"
  - "443:443"
```

2. Start the container:

```bash
docker compose -f docker-compose.mcp.yml up -d
```

The container will automatically detect your certificates and enable HTTPS on port 443. Access the MCP server at: https://localhost/mcp

### GitHub Actions Integration

The repository includes a ready-to-use GitHub Actions workflow for running network discovery:

```yaml
name: Discover Network

on:
  workflow_dispatch:
    inputs:
      seed_host:
        description: "Seed device IP or hostname"
        required: true
        default: "192.168.100.1"

jobs:
  discover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run network discovery
        uses: ./.github/workflows/run-network-discovery.yml
        with:
          seed_host: ${{ github.event.inputs.seed_host }}
          username: "admin"
        env:
          DEVICE_PASSWORD: ${{ secrets.DEVICE_PASSWORD }}
```

This workflow:
1. Deploys the network discovery environment using Docker Compose
2. Runs the full discovery pipeline from a seed device
3. Uploads artifacts including topology visualization

### Advanced Deployment Options

#### Port Forwarding Configuration

If you need to run behind a reverse proxy or port forwarding, use the BASE_PATH environment variable:

```bash
# Example: Using a base path with external port forwarding
export BASE_PATH="/api"
docker compose -f docker-compose.mcp.yml up -d
```

Access the MCP server at: http://your-server:8000/api/mcp

#### Single Container Deployment

If you prefer to run just the network discovery container:

```bash
# REST API Mode
docker pull ghcr.io/username/network-discovery-mcp:latest
docker run -p 8080:8080 -e ARTIFACT_DIR=/data -v /path/to/data:/data ghcr.io/username/network-discovery-mcp:latest

# MCP Mode (HTTP)
docker run -p 8080:8080 -e ENABLE_MCP=true -e TRANSPORT=http -e ARTIFACT_DIR=/data -v /path/to/data:/data ghcr.io/username/network-discovery-mcp:latest

# MCP Mode (HTTPS with certificates)
docker run -p 443:443 -p 8080:8080 \
  -e ENABLE_MCP=true -e TRANSPORT=https -e ARTIFACT_DIR=/data \
  -v /path/to/data:/data \
  -v /etc/ssl/certs/fullchain.pem:/certs/fullchain.pem:ro \
  -v /etc/ssl/private/privkey.pem:/certs/privkey.pem:ro \
  ghcr.io/username/network-discovery-mcp:latest
```

Note: Running without Batfish will disable topology visualization and analysis features.

## Integration Methods

### REST API Integration

The REST API mode provides traditional HTTP endpoints for programmatic access. This is ideal for:

- Integration with existing tools and scripts
- CI/CD pipelines and automation workflows
- Custom applications that need network discovery capabilities

Example API call to start the discovery process:

```bash
curl -X POST http://localhost:8000/v1/seed \
  -H "Content-Type: application/json" \
  -d '{
    "seed_host": "192.168.1.1",
    "credentials": {
      "username": "admin",
      "password": "cisco"
    },
    "methods": ["interfaces", "routing", "arp", "cdp"]
  }'
```

See the [API Endpoints Reference](#api-endpoints-reference) for a complete list of available endpoints.

### AI Agent Integration with MCP

The MCP mode provides a Model Context Protocol interface for direct AI agent integration. This enables AI agents to:

- Discover and analyze networks autonomously
- Make decisions based on network topology and configuration
- Execute complex workflows without human intervention

#### Available MCP Tools

The MCP server exposes tools in these categories:

**Seeder Tools**
- `seed_device`: Start network discovery from a seed device
- `get_targets`: Retrieve targets collected from the seed device

**Scanner Tools**
- `scan_targets`: Scan targets for open management ports
- `scan_from_subnets`: Scan specific subnets for open management ports
- `get_reachable_hosts`: Get only reachable hosts from scan results

**Fingerprinter Tools**
- `fingerprint_devices`: Start fingerprinting discovered devices
- `get_fingerprint_results`: Get fingerprinting results for a job

**Config Collector Tools**
- `collect_device_configs`: Collect device configurations
- `get_device_config`: Get configuration for a specific device

**Batfish Tools**
- `build_batfish_snapshot`: Build a Batfish snapshot
- `load_batfish_snapshot`: Load a Batfish snapshot
- `get_topology`: Get network topology in JSON format (supports network_name and snapshot_name)
- `generate_topology_visualization`: Generate interactive HTML visualization (supports network_name and snapshot_name)

**Artifact Tools**
- `get_artifact_content`: Retrieve an artifact file from the job directory (HTML, JSON, or binary)

#### Testing with FastMCP Inspector

You can test the MCP server using the FastMCP Inspector:

```bash
# Install FastMCP Inspector
npm install -g @presidio-federal/fastmcp-inspector

# Connect to HTTP MCP server
fastmcp-inspector http://localhost:8080/mcp

# OR connect to HTTPS MCP server (with self-signed certificates)
fastmcp-inspector https://localhost/mcp --tls-no-verify
```

#### Example MCP Workflow

Here's how an AI agent would interact with the MCP server:

```python
# 1. Seed from a device
result = mcp.invoke("seed_device", {
    "seed_host": "192.168.1.1",
    "credentials": {"username": "admin", "password": "cisco"},
    "methods": ["interfaces", "routing", "arp", "cdp"]
})
job_id = result["job_id"]

# 2. Scan discovered targets
mcp.invoke("scan_targets", {
    "job_id": job_id,
    "ports": [22, 443, 830]
})

# 3. Fingerprint discovered devices
mcp.invoke("fingerprint_devices", {"job_id": job_id})

# 4. Collect device configurations
mcp.invoke("collect_device_configs", {
    "job_id": job_id,
    "credentials": {"username": "admin", "password": "cisco"}
})

# 5. Build and load Batfish snapshot
mcp.invoke("build_batfish_snapshot", {"job_id": job_id})
mcp.invoke("load_batfish_snapshot", {"job_id": job_id})

# 6. Generate topology visualization
result = mcp.invoke("generate_topology_visualization", {"job_id": job_id})
topology_path = result["path"]

# Alternative: Generate topology from existing snapshot
result = mcp.invoke("generate_topology_visualization", {
    "network_name": "my_network",
    "snapshot_name": "my_snapshot"
})
topology_path = result["path"]

# 7. Retrieve artifact content directly
result = mcp.invoke("get_artifact_content", {
    "job_id": job_id,
    "filename": "topology.html"
})
html_content = result["content"]
```

#### MCP Configuration

The MCP server can be configured using the following environment variables:

- `ENABLE_MCP`: Set to `true` to enable MCP mode (default: `false`)
- `TRANSPORT`: MCP transport type, set to `http` or `https` (default: `https`)
- `HOST`: Host to bind the server to (default: `0.0.0.0`)
- `PORT`: Port to listen on (default: `8080`)
- `BASE_PATH`: Base path for the MCP endpoint (default: `""`)

##### SSL Certificate Configuration

The container automatically detects mounted SSL certificates:

- If certificates are present at `/certs/fullchain.pem` and `/certs/privkey.pem`, nginx will start with HTTPS on port 443
- If no certificates are found, the server runs in HTTP mode on port 8080

You can mount your own certificates using volume mounts:

```yaml
volumes:
  - /path/to/fullchain.pem:/certs/fullchain.pem:ro
  - /path/to/privkey.pem:/certs/privkey.pem:ro
```

## Architecture

```
network-discovery-mcp/
  ├── network_discovery/
  │   ├── __init__.py
  │   ├── __main__.py         # main entry point (supports both API and MCP modes)
  │   ├── api.py              # FastAPI endpoints
  │   ├── mcp_server.py       # MCP server implementation
  │   ├── artifacts.py        # atomic write/read helpers
  │   ├── seeder.py           # collects from seed device → produces targets + device state
  │   ├── scanner.py          # probes ports for reachability (22, 443, etc.)
  │   ├── fingerprinter.py    # infers device vendor/model from scan results
  │   ├── config_collector.py # retrieves device configurations in parallel
  │   ├── batfish_loader.py   # builds and loads Batfish snapshots
  │   ├── topology_visualizer.py # generates interactive HTML visualizations
  │   ├── config.py
  │   ├── workers.py          # async task orchestration
  ├── tests/
  │   ├── test_artifacts.py
  │   ├── test_seeder.py
  │   ├── test_scanner.py
  │   ├── test_fingerprinter.py
  │   ├── test_config_collector.py
  │   └── fixtures/
  ├── Dockerfile              # multi-stage build with MCP support
  ├── docker-compose.yml      # REST API mode configuration
  ├── docker-compose.mcp.yml  # MCP mode configuration
  ├── requirements.txt
  └── .github/workflows/build-and-publish.yml
```

## Artifact Storage

Environment variable: `ARTIFACT_DIR` (default: `/tmp/network_discovery_artifacts`)

Each run creates a job directory:

```
{ARTIFACT_DIR}/{job_id}/
  ├── targets.json             # <-- Seeder output (consumed by scanner)
  ├── device_states/{host}.json
  ├── ip_scan.json             # <-- Scanner output
  ├── fingerprints.json        # <-- Fingerprinter output
  ├── state/                   # <-- Config collector output
  │   ├── HAI-HQ.json
  │   ├── HAI-BRANCH-1.json
  │   └── ...
  ├── batfish_snapshot/        # <-- Batfish loader output
  │   └── configs/             # <-- Device config files for Batfish
  │       ├── HAI-HQ.cfg
  │       ├── HAI-BRANCH-1.cfg
  │       └── ...
  ├── topology.html            # <-- Interactive network visualization
  ├── status.json              # module status
  ├── summary.log
  └── error.json
```

All writes are atomic (`.tmp` → rename).

### Artifact Retrieval

The service provides direct access to artifacts through the `/v1/artifacts/{job_id}/{filename}` endpoint and the `get_artifact_content` MCP tool. This allows retrieving any file stored in the job directory:

```bash
# Retrieve the topology HTML file
curl -X GET http://localhost:8000/v1/artifacts/demo/topology.html

# Retrieve the scan results JSON file
curl -X GET http://localhost:8000/v1/artifacts/demo/ip_scan.json
```

The response format depends on the file type:
- Text files (HTML, JSON, TXT) are returned as raw text with the appropriate MIME type
- Binary files are returned as base64-encoded JSON

For MCP clients:
```python
# Retrieve artifact content
result = mcp.invoke("get_artifact_content", {
    "job_id": "demo",
    "filename": "topology.html"
})
html_content = result["content"]
```

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/seed` | Starts seeder, creates targets.json + device_states/ |
| POST | `/v1/scan` | Runs scanner using existing job targets |
| POST | `/v1/scan/from-subnets` | Runs scan directly from provided subnets |
| POST | `/v1/scan/add-subnets` | Merges new subnets into targets.json |
| GET | `/v1/status/{job_id}` | Returns module statuses |
| GET | `/v1/artifacts/{job_id}/{filename}` | Safely serves artifact files |
| GET | `/v1/scan/{job_id}` | Returns latest ip_scan.json |
| GET | `/v1/scan/{job_id}/reachable` | Returns only reachable hosts from scan results |
| POST | `/v1/fingerprint` | Starts fingerprinter, creates fingerprints.json |
| GET | `/v1/fingerprint/{job_id}` | Returns latest fingerprints.json |
| POST | `/v1/state/collect` | Collect all device states in parallel |
| GET | `/v1/state/{hostname}` | Retrieve one device's state |
| POST | `/v1/state/update/{hostname}` | Re-collect one device's state |
| POST | `/v1/batfish/build` | Convert state JSON → .cfg snapshot |
| POST | `/v1/batfish/load` | Load snapshot into Batfish |
| GET | `/v1/batfish/topology` | Return Layer-3 adjacency graph in JSON format (supports job_id, network_name, or snapshot_name) |
| GET | `/v1/batfish/topology/html` | Generate and return interactive HTML visualization of network topology (supports job_id, network_name, or snapshot_name) |
| GET | `/v1/artifacts/{job_id}/{filename}` | Retrieve an artifact file from the job directory (HTML, JSON, or binary) |
| GET | `/v1/batfish/networks` | List all networks in Batfish |
| POST | `/v1/batfish/networks/{network_name}` | Set current network in Batfish |
| GET | `/v1/batfish/networks/{network_name}/snapshots` | List all snapshots in a network |
| GET | `/v1/batfish/networks/{network_name}/snapshot` | Get current snapshot for a network |
| POST | `/v1/batfish/networks/{network_name}/snapshot/{snapshot_name}` | Set current snapshot for a network |

### Usage Examples

#### Seed from a device

```bash
curl -X POST http://localhost:8000/v1/seed \
  -H "Content-Type: application/json" \
  -d '{
    "seed_host": "192.168.1.1",
    "credentials": {
      "username": "admin",
      "password": "cisco"
    },
    "methods": ["interfaces", "routing", "arp", "cdp"]
  }'
```

Response:
```json
{
  "job_id": "abc123",
  "status": "running",
  "message": "Seeding started from 192.168.1.1"
}
```

#### Scan from targets

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "abc123",
    "ports": [22, 443, 830],
    "concurrency": 200
  }'
```

Response:
```json
{
  "job_id": "abc123",
  "status": "running",
  "message": "Scan started for job abc123"
}
```

#### Check status

```bash
curl http://localhost:8000/v1/status/abc123
```

Response:
```json
{
  "job_id": "abc123",
  "seeder": {
    "status": "completed",
    "targets_count": 256,
    "completed_at": "2025-10-19T14:30:00Z"
  },
  "scanner": {
    "status": "completed",
    "hosts_scanned": 256,
    "hosts_reachable": 15,
    "completed_at": "2025-10-19T14:45:00Z"
  },
  "fingerprinter": {
    "status": "running",
    "started_at": "2025-10-19T14:50:00Z"
  }
}
```

## Interactive HTML Topology Visualization

The `/v1/batfish/topology/html` endpoint generates an interactive HTML visualization of the network topology. This visualization is built using D3.js and provides a rich, interactive experience for exploring the network.

### Features

- **Force-directed graph layout**: Automatically arranges nodes based on their connections
- **Device names as node labels**: Clearly identifies each network device
- **Interactive controls**:
  - Drag nodes to rearrange the layout
  - Fix/unfix node positions with a toggle switch
  - Zoom in/out with mouse wheel or pinch gesture
  - Pan the view by clicking and dragging the background
  - Hover over nodes to see detailed device information
  - Export interface data as JSON
- **Auto-sizing**: Adapts to the browser window size
- **Self-contained**: HTML file includes all necessary visualization code
- **Detailed interface information**: Shows IP addresses, descriptions, and connection details

### How It Works

1. The endpoint connects to Batfish using the Session API
2. It retrieves the network topology data from `bf.q.edges().answer().frame()`
3. It collects detailed interface properties using `bf.q.interfaceProperties()`
4. Device names are extracted from interface identifiers (e.g., "Gig0/0@ROUTER-1" becomes "ROUTER-1")
5. A D3.js force-directed graph is constructed from the node relationships
6. The HTML is saved to `/artifacts/{job_id}/topology.html` and returned as a download

### Using Existing Batfish Snapshots

You can generate topology visualizations from any existing Batfish snapshot without running through the full discovery process:

```bash
# Generate topology from an existing Batfish snapshot
curl -X GET "http://localhost:8000/v1/batfish/topology/html?network_name=my_network&snapshot_name=my_snapshot" -o network_topology.html
```

This is useful when you already have snapshots in Batfish and want to quickly visualize them.

### Example Usage Workflow

```bash
# 1. Collect device configurations
curl -X POST http://localhost:8000/v1/state/collect -H "Content-Type: application/json" \
  -d '{"job_id": "demo", "credentials": {"username": "admin", "password": "cisco"}}'

# 2. Build and load Batfish snapshot
curl -X POST http://localhost:8000/v1/batfish/build -H "Content-Type: application/json" \
  -d '{"job_id": "demo"}'
curl -X POST http://localhost:8000/v1/batfish/load -H "Content-Type: application/json" \
  -d '{"job_id": "demo"}'

# 3. Generate and download the topology visualization
curl -X GET http://localhost:8000/v1/batfish/topology/html?job_id=demo -o network_topology.html

# 4. Open the HTML file in any web browser
open network_topology.html

# 5. Alternatively, retrieve the topology HTML directly from artifacts
curl -X GET http://localhost:8000/v1/artifacts/demo/topology.html > topology.html
```

## Environment Variables

### Core Settings
- `ARTIFACT_DIR`: Directory for storing job artifacts (default: `/tmp/network_discovery_artifacts`)
- `DEFAULT_PORTS`: Default ports to scan (default: `22,443`)
- `DEFAULT_CONCURRENCY`: Default concurrency level for scanning (default: `200`)
- `CONNECT_TIMEOUT`: Connection timeout in seconds (default: `1.5`)
- `LOG_LEVEL`: Logging level (default: `info`)

### Batfish Settings
- `BATFISH_HOST`: Hostname of the Batfish server (default: `batfish`)
- `BATFISH_PORT`: Port of the Batfish server (default: `9996`)

### Server Settings
- `HOST`: Host to bind the server to (default: `0.0.0.0`)
- `PORT`: Port to listen on (default: `8000`)

### MCP Settings
- `ENABLE_MCP`: Enable MCP mode (default: `false`)
- `TRANSPORT`: MCP transport type (default: `http`)
- `BASE_PATH`: Base path for the MCP endpoint (default: `""`) - useful for port forwarding scenarios

## Dependencies

The network-discovery-mcp service relies on the following key dependencies:

### Core Framework
- FastAPI and Uvicorn for the API server
- Pydantic for data validation and settings management
- FastMCP for Model Context Protocol support (v2.12.0+)

### Network Discovery
- Netmiko and Paramiko for SSH connectivity
- Nornir for parallel task execution
- NAPALM for multi-vendor network automation
- Scapy and PySnmp for network probing and SNMP operations

### Data Processing
- Pandas for data manipulation
- NetworkX for graph operations and topology analysis
- Plotly for interactive visualizations

### Batfish Integration
- Pybatfish for network analysis and validation

### Deployment
- Docker and Docker Compose for containerization
- GitHub Actions for CI/CD

For a complete list of dependencies and version requirements, see the `requirements.txt` file.