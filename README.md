# Network Discovery MCP

A modular, containerized network discovery service for the HAI platform.

## Overview

This service provides lightweight, API-driven network discovery capabilities through six main modules:

1. **SEEDER**: Starts from a known device (seed) and collects potential subnets and candidate IPs via interfaces, VRFs, ARP, CDP/LLDP, and routing tables.
2. **IP-SCANNER**: Probes for open management ports (default: 22 and 443) across candidate IPs or subnets.
3. **FINGERPRINTER**: Analyzes hosts discovered by the scanner and infers likely vendor, model, and management protocol without logging in.
4. **CONFIG-COLLECTOR**: Retrieves each device's running configuration in parallel and stores it as a separate JSON file.
5. **BATFISH-LOADER**: Builds and loads Batfish snapshots for network analysis and topology extraction.
6. **TOPOLOGY-VISUALIZER**: Generates interactive HTML visualizations of network topologies using Batfish data.

The service produces well-structured artifacts for downstream tools (NSO, Batfish, etc.) in a job-scoped workspace.

## Architecture

```
network-discovery-mcp/
  ├── network_discovery/
  │   ├── __init__.py
  │   ├── api.py              # FastAPI endpoints
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
  ├── Dockerfile
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

## API Endpoints

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
| GET | `/v1/batfish/topology` | Return Layer-3 adjacency graph in JSON format |
| GET | `/v1/batfish/topology/html` | Generate and return interactive HTML visualization of network topology |
| GET | `/v1/batfish/networks` | List all networks in Batfish |
| POST | `/v1/batfish/networks/{network_name}` | Set current network in Batfish |
| GET | `/v1/batfish/networks/{network_name}/snapshots` | List all snapshots in a network |
| GET | `/v1/batfish/networks/{network_name}/snapshot` | Get current snapshot for a network |
| POST | `/v1/batfish/networks/{network_name}/snapshot/{snapshot_name}` | Set current snapshot for a network |

## Usage Examples

### Seed from a device

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

### Scan from targets

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

### Check status

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

### Get scan results

```bash
curl http://localhost:8000/v1/scan/abc123
```

### Get reachable hosts only

```bash
curl http://localhost:8000/v1/scan/abc123/reachable
```

### Fingerprint discovered devices

```bash
curl -X POST http://localhost:8000/v1/fingerprint \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "abc123",
    "snmp_community": "public",
    "concurrency": 100
  }'
```

Response:
```json
{
  "job_id": "abc123",
  "status": "running",
  "message": "Fingerprinting started for job abc123"
}
```

### Get fingerprint results

```bash
curl http://localhost:8000/v1/fingerprint/abc123
```

Response:
```json
{
  "job_id": "abc123",
  "fingerprinted_at": "2025-10-19T15:00:00Z",
  "hosts": [
    {
      "ip": "10.0.0.5",
      "evidence": {
        "ssh_banner": "SSH-2.0-Cisco-1.25",
        "tls_cn": "csr1000v.local",
        "http_server": "Cisco-IOS-XE"
      },
      "inference": {
        "vendor": "Cisco",
        "model": "IOS-XE",
        "protocols": ["ssh", "https"],
        "confidence": 0.9
      }
    }
  ]
}
```

## Docker Deployment

### Single Container

```bash
docker pull ghcr.io/username/network-discovery-mcp:latest
docker run -p 8000:8000 -e ARTIFACT_DIR=/data -v /path/to/data:/data ghcr.io/username/network-discovery-mcp:latest
```

### Docker Compose with Batfish

For the full pipeline with Batfish integration:

```bash
docker compose up --build
```

This will start both the network-discovery-mcp service and the Batfish container with a shared volume for artifact exchange.

## Environment Variables

- `ARTIFACT_DIR`: Directory for storing job artifacts (default: `/tmp/network_discovery_artifacts`)
- `DEFAULT_PORTS`: Default ports to scan (default: `22,443`)
- `DEFAULT_CONCURRENCY`: Default concurrency level for scanning (default: `200`)
- `CONNECT_TIMEOUT`: Connection timeout in seconds (default: `1.5`)
- `BATFISH_HOST`: URL of the Batfish server (default: `http://batfish:9997`)

## Fingerprinter Module

The fingerprinter module analyzes hosts discovered by the scanner and infers likely vendor, model, and management protocol without logging in.

### Features

- Consumes only ip_scan.json produced by the scanner
- Performs non-intrusive device fingerprinting:
  - SSH banner analysis
  - TLS certificate inspection
  - HTTP server header examination
  - Optional SNMP sysDescr retrieval (if community string provided)
- Never attempts authentication or configuration access
- Uses pattern matching and heuristics to infer device type
- Produces fingerprints.json for use by higher-level agents (e.g., NSO onboarding or Batfish enrichment)

### Confidence Scoring

The fingerprinter uses a confidence scoring system to indicate the reliability of its inferences:

- SSH banner match: +0.4
- HTTP/TLS match: +0.2
- SNMP sysDescr match: +0.4
- Maximum confidence score: 1.0

## Config Collector Module

The config collector module retrieves each device's running configuration in parallel and stores it as a separate JSON file.

### Features

- Consumes fingerprints.json produced by the fingerprinter
- Retrieves running configurations using appropriate methods based on device type:
  - SSH: `show running-config` (Cisco/Arista) or `show configuration | display set` (Juniper)
  - NETCONF: For supported devices
  - RESTCONF: For supported Cisco devices
- Runs concurrent SSH/API sessions for speed (with semaphore control)
- Stores each device's config in a separate file under state/{hostname}.json
- Supports re-collecting a single device's configuration

### Usage Example

Collect all device configurations:

```bash
curl -X POST http://localhost:8000/v1/state/collect \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "abc123",
    "credentials": {
      "username": "admin",
      "password": "cisco"
    },
    "concurrency": 25
  }'
```

Response:
```json
{
  "job_id": "abc123",
  "status": "running",
  "message": "State collection started for job abc123"
}
```

Retrieve a specific device's configuration:

```bash
curl http://localhost:8000/v1/state/HAI-HQ?job_id=abc123
```

Response:
```json
{
  "hostname": "HAI-HQ",
  "vendor": "Cisco",
  "collected_at": "2025-10-21T00:00:00Z",
  "protocol": "ssh",
  "running_config": "!\nversion 17.9\nhostname HAI-HQ\n..."
}
```

Update a single device's configuration:

```bash
curl -X POST http://localhost:8000/v1/state/update/HAI-HQ \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "abc123",
    "credentials": {
      "username": "admin",
      "password": "cisco"
    }
  }'
```

Response:
```json
{
  "job_id": "abc123",
  "status": "running",
  "message": "State update started for device HAI-HQ"
}
```

## Batfish Integration Module

The Batfish integration module builds and loads Batfish snapshots for network analysis and topology extraction.

### Features

- Consumes state/{hostname}.json files produced by the config collector
- Extracts running configurations and writes them to .cfg files
- Loads snapshots into a Batfish server for analysis
- Provides network topology information

### Workflow

1. Collect device configurations:
```bash
# 1. Collect configs
curl -X POST http://localhost:8000/v1/state/collect \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "demo",
    "credentials": {
      "username": "admin",
      "password": "cisco"
    }
  }'
```

2. Build Batfish snapshot:
```bash
# 2. Build snapshot
curl -X POST http://localhost:8000/v1/batfish/build \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "demo"
  }'
```

3. Load snapshot into Batfish:
```bash
# 3. Load snapshot into Batfish
curl -X POST http://localhost:8000/v1/batfish/load \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "demo"
  }'
```

4. Get network topology:
```bash
# 4. Get topology (JSON format)
curl -X GET http://localhost:8000/v1/batfish/topology?job_id=demo
```

Response:
```json
{
  "job_id": "demo",
  "edges": [
    {"Interface": "Gig0/0@HAI-HQ", "Remote_Interface": "Gig0/1@HAI-BRANCH-1"},
    {"Interface": "Gig0/1@HAI-HQ", "Remote_Interface": "Gig0/0@HAI-BRANCH-2"}
  ]
}
```

5. Get interactive HTML topology visualization:
```bash
# 5. Get HTML visualization
curl -X GET http://localhost:8000/v1/batfish/topology/html?job_id=demo -o topology.html
```

This will download an interactive HTML file that can be opened in any web browser. The visualization is generated using Plotly and NetworkX, providing a rich interactive experience.

#### Visualization Features

- **Force-directed graph layout**: Automatically arranges nodes based on their connections
- **Device names as node labels**: Clearly identifies each network device
- **Interactive controls**:
  - Drag nodes to rearrange the layout
  - Zoom in/out with mouse wheel or pinch gesture
  - Pan the view by clicking and dragging the background
  - Hover over nodes to see detailed device information
- **Auto-sizing**: Adapts to the browser window size
- **Self-contained**: HTML file includes all necessary visualization code

#### How It Works

1. The endpoint connects to Batfish using the Session API
2. It retrieves the network topology data from `bf.q.edges().answer().frame()`
3. Device names are extracted from interface identifiers (e.g., "Gig0/0@ROUTER-1" becomes "ROUTER-1")
4. A NetworkX graph is constructed from the node relationships
5. Plotly generates an interactive visualization of the graph
6. The HTML is saved to `/artifacts/{job_id}/topology.html` and returned as a download

#### Example Usage Workflow

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
```

## API Endpoints Reference

The network-discovery-mcp service provides the following API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/seed` | Start a seeder operation from a device |
| POST | `/v1/scan` | Start a scanner operation using existing job targets |
| POST | `/v1/scan/from-subnets` | Start a scanner operation using subnets |
| POST | `/v1/scan/add-subnets` | Add subnets to an existing scan job |
| GET | `/v1/scan/{job_id}` | Get scan results for a job |
| GET | `/v1/scan/{job_id}/reachable` | Get only reachable hosts from scan results |
| POST | `/v1/fingerprint` | Start a fingerprinting operation |
| GET | `/v1/fingerprint/{job_id}` | Get fingerprinting results for a job |
| POST | `/v1/state/collect` | Collect device configurations |
| GET | `/v1/state/{hostname}` | Get configuration for a specific device |
| POST | `/v1/state/update/{hostname}` | Update configuration for a specific device |
| GET | `/v1/state/status` | Get status of configuration collection |
| POST | `/v1/batfish/build` | Build a Batfish snapshot |
| POST | `/v1/batfish/load` | Load a Batfish snapshot |
| GET | `/v1/batfish/topology` | Get network topology in JSON format |
| GET | `/v1/batfish/topology/html` | Get interactive HTML visualization of network topology |
| GET | `/v1/batfish/networks` | List all Batfish networks |
| POST | `/v1/batfish/networks/{network_name}` | Set current Batfish network |
| GET | `/v1/batfish/networks/{network_name}/snapshots` | List snapshots in a network |
| GET | `/v1/batfish/networks/{network_name}/snapshot` | Get current snapshot |
| POST | `/v1/batfish/networks/{network_name}/snapshot/{snapshot_name}` | Set current snapshot |

### Batfish Network Management

The network-discovery-mcp service provides the following endpoints for managing Batfish networks and snapshots:

#### List all networks

```bash
curl -X GET http://localhost:8000/v1/batfish/networks
```

Response:
```json
["demo", "network1", "network2"]
```

#### Set current network

```bash
curl -X POST http://localhost:8000/v1/batfish/networks/demo
```

Response:
```json
{
  "network": "demo",
  "snapshots": ["snapshot_latest"]
}
```

#### List snapshots in a network

```bash
curl -X GET http://localhost:8000/v1/batfish/networks/demo/snapshots
```

Response:
```json
["snapshot_latest", "snapshot_2025_10_22"]
```

#### Get current snapshot

```bash
curl -X GET http://localhost:8000/v1/batfish/networks/demo/snapshot
```

Response:
```json
{
  "network": "demo",
  "snapshot": "snapshot_latest",
  "status": "success"
}
```

#### Set current snapshot

```bash
curl -X POST http://localhost:8000/v1/batfish/networks/demo/snapshot/snapshot_2025_10_22
```

Response:
```json
{
  "network": "demo",
  "snapshot": "snapshot_2025_10_22",
  "status": "success"
}
```

## Running Modes

The network-discovery-mcp service can run in two modes:

### 1. REST API Mode (Default)

In this mode, the service exposes a REST API using FastAPI:

```bash
# Run with default REST API mode
docker-compose up -d
```

Access the API documentation at: http://localhost:4437/docs

### 2. MCP (Model Context Protocol) Mode

In this mode, the service exposes an MCP interface for integration with AI agents:

```bash
# Run in MCP mode
docker-compose -f docker-compose.mcp.yml up -d
```

The MCP server will be available at: http://localhost:4437/mcp

You can test the MCP server using the FastMCP Inspector:

```bash
# Install FastMCP Inspector
npm install -g @presidio-federal/fastmcp-inspector

# Connect to the MCP server
fastmcp-inspector http://localhost:4437/mcp
```

## Dependencies

The network-discovery-mcp service relies on the following key dependencies:

### Core Framework
- FastAPI and Uvicorn for the API server
- Pydantic for data validation and settings management
- FastMCP for Model Context Protocol support

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
