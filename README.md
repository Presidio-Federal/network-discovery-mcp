# Network Discovery MCP - User Guide

A modular, containerized network discovery service for automated network mapping and analysis. Network Discovery MCP automatically discovers network devices, collects configurations, and generates interactive topology visualizations starting from a single seed device.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
- [Deployment Modes](#deployment-modes)
- [Using the REST API](#using-the-rest-api)
- [Using with AI Agents (MCP)](#using-with-ai-agents-mcp)
- [GitHub Actions Integration](#github-actions-integration)
- [API Reference](#api-reference)
- [MCP Tools Reference](#mcp-tools-reference)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

---

## Overview

Network Discovery MCP provides automated network infrastructure discovery and mapping. The system supports two discovery approaches:

### Discovery Method 1: Seed Device Discovery
1. Connects to a single "seed" network device
2. Automatically discovers the network topology through:
   - Interface information (subnets, VRFs)
   - Routing tables (known networks)
   - ARP tables (active hosts)
   - CDP/LLDP neighbors (directly connected devices)
3. Scans all discovered IP addresses for reachability
4. Identifies device vendors and models
5. Collects device configurations
6. Generates interactive network topology visualizations

**Use this method when**: You have network access to devices and want automated topology discovery.

### Discovery Method 2: Direct IP/Subnet Scanning
1. Accepts a list of IP addresses or subnets directly
2. Scans the provided addresses for reachability
3. Identifies device vendors and models
4. Collects device configurations
5. Generates network topology visualizations

**Use this method when**: You have a source of truth (like NetBox, spreadsheet, or IPAM) with device IPs and want to skip topology discovery.

### Operating Modes

The service can operate in two modes:
- **REST API Mode**: Traditional HTTP API for integration with scripts, tools, and CI/CD pipelines
- **MCP Mode**: Model Context Protocol interface for direct AI agent integration

Both modes provide identical functionality with different integration patterns.

---

## Features

### Core Discovery Features

- **Automated Network Mapping**: Discover entire network topology from a single seed device
- **Intelligent Multi-Vendor Support**: Automatically detects device OS after login (Cisco, Juniper, Arista, Palo Alto, Fortinet, Huawei)
- **Enhanced Device Fingerprinting**: Improved vendor identification with support for Arista EOS, Juniper JUNOS, and Palo Alto PAN-OS
- **Parallel Operations**: High-performance scanning and configuration collection
- **Configuration Management**: Securely collect and store device configurations with vendor-specific commands
- **Interactive Visualizations**: Generate interactive HTML network topology maps with color-coded device status
- **Batfish Integration**: Advanced network analysis and validation

### Reliability Features

- **Credential Validation**: Test credentials before starting expensive operations (saves 30+ minutes on failures)
- **Job Resume**: Resume failed jobs without re-doing completed work (critical for large networks)
- **Retry Logic**: Automatic retry with exponential backoff for transient failures
- **Timeout Handling**: Configurable timeouts prevent hanging operations
- **Graceful Shutdown**: Clean shutdown handling for containerized environments

### Monitoring and Observability

- **System Health Checks**: Monitor system resources before starting scans
- **Job Statistics**: Detailed progress tracking and success metrics
- **Failure Analysis**: Intelligent recommendations for troubleshooting
- **Historical Tracking**: Track job history and success rates over time

### Intelligent Features

- **Automatic OS Detection**: Detects device operating system after SSH login (eliminates need for platform parameter)
- **Vendor-Specific Commands**: Automatically selects correct commands for each vendor
- **Fingerprint Correction**: Corrects misidentifications by validating OS post-authentication
- **Fallback Mechanisms**: Uses fingerprint data if OS detection fails

### Security Features

- **Secure Credential Handling**: Passwords masked in logs and representations
- **Atomic File Operations**: Prevent data corruption during writes
- **Container Isolation**: Runs in isolated container environments
- **Optional HTTPS**: Support for encrypted MCP communications

---

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- Network access to devices you want to discover
- Valid credentials for at least one "seed" device

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/username/network-discovery-mcp.git
cd network-discovery-mcp
```

2. Choose your deployment mode:

**For REST API Mode:**
```bash
docker compose up -d
```

**For MCP Mode (AI Agents):**
```bash
docker compose -f docker-compose.mcp.yml up -d
```

3. Verify the service is running:

**REST API:**
```bash
curl http://localhost:8000/health
```

**MCP:**
```bash
curl http://localhost:8080/mcp
```

4. Start a discovery (REST API example):
```bash
curl -X POST http://localhost:8000/v1/seed \
  -H "Content-Type: application/json" \
  -d '{
    "seed_host": "192.168.1.1",
    "credentials": {
      "username": "admin",
      "password": "your_password"
    },
    "methods": ["interfaces", "routing", "arp", "cdp"]
  }'
```

**Note**: The `platform` parameter (like `cisco_ios`) is now optional! The system automatically detects the device OS after login and selects the appropriate commands. You can still provide `platform` as a fallback if needed.

The response includes a job_id that you can use to track progress and retrieve results.

---

## Deployment Modes

### REST API Mode (Default)

REST API mode provides traditional HTTP endpoints for programmatic access.

**Use this mode when:**
- Integrating with existing tools and scripts
- Running from CI/CD pipelines
- Building custom applications
- You need language-agnostic HTTP access

**Starting REST API mode:**
```bash
docker compose up -d
```

**Accessing the API:**
- API Base URL: `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

**Configuration file:** `docker-compose.yml`

---

### MCP Mode (AI Agent Integration)

MCP mode provides a Model Context Protocol interface for AI agent integration.

**Use this mode when:**
- Integrating with AI agents (Claude, GPT, etc.)
- Building autonomous network discovery workflows
- You want AI-driven network operations

**Starting MCP mode:**
```bash
docker compose -f docker-compose.mcp.yml up -d
```

**Accessing the MCP server:**
- MCP Endpoint: `http://localhost:8080/mcp`
- Health Check: `http://localhost:8080/health`

**Configuration file:** `docker-compose.mcp.yml`

#### MCP with HTTPS

Some AI agent frameworks (like certain Claude implementations or enterprise AI platforms) require HTTPS connections and will not accept HTTP. If your AI agent requires HTTPS, you need to configure SSL certificates.

**When to use HTTPS:**
- Your AI agent framework refuses HTTP connections
- Your AI agent is running on a different network and requires encryption
- Corporate security policies mandate encrypted communications
- You're exposing the MCP server to the internet

**Prerequisites:**
- SSL certificate file (fullchain.pem or certificate.crt)
- SSL private key file (privkey.pem or private.key)

##### Step 1: Prepare Your Certificates

Option A - Using Let's Encrypt certificates:
```bash
# If using Let's Encrypt/Certbot, certificates are typically at:
# Certificate: /etc/letsencrypt/live/yourdomain.com/fullchain.pem
# Private key: /etc/letsencrypt/live/yourdomain.com/privkey.pem
```

Option B - Using self-signed certificates (for testing):
```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout privkey.pem \
  -out fullchain.pem \
  -subj "/CN=localhost"
```

Option C - Using corporate certificates:
```bash
# Use certificates provided by your organization
# Ensure you have both the certificate and private key files
```

##### Step 2: Modify docker-compose.mcp.yml

Edit the `docker-compose.mcp.yml` file to mount your certificates:

```yaml
services:
  network-discovery-mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: network-discovery-mcp
    environment:
      - ENABLE_MCP=true
      - TRANSPORT=https                    # Set transport to https
      - PORT=8080
      - HOST=0.0.0.0
      - ARTIFACT_DIR=/artifacts
      - BATFISH_HOST=batfish
      - LOG_LEVEL=info
    ports:
      - "8080:8080"                         # HTTP port (optional, for health checks)
      - "443:443"                           # HTTPS port (required)
volumes:
  - ./artifacts:/artifacts
      # Mount your SSL certificates (REQUIRED for HTTPS):
      - /path/to/your/fullchain.pem:/certs/fullchain.pem:ro
      - /path/to/your/privkey.pem:/certs/privkey.pem:ro
    depends_on:
      - batfish
    networks:
      - discovery-network

  batfish:
    image: batfish/batfish:latest
    container_name: batfish
ports:
      - "9996:9996"
      - "9997:9997"
    networks:
      - discovery-network

networks:
  discovery-network:
    driver: bridge
```

**Important changes:**
1. Change `TRANSPORT` from `http` to `https`
2. Add port mapping for `443:443`
3. Uncomment and update the certificate volume mounts with your actual certificate paths
4. Replace `/path/to/your/` with the actual path to your certificates

##### Step 3: Start the Service

```bash
# Start with HTTPS enabled
docker compose -f docker-compose.mcp.yml up -d

# Check logs to verify HTTPS is working
docker compose -f docker-compose.mcp.yml logs network-discovery-mcp

# You should see logs indicating nginx started with HTTPS on port 443
```

##### Step 4: Verify HTTPS is Working

```bash
# Test HTTPS endpoint
curl https://localhost/mcp

# If using self-signed certificates, use -k to skip verification
curl -k https://localhost/mcp

# You should get a response from the MCP server
```

##### Step 5: Configure Your AI Agent

Update your AI agent configuration to use the HTTPS endpoint:

```python
# Example: Connecting AI agent to HTTPS MCP server
import mcp

# With valid certificates
client = mcp.Client("https://your-server.com/mcp")

# With self-signed certificates (development only)
import ssl
context = ssl._create_unverified_context()
client = mcp.Client("https://localhost/mcp", ssl_context=context)
```

##### Troubleshooting HTTPS

**Problem: "Certificate verification failed"**

If using self-signed certificates, your AI agent may reject them. Solutions:

1. For testing, disable certificate verification in your agent (not recommended for production)
2. Add the self-signed certificate to your system's trusted certificates
3. Use properly signed certificates from Let's Encrypt or a CA

**Problem: "Connection refused on port 443"**

Check that:
```bash
# 1. Container is running
docker compose -f docker-compose.mcp.yml ps

# 2. Port 443 is mapped
docker compose -f docker-compose.mcp.yml port network-discovery-mcp 443

# 3. Nginx is running with HTTPS
docker compose -f docker-compose.mcp.yml logs network-discovery-mcp | grep nginx

# 4. Certificates are mounted correctly
docker exec network-discovery-mcp ls -la /certs/
```

**Problem: "Cannot find certificates"**

The container looks for certificates at:
- `/certs/fullchain.pem`
- `/certs/privkey.pem`

Verify they're mounted:
```bash
docker exec network-discovery-mcp ls -la /certs/
# Should show both files
```

##### Example: Complete HTTPS Setup with Let's Encrypt

```bash
# 1. Obtain Let's Encrypt certificates (on host machine)
sudo certbot certonly --standalone -d your-domain.com

# 2. Update docker-compose.mcp.yml with certificate paths
# Edit the volumes section:
volumes:
  - ./artifacts:/artifacts
  - /etc/letsencrypt/live/your-domain.com/fullchain.pem:/certs/fullchain.pem:ro
  - /etc/letsencrypt/live/your-domain.com/privkey.pem:/certs/privkey.pem:ro

# 3. Ensure TRANSPORT is set to https
# environment:
#   - TRANSPORT=https

# 4. Start the service
docker compose -f docker-compose.mcp.yml up -d

# 5. Test HTTPS connection
curl https://your-domain.com/mcp

# 6. Configure AI agent to use HTTPS endpoint
# In your AI agent config:
# mcp_server_url: https://your-domain.com/mcp
```

##### HTTP vs HTTPS Decision Matrix

| Scenario | Use HTTP | Use HTTPS |
|----------|----------|-----------|
| Testing locally with AI agent on same machine | Yes | No |
| AI agent framework requires HTTPS | No | Yes |
| Exposing MCP server over network | No | Yes |
| Corporate security policy | No | Yes |
| AI agent on different network | No | Yes |
| Development/testing environment | Yes | Optional |
| Production environment | No | Yes |

**Summary:**
- HTTP (port 8080) is simpler for local testing
- HTTPS (port 443) is required for AI agent frameworks that don't accept HTTP
- The service automatically detects mounted certificates and enables HTTPS
- Both HTTP and HTTPS can run simultaneously (useful for health checks on port 8080)

#### Testing Your MCP Server

You can test the MCP server using standard HTTP tools:

```bash
# Test HTTP MCP server
curl http://localhost:8080/mcp

# Test HTTPS MCP server
curl https://localhost/mcp --insecure

# Check available tools (pretty print)
curl http://localhost:8080/mcp | jq '.tools'

# Verify specific tool availability
curl http://localhost:8080/mcp | jq '.tools[] | select(.name=="run_network_discovery")'
```

You can also use the MCP Inspector tool from the official MCP SDK if you have it installed locally, or integrate directly with AI agent frameworks like Claude Desktop, Cline, or other MCP-compatible clients.

---

### Single Container Deployment

For advanced users who want more control or don't need Batfish:

**REST API Mode:**
```bash
docker run -d \
  -p 8000:8000 \
  -e ARTIFACT_DIR=/data \
  -v /path/to/artifacts:/data \
  ghcr.io/username/network-discovery-mcp:latest
```

**MCP Mode (HTTP):**
```bash
docker run -d \
  -p 8080:8080 \
  -e ENABLE_MCP=true \
  -e TRANSPORT=http \
  -e ARTIFACT_DIR=/data \
  -v /path/to/artifacts:/data \
  ghcr.io/username/network-discovery-mcp:latest
```

**MCP Mode (HTTPS):**
```bash
docker run -d \
  -p 443:443 -p 8080:8080 \
  -e ENABLE_MCP=true \
  -e TRANSPORT=https \
  -e ARTIFACT_DIR=/data \
  -v /path/to/artifacts:/data \
  -v /etc/ssl/certs/fullchain.pem:/certs/fullchain.pem:ro \
  -v /etc/ssl/private/privkey.pem:/certs/privkey.pem:ro \
  ghcr.io/username/network-discovery-mcp:latest
```

**Note:** Running without the Batfish container disables topology visualization and analysis features.

---

## Using the REST API

The REST API provides programmatic access to all network discovery functionality.

### Complete Discovery Workflow

Here's a complete example of discovering a network using the REST API:

#### Step 1: Validate Credentials (Recommended)

Test credentials before starting the discovery to avoid wasting time:

```bash
curl -X POST http://localhost:8000/v1/credentials/validate \
  -H "Content-Type: application/json" \
  -d '{
    "seed_host": "192.168.1.1",
    "username": "admin",
    "password": "cisco123"
  }'
```

**Note**: The `platform` parameter is optional. The system will automatically detect the OS after connecting.

Response:
```json
{
  "valid": true,
  "latency_ms": 2340,
  "detected_vendor": "Cisco",
  "detected_model": "IOS-XE",
  "can_read_config": true
}
```

If credentials are invalid, you'll get an error with suggestions before wasting time on discovery.

#### Step 2: Seed from a Device

Start discovery from a seed device:

```bash
curl -X POST http://localhost:8000/v1/seed \
  -H "Content-Type: application/json" \
  -d '{
    "seed_host": "192.168.1.1",
    "credentials": {
      "username": "admin",
      "password": "cisco123"
    },
    "methods": ["interfaces", "routing", "arp", "cdp"]
  }'
```

**Note**: Platform auto-detection happens automatically. You can optionally provide `"platform": "cisco_ios"` as a fallback if detection should fail.

Response:
```json
{
  "job_id": "net-disc-20251102-123456",
  "status": "completed",
  "targets_count": 256,
  "targets_path": "/artifacts/net-disc-20251102-123456/targets.json"
}
```

Save the `job_id` for subsequent operations.

#### Step 3: Scan Discovered Targets

Scan the discovered targets for reachability:

```bash
curl -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-20251102-123456",
    "ports": [22, 443],
    "concurrency": 200
  }'
```

Response:
```json
{
  "job_id": "net-disc-20251102-123456",
  "status": "completed",
  "hosts_scanned": 256,
  "hosts_reachable": 42
}
```

#### Step 4: Fingerprint Devices

Identify vendors and models:

```bash
curl -X POST http://localhost:8000/v1/fingerprint \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-20251102-123456"
  }'
```

Response:
```json
{
  "job_id": "net-disc-20251102-123456",
  "status": "completed",
  "hosts_fingerprinted": 42,
  "identified_count": 38
}
```

#### Step 5: Collect Configurations

Collect device configurations (platform auto-detected):

```bash
curl -X POST http://localhost:8000/v1/state/collect \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-20251102-123456",
    "credentials": {
      "username": "admin",
      "password": "cisco123"
    },
    "concurrency": 50
  }'
```

**Note**: The system automatically detects each device's OS after login and runs the appropriate commands:
- Cisco: `show running-config`
- Arista: `show running-config`  
- Juniper: `show configuration | display set`
- Palo Alto: `show config running`
- Fortinet: `show full-configuration`
- Huawei: `display current-configuration`

Response:
```json
{
  "job_id": "net-disc-20251102-123456",
  "status": "completed",
  "device_count": 42,
  "success_count": 38,
  "failed_count": 4
}
```

#### Step 6: Generate Topology Visualization

Build Batfish snapshot and generate visualization:

```bash
# Build Batfish snapshot
curl -X POST http://localhost:8000/v1/batfish/build \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-20251102-123456"
  }'

# Load into Batfish
curl -X POST http://localhost:8000/v1/batfish/load \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-20251102-123456"
  }'

# Generate visualization
curl -X GET "http://localhost:8000/v1/batfish/topology/html?job_id=net-disc-20251102-123456" \
  -o network_topology.html

# Open in browser
open network_topology.html
```

#### Step 7: Check Job Status

Monitor progress at any time:

```bash
curl http://localhost:8000/v1/status/net-disc-20251102-123456
```

Response:
```json
{
  "job_id": "net-disc-20251102-123456",
  "seeder": {
    "status": "completed",
    "targets_count": 256,
    "completed_at": "2025-11-02T12:34:56Z"
  },
  "scanner": {
    "status": "completed",
    "hosts_scanned": 256,
    "hosts_reachable": 42,
    "completed_at": "2025-11-02T12:38:45Z"
  },
  "fingerprinter": {
    "status": "completed",
    "hosts_fingerprinted": 42,
    "completed_at": "2025-11-02T12:40:22Z"
  },
  "state_collector": {
    "status": "completed",
    "device_count": 42,
    "success_count": 38,
    "failed_count": 4,
    "completed_at": "2025-11-02T12:55:33Z"
  }
}
```

### Handling Failures: Job Resume

If a job fails partway through (e.g., during config collection), you can resume it without re-doing completed work:

```bash
# Check for resumable jobs
curl http://localhost:8000/v1/jobs/resumable

# Resume a specific job
curl -X POST http://localhost:8000/v1/jobs/resume \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-20251102-123456",
    "credentials": {
      "username": "admin",
      "password": "cisco123",
      "platform": "cisco_ios"
    }
  }'
```

The resume operation:
- Detects which phases completed successfully
- Skips completed work
- Retries only failed or incomplete phases
- Preserves all successful results

This is critical for large networks where a transient failure shouldn't require restarting the entire discovery process.

### Alternative: Scan from Subnets Directly

If you don't need seed-based discovery and already have a list of IP addresses or subnets (from NetBox, IPAM, spreadsheet, etc.), you can scan them directly:

```bash
curl -X POST http://localhost:8000/v1/scan/from-subnets \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "manual-scan-001",
    "subnets": ["192.168.1.0/24", "10.0.0.0/24"],
    "ports": [22, 443],
    "concurrency": 200
  }'
```

Then continue with fingerprinting and config collection as normal.

### Working with Source of Truth Systems

If you maintain an inventory in a source of truth system (NetBox, phpIPAM, etc.), you can extract the IP addresses and scan them directly without seed device discovery.

**Example: Using NetBox as Source of Truth**

```bash
# 1. Query NetBox for device IPs (this is pseudocode)
DEVICE_IPS=$(curl -H "Authorization: Token YOUR_TOKEN" \
  https://netbox.example.com/api/dcim/devices/ | \
  jq -r '.results[].primary_ip.address' | \
  cut -d'/' -f1)

# 2. Convert to JSON array
SUBNETS=$(echo "$DEVICE_IPS" | jq -R -s -c 'split("\n")[:-1]')

# 3. Start scan with those IPs
curl -X POST http://localhost:8000/v1/scan/from-subnets \
  -H "Content-Type: application/json" \
  -d "{
    \"job_id\": \"netbox-scan\",
    \"subnets\": $SUBNETS,
    \"ports\": [22, 443],
    \"concurrency\": 200
  }"

# 4. Continue with fingerprinting
curl -X POST http://localhost:8000/v1/fingerprint \
  -H "Content-Type: application/json" \
  -d '{"job_id": "netbox-scan"}'

# 5. Collect configs
curl -X POST http://localhost:8000/v1/state/collect \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "netbox-scan",
    "credentials": {
      "username": "admin",
      "password": "your_password",
      "platform": "cisco_ios"
    }
  }'

# 6. Generate topology
curl -X POST http://localhost:8000/v1/batfish/build \
  -H "Content-Type: application/json" \
  -d '{"job_id": "netbox-scan"}'

curl -X POST http://localhost:8000/v1/batfish/load \
  -H "Content-Type: application/json" \
  -d '{"job_id": "netbox-scan"}'

curl -X GET "http://localhost:8000/v1/batfish/topology/html?job_id=netbox-scan" \
  -o topology.html
```

**Example: Using a CSV File with IP Addresses**

```bash
# 1. Convert CSV to subnet list
# Assuming devices.csv has a column "ip_address"
SUBNETS=$(tail -n +2 devices.csv | cut -d',' -f1 | jq -R -s -c 'split("\n")[:-1]')

# 2. Start scan
curl -X POST http://localhost:8000/v1/scan/from-subnets \
  -H "Content-Type: application/json" \
  -d "{
    \"job_id\": \"csv-scan\",
    \"subnets\": $SUBNETS,
    \"ports\": [22, 443]
  }"
```

**AI Agent Example with Source of Truth**

```python
import mcp
import requests

# Connect to MCP server
client = mcp.Client("http://localhost:8080/mcp")

# 1. Retrieve device IPs from NetBox
netbox_response = requests.get(
    "https://netbox.example.com/api/dcim/devices/",
    headers={"Authorization": "Token YOUR_TOKEN"}
)
device_ips = [d["primary_ip"]["address"].split("/")[0] 
              for d in netbox_response.json()["results"] 
              if d.get("primary_ip")]

# 2. Scan the devices from NetBox
result = client.call_tool("scan_from_subnets", {
    "job_id": "netbox-discovery",
    "subnets": device_ips,
    "ports": [22, 443]
})

# 3. Continue with fingerprinting and config collection
client.call_tool("fingerprint_devices", {"job_id": "netbox-discovery"})
client.call_tool("collect_device_configs", {
    "job_id": "netbox-discovery",
    "credentials": {
        "username": "admin",
        "password": "password",
        "platform": "cisco_ios"
    }
})

# 4. Generate topology
client.call_tool("build_batfish_snapshot", {"job_id": "netbox-discovery"})
client.call_tool("load_batfish_snapshot", {"job_id": "netbox-discovery"})
topology = client.call_tool("generate_topology_visualization", {"job_id": "netbox-discovery"})

print(f"Topology visualization saved to: {topology['path']}")
```

This approach is ideal when:
- You already maintain device inventory in another system
- You want to validate your source of truth data
- You need to discover only specific devices, not the entire network
- You want to avoid CDP/LLDP-based discovery

---

## Using with AI Agents (MCP)

The MCP interface provides tools that AI agents can use to discover and analyze networks autonomously.

### MCP Workflow Example

Here's how an AI agent would interact with the MCP server:

```python
import mcp

# Connect to MCP server
client = mcp.Client("http://localhost:8080/mcp")

# Step 1: Validate credentials first
validation = client.call_tool("validate_device_credentials", {
    "seed_host": "192.168.1.1",
    "username": "admin",
    "password": "cisco123",
    "platform": "cisco_ios"
})

if not validation["valid"]:
    print(f"Invalid credentials: {validation['error']}")
    print(f"Suggestion: {validation['suggestion']}")
    exit(1)

print("Credentials validated successfully!")

# Step 2: Check system health
health = client.call_tool("check_system_health", {})
if not health["ready_for_scan"]:
    print(f"System not ready: {health['issues']}")
    exit(1)

# Step 3: Seed from device
result = client.call_tool("seed_device", {
    "seed_host": "192.168.1.1",
    "credentials": {
        "username": "admin",
        "password": "cisco123",
        "platform": "cisco_ios"
    },
    "methods": ["interfaces", "routing", "arp", "cdp"]
})
job_id = result["job_id"]

# Step 4: Scan targets
client.call_tool("scan_targets", {
    "job_id": job_id,
    "ports": [22, 443]
})

# Step 5: Get job statistics
stats = client.call_tool("get_job_stats", {
    "job_id": job_id
})
print(f"Found {stats['results']['scanning']['reachable_hosts']} devices")

# Step 6: Fingerprint devices
client.call_tool("fingerprint_devices", {
    "job_id": job_id
})

# Step 7: Collect configs
result = client.call_tool("collect_device_configs", {
    "job_id": job_id,
    "credentials": {
        "username": "admin",
        "password": "cisco123",
        "platform": "cisco_ios"
    }
})

# Step 8: Generate topology
client.call_tool("build_batfish_snapshot", {"job_id": job_id})
client.call_tool("load_batfish_snapshot", {"job_id": job_id})
viz = client.call_tool("generate_topology_visualization", {"job_id": job_id})

print(f"Topology saved to: {viz['path']}")

# Step 9: Get final statistics
final_stats = client.call_tool("get_job_stats", {"job_id": job_id})
print(f"Discovery complete!")
print(f"- Devices discovered: {final_stats['results']['scanning']['reachable_hosts']}")
print(f"- Vendors identified: {final_stats['results']['vendors']}")
print(f"- Configs collected: {final_stats['results']['config_collection']['configs_collected']}")
```

### AI Agent Best Practices

#### 1. Always Validate Credentials First

Before starting expensive discovery operations, validate credentials:

```python
# GOOD: Validate first (10 seconds)
validation = client.call_tool("validate_device_credentials", {...})
if validation["valid"]:
    # Proceed with discovery
    
# BAD: Skip validation, waste 30 minutes on wrong credentials
client.call_tool("seed_device", {...})  # Fails after 30 min
```

#### 2. Check System Health Before Large Scans

```python
health = client.call_tool("check_system_health", {})
if health["cpu"]["usage_percent"] > 80:
    print("System busy, waiting...")
    time.sleep(60)
```

#### 3. Resume Failed Jobs

```python
# Check for failed jobs
resumable = client.call_tool("list_resumable_jobs", {})

if resumable["count"] > 0:
    # Offer to resume
    client.call_tool("resume_failed_job", {
        "job_id": resumable["resumable_jobs"][0]["job_id"],
        "username": "admin",
        "password": "cisco123"
    })
```

#### 4. Use Job Statistics for Reporting

```python
stats = client.call_tool("get_job_stats", {"job_id": job_id})

# Generate user-friendly report
print(f"""
Network Discovery Complete:
- Devices discovered: {stats['results']['scanning']['reachable_hosts']}
- Identification rate: {stats['results']['fingerprinting']['identification_rate'] * 100}%
- Vendor breakdown:
  - Cisco: {stats['results']['vendors'].get('cisco', 0)}
  - Juniper: {stats['results']['vendors'].get('juniper', 0)}
  - Arista: {stats['results']['vendors'].get('arista', 0)}
- Configs collected: {stats['results']['config_collection']['configs_collected']}
""")
```

---

## GitHub Actions Integration

The repository includes workflows for running network discovery from GitHub Actions.

### Setup

1. Add your device credentials as GitHub Secrets:
   - Go to Settings > Secrets and variables > Actions
   - Add `DEVICE_USERNAME`
   - Add `DEVICE_PASSWORD`

2. Use the workflow:

Create `.github/workflows/discover-network.yml`:

```yaml
name: Discover Network

on:
  workflow_dispatch:
    inputs:
      seed_host:
        description: "Seed device IP or hostname"
        required: true
        default: "192.168.1.1"
      platform:
        description: "Device platform"
        required: true
        default: "cisco_ios"
        type: choice
        options:
          - cisco_ios
          - cisco_nxos
          - juniper_junos
          - arista_eos

jobs:
  discover:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Start containers
        run: docker compose up -d
      
      - name: Wait for service
        run: |
          timeout 60 bash -c 'until curl -s http://localhost:8000/health; do sleep 2; done'
      
      - name: Validate credentials
        run: |
          curl -X POST http://localhost:8000/v1/credentials/validate \
            -H "Content-Type: application/json" \
            -d '{
              "seed_host": "${{ github.event.inputs.seed_host }}",
              "username": "${{ secrets.DEVICE_USERNAME }}",
              "password": "${{ secrets.DEVICE_PASSWORD }}",
              "platform": "${{ github.event.inputs.platform }}"
            }'
      
      - name: Run discovery
        run: |
          JOB_ID=$(curl -X POST http://localhost:8000/v1/seed \
            -H "Content-Type: application/json" \
            -d '{
              "seed_host": "${{ github.event.inputs.seed_host }}",
              "credentials": {
                "username": "${{ secrets.DEVICE_USERNAME }}",
                "password": "${{ secrets.DEVICE_PASSWORD }}",
                "platform": "${{ github.event.inputs.platform }}"
              },
              "methods": ["interfaces", "routing", "arp", "cdp"]
            }' | jq -r '.job_id')
          
          echo "JOB_ID=$JOB_ID" >> $GITHUB_ENV
          
          # Scan
          curl -X POST http://localhost:8000/v1/scan \
            -H "Content-Type: application/json" \
            -d "{\"job_id\": \"$JOB_ID\", \"ports\": [22, 443]}"
          
          # Fingerprint
          curl -X POST http://localhost:8000/v1/fingerprint \
            -H "Content-Type: application/json" \
            -d "{\"job_id\": \"$JOB_ID\"}"
          
          # Collect configs
          curl -X POST http://localhost:8000/v1/state/collect \
            -H "Content-Type: application/json" \
            -d "{
              \"job_id\": \"$JOB_ID\",
              \"credentials\": {
                \"username\": \"${{ secrets.DEVICE_USERNAME }}\",
                \"password\": \"${{ secrets.DEVICE_PASSWORD }}\",
                \"platform\": \"${{ github.event.inputs.platform }}\"
              }
            }"
          
          # Generate topology
          curl -X POST http://localhost:8000/v1/batfish/build \
            -H "Content-Type: application/json" \
            -d "{\"job_id\": \"$JOB_ID\"}"
          
          curl -X POST http://localhost:8000/v1/batfish/load \
            -H "Content-Type: application/json" \
            -d "{\"job_id\": \"$JOB_ID\"}"
          
          curl -X GET "http://localhost:8000/v1/batfish/topology/html?job_id=$JOB_ID" \
            -o topology.html
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: network-discovery-results
          path: |
            topology.html
            /tmp/network_discovery_artifacts/${{ env.JOB_ID }}/
```

### Running the Workflow

1. Go to Actions tab in GitHub
2. Select "Discover Network"
3. Click "Run workflow"
4. Enter seed device IP and platform
5. View results in the workflow artifacts

---

## API Reference

### Core Discovery Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/seed` | Start seeder from a device, creates targets.json |
| POST | `/v1/scan` | Scan targets from existing job |
| POST | `/v1/scan/from-subnets` | Scan specific subnets directly |
| POST | `/v1/scan/add-subnets` | Add subnets to existing job |
| POST | `/v1/fingerprint` | Fingerprint discovered devices |
| POST | `/v1/state/collect` | Collect device configurations |
| POST | `/v1/state/update/{hostname}` | Re-collect single device config |

### Credential Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/credentials/validate` | Validate credentials before discovery |
| POST | `/v1/credentials/validate/batch` | Validate against multiple devices |

### Job Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/status/{job_id}` | Get job status and progress |
| GET | `/v1/jobs/resumable` | List jobs that can be resumed |
| POST | `/v1/jobs/resume` | Resume a failed job |

### Batfish Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/batfish/build` | Build Batfish snapshot from configs |
| POST | `/v1/batfish/load` | Load snapshot into Batfish |
| GET | `/v1/batfish/topology` | Get topology in JSON format |
| GET | `/v1/batfish/topology/html` | Generate interactive HTML visualization |
| GET | `/v1/batfish/networks` | List all networks |
| GET | `/v1/batfish/networks/{name}/snapshots` | List snapshots for network |
| POST | `/v1/batfish/networks/{name}/snapshot/{snapshot}` | Set current snapshot |

### Data Retrieval Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/scan/{job_id}` | Get scan results |
| GET | `/v1/scan/{job_id}/reachable` | Get only reachable hosts |
| GET | `/v1/fingerprint/{job_id}` | Get fingerprinting results |
| GET | `/v1/state/{hostname}` | Get device configuration |
| GET | `/v1/artifacts/{job_id}/{filename}` | Get any artifact file |

### System Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Basic health check |
| GET | `/ready` | Readiness check with validation |
| GET | `/docs` | Interactive API documentation |

---

## MCP Tools Reference

### Seeder Tools

**seed_device**
- Start network discovery from a seed device
- Parameters: seed_host, credentials, methods, job_id
- Returns: job_id, status, targets_count

**get_targets**
- Retrieve targets collected from seed device
- Parameters: job_id
- Returns: targets array with IPs and subnets

### Scanner Tools

**scan_targets**
- Scan targets for open management ports
- Parameters: job_id, ports, concurrency
- Returns: hosts_scanned, hosts_reachable

**scan_from_subnets**
- Scan specific subnets directly (no seeding required)
- Parameters: job_id, subnets, ports, concurrency
- Returns: hosts_scanned, hosts_reachable

**get_reachable_hosts**
- Get only reachable hosts from scan results
- Parameters: job_id
- Returns: reachable hosts array

### Fingerprinter Tools

**fingerprint_devices**
- Identify device vendors and models
- Parameters: job_id, snmp_community (optional)
- Returns: hosts_fingerprinted, identified_count

**get_fingerprint_results**
- Get fingerprinting results
- Parameters: job_id
- Returns: detailed fingerprint data with vendors

### Config Collector Tools

**collect_device_configs**
- Collect device configurations in parallel
- Parameters: job_id, credentials, concurrency
- Returns: device_count, success_count, failed_count

**get_device_config**
- Get configuration for specific device
- Parameters: job_id, hostname
- Returns: device configuration JSON

### Batfish Tools

**build_batfish_snapshot**
- Build Batfish snapshot from collected configs
- Parameters: job_id
- Returns: snapshot_dir, device_count

**load_batfish_snapshot**
- Load snapshot into Batfish for analysis
- Parameters: job_id
- Returns: network_name, snapshot_name

**get_topology**
- Get network topology in JSON format
- Parameters: job_id OR network_name + snapshot_name
- Returns: topology graph with nodes and edges

**generate_topology_visualization**
- Generate interactive HTML visualization
- Parameters: job_id OR network_name + snapshot_name
- Returns: path to HTML file

### Credential Validation Tools

**validate_device_credentials**
- Quick credential test (5-15 seconds)
- Parameters: seed_host, username, password, platform
- Returns: valid, latency_ms, vendor, platform_correct, error, suggestion
- Use this BEFORE starting expensive discovery operations

**validate_credentials_multiple**
- Test credentials against multiple devices in parallel
- Parameters: devices array, username, password, concurrency
- Returns: total_devices, valid_count, invalid_count, success_rate, per-device results
- Useful for testing credentials across different device types

### Job Resume Tools

**resume_failed_job**
- Resume failed job without re-doing completed work
- Parameters: job_id, phase (optional), credentials
- Returns: resumed_from, phases_executed, summary
- Critical for large networks - saves hours on partial failures

**list_resumable_jobs**
- Get list of jobs that can be resumed
- Parameters: none
- Returns: resumable_jobs array with failed_phases and completed_phases
- Useful for proactively offering to resume failed jobs

### Monitoring Tools

**check_system_health**
- Check system resources before starting scans
- Parameters: none
- Returns: CPU, memory, disk usage, ready_for_scan status
- Use before large scans to ensure system capacity

**get_job_stats**
- Get detailed statistics for a job
- Parameters: job_id
- Returns: module statuses, scan results, vendor breakdown, timing
- Use for progress monitoring and reporting

**get_recent_job_history**
- Analyze recent job executions
- Parameters: hours (default: 24), limit (default: 50)
- Returns: success_rate, failed_jobs, health assessment
- Use for identifying trends and recurring issues

**get_system_recommendations**
- Get intelligent recommendations and warnings
- Parameters: none
- Returns: warnings, recommendations, quick_actions
- Use for proactive issue detection

### Artifact Tools

**get_artifact_content**
- Retrieve any artifact file from job directory
- Parameters: job_id, filename
- Returns: file content (text or base64-encoded)
- Supports HTML, JSON, text, and binary files

---

## Configuration

### Environment Variables

#### Core Settings
- `ARTIFACT_DIR`: Directory for job artifacts (default: `/tmp/network_discovery_artifacts`)
- `DEFAULT_PORTS`: Comma-separated ports to scan (default: `22,443`)
- `DEFAULT_CONCURRENCY`: Parallel operation limit (default: `200`)
- `CONNECT_TIMEOUT`: Connection timeout in seconds (default: `1.5`)
- `LOG_LEVEL`: Logging verbosity (default: `info`)

#### Batfish Settings
- `BATFISH_HOST`: Batfish server hostname (default: `batfish`)
- `BATFISH_PORT`: Batfish server port (default: `9996`)

#### Server Settings
- `HOST`: Server bind address (default: `0.0.0.0`)
- `PORT`: Server port (default: REST: `8000`, MCP: `8080`)

#### MCP Settings
- `ENABLE_MCP`: Enable MCP mode (default: `false`)
- `TRANSPORT`: Transport type `http` or `https` (default: `http`)
- `BASE_PATH`: URL base path for proxied deployments (default: `""`)

### Docker Compose Configuration

The service comes with two Docker Compose files:

**docker-compose.yml** (REST API Mode)
```yaml
services:
  network-discovery:
    environment:
      - ARTIFACT_DIR=/artifacts
      - DEFAULT_PORTS=22,443
      - DEFAULT_CONCURRENCY=200
      - BATFISH_HOST=batfish
    ports:
      - "8000:8000"
volumes:
      - ./artifacts:/artifacts
```

**docker-compose.mcp.yml** (MCP Mode)
```yaml
services:
  network-discovery-mcp:
    environment:
      - ENABLE_MCP=true
      - TRANSPORT=http
      - PORT=8080
      - ARTIFACT_DIR=/artifacts
      - BATFISH_HOST=batfish
    ports:
      - "8080:8080"
    volumes:
      - ./artifacts:/artifacts
```

You can customize these files or override values:

```bash
# Override concurrency
DEFAULT_CONCURRENCY=400 docker compose up -d

# Use custom artifact directory
ARTIFACT_DIR=/var/network-discovery docker compose up -d
```

---

## Architecture

### System Components

Network Discovery MCP consists of six main modules:

1. **Seeder**: Connects to seed device and discovers network topology
   - Collects interface information
   - Retrieves routing tables
   - Gathers ARP entries
   - Discovers neighbors via CDP/LLDP
   - Outputs: `targets.json`, `device_states/{host}.json`

2. **Scanner**: Probes discovered targets for reachability
   - Parallel port scanning with configurable concurrency
   - Tests management ports (SSH, HTTPS, etc.)
   - Outputs: `ip_scan.json`, `reachable.json`

3. **Fingerprinter**: Identifies device vendors and models
   - Banner analysis
   - SNMP probing (optional)
   - Pattern matching
   - Outputs: `fingerprints.json`

4. **Config Collector**: Retrieves device configurations
   - Multi-vendor support (Cisco, Juniper, Arista, etc.)
   - Parallel collection with retry logic
   - Credential validation
   - Outputs: `state/{hostname}.json`

5. **Batfish Loader**: Prepares network for analysis
   - Converts configs to Batfish format
   - Builds network snapshots
   - Loads into Batfish for analysis
   - Outputs: `batfish_snapshot/configs/{hostname}.cfg`

6. **Topology Visualizer**: Generates interactive visualizations
   - Queries Batfish for topology data
   - Generates D3.js force-directed graphs
   - Outputs: `topology.html`, `topology.json`

### Data Flow

```
[Seed Device] 
    ↓
[Seeder] → targets.json
    ↓
[Scanner] → ip_scan.json, reachable.json
    ↓
[Fingerprinter] → fingerprints.json
    ↓
[Config Collector] → state/*.json
    ↓
[Batfish Loader] → batfish_snapshot/configs/*.cfg
    ↓
[Topology Visualizer] → topology.html
```

### Directory Structure

```
network-discovery-mcp/
  ├── network_discovery/
│   ├── __main__.py              # Entry point (REST API or MCP mode)
│   ├── api.py                   # FastAPI REST endpoints
│   ├── mcp_server.py            # MCP tools implementation
│   ├── seeder.py                # Network discovery seeding
│   ├── scanner.py               # Port scanning
│   ├── fingerprinter.py         # Device identification
│   ├── config_collector.py      # Configuration collection
│   ├── batfish_loader.py        # Batfish integration
│   ├── topology_visualizer.py   # Visualization generation
│   ├── credential_validator.py  # Credential testing
│   ├── job_resume.py            # Job resumption logic
│   ├── metrics.py               # System monitoring
│   ├── artifacts.py             # File I/O operations
│   ├── config.py                # Configuration management
│   └── workers.py               # Async task coordination
├── tests/                       # Unit tests
├── Dockerfile                   # Container image definition
├── docker-compose.yml           # REST API deployment
├── docker-compose.mcp.yml       # MCP deployment
└── requirements.txt             # Python dependencies
```

### Artifact Storage Structure

Each discovery job creates a directory structure:

```
{ARTIFACT_DIR}/{job_id}/
├── targets.json                 # Discovered network targets
├── device_states/
│   └── {hostname}.json          # Per-device state from seeder
├── ip_scan.json                 # Full scan results
├── reachable.json               # Filtered reachable hosts
├── fingerprints.json            # Device identification results
├── state/
│   ├── {hostname1}.json         # Device configurations
│   ├── {hostname2}.json
  │   └── ...
├── batfish_snapshot/
│   └── configs/
│       ├── {hostname1}.cfg      # Batfish-format configs
│       ├── {hostname2}.cfg
  │       └── ...
├── topology.json                # Topology graph data
├── topology.html                # Interactive visualization
├── status.json                  # Job status tracking
└── error.json                   # Error details (if any)
```

All file writes are atomic (write to `.tmp`, then rename) to prevent corruption.

---

## Troubleshooting

### Service Won't Start

**Problem**: Container fails to start
```bash
docker compose up -d
# Error: port already in use
```

**Solution**: Check for port conflicts
```bash
# Check what's using port 8000
lsof -i :8000

# Use different port
PORT=8001 docker compose up -d
```

---

### Authentication Failures

**Problem**: All devices fail authentication
```
Error: Authentication failed for all devices
```

**Solution**: Validate credentials first
```bash
# Test credentials before discovery
curl -X POST http://localhost:8000/v1/credentials/validate \
  -H "Content-Type: application/json" \
  -d '{
    "seed_host": "192.168.1.1",
      "username": "admin",
    "password": "your_password",
    "platform": "cisco_ios"
  }'

# Check response for specific error
{
  "valid": false,
  "error": "Authentication failed - invalid username or password",
  "suggestion": "Verify credentials for user 'admin' on this device"
}
```

---

### Job Failures During Config Collection

**Problem**: Job fails after collecting some configs
```
Status: 200/450 configs collected, then failure
```

**Solution**: Resume the job instead of restarting
```bash
# List resumable jobs
curl http://localhost:8000/v1/jobs/resumable

# Resume the failed job
curl -X POST http://localhost:8000/v1/jobs/resume \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "net-disc-123",
    "credentials": {"username": "admin", "password": "pass"}
  }'

# This will retry only the 250 failed devices
```

---

### Slow Discovery

**Problem**: Discovery taking too long

**Solution**: Check system resources
```bash
# Check system health
curl http://localhost:8000/v1/health

# Check specific job statistics
curl http://localhost:8000/v1/status/{job_id}

# Reduce concurrency if CPU high
curl -X POST http://localhost:8000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"job_id": "...", "concurrency": 50}'
```

---

### Batfish Connection Issues

**Problem**: Topology generation fails
```
Error: Cannot connect to Batfish
```

**Solution**: Verify Batfish container
```bash
# Check Batfish is running
docker compose ps

# Check Batfish logs
docker compose logs batfish

# Restart if needed
docker compose restart batfish

# Wait for Batfish to initialize
sleep 30
```

---

### Large Network Timeouts

**Problem**: Timeouts on large subnets

**Solution**: Increase timeouts or reduce scope
```bash
# Increase timeout
CONNECT_TIMEOUT=5.0 docker compose up -d

# Or scan in smaller batches
curl -X POST http://localhost:8000/v1/scan/from-subnets \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "batch1",
    "subnets": ["192.168.1.0/24"],
    "concurrency": 100
  }'
```

---

### View Logs

For debugging, check container logs:

```bash
# REST API mode
docker compose logs -f network-discovery

# MCP mode
docker compose -f docker-compose.mcp.yml logs -f network-discovery-mcp

# Just errors
docker compose logs network-discovery | grep ERROR

# Specific time range
docker compose logs --since 30m network-discovery
```

---

### Get Help

If you encounter issues not covered here:

1. Check logs: `docker compose logs network-discovery`
2. Review job status: `curl http://localhost:8000/v1/status/{job_id}`
3. Check system recommendations: Use `get_system_recommendations` MCP tool
4. Review artifact files in `{ARTIFACT_DIR}/{job_id}/`

---

## Additional Resources

- **API Documentation**: http://localhost:8000/docs (interactive Swagger UI)
- **GitHub Releases**: https://github.com/username/network-discovery-mcp/releases (version history and changelogs)

---

## License

This project is licensed under the terms specified in the LICENSE file.
