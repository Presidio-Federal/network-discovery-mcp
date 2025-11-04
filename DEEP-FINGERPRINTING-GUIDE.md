# Deep Fingerprinting Guide

## Overview

Deep Fingerprinting is an authenticated device identification method that solves the problem of devices with generic SSH banners (like Arista with `SSH-2.0-OpenSSH_8.7`) being misidentified as "Linux/Unix".

## The Problem

**Passive fingerprinting** (SSH banners, HTTPS headers, SNMP) can fail when:
- Devices use generic OpenSSH without vendor branding
- SSH banners don't include vendor information
- HTTPS and SNMP are disabled or not responding

**Example:**
```json
{
  "ip": "70.0.0.2",
  "evidence": {
    "ssh_banner": "SSH-2.0-OpenSSH_8.7"
  },
  "inference": {
    "vendor": "Linux/Unix",  // ❌ Wrong!
    "model": "unknown",
    "confidence": 0.4        // Low confidence
  }
}
```

## The Solution

**Deep fingerprinting** authenticates and runs `show version` to detect the actual OS:

1. Identifies low-confidence devices (< 0.6) or unknown vendors
2. Logs in via SSH
3. Runs `show version` command
4. Matches output against vendor patterns
5. Updates fingerprints with accurate information

## REST API Usage

### Step 1: Regular Fingerprinting

```bash
curl -X POST http://localhost:8000/v1/fingerprint \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "my-discovery",
    "concurrency": 100
  }'
```

### Step 2: Check Results

```bash
# Get all fingerprints
curl http://localhost:8000/v1/fingerprint/my-discovery

# Check for low-confidence devices
curl http://localhost:8000/v1/fingerprint/my-discovery | \
  jq '.hosts[] | select(.inference.confidence < 0.6 or .inference.vendor=="Linux/Unix" or .inference.vendor=="unknown")'
```

### Step 3: Run Deep Fingerprinting

```bash
curl -X POST http://localhost:8000/v1/fingerprint/deep \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "my-discovery",
    "credentials": {
      "username": "admin",
      "password": "your_password"
    },
    "confidence_threshold": 0.6,
    "concurrency": 50
  }'
```

**Response:**
```json
{
  "job_id": "my-discovery",
  "status": "completed",
  "devices_checked": 5,
  "devices_updated": 3,
  "devices_failed": 2,
  "fingerprints_path": "/artifacts/my-discovery/fingerprints.json"
}
```

### Step 4: Verify Updated Fingerprints

```bash
# Check the Arista device
curl http://localhost:8000/v1/fingerprint/my-discovery | \
  jq '.hosts[] | select(.ip=="70.0.0.2")'
```

**Updated result:**
```json
{
  "ip": "70.0.0.2",
  "evidence": {
    "ssh_banner": "SSH-2.0-OpenSSH_8.7",
    "deep_fingerprint": "Arista DCS-7050QX-32-F\nArista EOS version 4.21.1F..."
  },
  "inference": {
    "vendor": "Arista",          // ✅ Correct!
    "model": "EOS",
    "confidence": 1.0,            // High confidence
    "detection_method": "deep_fingerprint"
  }
}
```

## MCP Tool Usage (AI Agent)

```python
import mcp

client = mcp.Client("http://localhost:8080/mcp")

# Step 1: Regular fingerprinting
print("Running regular fingerprinting...")
fp_result = client.call_tool("fingerprint_hosts", {
    "job_id": "my-discovery"
})

# Step 2: Get results and check confidence
print("Checking fingerprint results...")
results = client.call_tool("get_fingerprint_results", {
    "job_id": "my-discovery"
})

# Step 3: Count low-confidence devices
low_confidence_devices = [
    host for host in results["hosts"]
    if host["inference"]["confidence"] < 0.6 or 
       host["inference"]["vendor"] in ["unknown", "Linux/Unix"]
]

print(f"Found {len(low_confidence_devices)} devices with low confidence:")
for device in low_confidence_devices:
    print(f"  - {device['ip']}: {device['inference']['vendor']} (confidence: {device['inference']['confidence']})")

# Step 4: Run deep fingerprinting if needed
if low_confidence_devices:
    print("\nRunning deep fingerprinting on low-confidence devices...")
    deep_result = client.call_tool("deep_fingerprint_devices", {
        "job_id": "my-discovery",
        "username": "admin",
        "password": "your_password",
        "confidence_threshold": 0.6,
        "concurrency": 50
    })
    
    print(f"""
Deep Fingerprinting Results:
- Devices checked: {deep_result['devices_checked']}
- Devices updated: {deep_result['devices_updated']}
- Devices failed: {deep_result['devices_failed']}
""")

# Step 5: Verify updated fingerprints
print("Verifying updated fingerprints...")
updated_results = client.call_tool("get_fingerprint_results", {
    "job_id": "my-discovery"
})

for device in low_confidence_devices:
    updated_device = next(
        (h for h in updated_results["hosts"] if h["ip"] == device["ip"]),
        None
    )
    if updated_device:
        print(f"""
Device {device['ip']}:
  Before: {device['inference']['vendor']} (confidence: {device['inference']['confidence']})
  After: {updated_device['inference']['vendor']} (confidence: {updated_device['inference']['confidence']})
""")
```

## Automated Workflow

For AI agents, you can automate the entire process:

```python
def discover_network_with_deep_fingerprinting(seed_host, username, password):
    """
    Complete network discovery with automatic deep fingerprinting.
    """
    client = mcp.Client("http://localhost:8080/mcp")
    job_id = f"discovery-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    # Step 1: Seed and scan
    client.call_tool("seed_device", {
        "seed_host": seed_host,
        "credentials": {"username": username, "password": password},
        "job_id": job_id
    })
    
    client.call_tool("scan_targets", {
        "job_id": job_id,
        "ports": [22, 443]
    })
    
    # Step 2: Regular fingerprinting
    client.call_tool("fingerprint_hosts", {"job_id": job_id})
    
    # Step 3: Automatic deep fingerprinting for low-confidence devices
    results = client.call_tool("get_fingerprint_results", {"job_id": job_id})
    
    low_confidence_count = sum(
        1 for h in results["hosts"]
        if h["inference"]["confidence"] < 0.6 or 
           h["inference"]["vendor"] in ["unknown", "Linux/Unix"]
    )
    
    if low_confidence_count > 0:
        print(f"🔍 Found {low_confidence_count} devices needing deep fingerprinting")
        deep_result = client.call_tool("deep_fingerprint_devices", {
            "job_id": job_id,
            "username": username,
            "password": password,
            "confidence_threshold": 0.6
        })
        print(f"✅ Updated {deep_result['devices_updated']} devices")
    
    # Step 4: Collect configs (now with accurate vendor info)
    client.call_tool("collect_device_configs", {
        "job_id": job_id,
        "username": username,
        "password": password
    })
    
    # Step 5: Generate topology
    client.call_tool("build_batfish_snapshot", {"job_id": job_id})
    client.call_tool("load_batfish_snapshot", {"job_id": job_id})
    topology = client.call_tool("generate_topology_visualization", {"job_id": job_id})
    
    print(f"🎉 Discovery complete! Topology: {topology['path']}")
    return job_id
```

## Parameters

### confidence_threshold (float, default: 0.6)

Devices with confidence scores below this threshold will be re-fingerprinted.

**Recommended values:**
- `0.6` (default): Balanced - catches most uncertain devices
- `0.8`: Strict - only re-fingerprints very uncertain devices
- `0.4`: Lenient - re-fingerprints more aggressively

**Example:**
```bash
# Only re-fingerprint devices with very low confidence
curl -X POST http://localhost:8000/v1/fingerprint/deep \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "my-discovery",
    "credentials": {...},
    "confidence_threshold": 0.8
  }'
```

### concurrency (int, default: 100)

Number of parallel SSH connections for deep fingerprinting.

**Recommended values:**
- `50`: Conservative - for slow networks or limited resources
- `100` (default): Balanced - good for most networks
- `200`: Aggressive - for fast networks with many devices

## Supported Vendors

Deep fingerprinting detects:

| Vendor | Model | Detection Pattern |
|--------|-------|------------------|
| Cisco | IOS | `Cisco IOS Software` |
| Cisco | IOS-XE | `Cisco IOS XE Software` |
| Cisco | NX-OS | `Cisco Nexus Operating System` |
| Cisco | ASA | `Cisco Adaptive Security Appliance` |
| Arista | EOS | `Arista .* EOS` |
| Juniper | JUNOS | `JUNOS` or `Juniper Networks` |
| Palo Alto | PAN-OS | `PAN-OS` |
| Fortinet | FortiOS | `FortiGate` |
| Huawei | VRP | `Huawei Versatile Routing Platform` |

## Troubleshooting

### Problem: Deep fingerprinting fails for all devices

**Cause:** Wrong credentials or SSH not working

**Solution:**
1. Validate credentials first:
```bash
curl -X POST http://localhost:8000/v1/credentials/validate \
  -d '{"seed_host": "70.0.0.2", "username": "admin", "password": "pass"}'
```

2. Check SSH access:
```bash
ssh admin@70.0.0.2 "show version"
```

### Problem: Device updated but still showing wrong vendor

**Cause:** Viewing cached results

**Solution:** Force refresh by re-reading fingerprints:
```bash
curl http://localhost:8000/v1/fingerprint/my-discovery?nocache=true
```

### Problem: Some devices updated, others failed

**Cause:** Different credentials or device types

**Solution:** Check the failed devices list:
```bash
# Deep fingerprinting response shows devices_failed
# Check logs for specific errors
docker logs network-discovery | grep "Deep fingerprint failed"
```

## Performance

**Timing:**
- Regular fingerprinting: ~1-2 seconds per device (no auth)
- Deep fingerprinting: ~3-5 seconds per device (with auth)

**For 100 devices:**
- Regular: ~2 minutes
- Deep (if needed): ~5 minutes additional

**Recommendation:** Only use deep fingerprinting when needed (low confidence or unknown vendors)

## Best Practices

### 1. Use Deep Fingerprinting Selectively

```bash
# Good: Only re-fingerprint uncertain devices
curl -X POST .../fingerprint/deep \
  -d '{"confidence_threshold": 0.6, ...}'

# Avoid: Re-fingerprinting everything
curl -X POST .../fingerprint/deep \
  -d '{"confidence_threshold": 1.0, ...}'  # Re-fingerprints ALL devices
```

### 2. Check Results Before Config Collection

```bash
# Step 1: Fingerprint
curl -X POST .../fingerprint -d '{"job_id": "disc"}'

# Step 2: Deep fingerprint if needed
LOW_COUNT=$(curl .../fingerprint/disc | jq '[.hosts[] | select(.inference.confidence < 0.6)] | length')
if [ $LOW_COUNT -gt 0 ]; then
  curl -X POST .../fingerprint/deep -d '{"job_id": "disc", ...}'
fi

# Step 3: Collect configs (with accurate vendor info)
curl -X POST .../state/collect -d '{"job_id": "disc", ...}'
```

### 3. Log Detection Changes

Deep fingerprinting adds audit trail:
```json
{
  "evidence": {
    "ssh_banner": "SSH-2.0-OpenSSH_8.7",
    "deep_fingerprint": "Arista DCS-7050QX-32-F\nArista EOS version 4.21.1F..."
  },
  "inference": {
    "detection_method": "deep_fingerprint"
  }
}
```

## Summary

Deep fingerprinting solves the Arista detection problem and works for any device with generic SSH banners. Use it:

✅ After regular fingerprinting shows low confidence  
✅ Before config collection to ensure correct vendor detection  
✅ For devices identified as "Linux/Unix" or "unknown"  
✅ In automated workflows to improve accuracy  

The combination of **passive fingerprinting → deep fingerprinting → config collection with OS detection** provides triple-layer device identification for maximum accuracy!

