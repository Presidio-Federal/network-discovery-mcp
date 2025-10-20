"""Tests for fingerprinter module."""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import asyncio

from network_discovery.fingerprinter import (
    fingerprint_job,
    get_fingerprints,
    _fingerprint_host,
    _infer_device_type
)

@pytest.fixture
def mock_scan_result():
    """Create a mock scan result."""
    return {
        "job_id": "test",
        "scanned_at": "2025-10-20T00:00:00Z",
        "targets_count": 1,
        "hosts": [
            {
                "ip": "10.0.0.5",
                "reachable": True,
                "ports": {"22": "open"},
                "banner": "SSH-2.0-Cisco-1.25"
            }
        ]
    }

@pytest.fixture
def mock_job_dir(tmp_path):
    """Create a mock job directory."""
    job_dir = tmp_path / "test"
    job_dir.mkdir()
    return job_dir

@pytest.fixture
def mock_scan_file(mock_job_dir, mock_scan_result):
    """Create a mock scan file."""
    scan_path = mock_job_dir / "ip_scan.json"
    with open(scan_path, "w") as f:
        json.dump(mock_scan_result, f)
    return scan_path

@pytest.mark.asyncio
async def test_fingerprint_job(mock_job_dir, mock_scan_file, monkeypatch):
    """Test fingerprint_job function."""
    # Mock get_scan_path to return our mock scan file
    def mock_get_scan_path(job_id):
        return mock_scan_file
    
    # Mock get_fingerprints_path to return a path in our mock job dir
    def mock_get_fingerprints_path(job_id):
        return mock_job_dir / "fingerprints.json"
    
    # Mock update_status to do nothing
    async_mock = AsyncMock()
    
    with patch("network_discovery.fingerprinter.get_scan_path", mock_get_scan_path), \
         patch("network_discovery.fingerprinter.get_fingerprints_path", mock_get_fingerprints_path), \
         patch("network_discovery.fingerprinter.update_status"), \
         patch("network_discovery.fingerprinter._fingerprint_host", return_value={
             "ip": "10.0.0.5",
             "evidence": {"ssh_banner": "SSH-2.0-Cisco-1.25"},
             "inference": {"vendor": "Cisco", "model": "IOS", "protocols": ["ssh"], "confidence": 0.4}
         }):
        
        # Run the fingerprint job
        result = await fingerprint_job("test")
        
        # Check that the fingerprints file was created
        fingerprints_path = mock_job_dir / "fingerprints.json"
        assert fingerprints_path.exists()
        
        # Check the content of the fingerprints file
        with open(fingerprints_path) as f:
            fingerprints = json.load(f)
        
        assert fingerprints["job_id"] == "test"
        assert len(fingerprints["hosts"]) == 1
        assert fingerprints["hosts"][0]["ip"] == "10.0.0.5"
        assert "inference" in fingerprints["hosts"][0]
        assert fingerprints["hosts"][0]["inference"]["vendor"] == "Cisco"
        
        # Check the result
        assert result["status"] == "completed"
        assert result["hosts_count"] == 1
        assert result["fingerprinted_count"] == 1

@pytest.mark.asyncio
async def test_fingerprint_host():
    """Test _fingerprint_host function."""
    host = {
        "ip": "10.0.0.5",
        "reachable": True,
        "ports": {"22": "open"},
        "banner": "SSH-2.0-Cisco-1.25"
    }
    
    semaphore = asyncio.Semaphore(1)
    
    # Mock the SSH, TLS, and SNMP functions
    with patch("network_discovery.fingerprinter._get_ssh_banner", return_value=None), \
         patch("network_discovery.fingerprinter._get_tls_info", return_value={}), \
         patch("network_discovery.fingerprinter._get_snmp_info", return_value={}):
        
        result = await _fingerprint_host(host, semaphore, None)
        
        assert result["ip"] == "10.0.0.5"
        assert "evidence" in result
        assert result["evidence"]["ssh_banner"] == "SSH-2.0-Cisco-1.25"
        assert "inference" in result
        assert result["inference"]["vendor"] == "Cisco"
        assert result["inference"]["model"] == "IOS"
        assert "ssh" in result["inference"]["protocols"]
        assert result["inference"]["confidence"] > 0

def test_infer_device_type():
    """Test _infer_device_type function."""
    # Test SSH banner evidence
    evidence = {"ssh_banner": "SSH-2.0-Cisco-1.25"}
    inference = _infer_device_type(evidence)
    assert inference["vendor"] == "Cisco"
    assert inference["model"] == "IOS"
    assert "ssh" in inference["protocols"]
    assert inference["confidence"] > 0
    
    # Test HTTP server evidence
    evidence = {"http_server": "Cisco-IOS-XE"}
    inference = _infer_device_type(evidence)
    assert inference["vendor"] == "Cisco"
    assert inference["model"] == "IOS-XE"
    assert "https" in inference["protocols"]
    assert inference["confidence"] > 0
    
    # Test SNMP evidence
    evidence = {"snmp_sysdescr": "Cisco IOS Software"}
    inference = _infer_device_type(evidence)
    assert inference["vendor"] == "Cisco"
    assert "snmp" in inference["protocols"]
    assert inference["confidence"] > 0
    
    # Test multiple evidence sources
    evidence = {
        "ssh_banner": "SSH-2.0-Cisco-1.25",
        "http_server": "Cisco-IOS-XE",
        "snmp_sysdescr": "Cisco IOS Software"
    }
    inference = _infer_device_type(evidence)
    assert inference["vendor"] == "Cisco"
    assert set(inference["protocols"]) == set(["ssh", "https", "snmp"])
    assert inference["confidence"] > 0.5  # Should be higher with multiple sources

def test_get_fingerprints(mock_job_dir):
    """Test get_fingerprints function."""
    # Create a mock fingerprints file
    fingerprints = {
        "job_id": "test",
        "fingerprinted_at": "2025-10-20T00:00:00Z",
        "hosts": [
            {
                "ip": "10.0.0.5",
                "evidence": {"ssh_banner": "SSH-2.0-Cisco-1.25"},
                "inference": {"vendor": "Cisco", "model": "IOS", "protocols": ["ssh"], "confidence": 0.4}
            }
        ]
    }
    
    fingerprints_path = mock_job_dir / "fingerprints.json"
    with open(fingerprints_path, "w") as f:
        json.dump(fingerprints, f)
    
    # Mock get_fingerprints_path to return our mock fingerprints file
    with patch("network_discovery.fingerprinter.get_fingerprints_path", return_value=fingerprints_path):
        result = get_fingerprints("test")
        
        assert result["job_id"] == "test"
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["ip"] == "10.0.0.5"
        assert result["hosts"][0]["inference"]["vendor"] == "Cisco"

def test_no_device_state_access(mock_job_dir, mock_scan_file, monkeypatch):
    """Test that fingerprinter does not access device_states directory."""
    # Create a device_states directory
    device_states_dir = mock_job_dir / "device_states"
    device_states_dir.mkdir()
    
    # Create a device state file
    device_state_path = device_states_dir / "10.0.0.5.json"
    with open(device_state_path, "w") as f:
        json.dump({"hostname": "test-device"}, f)
    
    # Mock get_scan_path to return our mock scan file
    def mock_get_scan_path(job_id):
        return mock_scan_file
    
    # Mock get_fingerprints_path to return a path in our mock job dir
    def mock_get_fingerprints_path(job_id):
        return mock_job_dir / "fingerprints.json"
    
    # Create a spy to check if device_states directory is accessed
    original_open = open
    
    def spy_open(*args, **kwargs):
        path = args[0]
        if isinstance(path, str) and "device_states" in path:
            pytest.fail("Fingerprinter should not access device_states directory")
        return original_open(*args, **kwargs)
    
    # Mock open to use our spy
    with patch("builtins.open", spy_open), \
         patch("network_discovery.fingerprinter.get_scan_path", mock_get_scan_path), \
         patch("network_discovery.fingerprinter.get_fingerprints_path", mock_get_fingerprints_path), \
         patch("network_discovery.fingerprinter.update_status"), \
         patch("network_discovery.fingerprinter._fingerprint_host", return_value={
             "ip": "10.0.0.5",
             "evidence": {"ssh_banner": "SSH-2.0-Cisco-1.25"},
             "inference": {"vendor": "Cisco", "model": "IOS", "protocols": ["ssh"], "confidence": 0.4}
         }):
        
        # Run the fingerprint job
        asyncio.run(fingerprint_job("test"))
        
        # If we get here without pytest.fail being called, the test passes
