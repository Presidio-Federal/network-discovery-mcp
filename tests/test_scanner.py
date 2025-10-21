"""Tests for scanner module."""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from network_discovery.scanner import (
    add_subnets,
    get_scan,
    scan_from_subnets,
    scan_from_targets,
)


@pytest.fixture
def sample_targets():
    """Sample targets.json data."""
    return {
        "job_id": "test_job",
        "collected_at": "2025-10-19T12:00:00Z",
        "seed_host": "192.168.1.1",
        "subnets": ["192.168.1.0/24", "10.0.0.0/24"],
        "candidate_ips": ["192.168.1.1", "192.168.1.2", "10.0.0.1"]
    }


@pytest.fixture
def sample_scan_results():
    """Sample scan results."""
    return [
        {
            "ip": "192.168.1.1",
            "reachable": True,
            "latency_ms": 5,
            "ports": {"22": "open", "443": "closed"},
            "banner": "SSH-2.0-OpenSSH_8.9"
        },
        {
            "ip": "192.168.1.2",
            "reachable": True,
            "latency_ms": 8,
            "ports": {"22": "closed", "443": "open"},
            "banner": "CN=example.com"
        },
        {
            "ip": "10.0.0.1",
            "reachable": False,
            "ports": {"22": "closed", "443": "closed"}
        }
    ]


@pytest_asyncio.fixture
async def mock_scan_ips():
    """Mock _scan_ips function."""
    with patch("network_discovery.scanner._scan_ips", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_scan_from_targets(sample_targets, sample_scan_results, mock_scan_ips):
    """Test scan_from_targets function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a mock job directory
        job_dir = Path(tmp_dir) / "test_job"
        job_dir.mkdir()
        
        # Create a mock targets.json file
        targets_path = job_dir / "targets.json"
        with open(targets_path, 'w') as f:
            json.dump(sample_targets, f)
        
        # Mock functions
        mock_scan_ips.return_value = sample_scan_results
        
        with patch("network_discovery.scanner.get_job_dir", return_value=job_dir), \
             patch("network_discovery.scanner.get_targets_path", return_value=targets_path), \
             patch("network_discovery.scanner.get_scan_path", return_value=job_dir / "ip_scan.json"), \
             patch("network_discovery.scanner.get_reachable_hosts_path", return_value=job_dir / "reachable_hosts.json"), \
             patch("network_discovery.scanner.update_status"), \
             patch("network_discovery.scanner.atomic_write_json") as mock_write:
            
            # Call the function
            result = await scan_from_targets("test_job")
            
            # Check that _scan_ips was called with the right arguments
            mock_scan_ips.assert_called_once()
            call_args = mock_scan_ips.call_args[0]
            assert set(call_args[0]) == set(["192.168.1.1", "192.168.1.2", "10.0.0.1"])
            assert call_args[1] == [22, 443]
            
            # Check that atomic_write_json was called twice (once for scan results, once for reachable hosts)
            assert mock_write.call_count == 2
            
            # Check the first call (ip_scan.json)
            first_call_args = mock_write.call_args_list[0][0]
            assert first_call_args[0]["job_id"] == "test_job"
            assert first_call_args[0]["hosts"] == sample_scan_results
            
            # Check the result
            assert result["job_id"] == "test_job"
            assert result["status"] == "completed"
            assert result["hosts_scanned"] == 3
            assert result["hosts_reachable"] == 2


@pytest.mark.asyncio
async def test_scan_from_subnets(sample_scan_results, mock_scan_ips):
    """Test scan_from_subnets function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a mock job directory
        job_dir = Path(tmp_dir) / "test_job"
        job_dir.mkdir()
        
        # Mock functions
        mock_scan_ips.return_value = sample_scan_results
        
        with patch("network_discovery.scanner.get_job_dir", return_value=job_dir), \
             patch("network_discovery.scanner.get_scan_path", return_value=job_dir / "ip_scan.json"), \
             patch("network_discovery.scanner.get_reachable_hosts_path", return_value=job_dir / "reachable_hosts.json"), \
             patch("network_discovery.scanner.update_status"), \
             patch("network_discovery.scanner.atomic_write_json") as mock_write:
            
            # Call the function
            result = await scan_from_subnets("test_job", ["192.168.1.0/24", "10.0.0.0/24"])
            
            # Check that _scan_ips was called
            mock_scan_ips.assert_called_once()
            
            # Check that atomic_write_json was called twice (once for scan results, once for reachable hosts)
            assert mock_write.call_count == 2
            
            # Check the result
            assert result["job_id"] == "test_job"
            assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_add_subnets(sample_targets):
    """Test add_subnets function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a mock job directory
        job_dir = Path(tmp_dir) / "test_job"
        job_dir.mkdir()
        
        # Create a mock targets.json file
        targets_path = job_dir / "targets.json"
        with open(targets_path, 'w') as f:
            json.dump(sample_targets, f)
        
        with patch("network_discovery.scanner.get_targets_path", return_value=targets_path), \
             patch("network_discovery.scanner.atomic_write_json") as mock_write:
            
            # Call the function
            result = await add_subnets("test_job", ["172.16.0.0/24"])
            
            # Check that atomic_write_json was called
            mock_write.assert_called_once()
            write_args = mock_write.call_args[0]
            assert "172.16.0.0/24" in write_args[0]["subnets"]
            
            # Check the result
            assert result["job_id"] == "test_job"
            assert result["status"] == "completed"
            assert result["subnets_added"] == 1
            assert result["total_subnets"] == 3


def test_get_scan(sample_scan_results):
    """Test get_scan function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a mock job directory
        job_dir = Path(tmp_dir) / "test_job"
        job_dir.mkdir()
        
        # Create a mock ip_scan.json file
        scan_path = job_dir / "ip_scan.json"
        scan_data = {
            "job_id": "test_job",
            "scanned_at": "2025-10-19T12:00:00Z",
            "targets_count": 3,
            "hosts": sample_scan_results
        }
        
        with open(scan_path, 'w') as f:
            json.dump(scan_data, f)
        
        with patch("network_discovery.scanner.get_scan_path", return_value=scan_path):
            # Call the function
            result = get_scan("test_job")
            
            # Check the result
            assert result["job_id"] == "test_job"
            assert result["hosts"] == sample_scan_results


def test_scanner_doesnt_read_device_states():
    """
    Test that scanner explicitly does not read device_states.
    
    This test verifies that the scanner module has comments explicitly stating
    that it does not read device_states files, which is a security requirement.
    """
    # Read the scanner.py file
    with open("network_discovery/scanner.py", 'r') as f:
        scanner_code = f.read()
    
    # Check for explicit comments about not reading device_states
    assert "explicitly does NOT read device_states" in scanner_code
    assert "Scanner explicitly must not read device_states" in scanner_code
    
    # Check for code that enforces this policy
    assert "scanner is ignoring device_states directory as per security policy" in scanner_code
