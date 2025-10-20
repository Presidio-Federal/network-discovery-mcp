"""Tests for config_collector module."""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import asyncio

from network_discovery.config_collector import (
    collect_all_state,
    collect_single_state,
    get_device_state,
    _collect_device_config,
    _collect_via_ssh
)

@pytest.fixture
def mock_fingerprints_result():
    """Create mock fingerprints result."""
    return {
        "job_id": "test",
        "hosts": [
            {
                "ip": "10.0.0.5",
                "inference": {"vendor": "Cisco", "confidence": 0.9},
                "protocols": ["ssh"],
                "hostname": "HAI-HQ"
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
def mock_fingerprints_file(mock_job_dir, mock_fingerprints_result):
    """Create a mock fingerprints file."""
    fingerprints_path = mock_job_dir / "fingerprints.json"
    with open(fingerprints_path, "w") as f:
        json.dump(mock_fingerprints_result, f)
    return fingerprints_path

@pytest.fixture
def mock_state_dir(mock_job_dir):
    """Create a mock state directory."""
    state_dir = mock_job_dir / "state"
    state_dir.mkdir()
    return state_dir

@pytest.mark.asyncio
async def test_collect_all_state(mock_job_dir, mock_fingerprints_file, mock_state_dir, monkeypatch):
    """Test collect_all_state function."""
    # Mock get_fingerprints_path to return our mock fingerprints file
    def mock_get_fingerprints_path(job_id):
        return mock_fingerprints_file
    
    # Mock get_state_dir to return our mock state directory
    def mock_get_state_dir(job_id):
        return mock_state_dir
    
    # Mock get_state_path to return a path in our mock state directory
    def mock_get_state_path(job_id, hostname):
        return mock_state_dir / f"{hostname}.json"
    
    # Mock update_status to do nothing
    async_mock = AsyncMock()
    
    # Mock _collect_device_config to return success
    mock_config_result = {
        "status": "success",
        "hostname": "HAI-HQ",
        "state_path": str(mock_state_dir / "HAI-HQ.json")
    }
    
    with patch("network_discovery.config_collector.get_fingerprints_path", mock_get_fingerprints_path), \
         patch("network_discovery.config_collector.get_state_dir", mock_get_state_dir), \
         patch("network_discovery.config_collector.get_state_path", mock_get_state_path), \
         patch("network_discovery.config_collector.update_status"), \
         patch("network_discovery.config_collector._collect_device_config", return_value=mock_config_result):
        
        # Run the collect_all_state function
        creds = {"username": "admin", "password": "cisco"}
        result = await collect_all_state("test", creds)
        
        # Check the result
        assert result["status"] == "completed"
        assert result["device_count"] == 1
        assert result["success_count"] == 1
        assert result["result_dir"] == "state/"

@pytest.mark.asyncio
async def test_collect_single_state(mock_job_dir, mock_fingerprints_file, mock_state_dir, monkeypatch):
    """Test collect_single_state function."""
    # Mock get_fingerprints_path to return our mock fingerprints file
    def mock_get_fingerprints_path(job_id):
        return mock_fingerprints_file
    
    # Mock get_state_dir to return our mock state directory
    def mock_get_state_dir(job_id):
        return mock_state_dir
    
    # Mock get_state_path to return a path in our mock state directory
    def mock_get_state_path(job_id, hostname):
        return mock_state_dir / f"{hostname}.json"
    
    # Mock update_status to do nothing
    async_mock = AsyncMock()
    
    # Mock _collect_device_config to return success
    mock_config_result = {
        "status": "success",
        "hostname": "HAI-HQ",
        "state_path": str(mock_state_dir / "HAI-HQ.json")
    }
    
    with patch("network_discovery.config_collector.get_fingerprints_path", mock_get_fingerprints_path), \
         patch("network_discovery.config_collector.get_state_dir", mock_get_state_dir), \
         patch("network_discovery.config_collector.get_state_path", mock_get_state_path), \
         patch("network_discovery.config_collector.update_status"), \
         patch("network_discovery.config_collector._collect_device_config", return_value=mock_config_result):
        
        # Run the collect_single_state function
        creds = {"username": "admin", "password": "cisco"}
        result = await collect_single_state("test", creds, "HAI-HQ")
        
        # Check the result
        assert result["status"] == "updated"
        assert result["device_updated"] == "HAI-HQ"

@pytest.mark.asyncio
async def test_get_device_state(mock_job_dir, mock_state_dir):
    """Test get_device_state function."""
    # Create a mock state file
    state_data = {
        "hostname": "HAI-HQ",
        "vendor": "Cisco",
        "collected_at": "2025-10-21T00:00:00Z",
        "protocol": "ssh",
        "running_config": "!\nversion 17.9\nhostname HAI-HQ\n..."
    }
    
    state_path = mock_state_dir / "HAI-HQ.json"
    with open(state_path, "w") as f:
        json.dump(state_data, f)
    
    # Mock get_state_dir to return our mock state directory
    def mock_get_state_dir(job_id):
        return mock_state_dir
    
    with patch("network_discovery.config_collector.get_state_dir", mock_get_state_dir):
        # Run the get_device_state function
        result = await get_device_state("test", "HAI-HQ")
        
        # Check the result
        assert result["hostname"] == "HAI-HQ"
        assert result["vendor"] == "Cisco"
        assert "running_config" in result

@pytest.mark.asyncio
async def test_collect_device_config(mock_job_dir, mock_state_dir):
    """Test _collect_device_config function."""
    # Mock get_state_path to return a path in our mock state directory
    def mock_get_state_path(job_id, hostname):
        return mock_state_dir / f"{hostname}.json"
    
    # Mock _collect_via_ssh to return a config
    mock_ssh_config = "!\nversion 17.9\nhostname HAI-HQ\n..."
    
    with patch("network_discovery.config_collector.get_state_path", mock_get_state_path), \
         patch("network_discovery.config_collector._collect_via_ssh", return_value=mock_ssh_config), \
         patch("network_discovery.config_collector.atomic_write_json"):
        
        # Run the _collect_device_config function
        device = {
            "ip": "10.0.0.5",
            "vendor": "Cisco",
            "hostname": "HAI-HQ",
            "protocols": ["ssh"]
        }
        creds = {"username": "admin", "password": "cisco"}
        semaphore = asyncio.Semaphore(1)
        
        result = await _collect_device_config(device, creds, "test", semaphore)
        
        # Check the result
        assert result["status"] == "success"
        assert result["hostname"] == "HAI-HQ"

@pytest.mark.asyncio
async def test_collect_via_ssh():
    """Test _collect_via_ssh function."""
    # Mock asyncssh.connect
    mock_conn = AsyncMock()
    mock_conn.__aenter__ = AsyncMock()
    mock_conn.__aenter__.return_value = mock_conn
    mock_conn.__aexit__ = AsyncMock()
    
    mock_result = AsyncMock()
    mock_result.exit_status = 0
    mock_result.stdout = "!\nversion 17.9\nhostname HAI-HQ\n..."
    
    mock_conn.run = AsyncMock(return_value=mock_result)
    
    with patch("asyncssh.connect", return_value=mock_conn):
        # Run the _collect_via_ssh function
        creds = {"username": "admin", "password": "cisco"}
        config = await _collect_via_ssh("10.0.0.5", creds, "Cisco")
        
        # Check the result
        assert "version 17.9" in config
        assert "hostname HAI-HQ" in config

def test_no_device_state_access(mock_job_dir, mock_fingerprints_file, mock_state_dir):
    """Test that config collector does not access device_states directory."""
    # Create a device_states directory
    device_states_dir = mock_job_dir / "device_states"
    device_states_dir.mkdir()
    
    # Create a device state file
    device_state_path = device_states_dir / "HAI-HQ.json"
    with open(device_state_path, "w") as f:
        json.dump({"hostname": "HAI-HQ"}, f)
    
    # Mock get_fingerprints_path to return our mock fingerprints file
    def mock_get_fingerprints_path(job_id):
        return mock_fingerprints_file
    
    # Mock get_state_dir to return our mock state directory
    def mock_get_state_dir(job_id):
        return mock_state_dir
    
    # Mock get_state_path to return a path in our mock state directory
    def mock_get_state_path(job_id, hostname):
        return mock_state_dir / f"{hostname}.json"
    
    # Create a spy to check if device_states directory is accessed
    original_open = open
    
    def spy_open(*args, **kwargs):
        path = args[0]
        if isinstance(path, str) and "device_states" in path:
            pytest.fail("Config collector should not access device_states directory")
        return original_open(*args, **kwargs)
    
    # Mock open to use our spy
    with patch("builtins.open", spy_open), \
         patch("network_discovery.config_collector.get_fingerprints_path", mock_get_fingerprints_path), \
         patch("network_discovery.config_collector.get_state_dir", mock_get_state_dir), \
         patch("network_discovery.config_collector.get_state_path", mock_get_state_path), \
         patch("network_discovery.config_collector.update_status"), \
         patch("network_discovery.config_collector._collect_device_config", return_value={
             "status": "success",
             "hostname": "HAI-HQ",
             "state_path": str(mock_state_dir / "HAI-HQ.json")
         }):
        
        # Run the collect_all_state function
        creds = {"username": "admin", "password": "cisco"}
        asyncio.run(collect_all_state("test", creds))
        
        # If we get here without pytest.fail being called, the test passes

def test_concurrency(mock_job_dir, mock_fingerprints_file, mock_state_dir):
    """Test that concurrency is respected."""
    # Create a larger fingerprints result with multiple devices
    fingerprints_result = {
        "job_id": "test",
        "hosts": [
            {
                "ip": "10.0.0.5",
                "inference": {"vendor": "Cisco", "confidence": 0.9},
                "protocols": ["ssh"],
                "hostname": "HAI-HQ"
            },
            {
                "ip": "10.0.0.6",
                "inference": {"vendor": "Cisco", "confidence": 0.9},
                "protocols": ["ssh"],
                "hostname": "HAI-BRANCH-1"
            },
            {
                "ip": "10.0.0.7",
                "inference": {"vendor": "Cisco", "confidence": 0.9},
                "protocols": ["ssh"],
                "hostname": "HAI-BRANCH-2"
            }
        ]
    }
    
    # Write the fingerprints file
    fingerprints_path = mock_job_dir / "fingerprints.json"
    with open(fingerprints_path, "w") as f:
        json.dump(fingerprints_result, f)
    
    # Mock get_fingerprints_path to return our mock fingerprints file
    def mock_get_fingerprints_path(job_id):
        return fingerprints_path
    
    # Mock get_state_dir to return our mock state directory
    def mock_get_state_dir(job_id):
        return mock_state_dir
    
    # Mock get_state_path to return a path in our mock state directory
    def mock_get_state_path(job_id, hostname):
        return mock_state_dir / f"{hostname}.json"
    
    # Create a counter to track concurrent executions
    counter = 0
    max_concurrent = 0
    
    # Mock _collect_device_config to track concurrency
    async def mock_collect_device_config(device, creds, job_id, semaphore):
        nonlocal counter, max_concurrent
        async with semaphore:
            counter += 1
            max_concurrent = max(max_concurrent, counter)
            await asyncio.sleep(0.1)  # Simulate work
            counter -= 1
            return {
                "status": "success",
                "hostname": device["hostname"],
                "state_path": str(mock_state_dir / f"{device['hostname']}.json")
            }
    
    with patch("network_discovery.config_collector.get_fingerprints_path", mock_get_fingerprints_path), \
         patch("network_discovery.config_collector.get_state_dir", mock_get_state_dir), \
         patch("network_discovery.config_collector.get_state_path", mock_get_state_path), \
         patch("network_discovery.config_collector.update_status"), \
         patch("network_discovery.config_collector._collect_device_config", mock_collect_device_config):
        
        # Run the collect_all_state function with concurrency of 2
        creds = {"username": "admin", "password": "cisco"}
        asyncio.run(collect_all_state("test", creds, concurrency=2))
        
        # Check that concurrency was respected
        assert max_concurrent <= 2
