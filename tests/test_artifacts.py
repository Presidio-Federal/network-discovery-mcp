"""Tests for artifacts module."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from network_discovery.artifacts import atomic_write_json, read_json, update_status


def test_atomic_write_json():
    """Test atomic_write_json function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a test file path
        test_file = Path(tmp_dir) / "test.json"
        
        # Test data
        test_data = {"key": "value", "number": 42}
        
        # Write the data
        result = atomic_write_json(test_data, test_file)
        
        # Check the result
        assert result is True
        
        # Check that the file exists
        assert test_file.exists()
        
        # Check that the temporary file doesn't exist
        assert not test_file.with_suffix(".json.tmp").exists()
        
        # Read the file and check its contents
        with open(test_file, 'r') as f:
            content = json.load(f)
        
        assert content == test_data


def test_read_json():
    """Test read_json function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a test file
        test_file = Path(tmp_dir) / "test.json"
        test_data = {"key": "value", "number": 42}
        
        with open(test_file, 'w') as f:
            json.dump(test_data, f)
        
        # Read the file
        result = read_json(test_file)
        
        # Check the result
        assert result == test_data
        
        # Test reading a non-existent file
        non_existent_file = Path(tmp_dir) / "non_existent.json"
        result = read_json(non_existent_file)
        assert result is None
        
        # Test reading an invalid JSON file
        invalid_file = Path(tmp_dir) / "invalid.json"
        with open(invalid_file, 'w') as f:
            f.write("This is not valid JSON")
        
        result = read_json(invalid_file)
        assert result is None


def test_update_status(monkeypatch):
    """Test update_status function."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Mock get_job_dir to return our temporary directory
        def mock_get_job_dir(job_id):
            job_dir = Path(tmp_dir) / job_id
            job_dir.mkdir(exist_ok=True)
            return job_dir
        
        monkeypatch.setattr("network_discovery.artifacts.get_job_dir", mock_get_job_dir)
        
        # Test updating status for a new job
        job_id = "test_job"
        module = "seeder"
        status = "running"
        
        result = update_status(job_id, module, status, seed_host="192.168.1.1")
        
        # Check the result
        assert result is True
        
        # Check that the status file exists
        status_file = Path(tmp_dir) / job_id / "status.json"
        assert status_file.exists()
        
        # Read the status file and check its contents
        with open(status_file, 'r') as f:
            content = json.load(f)
        
        assert content["job_id"] == job_id
        assert content[module]["status"] == status
        assert content[module]["seed_host"] == "192.168.1.1"
        assert "updated_at" in content[module]
        
        # Test updating status for an existing job
        status = "completed"
        
        result = update_status(job_id, module, status, completed_at="2025-10-19T12:00:00Z")
        
        # Check the result
        assert result is True
        
        # Read the status file and check its contents
        with open(status_file, 'r') as f:
            content = json.load(f)
        
        assert content["job_id"] == job_id
        assert content[module]["status"] == status
        assert content[module]["seed_host"] == "192.168.1.1"  # Previous value preserved
        assert content[module]["completed_at"] == "2025-10-19T12:00:00Z"  # New value added
        
        # Test updating a different module
        module = "scanner"
        status = "running"
        
        result = update_status(job_id, module, status)
        
        # Check the result
        assert result is True
        
        # Read the status file and check its contents
        with open(status_file, 'r') as f:
            content = json.load(f)
        
        assert content["job_id"] == job_id
        assert content["seeder"]["status"] == "completed"  # Previous module preserved
        assert content[module]["status"] == status
        assert "updated_at" in content[module]
