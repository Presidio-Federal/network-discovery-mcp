"""Tests for seeder module."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from network_discovery.seeder import _extract_targets, collect_seed


def test_extract_targets():
    """Test _extract_targets function."""
    # Test data
    device_data = {
        "interfaces": {
            "summary": [
                {"interface": "GigabitEthernet0/0", "ip_address": "192.168.1.1", "status": "up"},
                {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.1", "status": "up"},
                {"interface": "Loopback0", "ip_address": "172.16.0.1", "status": "up"}
            ],
            "details": [
                {"interface": "GigabitEthernet0/0", "ip_address": "192.168.1.1", "subnet": "24"},
                {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.1", "subnet": "24"},
                {"interface": "Loopback0", "ip_address": "172.16.0.1", "subnet": "32"}
            ]
        },
        "routing": {
            "default": [
                {"protocol": "C", "network": "192.168.1.0/24", "nexthop_ip": ""},
                {"protocol": "C", "network": "10.0.0.0/24", "nexthop_ip": ""},
                {"protocol": "S", "network": "0.0.0.0/0", "nexthop_ip": "192.168.1.254"}
            ],
            "vrf": {
                "management": [
                    {"protocol": "C", "network": "172.16.0.0/24", "nexthop_ip": ""}
                ]
            }
        },
        "arp": {
            "default": [
                {"address": "192.168.1.2", "mac": "00:11:22:33:44:55"},
                {"address": "192.168.1.3", "mac": "00:11:22:33:44:66"}
            ],
            "vrf": {}
        },
        "cdp": [
            {"device_id": "SWITCH1", "management_ip": "192.168.1.10"},
            {"device_id": "SWITCH2", "management_ip": "192.168.1.11"}
        ],
        "lldp": [
            {"neighbor": "ROUTER1", "management_ip": "10.0.0.2"}
        ]
    }
    
    seed_host = "192.168.1.1"
    
    # Call the function
    targets = _extract_targets(device_data, seed_host)
    
    # Check the result
    assert targets["seed_host"] == seed_host
    assert "collected_at" in targets
    assert "job_id" in targets
    
    # Check extracted subnets
    assert "192.168.1.0/24" in targets["subnets"]
    assert "10.0.0.0/24" in targets["subnets"]
    assert "172.16.0.0/24" in targets["subnets"]
    
    # Check extracted candidate IPs
    assert "192.168.1.1" in targets["candidate_ips"]
    assert "10.0.0.1" in targets["candidate_ips"]
    assert "172.16.0.1" in targets["candidate_ips"]
    assert "192.168.1.2" in targets["candidate_ips"]
    assert "192.168.1.3" in targets["candidate_ips"]
    assert "192.168.1.10" in targets["candidate_ips"]
    assert "192.168.1.11" in targets["candidate_ips"]
    assert "10.0.0.2" in targets["candidate_ips"]
    assert "192.168.1.254" in targets["candidate_ips"]


@patch("network_discovery.seeder._process_fixture")
@patch("network_discovery.seeder._collect_from_device")
@patch("network_discovery.seeder.update_status")
def test_collect_seed_fixture(mock_update_status, mock_collect_from_device, mock_process_fixture):
    """Test collect_seed function with a fixture."""
    # Mock Path.exists to return True
    with patch("pathlib.Path.exists", return_value=True):
        # Set up mocks
        mock_process_fixture.return_value = {"job_id": "test_job", "status": "completed"}
        
        # Call the function
        result = collect_seed("router1", {"username": "admin", "password": "cisco"}, "test_job")
        
        # Check that _process_fixture was called
        mock_process_fixture.assert_called_once()
        
        # Check that _collect_from_device was not called
        mock_collect_from_device.assert_not_called()
        
        # Check the result
        assert result["job_id"] == "test_job"
        assert result["status"] == "completed"


@patch("network_discovery.seeder._process_fixture")
@patch("network_discovery.seeder._collect_from_device")
@patch("network_discovery.seeder.update_status")
def test_collect_seed_device(mock_update_status, mock_collect_from_device, mock_process_fixture):
    """Test collect_seed function with a device."""
    # Mock Path.exists to return False
    with patch("pathlib.Path.exists", return_value=False):
        # Set up mocks
        mock_collect_from_device.return_value = {"job_id": "test_job", "status": "completed"}
        
        # Call the function
        result = collect_seed("router1", {"username": "admin", "password": "cisco"}, "test_job")
        
        # Check that _process_fixture was not called
        mock_process_fixture.assert_not_called()
        
        # Check that _collect_from_device was called
        mock_collect_from_device.assert_called_once()
        
        # Check the result
        assert result["job_id"] == "test_job"
        assert result["status"] == "completed"


@patch("network_discovery.seeder.update_status")
@patch("network_discovery.seeder.log_error")
def test_collect_seed_exception(mock_log_error, mock_update_status):
    """Test collect_seed function with an exception."""
    # Mock Path.exists to raise an exception
    with patch("pathlib.Path.exists", side_effect=Exception("Test exception")):
        # Call the function
        result = collect_seed("router1", {"username": "admin", "password": "cisco"}, "test_job")
        
        # Check that update_status was called with failed status
        mock_update_status.assert_called_with("test_job", "seeder", "failed", error="Test exception")
        
        # Check that log_error was called
        mock_log_error.assert_called_once()
        
        # Check the result
        assert result["job_id"] == "test_job"
        assert result["status"] == "failed"
        assert result["error"] == "Test exception"
