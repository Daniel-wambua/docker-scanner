import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from unittest.mock import Mock, MagicMock
from checks.container_runtime_checks import (
    check_privileged_containers,
    check_resource_limits,
    check_host_network,
    check_sensitive_mounts
)


def test_check_privileged_containers():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {
            "Privileged": True
        }
    }
    findings = check_privileged_containers(container)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "privileged" in findings[0]["check"].lower()


def test_check_privileged_containers_not_privileged():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {
            "Privileged": False
        }
    }
    findings = check_privileged_containers(container)
    assert len(findings) == 0


def test_check_resource_limits_no_limits():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {
            "Memory": 0,
            "CpuShares": 0,
            "NanoCpus": 0
        }
    }
    findings = check_resource_limits(container)
    assert len(findings) == 2
    assert any("memory" in f["check"].lower() for f in findings)
    assert any("cpu" in f["check"].lower() for f in findings)


def test_check_resource_limits_with_limits():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {
            "Memory": 536870912,
            "CpuShares": 1024,
            "NanoCpus": 0
        }
    }
    findings = check_resource_limits(container)
    assert len(findings) == 0


def test_check_host_network():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {
            "NetworkMode": "host"
        }
    }
    findings = check_host_network(container)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "network" in findings[0]["check"].lower()


def test_check_host_network_bridge():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {
            "NetworkMode": "bridge"
        }
    }
    findings = check_host_network(container)
    assert len(findings) == 0


def test_check_sensitive_mounts():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "Mounts": [
            {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}
        ]
    }
    findings = check_sensitive_mounts(container)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "docker.sock" in findings[0]["details"]


def test_check_sensitive_mounts_root():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "Mounts": [
            {"Source": "/", "Destination": "/host"}
        ]
    }
    findings = check_sensitive_mounts(container)
    assert len(findings) == 1


def test_check_sensitive_mounts_safe():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "Mounts": [
            {"Source": "/data/app", "Destination": "/app"}
        ]
    }
    findings = check_sensitive_mounts(container)
    assert len(findings) == 0


def test_container_no_mounts():
    container = Mock()
    container.name = "test_container"
    container.attrs = {
        "HostConfig": {},
        "Mounts": []
    }
    findings = check_sensitive_mounts(container)
    assert len(findings) == 0
