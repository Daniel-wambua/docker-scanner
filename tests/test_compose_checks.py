import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from checks.compose_checks import (
    check_running_as_root,
    check_missing_resource_limits,
    check_privileged_mode,
    check_exposed_ports_without_mapping,
    check_unpinned_versions,
    run_compose_checks
)


def test_check_running_as_root():
    config = {
        "services": {
            "web": {"image": "nginx:1.21"},
            "db": {"image": "postgres:13", "user": "postgres"}
        }
    }
    findings = check_running_as_root(config)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "web" in findings[0]["details"]


def test_check_running_as_root_explicit():
    config = {
        "services": {
            "web": {"image": "nginx:1.21", "user": "root"}
        }
    }
    findings = check_running_as_root(config)
    assert len(findings) == 1


def test_check_missing_resource_limits():
    config = {
        "services": {
            "web": {"image": "nginx:1.21"}
        }
    }
    findings = check_missing_resource_limits(config)
    assert len(findings) == 2
    assert any("memory" in f["check"].lower() for f in findings)
    assert any("cpu" in f["check"].lower() for f in findings)


def test_check_missing_resource_limits_with_limits():
    config = {
        "services": {
            "web": {
                "image": "nginx:1.21",
                "mem_limit": "512m",
                "cpus": "0.5"
            }
        }
    }
    findings = check_missing_resource_limits(config)
    assert len(findings) == 0


def test_check_privileged_mode():
    config = {
        "services": {
            "web": {"image": "nginx:1.21", "privileged": True}
        }
    }
    findings = check_privileged_mode(config)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "privileged" in findings[0]["check"].lower()


def test_check_privileged_mode_false():
    config = {
        "services": {
            "web": {"image": "nginx:1.21", "privileged": False}
        }
    }
    findings = check_privileged_mode(config)
    assert len(findings) == 0


def test_check_exposed_ports_without_mapping():
    config = {
        "services": {
            "web": {"image": "nginx:1.21", "expose": ["80"]}
        }
    }
    findings = check_exposed_ports_without_mapping(config)
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"


def test_check_exposed_ports_with_mapping():
    config = {
        "services": {
            "web": {"image": "nginx:1.21", "expose": ["80"], "ports": ["8080:80"]}
        }
    }
    findings = check_exposed_ports_without_mapping(config)
    assert len(findings) == 0


def test_check_sensitive_port_mapping():
    config = {
        "services": {
            "ssh": {"image": "openssh", "ports": ["22:22"]}
        }
    }
    findings = check_exposed_ports_without_mapping(config)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "22" in findings[0]["details"]


def test_check_unpinned_versions():
    config = {
        "services": {
            "web": {"image": "nginx:latest"},
            "db": {"image": "postgres"}
        }
    }
    findings = check_unpinned_versions(config)
    assert len(findings) == 2
    assert all(f["severity"] == "HIGH" for f in findings)


def test_check_unpinned_versions_with_pinned():
    config = {
        "services": {
            "web": {"image": "nginx:1.21.3"}
        }
    }
    findings = check_unpinned_versions(config)
    assert len(findings) == 0


def test_run_compose_checks():
    config = {
        "services": {
            "web": {"image": "nginx", "privileged": True}
        }
    }
    findings = run_compose_checks(config)
    assert len(findings) >= 3


def test_empty_config():
    config = {}
    findings = run_compose_checks(config)
    assert isinstance(findings, list)


def test_malformed_service():
    config = {
        "services": {
            "web": "nginx:latest"
        }
    }
    findings = run_compose_checks(config)
    assert isinstance(findings, list)
