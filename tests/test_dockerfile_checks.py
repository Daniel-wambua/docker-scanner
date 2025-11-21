import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from checks.dockerfile_checks import (
    check_latest_tag,
    check_missing_user,
    check_sensitive_ports,
    check_add_instead_of_copy,
    check_missing_healthcheck,
    run_dockerfile_checks
)


def test_check_latest_tag():
    lines = ["FROM ubuntu:latest", "RUN apt-get update"]
    findings = check_latest_tag(lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "latest" in findings[0]["check"].lower()


def test_check_latest_tag_implicit():
    lines = ["FROM ubuntu", "RUN apt-get update"]
    findings = check_latest_tag(lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_check_latest_tag_with_version():
    lines = ["FROM ubuntu:20.04", "RUN apt-get update"]
    findings = check_latest_tag(lines)
    assert len(findings) == 0


def test_check_missing_user():
    lines = ["FROM ubuntu:20.04", "RUN apt-get update"]
    findings = check_missing_user(lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "USER" in findings[0]["check"]


def test_check_missing_user_with_user():
    lines = ["FROM ubuntu:20.04", "USER nobody"]
    findings = check_missing_user(lines)
    assert len(findings) == 0


def test_check_sensitive_ports():
    lines = ["FROM ubuntu:20.04", "EXPOSE 22", "EXPOSE 80"]
    findings = check_sensitive_ports(lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "22" in findings[0]["details"]


def test_check_sensitive_ports_none():
    lines = ["FROM ubuntu:20.04", "EXPOSE 8080"]
    findings = check_sensitive_ports(lines)
    assert len(findings) == 0


def test_check_add_instead_of_copy():
    lines = ["FROM ubuntu:20.04", "ADD app.py /app/", "COPY config.json /config/"]
    findings = check_add_instead_of_copy(lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert "ADD" in findings[0]["check"]


def test_check_add_for_archive():
    lines = ["FROM ubuntu:20.04", "ADD archive.tar.gz /app/"]
    findings = check_add_instead_of_copy(lines)
    assert len(findings) == 0


def test_check_missing_healthcheck():
    lines = ["FROM ubuntu:20.04", "RUN apt-get update"]
    findings = check_missing_healthcheck(lines)
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert "HEALTHCHECK" in findings[0]["check"]


def test_check_missing_healthcheck_with_healthcheck():
    lines = ["FROM ubuntu:20.04", "HEALTHCHECK CMD curl localhost"]
    findings = check_missing_healthcheck(lines)
    assert len(findings) == 0


def test_run_dockerfile_checks():
    lines = ["FROM ubuntu", "EXPOSE 22", "RUN apt-get update"]
    findings = run_dockerfile_checks(lines)
    assert len(findings) >= 3


def test_empty_dockerfile():
    lines = []
    findings = run_dockerfile_checks(lines)
    assert isinstance(findings, list)
