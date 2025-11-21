from config import SENSITIVE_PORTS


def check_running_as_root(config: dict) -> list[dict]:
    findings = []
    services = config.get("services", {})
    for name, service in services.items():
        if isinstance(service, dict):
            user = service.get("user")
            if not user or user == "root" or user == "0":
                findings.append({
                    "severity": "HIGH",
                    "check": "Container running as root",
                    "details": f"Service '{name}' has no user or runs as root"
                })
    return findings


def check_missing_resource_limits(config: dict) -> list[dict]:
    findings = []
    services = config.get("services", {})
    for name, service in services.items():
        if isinstance(service, dict):
            deploy = service.get("deploy", {})
            resources = deploy.get("resources", {})
            limits = resources.get("limits", {})
            
            if not limits.get("memory") and not service.get("mem_limit"):
                findings.append({
                    "severity": "MEDIUM",
                    "check": "Missing memory limit",
                    "details": f"Service '{name}' has no memory limit"
                })
            
            if not limits.get("cpus") and not service.get("cpus"):
                findings.append({
                    "severity": "MEDIUM",
                    "check": "Missing CPU limit",
                    "details": f"Service '{name}' has no CPU limit"
                })
    return findings


def check_privileged_mode(config: dict) -> list[dict]:
    findings = []
    services = config.get("services", {})
    for name, service in services.items():
        if isinstance(service, dict):
            if service.get("privileged"):
                findings.append({
                    "severity": "HIGH",
                    "check": "Privileged mode enabled",
                    "details": f"Service '{name}' runs in privileged mode"
                })
    return findings


def check_exposed_ports_without_mapping(config: dict) -> list[dict]:
    findings = []
    services = config.get("services", {})
    for name, service in services.items():
        if isinstance(service, dict):
            expose = service.get("expose", [])
            ports = service.get("ports", [])
            
            if expose and not ports:
                findings.append({
                    "severity": "LOW",
                    "check": "Exposed ports without mapping",
                    "details": f"Service '{name}' exposes ports but no port mapping"
                })
            
            for port_def in ports:
                if isinstance(port_def, str):
                    parts = port_def.split(":")
                    if len(parts) >= 2:
                        try:
                            host_port = int(parts[0])
                            if host_port in SENSITIVE_PORTS:
                                findings.append({
                                    "severity": "HIGH",
                                    "check": "Sensitive port mapped",
                                    "details": f"Service '{name}' maps sensitive port {host_port}"
                                })
                        except ValueError:
                            continue
    return findings


def check_unpinned_versions(config: dict) -> list[dict]:
    findings = []
    services = config.get("services", {})
    for name, service in services.items():
        if isinstance(service, dict):
            image = service.get("image", "")
            if image:
                if ":latest" in image or ":" not in image:
                    findings.append({
                        "severity": "HIGH",
                        "check": "Unpinned image version",
                        "details": f"Service '{name}' uses latest or no tag: {image}"
                    })
    return findings


COMPOSE_CHECKS = [
    check_running_as_root,
    check_missing_resource_limits,
    check_privileged_mode,
    check_exposed_ports_without_mapping,
    check_unpinned_versions,
]


def run_compose_checks(config: dict) -> list[dict]:
    findings = []
    for check in COMPOSE_CHECKS:
        findings.extend(check(config))
    return findings
