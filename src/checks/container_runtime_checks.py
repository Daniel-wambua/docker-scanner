import docker
from config import SENSITIVE_HOST_PATHS


def check_privileged_containers(container) -> list[dict]:
    findings = []
    host_config = container.attrs.get("HostConfig", {})
    if host_config.get("Privileged"):
        findings.append({
            "severity": "HIGH",
            "check": "Privileged container",
            "details": f"Container {container.name} runs in privileged mode"
        })
    return findings


def check_resource_limits(container) -> list[dict]:
    findings = []
    host_config = container.attrs.get("HostConfig", {})
    
    memory = host_config.get("Memory", 0)
    if memory == 0:
        findings.append({
            "severity": "MEDIUM",
            "check": "No memory limit",
            "details": f"Container {container.name} has no memory limit"
        })
    
    cpu_shares = host_config.get("CpuShares", 0)
    nano_cpus = host_config.get("NanoCpus", 0)
    if cpu_shares == 0 and nano_cpus == 0:
        findings.append({
            "severity": "MEDIUM",
            "check": "No CPU limit",
            "details": f"Container {container.name} has no CPU limit"
        })
    
    return findings


def check_host_network(container) -> list[dict]:
    findings = []
    host_config = container.attrs.get("HostConfig", {})
    network_mode = host_config.get("NetworkMode", "")
    if network_mode == "host":
        findings.append({
            "severity": "HIGH",
            "check": "Host network mode",
            "details": f"Container {container.name} uses host network"
        })
    return findings


def check_sensitive_mounts(container) -> list[dict]:
    findings = []
    mounts = container.attrs.get("Mounts", [])
    
    for mount in mounts:
        source = mount.get("Source", "")
        for sensitive_path in SENSITIVE_HOST_PATHS:
            if source == sensitive_path or (source.startswith(sensitive_path + "/") and sensitive_path != "/"):
                findings.append({
                    "severity": "HIGH",
                    "check": "Sensitive host path mounted",
                    "details": f"Container {container.name} mounts {source}"
                })
                break
    
    return findings


RUNTIME_CHECKS = [
    check_privileged_containers,
    check_resource_limits,
    check_host_network,
    check_sensitive_mounts,
]


def run_runtime_checks() -> list[dict]:
    try:
        client = docker.from_env()
        containers = client.containers.list()
    except docker.errors.DockerException as e:
        return [{
            "severity": "HIGH",
            "check": "Docker connection error",
            "details": f"Cannot connect to Docker: {str(e)}"
        }]
    
    findings = []
    for container in containers:
        for check in RUNTIME_CHECKS:
            findings.extend(check(container))
    
    return findings
