from config import SENSITIVE_PORTS


def check_latest_tag(lines: list[str]) -> list[dict]:
    findings = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("FROM "):
            image = stripped[5:].split()[0]
            if ":latest" in image or ":" not in image:
                findings.append({
                    "severity": "HIGH",
                    "check": "Latest tag detected",
                    "details": f"Line {i+1}: {stripped}"
                })
    return findings


def check_missing_user(lines: list[str]) -> list[dict]:
    has_user = any(line.strip().startswith("USER ") for line in lines)
    if not has_user:
        return [{
            "severity": "MEDIUM",
            "check": "Missing USER directive",
            "details": "Container runs as root"
        }]
    return []


def check_sensitive_ports(lines: list[str]) -> list[dict]:
    findings = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("EXPOSE "):
            ports_str = stripped[7:]
            for port_str in ports_str.split():
                try:
                    port = int(port_str.split("/")[0])
                    if port in SENSITIVE_PORTS:
                        findings.append({
                            "severity": "HIGH",
                            "check": "Sensitive port exposed",
                            "details": f"Line {i+1}: Port {port}"
                        })
                except ValueError:
                    continue
    return findings


def check_add_instead_of_copy(lines: list[str]) -> list[dict]:
    findings = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("ADD ") and not any(x in stripped for x in [".tar", ".gz", ".zip", "http"]):
            findings.append({
                "severity": "LOW",
                "check": "ADD instead of COPY",
                "details": f"Line {i+1}: Use COPY for local files"
            })
    return findings


def check_missing_healthcheck(lines: list[str]) -> list[dict]:
    has_healthcheck = any(line.strip().startswith("HEALTHCHECK ") for line in lines)
    if not has_healthcheck:
        return [{
            "severity": "LOW",
            "check": "Missing HEALTHCHECK",
            "details": "No health monitoring configured"
        }]
    return []


DOCKERFILE_CHECKS = [
    check_latest_tag,
    check_missing_user,
    check_sensitive_ports,
    check_add_instead_of_copy,
    check_missing_healthcheck,
]


def run_dockerfile_checks(lines: list[str]) -> list[dict]:
    findings = []
    for check in DOCKERFILE_CHECKS:
        findings.extend(check(lines))
    return findings
