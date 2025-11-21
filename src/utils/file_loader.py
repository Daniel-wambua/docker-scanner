from pathlib import Path
from typing import Optional
import yaml


def load_dockerfile(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Dockerfile not found: {path}")
    
    with open(file_path, "r") as f:
        return [line.rstrip() for line in f.readlines()]


def load_compose_file(path: str) -> dict:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Compose file not found: {path}")
    
    with open(file_path, "r") as f:
        config = yaml.safe_load(f)
        return config if config else {}
