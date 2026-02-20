"""
Broker authorization policy files.

- broker_policies.json: Authorization policies for Linux (UID/GID matching)
- broker_policies_windows.json: Authorization policies for Windows (SID matching)

Broker configuration is in project_config.json (sections: aws, broker, service).
"""

from pathlib import Path

CONFIG_DIR = Path(__file__).parent

BROKER_POLICIES = CONFIG_DIR / "broker_policies.json"
BROKER_POLICIES_WINDOWS = CONFIG_DIR / "broker_policies_windows.json"


def get_policies_path(filename: str) -> Path:
    """Get path to a policy file in this directory."""
    return CONFIG_DIR / filename
