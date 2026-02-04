"""
Output file management utilities.

Provides default output directories with timestamp-based organization.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional


def get_output_base_dir() -> Path:
    """
    Get base output directory.
    
    Returns:
        Path to output directory (created if doesn't exist)
    """
    # Get project root (assuming this file is in utils/)
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent
    output_dir = project_root / "output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


def get_timestamped_dir(prefix: str = "keys") -> Path:
    """
    Get timestamped output directory.
    
    Args:
        prefix: Directory name prefix (e.g., "keys", "firmware", "encrypted")
    
    Returns:
        Path to timestamped directory (created if doesn't exist)
    
    Example:
        get_timestamped_dir("keys") -> output/keys_20251212_143000/
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_name = f"{prefix}_{timestamp}"
    output_dir = get_output_base_dir() / dir_name
    output_dir.mkdir(exist_ok=True, parents=True)
    return output_dir


def get_default_output_path(filename: str, prefix: str = "keys") -> Path:
    """
    Get default output file path in timestamped directory.
    
    Args:
        filename: Output filename (e.g., "ufpk.key", "oem_root.rkey")
        prefix: Directory prefix (e.g., "keys", "firmware", "encrypted")
    
    Returns:
        Full path to output file
    
    Example:
        get_default_output_path("ufpk.key", "keys") 
        -> output/keys_20251212_143000/ufpk.key
    """
    output_dir = get_timestamped_dir(prefix)
    return output_dir / filename


def get_latest_output_dir(prefix: str = "keys") -> Optional[Path]:
    """
    Get the most recent timestamped output directory.
    
    Args:
        prefix: Directory name prefix
    
    Returns:
        Path to latest directory, or None if no directories exist
    """
    base_dir = get_output_base_dir()
    matching_dirs = [
        d for d in base_dir.iterdir()
        if d.is_dir() and d.name.startswith(f"{prefix}_")
    ]
    
    if not matching_dirs:
        return None
    
    # Sort by name (timestamp is sortable)
    matching_dirs.sort(key=lambda x: x.name, reverse=True)
    return matching_dirs[0]


def ensure_output_dir(path: Path) -> Path:
    """
    Ensure output directory exists for given file path.
    
    Args:
        path: File path (directory will be created if needed)
    
    Returns:
        Path with directory created
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    return path



