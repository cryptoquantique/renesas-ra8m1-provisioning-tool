"""
Renesas Key Verification Utilities.

This module provides utilities to verify and locate Renesas public key files.
"""

from pathlib import Path
from typing import List


def verify_renesas_public_key(key_path: Path) -> bool:
    """
    Verify that a file is a valid Renesas public key.
    
    Args:
        key_path: Path to the key file
        
    Returns:
        True if the key appears to be a valid Renesas public key, False otherwise
    """
    if not key_path.exists() or not key_path.is_file():
        return False
    
    try:
        # Read first few bytes to check if it looks like a PGP key
        with open(key_path, 'rb') as f:
            header = f.read(100)
        
        # Check for ASCII armored PGP key markers
        header_str = header.decode('utf-8', errors='ignore')
        if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in header_str:
            return True
        
        # Check for binary PGP key format
        # PGP keys typically start with specific packet tags
        if len(header) > 0 and header[0] in [0x99, 0x98, 0x95, 0x94]:
            return True
        
        # For .key files, check if it's a raw RSA key
        if key_path.suffix.lower() == '.key':
            # Raw keys are typically 256-512 bytes for RSA 2048-4096
            file_size = key_path.stat().st_size
            if 200 < file_size < 1024:
                return True
        
        return False
        
    except Exception:
        return False


def find_renesas_key_files() -> List[Path]:
    """
    Search for Renesas public key files in common locations.
    
    Returns:
        List of paths to potential Renesas key files
    """
    found_keys = []
    
    # Define search locations
    current_dir = Path.cwd()
    project_root = current_dir
    
    # Try to find project root (where provisioning_tool directory is)
    if current_dir.name == "provisioning_tool":
        project_root = current_dir.parent
    elif (current_dir / "provisioning_tool").exists():
        project_root = current_dir
    
    # Common file names for Renesas keys
    common_names = [
        "keywrap-pub.key",
        "keywrap-pub.asc",
        "Keywrap-pub.key",
        "Keywrap-pub.asc",
        "renesas_public_key.asc",
        "renesas_public_key.key",
        "Renesas-pub.key",
        "Renesas-pub.asc",
    ]
    
    # Search locations
    search_dirs = [
        project_root / "prerequisites",  # Preferred location
        project_root / "provisioning_tool" / "prerequisites",
        project_root,
        project_root.parent,  # Parent directory (e.g., C:\Work\Renesas)
        current_dir,
    ]
    
    # Search for keys
    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        
        for name in common_names:
            key_path = search_dir / name
            if key_path.exists() and key_path.is_file():
                # Verify it looks like a valid key
                if verify_renesas_public_key(key_path):
                    if key_path not in found_keys:
                        found_keys.append(key_path)
    
    return found_keys
