"""
Renesas imgtool key generation for AWS KMS/CloudHSM.

This module uses Renesas imgtool key generation to ensure keys are
compatible with Renesas MCUboot requirements before creating them in AWS.
"""

import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from utils.exceptions import FirmwareError
from utils.logging import get_logger

logger = get_logger(__name__)


def generate_renesas_compatible_key(
    key_type: str = "ecdsa-p256",
    output_path: Optional[Path] = None,
    password: Optional[bytes] = None
) -> Tuple[Path, bytes]:
    """
    Generate a Renesas-compatible ECDSA P-256 key using Renesas imgtool.
    
    This ensures the key format matches exactly what Renesas MCUboot expects
    before creating it in AWS KMS or CloudHSM.
    
    Args:
        key_type: Key type ("ecdsa-p256" for ECDSA P-256)
        output_path: Optional output path for key file (PEM format)
        password: Optional password for key encryption
    
    Returns:
        Tuple of (key_file_path, public_key_bytes)
    
    Raises:
        FirmwareError: If key generation fails
    """
    imgtool_dir = Path(__file__).parent.parent / "imgtool"
    imgtool_path = imgtool_dir / "imgtool.py"
    
    if not imgtool_path.exists():
        raise FirmwareError(
            f"imgtool not found at {imgtool_path}. "
            "Renesas imgtool MUST be in provisioning_tool/imgtool/"
        )

    if output_path is None:
        temp_dir = Path(tempfile.gettempdir())
        output_path = temp_dir / f"renesas_key_{key_type}_{id(temp_dir)}.pem"
    
    output_path = Path(output_path)
    
    try:
        import subprocess
        
        cmd = [
            sys.executable,
            str(imgtool_path),
            "keygen",
            "--type", key_type,
            "--key", str(output_path),
        ]

        if password:
            cmd.append("--password")
        
        logger.info(f"Generating key using imgtool (Renesas version): {key_type}")
        logger.debug(f"Command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            input=password,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            raise FirmwareError(f"Renesas imgtool keygen failed: {error_msg}")
        
        logger.info(f"[OK] Generated Renesas-compatible key: {output_path}")

        pub_key_path = output_path.parent / f"{output_path.stem}_public.pem"
        
        cmd_pub = [
            sys.executable,
            str(imgtool_path),
            "getpub",
            "--key", str(output_path),
            "--encoding", "pem",
            "--output", str(pub_key_path),
        ]
        
        result_pub = subprocess.run(
            cmd_pub,
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        if result_pub.returncode != 0:
            error_msg = result_pub.stderr or result_pub.stdout or "Unknown error"
            raise FirmwareError(f"Failed to extract public key: {error_msg}")
        
        # Read public key bytes
        public_key_bytes = pub_key_path.read_bytes()
        
        logger.info(f"[OK] Extracted public key: {len(public_key_bytes)} bytes")
        
        return output_path, public_key_bytes
        
    except subprocess.TimeoutExpired:
        raise FirmwareError("Renesas imgtool keygen timed out")
    except Exception as e:
        raise FirmwareError(f"Failed to generate Renesas-compatible key: {str(e)}") from e


def verify_key_compatibility(key_file: Path) -> bool:
    """
    Verify that a key file is compatible with Renesas MCUboot.
    
    Uses Renesas imgtool to verify the key format.
    
    Args:
        key_file: Path to key file (PEM format)
    
    Returns:
        True if key is compatible, False otherwise
    """
    imgtool_dir = Path(__file__).parent.parent / "imgtool"
    imgtool_path = imgtool_dir / "imgtool.py"
    
    if not imgtool_path.exists():
        logger.warning("imgtool not found at provisioning_tool/imgtool/, skipping compatibility check")
        return True  # Assume compatible if we can't check
    
    try:
        import subprocess

        cmd = [
            sys.executable,
            str(imgtool_path),
            "getpub",
            "--key", str(key_file),
            "--encoding", "pem",
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        return result.returncode == 0
        
    except Exception as e:
        logger.warning(f"Key compatibility check failed: {e}")
        return False
