"""
Direct imgtool runner - uses ONLY imgtool/ from project folder.

NO wrapper, NO complexity - just runs imgtool/main.py directly.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from utils.exceptions import FirmwareError
from utils.logging import get_logger

logger = get_logger(__name__)

# Path to Renesas imgtool
IMGTOOL_DIR = Path(__file__).parent.parent / "imgtool"


def _get_imgtool_cmd() -> list:
    """Get command to run imgtool from project's imgtool/ folder."""
    if not IMGTOOL_DIR.exists() or not (IMGTOOL_DIR / "main.py").exists():
        raise FirmwareError(f"Renesas imgtool not found at: {IMGTOOL_DIR}")
    
    return [
        sys.executable, "-c",
        f"import sys; sys.path.insert(0, r'{IMGTOOL_DIR.parent}'); "
        f"from imgtool.main import imgtool; imgtool()"
    ]


def sign_image(
    input_file: Path,
    output_file: Path,
    key_file: Path,
    header_size: int,
    align: int,
    max_align: int,
    slot_size: int,
    max_sectors: int,
    version: str,
    pad_header: bool,
    pad: bool,
    confirm: bool,
) -> None:
    """
    Sign firmware image using Renesas imgtool.
    
    ALL PARAMETERS ARE REQUIRED (read from project_config.json).
    NO default values - caller MUST provide all parameters.
    
    Args:
        input_file: Input binary file
        output_file: Output signed binary file
        key_file: Private key file (PEM format)
        header_size: MCUboot header size (from imgtool.header_size)
        align: Flash alignment (from imgtool.align)
        max_align: Maximum flash alignment (from imgtool.max_align)
        slot_size: Image slot size (from imgtool.slot_size)
        max_sectors: Maximum sectors (from imgtool.max_sectors)
        version: Image version string (from imgtool.version)
        pad_header: Pad header to header_size (from imgtool.pad_header)
        pad: Pad image to slot_size (from imgtool.pad)
        confirm: Set image as confirmed (from imgtool.confirm)
    """
    cmd = _get_imgtool_cmd() + [
        "sign",
        "--key", str(key_file),
        "--header-size", hex(header_size),
        "--align", str(align),
        "--max-align", str(max_align),
        "--slot-size", hex(slot_size),
        "--max-sectors", str(max_sectors),
    ]
    
    if version:
        cmd.extend(["--version", version])
    
    if pad_header:
        cmd.append("--pad-header")
    
    if pad:
        cmd.append("--pad")
    
    if confirm:
        cmd.append("--confirm")
    
    cmd.extend([str(input_file), str(output_file)])
    
    logger.debug(f"Running imgtool: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        logger.info(f"Image signed: {output_file}")
    except subprocess.CalledProcessError as e:
        error_msg = f"imgtool sign failed: {e.stderr or e.stdout}"
        logger.error(error_msg)
        raise FirmwareError(error_msg) from e
    except subprocess.TimeoutExpired:
        raise FirmwareError("imgtool sign timed out")


def verify_image(image_file: Path, key_file: Path) -> bool:
    """
    Verify signed firmware image.
    
    Args:
        image_file: Signed binary file to verify
        key_file: Public key file (PEM format)
        
    Returns:
        True if signature is valid, False otherwise
    """
    cmd = _get_imgtool_cmd() + [
        "verify",
        "--key", str(key_file),
        str(image_file),
    ]
    
    logger.debug(f"Running imgtool verify: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        # imgtool verify returns 0 on success
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.error("imgtool verify timed out")
        return False
    except Exception as e:
        logger.error(f"imgtool verify failed: {e}")
        return False


def get_image_info(image_file: Path) -> dict:
    """
    Get information about a signed image.
    
    Args:
        image_file: Signed binary file
        
    Returns:
        Dictionary with image information
    """
    cmd = _get_imgtool_cmd() + [
        "dumpinfo",
        str(image_file),
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        info = {"raw_output": result.stdout}
        
        # Parse some common fields
        for line in result.stdout.splitlines():
            if "version:" in line.lower():
                info["version"] = line.split(":")[-1].strip()
            elif "image size:" in line.lower():
                info["image_size"] = line.split(":")[-1].strip()
                
        return info
    except Exception as e:
        logger.error(f"imgtool dumpinfo failed: {e}")
        return {}


class ImgToolRunner:
    """Simple class wrapper for backward compatibility."""
    
    @staticmethod
    def sign_image(**kwargs):
        return sign_image(**kwargs)
    
    @staticmethod
    def verify_image(image_file: Path, key_file: Path) -> bool:
        return verify_image(image_file, key_file)
    
    @staticmethod
    def get_image_info(image_file: Path) -> dict:
        return get_image_info(image_file)
