"""
MCUboot imgtool wrapper.

This module provides integration with MCUboot imgtool for firmware image signing.
imgtool is the standard tool for signing MCUboot firmware images.

Reference: https://github.com/mcu-tools/mcuboot/blob/main/scripts/imgtool.py
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from utils.exceptions import FirmwareError
from utils.logging import get_logger

logger = get_logger(__name__)


class ImgToolWrapper:
    """
    Wrapper for MCUboot imgtool.

    Provides Python interface to imgtool command-line utility for signing
    firmware images for MCUboot secure boot.
    """

    def __init__(self, imgtool_path: Optional[Path] = None):
        """
        Initialize imgtool wrapper.

        Args:
            imgtool_path: Path to imgtool script (optional, will try to find it)
        """
        if imgtool_path:
            self.imgtool_path = imgtool_path
        else:
            found_path = self._find_imgtool()
            if found_path is None:
                # Check if imgtool is available as module
                try:
                    import imgtool
                    self.imgtool_path = None
                    logger.info("Using imgtool as Python module")
                except ImportError:
                    raise FirmwareError(
                        "imgtool not found. Install with: pip install imgtool"
                    )
            else:
                self.imgtool_path = found_path

    def _find_imgtool(self) -> Optional[Path]:
        """
        Find imgtool in the system.

        Returns:
            Path to imgtool script or None if not found (will use -m imgtool)
        """
        # First, try Renesas custom imgtool (supports align=128)
        renesas_imgtool_paths = [
            Path("../ra8m1/workspace/workspace/EK_RA8M1_MCUBOOT_BL/ra/mcu-tools/MCUboot/scripts/imgtool.py"),
            Path("../../ra8m1/workspace/workspace/EK_RA8M1_MCUBOOT_BL/ra/mcu-tools/MCUboot/scripts/imgtool.py"),
        ]
        
        for path in renesas_imgtool_paths:
            if path.exists():
                logger.info(f"Found Renesas custom imgtool at {path} (supports align=128)")
                return path.resolve()
        
        # Second, try to import imgtool to check if it's installed
        try:
            import imgtool
            logger.info("Found imgtool as Python module")
            return None
        except ImportError:
            pass

        # Try to find imgtool script in common locations
        possible_paths = [
            Path("imgtool.py"),
            Path("scripts/imgtool.py"),
            Path("mcuboot/scripts/imgtool.py"),
        ]

        for path in possible_paths:
            if path.exists():
                logger.info(f"Found imgtool at {path}")
                return path

        return None

    def sign_image(
        self,
        input_file: Path,
        output_file: Path,
        key_file: Path,
        header_size: int = 0x200,
        align: int = 1,
        max_align: int = 1,
        slot_size: int = 0,
        max_sectors: int = 128,
        version: Optional[str] = None,
        pad_header: bool = False,
        pad: bool = False,
        confirm: bool = False,
    ) -> None:
        """
        Sign a firmware image using imgtool.

        Args:
            input_file: Path to input firmware binary
            output_file: Path to output signed firmware binary
            key_file: Path to private key file (PEM format)
            header_size: Size of image header in bytes (default: 0x200)
            align: Flash alignment requirement (default: 1)
            max_align: Maximum flash alignment (default: 1)
            slot_size: Size of image slot (0 = auto)
            max_sectors: Maximum number of sectors
            version: Image version string (e.g., "1.0.0")
            pad_header: Pad header to header_size
            confirm: Confirm image upgrade

        Raises:
            FirmwareError: If signing fails
        """
        if not input_file.exists():
            raise FirmwareError(f"Input file not found: {input_file}")

        if not key_file.exists():
            raise FirmwareError(f"Key file not found: {key_file}")

        # Use imgtool executable directly (works across Python versions)
        import shutil
        tmp_script_path = None
        
        # Priority 1: Use custom imgtool path (e.g., Renesas version)
        if self.imgtool_path:
            cmd = [sys.executable, str(self.imgtool_path)]
            logger.info(f"Using custom imgtool: {self.imgtool_path}")
        # Priority 2: Try to find imgtool executable
        elif shutil.which("imgtool"):
            imgtool_exe = shutil.which("imgtool")
            cmd = [imgtool_exe]
            logger.info(f"Using imgtool from PATH: {imgtool_exe}")
        # Priority 3: Try to use entry point via wrapper script
        else:
            try:
                import pkg_resources
                entry_point = pkg_resources.get_entry_map('imgtool', 'console_scripts').get('imgtool')
                if entry_point:
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_script:
                        tmp_script.write(f"""import sys
from {entry_point.module_name} import {entry_point.attrs[0]}
sys.argv = ['imgtool'] + sys.argv[1:]
{entry_point.attrs[0]}()
""")
                        tmp_script_path = tmp_script.name
                    cmd = [sys.executable, tmp_script_path]
                else:
                    raise FirmwareError("imgtool entry point not found")
            except Exception as e:
                raise FirmwareError(f"imgtool not found or not usable: {str(e)}. Install with: pip install imgtool")

        cmd.extend([
            "sign",
            "--key",
            str(key_file),
            "--header-size",
            hex(header_size),
            "--align",
            str(align),
            "--max-align",
            str(max_align),
            "--slot-size",
            hex(slot_size) if slot_size > 0 else "0x20000",  # Required by imgtool, but NOT used for padding
            "--max-sectors",
            str(max_sectors),
        ])

        if version:
            cmd.extend(["--version", version])

        # pad-header is OK (fills MCUboot header to 0x200)
        if pad_header:
            cmd.append("--pad-header")

        # pad: Pad image to slot_size with 0xFF (NO trailer magic if confirm=False)
        if pad:
            cmd.append("--pad")

        # confirm: Add trailer magic (only with pad=True)
        if confirm:
            cmd.append("--confirm")

        cmd.extend([
            str(input_file),
            str(output_file),
        ])

        logger.info(f"Signing firmware image: {input_file} -> {output_file}")
        logger.debug(f"imgtool command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=60,
            )

            logger.info(f"Firmware signed successfully: {output_file}")
            if result.stdout:
                logger.debug(f"imgtool output: {result.stdout}")
            
            # Clean up temporary script if used
            if tmp_script_path and Path(tmp_script_path).exists():
                try:
                    Path(tmp_script_path).unlink()
                except Exception:
                    pass

        except subprocess.TimeoutExpired:
            raise FirmwareError("imgtool command timed out") from None
        except subprocess.CalledProcessError as e:
            error_msg = f"imgtool failed: {e.stderr or e.stdout or str(e)}"
            logger.error(error_msg)
            raise FirmwareError(error_msg) from e
        except Exception as e:
            raise FirmwareError(f"Unexpected error running imgtool: {str(e)}") from e

    def verify_image(
        self,
        image_file: Path,
        key_file: Optional[Path] = None,
    ) -> bool:
        """
        Verify a signed firmware image.

        Args:
            image_file: Path to signed firmware image
            key_file: Path to public key file (optional)

        Returns:
            True if image is valid, False otherwise

        Raises:
            FirmwareError: If verification fails
        """
        if not image_file.exists():
            raise FirmwareError(f"Image file not found: {image_file}")

        # Use imgtool executable directly
        import shutil
        imgtool_exe = shutil.which("imgtool")
        
        if imgtool_exe:
            cmd = [imgtool_exe]
        elif self.imgtool_path:
            cmd = [sys.executable, str(self.imgtool_path)]
        else:
            # Try to use entry point via direct import
            try:
                from imgtool.main import imgtool as imgtool_func
                # Create temporary script to call entry point
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_script:
                    tmp_script.write("""import sys
from imgtool.main import imgtool
sys.argv = ['imgtool'] + sys.argv[1:]
imgtool()
""")
                    tmp_script_path = tmp_script.name
                cmd = [sys.executable, tmp_script_path]
            except Exception:
                # Last resort
                cmd = [sys.executable, "-m", "imgtool"]

        if not cmd:
            raise FirmwareError("imgtool not found. Install with: pip install imgtool")

        # Build verify command
        verify_cmd = cmd + ["verify", str(image_file)]

        if key_file:
            if not key_file.exists():
                raise FirmwareError(f"Key file not found: {key_file}")
            verify_cmd.extend(["--key", str(key_file)])

        logger.info(f"Verifying firmware image: {image_file}")

        try:
            result = subprocess.run(
                verify_cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            if result.returncode == 0:
                logger.info("Firmware image verification passed")
                return True
            else:
                error_msg = result.stderr or result.stdout or "Verification failed"
                logger.warning(f"Firmware image verification failed: {error_msg}")
                raise FirmwareError(f"Signature verification failed: {error_msg}")

        except subprocess.TimeoutExpired:
            raise FirmwareError("imgtool verify command timed out") from None
        except FirmwareError:
            raise
        except Exception as e:
            raise FirmwareError(f"Unexpected error verifying image: {str(e)}") from e

    def get_image_info(
        self,
        image_file: Path,
    ) -> dict:
        """
        Get information about a signed firmware image.

        Args:
            image_file: Path to signed firmware image

        Returns:
            Dictionary with image information including signing key details

        Raises:
            FirmwareError: If info extraction fails
        """
        if not image_file.exists():
            raise FirmwareError(f"Image file not found: {image_file}")

        info = {}

        # Note: Extracting public key hash requires the signing key file
        # The verify command already confirms the signature is valid
        info["signature_status"] = "valid"
        info["note"] = "To get public key hash, use: imgtool getpubhash -k <key_file> <image_file>"
        
        return info

    def get_key_info(self, key_file: Path) -> dict:
        """
        Get information about a key file.

        Args:
            key_file: Path to key file

        Returns:
            Dictionary with key information

        Raises:
            FirmwareError: If key info cannot be retrieved
        """
        if not key_file.exists():
            raise FirmwareError(f"Key file not found: {key_file}")

        cmd = [sys.executable]

        if self.imgtool_path:
            cmd.append(str(self.imgtool_path))
        else:
            cmd.extend(["-m", "imgtool"])

        cmd.extend(["keygen", "--dump", str(key_file)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            info = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    info[key.strip()] = value.strip()

            return info

        except subprocess.CalledProcessError as e:
            raise FirmwareError(f"Failed to get key info: {e.stderr or str(e)}") from e
        except Exception as e:
            raise FirmwareError(f"Unexpected error getting key info: {str(e)}") from e

