"""
Flow directory management.

This module manages the workflow directory lifecycle:
- Detects existing incomplete flows
- Creates new flow directories only when necessary
- Ensures all commands in the same workflow use the same directory
"""

from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

from utils.logging import get_logger

logger = get_logger(__name__)


class FlowManager:
    """
    Manages workflow directories for provisioning operations.
    
    A flow directory contains all artifacts for a single provisioning workflow:
    
    - application.bin.signed
    - oem_key_cert.bin, oem_code_cert.bin
    - combined.srec
    - public keys
    
    Rules:
    
    1. All commands in the same workflow MUST use the SAME flow directory
    2. Create NEW flow directory ONLY when no existing flow found,
       certificate version changed, or existing flow is COMPLETE
    3. Reuse existing flow if INCOMPLETE (missing files)
    """
    
    # Files that indicate a COMPLETE flow
    COMPLETE_FLOW_FILES = [
        "application.bin.signed",
        "certs/oem_key_cert_v{version}.bin",
        "certs/oem_code_cert_v{version}.bin",
        "combined.srec"
    ]
    
    def __init__(self, output_dir: Path):
        """
        Initialize flow manager.
        
        Args:
            output_dir: Base output directory (e.g., "output/")
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def get_or_create_flow(self, certificate_version: int, force_new: bool = False) -> Path:
        """
        Get existing flow directory or create new one.
        
        Args:
            certificate_version: Current certificate version from config
            force_new: Force creation of new flow directory (ignore existing)
        
        Returns:
            Path to flow directory to use
        """
        if force_new:
            flow_dir = self._create_new_flow()
            logger.info(f"Created NEW flow (force_new=True): {flow_dir.name}")
            return flow_dir
        
        # Find most recent flow
        existing_flow = self._find_latest_flow()
        
        if not existing_flow:
            # No existing flow found
            flow_dir = self._create_new_flow()
            logger.info(f"Created NEW flow (no existing flow): {flow_dir.name}")
            return flow_dir
        
        # Check if existing flow matches certificate version
        flow_version = self._get_flow_certificate_version(existing_flow)
        
        if flow_version is not None and flow_version != certificate_version:
            # Version mismatch - create new flow
            flow_dir = self._create_new_flow()
            logger.info(
                f"Created NEW flow (version changed: {flow_version} → {certificate_version}): "
                f"{flow_dir.name}"
            )
            return flow_dir
        
        # Check if existing flow is complete
        is_complete = self._is_flow_complete(existing_flow, certificate_version)
        
        if is_complete:
            # Flow is complete - create new one
            flow_dir = self._create_new_flow()
            logger.info(f"Created NEW flow (previous flow complete): {flow_dir.name}")
            return flow_dir
        
        # Reuse existing incomplete flow
        logger.info(f"Reusing EXISTING flow (incomplete): {existing_flow.name}")
        return existing_flow
    
    def _find_latest_flow(self) -> Optional[Path]:
        """
        Find the most recent flow directory.
        
        Returns:
            Path to latest flow directory, or None if no flows exist
        """
        flow_dirs = sorted(
            [d for d in self.output_dir.glob("flow_*") if d.is_dir()],
            key=lambda p: p.name,
            reverse=True
        )
        
        return flow_dirs[0] if flow_dirs else None
    
    def _create_new_flow(self) -> Path:
        """
        Create a new flow directory with timestamp.
        
        Returns:
            Path to new flow directory
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        flow_dir = self.output_dir / f"flow_{timestamp}"
        flow_dir.mkdir(parents=True, exist_ok=True)
        
        return flow_dir
    
    def _get_flow_certificate_version(self, flow_dir: Path) -> Optional[int]:
        """
        Extract certificate version from flow directory.
        
        Looks for certificate files like oem_key_cert_v1.bin to determine version.
        
        Args:
            flow_dir: Flow directory to inspect
        
        Returns:
            Certificate version number, or None if not found
        """
        certs_dir = flow_dir / "certs"
        if not certs_dir.exists():
            return None
        
        # Look for key certificate files
        for cert_file in certs_dir.glob("oem_key_cert_v*.bin"):
            try:
                # Extract version from filename: oem_key_cert_v1.bin -> 1
                version_str = cert_file.stem.split("_v")[-1]
                return int(version_str)
            except (ValueError, IndexError):
                continue
        
        return None
    
    def _is_flow_complete(self, flow_dir: Path, certificate_version: int) -> bool:
        """
        Check if a flow directory contains all required files.
        
        Args:
            flow_dir: Flow directory to check
            certificate_version: Certificate version to check for
        
        Returns:
            True if flow is complete (all files exist), False otherwise
        """
        required_files = [
            f.format(version=certificate_version) 
            for f in self.COMPLETE_FLOW_FILES
        ]
        
        for file_path in required_files:
            full_path = flow_dir / file_path
            if not full_path.exists():
                logger.debug(f"Flow incomplete - missing: {file_path}")
                return False
        
        logger.debug(f"Flow COMPLETE - all files present")
        return True


def get_current_flow(output_dir: Path, certificate_version: int, force_new: bool = False) -> Path:
    """
    Convenience function to get current flow directory.
    
    Args:
        output_dir: Base output directory
        certificate_version: Current certificate version from config
        force_new: Force creation of new flow
    
    Returns:
        Path to flow directory to use
    """
    manager = FlowManager(output_dir)
    return manager.get_or_create_flow(certificate_version, force_new)
