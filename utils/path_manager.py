"""
Path Manager for Provisioning Tool.

Manages all folder paths: prerequisites, reusable assets, flow output folders.
"""

import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from utils.logging import get_logger

logger = get_logger(__name__)


class PathManager:
    """Manages project folder paths and structure."""
    
    # Project root (provisioning_tool/)
    PROJECT_ROOT = Path(__file__).parent.parent
    
    # Prerequisites folder (user provides bootloader.srec, application.bin, etc.)
    PREREQUISITES_FOLDER = PROJECT_ROOT / "prerequisites"
    
    # Reusable folder (keys, certificates that can be reused across devices)
    REUSABLE_FOLDER = PROJECT_ROOT / "output" / "reusable"
    
    # Output folder (timestamped flow folders)
    OUTPUT_FOLDER = PROJECT_ROOT / "output"
    
    # Flow folder (current timestamped output)
    _current_flow_folder: Optional[Path] = None
    
    def get_prerequisites_folder(self) -> Path:
        """
        Get or create prerequisites folder in project root.
        
        Returns:
            Path to prerequisites/ folder
        """
        self.PREREQUISITES_FOLDER.mkdir(exist_ok=True)
        return self.PREREQUISITES_FOLDER
    
    def get_reusable_folder(self) -> Path:
        """
        Get or create reusable assets folder for keys and certificates.
        
        Returns:
            Path to output/reusable/ folder
        """
        self.REUSABLE_FOLDER.mkdir(parents=True, exist_ok=True)
        return self.REUSABLE_FOLDER
    
    def get_flow_folder(self) -> Path:
        """
        Get or create current flow folder with timestamp.
        
        If folder doesn't exist yet, creates one with format: flow_YYYYMMDD_HHMMSS
        Returns the same folder for subsequent calls in same workflow run.
        
        Returns:
            Path to current flow folder (e.g., output/flow_20240115_143022/)
        """
        if self._current_flow_folder is not None:
            return self._current_flow_folder
        
        # Create timestamped folder
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        flow_folder = self.OUTPUT_FOLDER / f"flow_{timestamp}"
        flow_folder.mkdir(parents=True, exist_ok=True)
        
        self._current_flow_folder = flow_folder
        return flow_folder
    
    def reset_flow_folder(self) -> None:
        """Reset current flow folder (for new workflow run)."""
        self._current_flow_folder = None
    
    def open_in_explorer(self, folder: Path) -> None:
        """
        Open folder in Windows Explorer.
        
        Args:
            folder: Path to folder to open
        """
        try:
            subprocess.run(["explorer", str(folder.absolute())], check=False)
        except Exception as e:
            logger.warning(f"Failed to open folder: {e}")


# Global instance
path_manager = PathManager()
