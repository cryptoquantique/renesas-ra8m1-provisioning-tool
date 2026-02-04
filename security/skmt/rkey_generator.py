"""
RKEY file generation workflow.

This module provides a complete workflow for generating .rkey files
by combining DLM UFPK wrapping with SKMT OEM Root key wrapping.
"""

from pathlib import Path
from typing import Optional

from config.settings import DLMConfig, PGPConfig, SKMTConfig
from utils.exceptions import DLMError, PGPError, SKMTError
from utils.logging import get_logger
from security.dlm.ufpk_wrapper import UFPKWrapper
from security.skmt.wrapper import SKMTWrapper

logger = get_logger(__name__)


class RKeyGenerator:
    """
    Complete workflow for generating .rkey files.

    This class orchestrates:
    1. Wrap UFPK through DLM (if needed)
    2. Wrap OEM Root public key with wrapped UFPK using SKMT
    3. Generate .rkey file
    """

    def __init__(
        self,
        skmt_config: SKMTConfig,
        pgp_config: Optional[PGPConfig] = None,
        dlm_config: Optional[DLMConfig] = None,
    ):
        """
        Initialize RKEY generator.

        Args:
            skmt_config: SKMT configuration
            pgp_config: Optional PGP configuration (required if using DLM)
            dlm_config: Optional DLM configuration (required if using DLM)
        """
        self.skmt_config = skmt_config
        self.pgp_config = pgp_config
        self.dlm_config = dlm_config
        self.skmt_wrapper = SKMTWrapper(
            skmt_path=skmt_config.skmt_path,
            working_directory=skmt_config.working_directory,
        )

    def generate_rkey(
        self,
        oem_root_pk_file: Path,
        ufpk_file: Path,
        output_file: Path,
        ufpk_is_wrapped: bool = False,
        device_id: Optional[str] = None,
    ) -> Path:
        """
        Generate .rkey file from OEM Root public key and UFPK.

        This method performs the complete workflow:
        1. If UFPK is not wrapped and DLM is configured, wrap UFPK through DLM
        2. Wrap OEM Root public key with (wrapped) UFPK using SKMT
        3. Generate .rkey file

        Args:
            oem_root_pk_file: Path to OEM Root public key file (PEM format)
            ufpk_file: Path to UFPK file (plain or wrapped)
            output_file: Path to output .rkey file
            ufpk_is_wrapped: Whether UFPK is already wrapped (skip DLM if True)
            device_id: Optional device ID for DLM operations

        Returns:
            Path to generated .rkey file

        Raises:
            SKMTError: If SKMT operations fail
            DLMError: If DLM operations fail (when needed)
            PGPError: If PGP operations fail (when needed)
        """
        if not oem_root_pk_file.exists():
            raise SKMTError(f"OEM Root public key file not found: {oem_root_pk_file}")

        if not ufpk_file.exists():
            raise SKMTError(f"UFPK file not found: {ufpk_file}")

        try:
            ufpk_to_use = ufpk_file

            if not ufpk_is_wrapped:
                if self.dlm_config and self.pgp_config:
                    logger.info("UFPK is not wrapped, wrapping through DLM...")
                    wrapped_ufpk = self._wrap_ufpk_through_dlm(
                        ufpk_file, device_id
                    )
                    ufpk_to_use = wrapped_ufpk
                else:
                    logger.warning(
                        "UFPK is not wrapped but DLM is not configured. "
                        "Assuming UFPK is already wrapped or will be provided wrapped."
                    )

            logger.info("Wrapping OEM Root public key with UFPK using SKMT...")
            oem_root_pk_bytes = oem_root_pk_file.read_bytes()

            wrapped_key = self.skmt_wrapper.wrap_oem_root_public_key(
                oem_root_pk=oem_root_pk_bytes,
                ufpk=str(ufpk_to_use),
                output_file=str(output_file),
            )

            logger.info(f"RKEY file generated successfully: {output_file}")
            return Path(wrapped_key.file_path)

        except Exception as e:
            if isinstance(e, (SKMTError, DLMError, PGPError)):
                raise
            raise SKMTError(f"Failed to generate RKEY file: {str(e)}") from e

    def _wrap_ufpk_through_dlm(
        self, ufpk_file: Path, device_id: Optional[str] = None
    ) -> Path:
        """
        Wrap UFPK through DLM server.

        Args:
            ufpk_file: Path to plain UFPK file
            device_id: Optional device ID

        Returns:
            Path to wrapped UFPK file

        Raises:
            DLMError: If DLM wrapping fails
        """
        import tempfile

        if not self.dlm_config or not self.pgp_config:
            raise DLMError("DLM and PGP configuration required for UFPK wrapping")

        temp_dir = Path(tempfile.mkdtemp(prefix="rkey_gen_"))
        wrapped_ufpk = temp_dir / "wrapped_ufpk.key"

        try:
            wrapper = UFPKWrapper(self.pgp_config, self.dlm_config)
            wrapped_file = wrapper.wrap_ufpk_complete(
                ufpk_file=ufpk_file,
                output_file=wrapped_ufpk,
                device_id=device_id,
            )
            return wrapped_file
        except Exception as e:
            import shutil
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            raise



